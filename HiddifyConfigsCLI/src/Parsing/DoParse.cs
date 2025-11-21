// src/Parsing/DoParse.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace HiddifyConfigsCLI.src.Parsing;

internal static class DoParse
{
    public static Regex LinkRegex => RegexPatterns.LinkRegex;

    // -----------------------------------------------------------------
    // 1. 下载并提取（主入口）
    // -----------------------------------------------------------------
    public static async Task<List<string>> DownloadAndExtractAsync( RunOptions opts )
    {
        // 防御性检查
        if (opts == null) throw new ArgumentNullException(nameof(opts));
        if (string.IsNullOrWhiteSpace(opts.Input))
            throw new ArgumentException("输入路径不能为空", nameof(opts.Input));

        var inputContent = await DownloadInputAsync(opts);

        // 整体 Base64 检测与解码
        if (Base64ProtocolDecoder.IsWholeBase64(inputContent))
        {
            LogHelper.Info("检测到输入文件为 Base64 编码格式，正在整体解码...");
            try
            {
                inputContent = Base64ProtocolDecoder.DecodeWholeBase64(inputContent);
                LogHelper.Info(" └─ 文件整体 Base64 解码成功");

                // 调试信息
                LogHelper.Debug($"解码预览:\n{inputContent}\n");
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"整体 Base64 解码失败（跳过整体解码）：{ex.Message}");
            }
        }

        // [关键] 判断输入是远程 URL 还是本地文件
        bool isRemoteInput = Uri.TryCreate(opts.Input, UriKind.Absolute, out var inputUri) &&
                             (inputUri.Scheme == Uri.UriSchemeHttp || inputUri.Scheme == Uri.UriSchemeHttps);

        LogHelper.Info($"输入类型: {(isRemoteInput ? "远程 URL 列表" : "本地文件")}");

        var allLinks = new List<string>();

        // 如果内容是链接列表（http/https），无论远程还是本地，均再次解析
        var subUrls = inputContent
        .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        .Select(l => l.Trim())
        .Where(l => !string.IsNullOrEmpty(l) &&
                    !IsCommentLine(l) &&
                    Uri.TryCreate(l, UriKind.Absolute, out var u) &&
                    (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))      // 解析 http/https 链接
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

        if (subUrls.Count > 0)
        {
            // 1：内容包含链接列表 → 批量下载（无论来源是远程还是本地）
            LogHelper.Info($"检测到 {subUrls.Count} 个子列表，开始批量下载并解析节点...");
            foreach (var url in subUrls)
            {
                try
                {
                    LogHelper.Info($" ├─ 下载子列表: {url}");
                    using var client = CreateHttpClient(opts);
                    var content = await client.GetStringAsync(url).ConfigureAwait(false);
                    var links = ExtractLinksFromText(content);
                    allLinks.AddRange(links);
                    LogHelper.Info($" └─ 提取节点 {links.Count} 条");
                }
                catch (Exception ex)
                {
                    LogHelper.Warn($" 子列表下载失败（跳过）: {url} → {ex.Message}");
                }
            }
        }
        else
        {
            // 2：否则 → 直接解析为节点列表
            LogHelper.Info("未检测到子列表链接，直接解析当前内容为节点列表");
            var links = ExtractLinksFromText(inputContent);
            allLinks.AddRange(links);
            LogHelper.Info($" └─ 提取节点 {links.Count} 条");
        }        

        // 标签或备注没有去重
        // return allLinks.Distinct().ToList();
        // 去重（去除 #备注后去重）
        // 目的：同一节点不同备注只保留一个，防止重复检测、重复输出
        // 做法：构建 (无备注链接 → 原始带备注链接) 的映射，取第一个出现的原始链接
        var uniqueLinks = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var link in allLinks)
        {
            var key = RemoveRemark(link);  // 去掉 #后面的备注作为去重键
            if (!uniqueLinks.ContainsKey(key))
            {
                uniqueLinks[key] = link;   // 只保留第一次出现的原始链接（带完整备注）
            }
        }

        var finalResult = uniqueLinks.Values.ToList();
        LogHelper.Info($"最终去重后得到 {finalResult.Count} 条唯一节点（已去除重复备注）");
        return finalResult;
    }

    // -----------------------------------------------------------------
    // 2. 从文本中提取协议链接（核心解析）
    // -----------------------------------------------------------------
    private static List<string> ExtractLinksFromText( string text )
    {
        var links = new List<string>();
        var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        bool inBlockComment = false;

        foreach (var rawLine in lines)
        {
            string line = rawLine.Trim();

            // ---------- 块注释跨行处理 ----------
            if (inBlockComment)
            {
                if (line.Contains("*/"))
                {
                    inBlockComment = false;
                    line = line.Split(new[] { "*/" }, 2, StringSplitOptions.None)[0];
                }
                else continue;
            }
            else if (line.Contains("/*") && line.Contains("*/"))
            {
                var parts = line.Split(new[] { "/*" }, 2, StringSplitOptions.None);
                line = parts[0];
                if (parts.Length > 1 && parts[1].Contains("*/")) continue;
            }
            else if (line.Contains("/*"))
            {
                var parts = line.Split(new[] { "/*" }, 2, StringSplitOptions.None);
                line = parts[0];
                inBlockComment = true;
            }

            // ---------- 新增 解码 Base64 编码行 ----------
            line = Base64ProtocolDecoder.TryDecode(line);
            // 在这里统一消灭 HTML 实体污染（&amp;）
            line = System.Net.WebUtility.HtmlDecode(line);
            line = line.Replace("&AMP;", "&", StringComparison.OrdinalIgnoreCase);
            // 保险起见：有些订阅把整个链接 Base64 了，里面还有 &amp;
            line = Base64ProtocolDecoder.TryDecode(line);  // 再解一次，防止嵌套

            // 正常流程
            if (string.IsNullOrWhiteSpace(line) ||
                RegexPatterns.CommentOrEmptyRegex.IsMatch(line) ||
                RegexPatterns.Base64LineRegex.IsMatch(line))
                continue;

            // 处理路径、查询字符串参数
            if (RegexPatterns.PathHasQEdRegex.IsMatch(line) ||
                RegexPatterns.PathMultiQueryRegex.IsMatch(line))
            {
                line = RegexPatterns.PathValueRegex.Replace(
                    line,
                    m =>
                    {
                        var pathValue = m.Groups[1].Value;
                        if (pathValue.Count(c => c == '?') > 1)
                        {
                            int firstQ = pathValue.IndexOf('?');
                            var fixedPath = pathValue[..(firstQ + 1)] +
                                            pathValue[(firstQ + 1)..].Replace('?', '&');
                            return "path=" + fixedPath;
                        }
                        return m.Value;
                    });

                line = RegexPatterns.FixQEdRegex.Replace(line, "path=/$1&ed=");
                line = RegexPatterns.EdValueFullRegex.Replace(
                    line,
                    m =>
                    {
                        var digitMatch = RegexPatterns.DigitRegex.Match(m.Groups[1].Value);
                        var numPart = digitMatch.Success ? digitMatch.Value : "";
                        return string.IsNullOrEmpty(numPart) ? m.Value : $"ed={numPart}";
                    });

                line = RegexPatterns.PathValueRegex.Replace(
                    line,
                    m =>
                    {
                        var pathValue = m.Groups[1].Value;
                        if (string.IsNullOrEmpty(pathValue)) return m.Value;
                        var firstChar = pathValue[0] == '/' ? "/" : "";
                        var toEncode = firstChar == "/" ? pathValue[1..] : pathValue;
                        return "path=" + firstChar + Uri.EscapeDataString(toEncode);
                    });
            }

            // 匹配链接
            var matches = LinkRegex.Matches(line);
            foreach (Match m in matches)
                links.Add(m.Value);
        }

        return links;
    }

    // -----------------------------------------------------------------
    // 3. 统一判断是否为注释行
    // -----------------------------------------------------------------
    private static bool IsCommentLine( string line ) =>
        RegexPatterns.CommentOrEmptyRegex.IsMatch(line);

    // -----------------------------------------------------------------
    // 4. 下载输入内容
    // -----------------------------------------------------------------
    private static async Task<string> DownloadInputAsync( RunOptions opts )
    {
        if (opts.EnableTelegram)
            throw new InvalidOperationException("DownloadInputAsync 不应在 Telegram 模式下调用");

        if (Uri.TryCreate(opts.Input, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        {
            using var client = CreateHttpClient(opts);
            try { return await client.GetStringAsync(uri); }
            catch (Exception ex) { throw new HttpRequestException($"下载失败: {opts.Input}", ex); }
        }

        var fullPath = Path.GetFullPath(opts.Input);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException($"文件不存在: {fullPath}");

        LogHelper.Info($"读取本地文件: {fullPath}");
        return await File.ReadAllTextAsync(fullPath, Encoding.UTF8);
    }

    // -----------------------------------------------------------------
    // 5. 创建 HttpClient（代理、UA、超时）
    // -----------------------------------------------------------------
    private static HttpClient CreateHttpClient( RunOptions opts )
    {
        var handler = new HttpClientHandler();

        // 统一代理配置，消除重复 + 安全解析
        if (!string.IsNullOrWhiteSpace(opts.Proxy))
        {
            var parts = opts.Proxy.Split(':', 2);
            if (parts.Length != 2)
                throw new FormatException($"代理格式错误: {opts.Proxy}，应为 host:port");

            var host = parts[0].Trim();
            var portStr = parts[1].Trim();

            if (!int.TryParse(portStr, out var port) || port < 1 || port > 65535)
                throw new FormatException($"代理端口错误: {portStr}，应为 1~65535 的整数");

            if (!System.Net.IPAddress.TryParse(host, out _))
                throw new FormatException($"代理主机错误: {host}，必须是有效 IPv4 或 IPv6 地址");

            // 只有校验通过才打印
            handler.Proxy = new WebProxy(host, port);
            handler.UseProxy = true;

            // LogHelper.Info($"[代理模式] 使用代理: {host}:{port}");
        }

        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(opts.HttpTimeout)
        };
        client.DefaultRequestHeaders.Add("User-Agent", opts.UserAgent);
        return client;
    }

    ///<summary>
    ///工具方法：去除链接中的备注部分（#及其后内容）
    ///兼容 vless:// trojan:// vmess:// hysteria2:// 等
    /// </summary>    
    private static string RemoveRemark( string link )
    {
        if (string.IsNullOrEmpty(link))
            return link;

        var hashIndex = link.LastIndexOf('#');
        if (hashIndex == -1)
            return link;

        // 注意：# 可能出现在 Base64 编码的 vmess:// 中，必须是最后一个 #
        // 例如：vmess://eyJyZW1hcms...#节点名  → 去掉最后的 #节点名
        return link[..hashIndex];
    }
}