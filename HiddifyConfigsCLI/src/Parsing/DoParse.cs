// DoParse.cs (最终修复版)
// 变更：
// 1. 本地文件直接提取 trojan:// 链接（不再当作子 URL 列表）
// 2. 统一注释过滤（#、//、;、/* */）
// 3. 修复 path=?ed= / 多 ? 问题（保留原有 chatGPT 自我补救逻辑）

using HiddifyConfigsCLI.src.Core;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace HiddifyConfigsCLI;

internal static class DoParse
{
    // 使用“GeneratedRegexAttribute”在编译时生成正则表达式实现。
    //private static readonly Regex LinkRegex = new(
    //    @"(vless|trojan|hysteria2|vmess|ss|tuic)://[^\s""]+",
    //    RegexOptions.Compiled | RegexOptions.IgnoreCase);
    public static Regex LinkRegex => RegexPatterns.LinkRegex;

    // -----------------------------------------------------------------
    // 1. 下载并提取（主入口）
    // -----------------------------------------------------------------
    public static async Task<List<string>> DownloadAndExtractAsync( RunOptions opts )
    {
        var inputContent = await DownloadInputAsync(opts);

        // [关键] 判断输入是远程 URL 还是本地文件
        bool isRemoteInput = Uri.TryCreate(opts.Input, UriKind.Absolute, out var inputUri) &&
                             (inputUri.Scheme == Uri.UriSchemeHttp || inputUri.Scheme == Uri.UriSchemeHttps);

        // 调试信息
        LogHelper.Info($"输入类型: {(isRemoteInput ? "远程 URL 列表" : "本地文件")}");

        var allLinks = new List<string>();

        if (isRemoteInput)
        {
            // 远程：解析子 URL 列表 → 下载每个子文件
            var sourceUrls = inputContent
                // 使用数组初始化语法
                // .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .Where(l => !string.IsNullOrEmpty(l) &&
                            !IsCommentLine(l) &&
                            Uri.TryCreate(l, UriKind.Absolute, out var u) &&
                            (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
                .Distinct()
                .ToList();

            foreach (var sourceUrl in sourceUrls)
            {
                try
                {
                    LogHelper.Info($"正在下载子文件: {sourceUrl}");
                    var client = CreateHttpClient(opts);
                    var txtContent = await client.GetStringAsync(sourceUrl);
                    var extracted = ExtractLinksFromText(txtContent);
                    LogHelper.Info($" └─ 提取到 {extracted.Count} 条链接");
                    allLinks.AddRange(extracted);
                }
                catch (Exception ex)
                {
                    LogHelper.Warn($"下载失败（跳过）: {sourceUrl} | {ex.Message}");
                }
            }
        }
        else
        {
            // [本地文件] 直接提取 trojan:// 链接
            LogHelper.Info($"处理本地输入文件: {Path.GetFullPath(opts.Input)}");
            var extracted = ExtractLinksFromText(inputContent);
            LogHelper.Info($" └─ 提取到 {extracted.Count} 条链接");
            allLinks.AddRange(extracted);
        }
        // 使用集合表达式
        // return allLinks.Distinct().ToList();
        return [.. allLinks.Distinct()];
    }

    // -----------------------------------------------------------------
    // 2. 从文本中提取协议链接（核心解析）
    // -----------------------------------------------------------------
    private static List<string> ExtractLinksFromText( string text )
    {
        var links = new List<string>();
        // 简化合集初始化
        // var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        var lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);

        // 块注释状态机（/* ... */）
        bool inBlockComment = false;

        foreach (var rawLine in lines)
        {
            // var trimmed = line.Trim();
            string line = rawLine.Trim();

            // ---------- 块注释跨行处理 ----------
            if (inBlockComment)
            {
                if (line.Contains("*/"))
                {
                    inBlockComment = false;
                    // 去掉 */ 之后的内容继续判断
                    // 简化合集初始化
                    // line = line.Split(new[] { "*/" }, 2, StringSplitOptions.None)[0];
                    line = line.Split(["*/"], 2, StringSplitOptions.None)[0];
                }
                else
                {
                    continue; // 仍在块注释中，直接跳过整行
                }
            }
            else if (line.Contains("/*") && line.Contains("*/"))
            {
                // 同一行出现 /* 和 */，只取 /* 之前的部分
                // 简化合集初始化
                // var parts = line.Split(new[] { "/*" }, 2, StringSplitOptions.None);
                var parts = line.Split(["/*"], 2, StringSplitOptions.None);
                line = parts[0];
                // 后面还有 */，跳过
                if (parts.Length > 1 && parts[1].Contains("*/"))
                    continue;
            }
            else if (line.Contains("/*"))
            {
                // 进入块注释
                // 简化合集初始化
                // var parts = line.Split(new[] { "/*" }, 2, StringSplitOptions.None);
                var parts = line.Split(["/*"], 2, StringSplitOptions.None);
                line = parts[0];
                inBlockComment = true;
            }

            // [统一过滤] 跳过注释、空行、Base64
            //if (string.IsNullOrEmpty(trimmed) ||
            //    IsCommentLine(trimmed) ||
            //    IsBase64String(trimmed))
            //    continue;
            // ---------- 统一过滤：空行、注释、Base64 ----------
            if (string.IsNullOrWhiteSpace(line) ||
                RegexPatterns.CommentOrEmptyRegex.IsMatch(line) ||
                RegexPatterns.Base64LineRegex.IsMatch(line))
                continue;

            // [保留] chatGPT 自我补救逻辑：修复 path=?ed= / 多 ?
            // 全部使用编译时生成的 RegexPatterns，零运行时开销
            if (RegexPatterns.PathHasQEdRegex.IsMatch(line) ||
                RegexPatterns.PathMultiQueryRegex.IsMatch(line))
            {
                // Step 0: 修复多余 ?（? → &）
                line = RegexPatterns.PathValueRegex.Replace(
                    line,
                    m =>
                    {
                        var pathValue = m.Groups[1].Value;
                        if (pathValue.Count(c => c == '?') > 1)
                        {
                            int firstQ = pathValue.IndexOf('?');
                            // 适用范围运算符
                            // var fixedPath = pathValue.Substring(0, firstQ + 1) +
                            //                pathValue.Substring(firstQ + 1).Replace('?', '&');
                            var fixedPath = pathValue[..(firstQ + 1)] +
                                              pathValue[(firstQ + 1)..].Replace('?', '&');
                            return "path=" + fixedPath;
                        }
                        return m.Value;
                    });

                // Step 1: ?ed= → &ed=
                //var fixedLine = Regex.Replace(line, @"path=\/([^?\s]*)\?ed=", "path=/$1&ed=", RegexOptions.IgnoreCase);
                //if (!fixedLine.Equals(line, StringComparison.Ordinal)) line = fixedLine;
                line = RegexPatterns.FixQEdRegex.Replace(line, "path=/$1&ed=");

                // Step 2: 提取 ed 数字（仍用运行时 Regex.Match 提取 \d+，可接受）
                line = RegexPatterns.EdValueFullRegex.Replace(
                    line,
                    m =>
                    {
                        // 从 ed=xxxx 中提取数字（如 ed=abc123def → 123）
                        var digitMatch = RegexPatterns.DigitRegex.Match(m.Groups[1].Value);
                        var numPart = digitMatch.Success ? digitMatch.Value : "";
                        return string.IsNullOrEmpty(numPart) ? m.Value : $"ed={numPart}";
                    });

                // Step 3: path 编码（保留首 /）
                line = RegexPatterns.PathValueRegex.Replace(
                    line,
                    m =>
                    {
                        var pathValue = m.Groups[1].Value;
                        if (string.IsNullOrEmpty(pathValue)) return m.Value;
                        var firstChar = pathValue[0] == '/' ? "/" : "";
                        // 使用范围运算符
                        // var toEncode = firstChar == "/" ? pathValue.Substring(1) : pathValue;
                        var toEncode = firstChar == "/" ? pathValue[1..] : pathValue;
                        return "path=" + firstChar + Uri.EscapeDataString(toEncode);
                    });
            }

            // 提取协议链接
            var matches = LinkRegex.Matches(line);
            foreach (Match m in matches)
                links.Add(m.Value);
        }

        return links;
    }

    // -----------------------------------------------------------------
    // 3. 统一判断是否为注释行（已使用 GeneratedRegex）
    // -----------------------------------------------------------------
    private static bool IsCommentLine( string line ) =>
        RegexPatterns.CommentOrEmptyRegex.IsMatch(line);

    // -----------------------------------------------------------------
    // 4. 下载输入内容（远程 URL 或本地文件）
    //      --telegram 模式下禁用此功能
    // -----------------------------------------------------------------
    private static async Task<string> DownloadInputAsync( RunOptions opts )
    {
        if (opts == null) throw new ArgumentNullException(nameof(opts));

        // 仅在非 Telegram 模式下调用
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
        var handler = new HttpClientHandler
        {
            UseProxy = !string.IsNullOrEmpty(opts.Proxy),
            Proxy = !string.IsNullOrEmpty(opts.Proxy)
                ? new WebProxy(opts.Proxy.Split(':')[0], int.Parse(opts.Proxy.Split(':')[1]))
                : null
        };

        if (!string.IsNullOrEmpty(opts.Proxy))
        {
            var parts = opts.Proxy.Split(':');
            if (parts.Length != 2 || !int.TryParse(parts[1], out _))
                throw new FormatException($"代理格式错误: {opts.Proxy}");
            handler.Proxy = new WebProxy(parts[0], int.Parse(parts[1]));
            handler.UseProxy = true;
        }

        var client = new HttpClient(handler, true)
        {
            Timeout = TimeSpan.FromSeconds(opts.HttpTimeout)
        };
        client.DefaultRequestHeaders.Add("User-Agent", opts.UserAgent);
        return client;
    }
}