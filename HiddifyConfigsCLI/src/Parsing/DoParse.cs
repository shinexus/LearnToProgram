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
        // 【Grok 修复】防御性检查
        if (opts == null) throw new ArgumentNullException(nameof(opts));
        if (string.IsNullOrWhiteSpace(opts.Input))
            throw new ArgumentException("输入路径不能为空", nameof(opts.Input));

        var inputContent = await DownloadInputAsync(opts);

        // [关键] 判断输入是远程 URL 还是本地文件
        bool isRemoteInput = Uri.TryCreate(opts.Input, UriKind.Absolute, out var inputUri) &&
                             (inputUri.Scheme == Uri.UriSchemeHttp || inputUri.Scheme == Uri.UriSchemeHttps);

        LogHelper.Info($"输入类型: {(isRemoteInput ? "远程 URL 列表" : "本地文件")}");

        var allLinks = new List<string>();

        if (isRemoteInput)
        {
            var sourceUrls = inputContent
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
            LogHelper.Info($"处理本地输入文件: {Path.GetFullPath(opts.Input)}");
            var extracted = ExtractLinksFromText(inputContent);
            LogHelper.Info($" └─ 提取到 {extracted.Count} 条链接");
            allLinks.AddRange(extracted);
        }

        return [.. allLinks.Distinct()];
    }

    // -----------------------------------------------------------------
    // 2. 从文本中提取协议链接（核心解析）
    // -----------------------------------------------------------------
    private static List<string> ExtractLinksFromText( string text )
    {
        var links = new List<string>();
        var lines = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
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
                    line = line.Split(["*/"], 2, StringSplitOptions.None)[0];
                }
                else continue;
            }
            else if (line.Contains("/*") && line.Contains("*/"))
            {
                var parts = line.Split(["/*"], 2, StringSplitOptions.None);
                line = parts[0];
                if (parts.Length > 1 && parts[1].Contains("*/")) continue;
            }
            else if (line.Contains("/*"))
            {
                var parts = line.Split(["/*"], 2, StringSplitOptions.None);
                line = parts[0];
                inBlockComment = true;
            }

            if (string.IsNullOrWhiteSpace(line) ||
                RegexPatterns.CommentOrEmptyRegex.IsMatch(line) ||
                RegexPatterns.Base64LineRegex.IsMatch(line))
                continue;

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

            var matches = LinkRegex.Matches(line);
            foreach (Match m in matches)
            {
                var rawLink = m.Value;

                // 【新增：Base64 包裹协议自动解码】
                // 同步方法中调用 .Result 是安全的，因为内部无 await/线程切换
                var decoded = Base64ProtocolDecoder.TryDecodeIfNeededAsync(rawLink).Result;

                links.Add(decoded);
            }
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

        // 【Grok 修复】统一代理配置，消除重复 + 安全解析
        if (!string.IsNullOrWhiteSpace(opts.Proxy))
        {
            var parts = opts.Proxy.Split(':');
            if (parts.Length != 2 || !int.TryParse(parts[1], out var port))
                throw new FormatException($"代理格式错误: {opts.Proxy}，应为 host:port");

            handler.Proxy = new WebProxy(parts[0], port);
            handler.UseProxy = true;
        }

        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(opts.HttpTimeout)
        };
        client.DefaultRequestHeaders.Add("User-Agent", opts.UserAgent);
        return client;
    }
}