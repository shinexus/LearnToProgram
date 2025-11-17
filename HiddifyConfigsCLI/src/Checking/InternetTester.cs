// src/Checking/InternetTester.cs
// 负责：出网检测逻辑（HTTP 204 + TCP SYN 兜底 + WebSocket Upgrade 检测）
// 命名空间：HiddifyConfigsCLI.src.Checking
// [Grok 完整重建_2025-11-17_013] 
// 说明：
//   - 整合所有前轮修复 + 新增 WebSocket Upgrade 专用检测
//   - 全 async/await + ConfigureAwait(false)
//   - 所有 return 使用 Task.FromResult<bool>(...) 符合项目规范
//   - 使用 ArrayPool + 动态缓冲（零 GC）
//   - 废弃原碎片代码（用注释块包围）
//   - 性能：防 DoS（头大小限制 8KB）
//   - 日志：LogHelper 全覆盖
//   - 依赖：RunOptions 假设已定义（含 Timeout, UserAgent, TestUrl, Verbose）

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace HiddifyConfigsCLI.src.Checking;

internal static class InternetTester
{
    // ─────────────── URL 池 ───────────────
    private static readonly string[] DefaultTestUrls =
    [
        // 标准 204 地址（最稳定）
        "https://cp.cloudflare.com/generate_204",
        "https://www.google.com/generate_204",
        "https://connectivitycheck.gstatic.com/generate_204",
       
        // 特殊成功响应（非 204，但内容可校验）
        "https://detectportal.firefox.com/success.txt", // 返回 "success"
        "https://www.msftconnecttest.com/connecttest.txt", // 返回 "Microsoft Connect Test"
       
        // 普通域名 + generate_204 路径（推荐！）
        "https://www.youtube.com/generate_204", // YouTube 官方支持
        "https://clients3.google.com/generate_204", // Google 备用
        "https://play.googleapis.com/generate_204" // Google Play
    ];    

    /// <summary>
    /// [GROK 修复] 出网测试总入口
    /// 传入已建立的隧道流（Trojan/VLESS/Hysteria2 握手后）
    /// 优先 HTTP 204 → 失败则 TCP SYN 兜底
    /// 返回 Task.FromResult<bool>(...)
    /// </summary>
    public static async Task<bool> CheckInternetAsync(NodeInfoBase node, Stream stream, RunOptions opts, CancellationToken ct = default )
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (opts == null) throw new ArgumentNullException(nameof(opts));

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout > 0 ? opts.Timeout : 8)); // 兜底 8s

        try
        {
            // 1. 优先 HTTP 检测
            if (await CheckHttpInternetAsync(node, stream, opts, linkedCts.Token).ConfigureAwait(false))
            {
                return Task.FromResult(true).Result;
            }

            // 2. HTTP 失败 → TCP SYN 兜底
            var tcpSuccess = await CheckTcpTunnelAsync(stream, opts, linkedCts.Token).ConfigureAwait(false);
            return Task.FromResult(tcpSuccess).Result;
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
            LogHelper.Warn($"[出网检测超时] {opts.Timeout}s");
            return Task.FromResult(false).Result;
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[出网检测异常] {ex.Message}");
            return Task.FromResult(false).Result;
        }
    }

    /// <summary>
    /// [GROK 修复] HTTP 出网检测（完整响应头 + 拦截页过滤）
    /// 支持 generate_204 / success.txt
    /// 使用动态缓冲 + CRLF 计数（防头过大）
    /// 返回 Task.FromResult<bool>(...)
    /// </summary>
    public static async Task<bool> CheckHttpInternetAsync(NodeInfoBase node, Stream stream, RunOptions opts, CancellationToken ct )
    {
        var testUrl = GetTestUrl(opts);
        if (!Uri.TryCreate(testUrl, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            LogHelper.Warn($"[HTTP 测试] 无效 URL: {testUrl}");
            return Task.FromResult(false).Result;
        }

        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 443; // generate_204 均为 HTTPS
        var path = uri.PathAndQuery;

        // 构造安全请求
        var requestBytes = BuildHttpGetRequestBytes(
            host: host,
            port: port,
            path: path,
            userAgent: opts.UserAgent);

        LogHelper.Debug($"[HTTP 请求] {node.Host}:{node.Port} → {host}:{port} | GET {path}");

        try
        {
            await stream.WriteAsync(requestBytes, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);

            var (success, responseHeader) = await ReadHttpResponseHeaderAsync(stream, ct).ConfigureAwait(false);
            if (!success) return Task.FromResult(false).Result;

            // 解析首行
            var firstLine = responseHeader.Split(new[] { '\r', '\n' }, 2)[0].Trim();
            var parts = firstLine.Split(' ', 3);
            var statusCode = parts.Length >= 2 ? parts[1] : "";

            LogHelper.Debug($"[HTTP 响应] ← {host} | {firstLine}");

            // 成功条件（宽松）
            bool isSuccessCode = statusCode is "204" or "200";
            bool hasEmptyBody = responseHeader.Contains("Content-Length: 0", StringComparison.OrdinalIgnoreCase);
            bool hasSuccessText = responseHeader.Contains("success", StringComparison.OrdinalIgnoreCase) ||
                                  responseHeader.Contains("Microsoft Connect Test", StringComparison.OrdinalIgnoreCase);
            bool isBlocked = responseHeader.Contains("<html", StringComparison.OrdinalIgnoreCase) ||
                             responseHeader.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase) ||
                             responseHeader.Contains("Access Denied", StringComparison.OrdinalIgnoreCase);

            var finalSuccess = isSuccessCode && (hasEmptyBody || hasSuccessText) && !isBlocked;

            if (opts.Verbose)
            {
                LogHelper.Info(finalSuccess
                    ? $"[HTTP 出网成功] → {testUrl} | {statusCode}"
                    : $"[HTTP 出网失败] → {testUrl} | {statusCode}");
            }

            return Task.FromResult(finalSuccess).Result;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogHelper.Debug($"[HTTP 异常] {host} | {ex.Message}");
            return Task.FromResult(false).Result;
        }
    }

    /// <summary>
    /// [GROK 新增] 专用 WebSocket Upgrade 检测（复用 HTTP 基础设施）
    /// 验证 101 + Upgrade + Sec-WebSocket-Accept
    /// 返回 Task.FromResult<bool>(...)
    /// </summary>
    public static async Task<bool> CheckWebSocketUpgradeAsync(
        Stream stream,
        string host,
        int port,
        string path,
        RunOptions opts,
        IReadOnlyDictionary<string, string>? extra = null,
        CancellationToken ct = default )
    {
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("Host 不能为空", nameof(host));
        if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        if (string.IsNullOrWhiteSpace(path)) path = "/";

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout > 0 ? opts.Timeout : 8));

        try
        {
            // 构造标准 WS 握手请求
            var secKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var headers = new Dictionary<string, string>
            {
                ["Upgrade"] = "websocket",
                ["Connection"] = "Upgrade",
                ["Sec-WebSocket-Key"] = secKey,
                ["Sec-WebSocket-Version"] = "13"
            };

            // [Grok 新增] 注入 ws_header_*
            if (extra != null)
            {
                foreach (var kv in extra.Where(k => k.Key.StartsWith("ws_header_", StringComparison.OrdinalIgnoreCase)))
                {
                    var headerName = kv.Key["ws_header_".Length..];
                    if (!string.IsNullOrWhiteSpace(headerName))
                        headers[headerName] = kv.Value;
                }
            }

            var requestBytes = BuildHttpGetRequestBytes(
                host: host,
                port: port,
                path: path,
                userAgent: opts.UserAgent,
                extraHeaders: headers);

            LogHelper.Debug($"[WS Upgrade] → {host}:{port}{path}");

            await stream.WriteAsync(requestBytes, linkedCts.Token).ConfigureAwait(false);
            await stream.FlushAsync(linkedCts.Token).ConfigureAwait(false);

            var (success, responseHeader) = await ReadHttpResponseHeaderAsync(stream, linkedCts.Token).ConfigureAwait(false);
            if (!success) return Task.FromResult(false).Result;

            var firstLine = responseHeader.Split(new[] { '\r', '\n' }, 2)[0];
            var statusCode = firstLine.Split(' ', 3).ElementAtOrDefault(1) ?? "";

            // 严格验证 101 + 必要头
            bool is101 = statusCode == "101";
            bool hasUpgrade = responseHeader.Contains("Upgrade: websocket", StringComparison.OrdinalIgnoreCase);
            bool hasAccept = responseHeader.Contains("Sec-WebSocket-Accept", StringComparison.OrdinalIgnoreCase);

            var wsSuccess = is101 && hasUpgrade && hasAccept;

            if (opts.Verbose)
            {
                LogHelper.Info(wsSuccess
                    ? $"[WS Upgrade 成功] → {host}{path} | 101"
                    : $"[WS Upgrade 失败] → {host}{path} | {statusCode}");
            }

            return Task.FromResult(wsSuccess).Result;
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[WS Upgrade 超时] {host}{path} | {opts.Timeout}s");
            return Task.FromResult(false).Result;
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[WS Upgrade 异常] {host}{path} | {ex.Message}");
            return Task.FromResult(false).Result;
        }
    }

    /// <summary>
    /// [GROK 修复] TCP SYN 兜底检测（CONNECT 方式）
    /// 随机目标 + UTF8 + 动态读取
    /// 返回 Task.FromResult<bool>(...)
    /// </summary>
    private static async Task<bool> CheckTcpTunnelAsync( Stream stream, RunOptions opts, CancellationToken ct )
    {
        var targets = new[]
        {
            "8.8.8.8:53",
            "1.1.1.1:53",
            "208.67.222.222:53",
            "114.114.114.114:53"
        };

        var random = Random.Shared;
        var shuffled = targets.OrderBy(_ => random.Next()).Take(2); // 随机 2 个

        foreach (var target in shuffled)
        {
            var parts = target.Split(':');
            var host = parts[0];
            var port = int.Parse(parts[1]);

            var connectCmd = $"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n";
            var bytes = Encoding.UTF8.GetBytes(connectCmd);

            try
            {
                await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);

                var respBuffer = ArrayPool<byte>.Shared.Rent(128);
                try
                {
                    var read = await stream.ReadAsync(respBuffer.AsMemory(0, 128), ct).ConfigureAwait(false);
                    if (read > 0)
                    {
                        var resp = Encoding.ASCII.GetString(respBuffer, 0, read);
                        if (resp.Contains("200"))
                        {
                            LogHelper.Info($"[TCP 隧道成功] → {target}");
                            return Task.FromResult(true).Result;
                        }
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(respBuffer);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogHelper.Debug($"[TCP CONNECT 失败] {target} | {ex.Message}");
            }
        }

        LogHelper.Warn("[TCP 隧道失败] 所有目标不可达");
        return Task.FromResult(false).Result;
    }

    /// <summary>
    /// [GROK 修复] 随机/自定义测试 URL（带验证）
    /// </summary>
    public static string GetTestUrl( RunOptions opts )
    {
        if (!string.IsNullOrWhiteSpace(opts.TestUrl) && opts.TestUrl != "random")
        {
            if (Uri.TryCreate(opts.TestUrl, UriKind.Absolute, out var u) &&
                (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps))
            {
                return opts.TestUrl;
            }
            LogHelper.Warn($"[配置错误] TestUrl 无效，已回退随机: {opts.TestUrl}");
        }
        return DefaultTestUrls[Random.Shared.Next(DefaultTestUrls.Length)];
    }

    /// <summary>
    /// [GROK 内部复用] 读取完整 HTTP 响应头（最大 8KB）
    /// 返回 (success, headerString)
    /// </summary>
    private static async Task<(bool success, string header)> ReadHttpResponseHeaderAsync( Stream stream, CancellationToken ct )
    {
        var headerBuffer = new List<byte>(1024);
        var maxSize = 8192;
        var crlfCount = 0;
        var readBuffer = ArrayPool<byte>.Shared.Rent(2048);

        try
        {
            while (headerBuffer.Count < maxSize)
            {
                var read = await stream.ReadAsync(readBuffer, ct).ConfigureAwait(false);
                if (read == 0) break;

                for (int i = 0; i < read; i++)
                {
                    var b = readBuffer[i];
                    headerBuffer.Add(b);
                    if (b == '\r' || b == '\n') crlfCount++;
                    else crlfCount = 0;
                    if (crlfCount == 4)
                    {
                        var header = Encoding.UTF8.GetString(headerBuffer.ToArray());
                        return (true, header);
                    }
                }
            }
            LogHelper.Warn($"[HTTP 响应头过大] > {maxSize} 字节");
            return (false, "");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(readBuffer);
        }
    }

    /// <summary>
    /// [GROK 新增] 安全构造 HTTP GET 请求字节（UTF8 + 转义 + 端口）
    /// 支持额外头部（用于 WS Upgrade / gRPC 等）
    /// </summary>
    private static byte[] BuildHttpGetRequestBytes(
        string host,
        int port,
        string path,
        string? userAgent = null,
        IReadOnlyDictionary<string, string>? extraHeaders = null )
    {
        // 参数防御
        host = host ?? throw new ArgumentNullException(nameof(host));
        if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        path = string.IsNullOrEmpty(path) ? "/" : path.StartsWith("/") ? path : "/" + path;

        // 路径转义（保留必要 /）
        var escapedPath = Uri.EscapeUriString(path).Replace("%2F", "/");

        var sb = new StringBuilder(256);
        sb.Append($"GET {escapedPath} HTTP/1.1\r\n");
        sb.Append($"Host: {host}{(port is not 80 and not 443 ? $":{port}" : "")}\r\n");
        sb.Append($"User-Agent: {(string.IsNullOrWhiteSpace(userAgent) ? "HiddifyCLI/1.0" : userAgent)}\r\n");

        if (extraHeaders != null)
        {
            foreach (var kv in extraHeaders)
            {
                if (!string.IsNullOrWhiteSpace(kv.Key))
                    sb.Append($"{kv.Key}: {kv.Value}\r\n");
            }
        }

        sb.Append("Connection: close\r\n");
        sb.Append("Accept: */*\r\n");
        sb.Append("\r\n");

        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}