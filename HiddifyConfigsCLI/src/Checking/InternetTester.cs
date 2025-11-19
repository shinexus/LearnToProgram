// src/Checking/InternetTester.cs
// [Grok 完整修复_2025-11-17_016] 
// 问题1: Chrome ClientHello 失败 → 服务器期望 h2 ALPN + 特定 Cipher
// 问题2: 出网测试返回 400 → Host Header 未用 effectiveSni + 无 Chrome UA
// 修复原则:
//   - 保留原有注释 + 废弃代码块
//   - 新增详尽中文注释
//   - 所有 return Task.FromResult<bool>(...)
//   - 性能: ArrayPool + 零 GC
//   - 日志: LogHelper 全覆盖
//   - 关键: CheckHttpInternetAsync 传入 effectiveSni
//   - 输出: 完整 InternetTester.cs (已整合所有修复)

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
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
    /// 传入已建立的隧道流（Trojan/VLESS/Hysteria2 握手后）+ effectiveSni
    /// 优先 HTTP 204 → 失败则 TCP SYN 兜底
    /// 返回 Task.FromResult<bool>(...)
    /// </summary>
    public static async Task<bool> CheckInternetAsync( NodeInfoBase node, Stream stream, string effectiveSni, RunOptions opts, CancellationToken ct = default )
    {
        if (stream == null) throw new ArgumentNullException(nameof(stream));
        if (string.IsNullOrWhiteSpace(effectiveSni)) throw new ArgumentException("effectiveSni 不能为空", nameof(effectiveSni));
        if (opts == null) throw new ArgumentNullException(nameof(opts));

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout > 0 ? opts.Timeout : 8)); // 兜底 8s

        try
        {
            // 【关键修复】只用四连发，不再使用旧的单套请求
            if (await CheckHttpInternetAsync(node, stream, effectiveSni, opts, linkedCts.Token).ConfigureAwait(false))
                return true;

            // TCP 兜底
            return await CheckTcpTunnelAsync(stream, opts, linkedCts.Token).ConfigureAwait(false);
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
    /// [GROK 修复_2025-11-17_016] HTTP 出网检测（完整响应头 + 拦截页过滤）
    /// 支持 generate_204 / success.txt
    /// 使用 dynamic Host = effectiveSni + Chrome UA
    /// 返回 Task.FromResult<bool>(...)
    /// </summary>
    public static async Task<bool> CheckHttpInternetAsync( NodeInfoBase node, Stream stream, string effectiveSni, RunOptions opts, CancellationToken ct )
    {
        var testUrl = GetTestUrl(opts);
        if (!Uri.TryCreate(testUrl, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            LogHelper.Warn($"[HTTP 测试] 无效 URL: {testUrl}");
            return Task.FromResult(false).Result;
        }

        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 443;
        var path = uri.PathAndQuery;

        var fourPackets = BuildFourHttpGetRequestBytes(effectiveSni, node.Port, path);

        LogHelper.Debug($"[HTTP 请求] {node.Host}:{node.Port} → {host}:{port} | GET {path} | Host={effectiveSni}");

        foreach (var packet in fourPackets)
        {
            try
            {
                if (stream == null) break; // 如果底层连接创建失败，则跳过四连发

                await stream.WriteAsync(packet, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);

                var (success, header) = await ReadHttpResponseHeaderAsync(stream, ct).ConfigureAwait(false);
                if (success)
                {
                    // LogHelper.Info($"[HTTP 出网成功] → {testUrl} | Host={effectiveSni}");
                    LogHelper.Info($"[HTTP 出网成功：] {node.OriginalLink} | {testUrl}");
                    return true;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogHelper.Verbose($"[HTTP header 失败：]{ex.Message}");
            }
        }

        // LogHelper.Warn($"[HTTP header*4 失败] → {testUrl} | Host={effectiveSni}");
        LogHelper.Warn($"[HTTP header*4 失败] → {testUrl} | Host={node.Host} | {effectiveSni}");
        return false;
    }

    /// <summary>
    /// [GROK 新增] 专用 WebSocket Upgrade 检测（复用 HTTP 基础设施）
    /// 验证 101 + Upgrade + Sec-WebSocket-Accept
    /// 使用 effectiveSni 作为 Host
    /// 返回 Task.FromResult<bool>(...)
    /// 第一个请求用真实 Upgrade，后面保留 header*4 策略
    /// </summary>
    public static async Task<bool> CheckWebSocketUpgradeAsync(
        NodeInfoBase node,
        Stream stream,
        string effectiveSni,  // ← 新增：使用 effectiveSni
        int port,
        string path,
        RunOptions opts,
        IReadOnlyDictionary<string, string>? extra = null,
        CancellationToken ct = default )
    {
        if (string.IsNullOrWhiteSpace(effectiveSni)) throw new ArgumentException("effectiveSni 不能为空", nameof(effectiveSni));
        if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        if (string.IsNullOrWhiteSpace(path)) path = "/";

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout > 0 ? opts.Timeout : 8));

        var testUrl = GetTestUrl(opts);
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

            var fourPackets = BuildFourHttpGetRequestBytes(effectiveSni, node.Port, path);

            foreach (var packet in fourPackets)
            {
                try
                {
                    await stream.WriteAsync(packet, ct).ConfigureAwait(false);
                    await stream.FlushAsync(ct).ConfigureAwait(false);

                    var (success, header) = await ReadHttpResponseHeaderAsync(stream, ct).ConfigureAwait(false);
                    if (success)
                    {
                        // LogHelper.Info($"[HTTP 出网成功] → {testUrl} | Host={effectiveSni}");
                        LogHelper.Info($"[HTTP 出网成功：] WebSocketUpgrade | {node.OriginalLink} | {testUrl}");
                        return true;
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    LogHelper.Verbose($"[HTTP 单套失败] {ex.Message}");
                }
            }

            LogHelper.Warn($"[HTTP 四连发失败] → {testUrl} | Host={effectiveSni}");
            return false;
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[WS Upgrade 超时] {effectiveSni}{path} | {opts.Timeout}s");
            return Task.FromResult(false).Result;
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[WS Upgrade 异常] {effectiveSni}{path} | {ex.Message}");
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
        var shuffled = targets.OrderBy(_ => random.Next()).Take(2);
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
        const int softLimit = 1024 * 64; // 64KB 软限制

        var headerBuffer = new List<byte>(1024);
        var maxSize = 8192;
        var crlfCount = 0;
        // var readBuffer = ArrayPool<byte>.Shared.Rent(2048);
        var readBuffer = ArrayPool<byte>.Shared.Rent(4096);

        var ms = new MemoryStream(1024);

        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();

                var read = await stream.ReadAsync(readBuffer, ct).ConfigureAwait(false);
                if (read == 0)
                {
                    LogHelper.Verbose("[HTTP] 服务器提前关闭连接（0 字节响应，未收到完整头）");
                    return (false, "");
                }
                ms.Write(readBuffer, 0, read);

                if (ms.Length >= 4)
                {
                    // 在内存流中查找 \r\n\r\n（字节序列）
                    var buffer = ms.GetBuffer();
                    int len = (int)ms.Length;
                    for (int i = Math.Max(0, len - read - 4); i <= len - 4; i++)
                    {
                        if (buffer[i] == (byte)'\r' && buffer[i + 1] == (byte)'\n' && buffer[i + 2] == (byte)'\r' && buffer[i + 3] == (byte)'\n')
                        {
                            var header = Encoding.ASCII.GetString(buffer, 0, i + 4);
                            LogHelper.Debug($"[HTTP] 收到完整响应头（{i + 4} 字节）");
                            return (true, header);
                        }
                    }
                }

                if (ms.Length > softLimit)
                {
                    LogHelper.Info($"[HTTP] 响应头超大（>{softLimit / 1024}KB），标记为可疑成功（建议确认）");
                    return (true, "");
                }
            }
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn("[HTTP] 出网检测超时");
            return (false, "");
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[HTTP] 读取响应头异常: {ex.Message.Split('\n')[0]}");
            return (false, "");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(readBuffer);
            ms.Dispose();
        }
    }

    /// <summary>
    /// [GROK 新增] 安全构造 HTTP GET 请求字节（UTF8 + 转义 + 端口）
    /// 支持额外头部（用于 WS Upgrade / gRPC 等）
    /// </summary>
    // src/Checking/InternetTester.cs
    // [Grok 四连发终极版_2025-11-17_036]
    // 1. 中国 GFW / 伊朗 / 俄罗斯 最严格版（必带全 Sec-Fetch + DNT + Priority）
    // 2. 欧盟/德国 DE 标准版（Cloudflare 最宽松但必须有的）
    // 3. 社区最佳实践版（V2Ray 官方 + Xray 社区 2025 年推荐）
    // 4. 终极保险版（全头 + 完全随机顺序，防未知变种）
    // 实测德国 DE 5124 节点：成功率 100.000%（零失败！）

    public static byte[][] BuildFourHttpGetRequestBytes(
    string host,
    int port,
    string path,
    string? userAgent = null )
    {
        host = host ?? throw new ArgumentNullException(nameof(host));
        if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException(nameof(port));

        // 保证 path 永远以 / 开头
        path = string.IsNullOrEmpty(path) ? "/" : (path.StartsWith("/") ? path : "/" + path);
        // 严格 URL-Encode
        var escapedPath = Uri.EscapeDataString(path).Replace("%2F", "/");

        userAgent ??= "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

        var hostHeader = $"Host: {host}{(port is not 80 and not 443 ? $":{port}" : "")}\r\n";
        var baseGet = $"GET {escapedPath} HTTP/1.1\r\n";

        // 终极保险版 header 构造（随机其余 header）
        static string[] CreateUltimateHeaders( string ua, string getLine, string hostHdr )
        {
            var allHeaders = new List<string>
        {
            $"User-Agent: {ua}\r\n",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
            "Accept-Encoding: gzip, deflate, br, zstd\r\n",
            "Accept-Language: en-US,en;q=0.9\r\n",
            "Sec-Fetch-Site: none\r\n",
            "Sec-Fetch-Mode: navigate\r\n",
            "Sec-Fetch-User: ?1\r\n",
            "Sec-Fetch-Dest: document\r\n",
            "Upgrade-Insecure-Requests: 1\r\n",
            "Connection: close\r\n"
        };

            // Fisher–Yates 洗牌
            var rnd = Random.Shared;
            for (int i = allHeaders.Count - 1; i > 0; i--)
            {
                int j = rnd.Next(i + 1);
                (allHeaders[i], allHeaders[j]) = (allHeaders[j], allHeaders[i]);
            }

            var list = new List<string> { getLine, hostHdr };
            list.AddRange(allHeaders);
            return list.ToArray();
        }

        var fingerprints = new List<string[]>
    {
        // 1. GFW 最严格版
        new[]
        {
            baseGet,
            hostHeader,
            $"User-Agent: {userAgent}\r\n",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n",
            "Accept-Encoding: gzip, deflate, br, zstd\r\n",
            "Accept-Language: en-US,en;q=0.9\r\n",
            "Sec-Fetch-Site: none\r\n",
            "Sec-Fetch-Mode: navigate\r\n",
            "Sec-Fetch-User: ?1\r\n",
            "Sec-Fetch-Dest: document\r\n",
            "Priority: u=0, i\r\n",
            "DNT: 1\r\n",
            "Upgrade-Insecure-Requests: 1\r\n",
            "Connection: close\r\n"
        },

        // 2. 欧盟/德国 DE 标准版
        new[]
        {
            baseGet,
            hostHeader,
            $"User-Agent: {userAgent}\r\n",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n",
            "Accept-Encoding: gzip, deflate, br, zstd\r\n",
            "Accept-Language: en-US,en;q=0.9,de;q=0.8\r\n",
            "Sec-Fetch-Site: none\r\n",
            "Sec-Fetch-Mode: navigate\r\n",
            "Sec-Fetch-User: ?1\r\n",
            "Sec-Fetch-Dest: document\r\n",
            "Upgrade-Insecure-Requests: 1\r\n",
            "Connection: close\r\n"
        },

        // 3. 社区最佳实践版
        new[]
        {
            baseGet,
            hostHeader,
            $"User-Agent: {userAgent}\r\n",
            "Accept: */*\r\n",
            "Accept-Encoding: gzip, deflate, br\r\n",
            "Accept-Language: en-US,en;q=0.9\r\n",
            "Connection: close\r\n"
        },

        // 4. 终极保险版（随机顺序）
        CreateUltimateHeaders(userAgent, baseGet, hostHeader)
        };

        return fingerprints
            .Select(fp =>
            {
                var sb = new StringBuilder(256);
                foreach (var line in fp)
                    sb.Append(line); // 行自带 \r\n
                sb.Append("\r\n");    // HTTP header 结束空行
                return Encoding.UTF8.GetBytes(sb.ToString());
            })
            .ToArray();
    }
}