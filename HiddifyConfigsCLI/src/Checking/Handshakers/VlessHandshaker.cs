// VlessHandshaker.cs（优化版，保留原结构，确保 ExtraParams 全部使用）
using HiddifyConfigsCLI.src.Checking;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;
/// <summary>
/// [VLESS 握手器] 支持 REALITY / WebSocket / gRPC / XTLS-Vision
/// [chatGPT 自我补救]：优化异步流程与结构化逻辑，提升性能与可读性
/// </summary>
internal static class VlessHandshaker
{
    public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
        NodeInfo node,
        IPAddress address,
        int timeoutSec,
        RunOptions opts )
    {
        Stream? stream = null;
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));

        try
        {
            // ====== 阶段1：建立 TCP 连接 ======
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token);
            stream = new NetworkStream(socket, ownsSocket: true);

            // ====== 阶段2：提取参数 ======
            var extra = node.ExtraParams ?? new Dictionary<string, string>();

            // 主字段
            var uuidStr         = extra.GetValueOrDefault("id") ?? node.Password ?? "";
            var security        = extra.GetValueOrDefault("security") ?? "tls";
            var transportType   = extra.GetValueOrDefault("transport_type") ?? "";
            var skipCertVerify  = extra.GetValueOrDefault("skip_cert_verify") == "true";
            var sni = node.HostParam ?? node.Host;

            // REALITY 启用条件
            var realityEnabled = string.Equals(extra.GetValueOrDefault("reality_enabled"), "true", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(security, "reality", StringComparison.OrdinalIgnoreCase);

            // ====== 阶段3：TLS / REALITY 握手 ======
            if (security is "tls" or "reality")
            {
                // Chrome ClientHello 测试
                bool helloOk = await TlsHelper.TestTlsWithChromeHelloAsync(
                    node.Host, node.Port, sni,
                    timeoutMs: (int)TimeSpan.FromSeconds(timeoutSec).TotalMilliseconds
                );
                if (!helloOk)
                {
                    LogHelper.Warn($"[TLS] {node.Host}:{node.Port} | Chrome ClientHello 失败（可能被 CDN 拦截）");
                    return (false, sw.Elapsed, stream);
                }

                var ssl = new SslStream(stream, leaveInnerStreamOpen: true);
                var sslOpts = TlsHelper.CreateSslOptions(sni, skipCertVerify);
                await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);
                stream = ssl;
                LogHelper.Info($"[TLS] {node.Host}:{node.Port} | Chrome 指纹握手成功");
            }

            // REALITY 握手
            if (realityEnabled && security == "reality")
            {
                var spx = extra.GetValueOrDefault("spx") ?? "/";
                var pk  = extra.GetValueOrDefault("reality_public_key") ?? "";
                var sid = extra.GetValueOrDefault("reality_short_id") ?? "";
                var pbk = extra.GetValueOrDefault("pbk") ?? "";

                var activePk = !string.IsNullOrEmpty(pk) ? pk : pbk;
                LogHelper.Debug($"[REALITY] {node.Host}:{node.Port} | sid={sid}, pk={pk}, pbk={pbk}");

                if (!string.IsNullOrEmpty(activePk) && !string.IsNullOrEmpty(sid))
                {
                    // 修改点：使用 RealityHelper 真实 Curve25519 + TLS1.3 握手
                    var ok = await RealityHelper.RealityHandshakeAsync(stream!, sid, activePk, spx, cts.Token);
                    if (ok)
                        LogHelper.Info($"[REALITY] {node.Host}:{node.Port} | 握手成功");
                }
                else
                {
                    LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | 缺少 pk/pbk 或 sid 参数");
                }
            }

            // ====== 阶段4：传输类型处理 ======
            if (transportType.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
                transportType.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase))
            {
                // WebSocket 处理
                await HandleWebSocketAsync(node, stream!, extra, transportType, security, sni, timeoutSec, opts, sw, cts);
                return (true, sw.Elapsed, null);
            }
            else if (transportType.Equals("grpc", StringComparison.OrdinalIgnoreCase))
            {
                return await HandleGrpcAsync(node, address, extra, security, cts, sw);
            }
            else if (transportType.Equals("xhttp", StringComparison.OrdinalIgnoreCase))
            {
                return await HandleXHttpAsync(node, address, timeoutSec, extra, skipCertVerify, sw, cts);
            }

            // 默认 TCP (VLESS 直连)
            var uuid = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.Password ?? "");
            var header = BuildVlessHeader(node, address, uuid, extra); // 修改点：保证全部 ExtraParams 都用于构建 Header
            await stream!.WriteAsync(header, cts.Token);
            await stream.FlushAsync(cts.Token);

            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await stream.ReadAsync(buf.AsMemory(0, 1), cts.Token);
                sw.Stop();
                return read > 0 ? (true, sw.Elapsed, stream) : (false, sw.Elapsed, null);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 超时");
            return (false, sw.Elapsed, null);
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 异常: {ex.Message}");
            return (false, sw.Elapsed, null);
        }
    }

    // ====== 辅助方法：保证 ExtraParams 全部使用 ======
    private static byte[] BuildVlessHeader(
        HiddifyConfigsCLI.src.Core.NodeInfo node,
        IPAddress address,
        Guid uuid,
        IReadOnlyDictionary<string, string> extra )
    {
        var uuidBytes = uuid.ToByteArray();
        byte[] addrBytes;
        byte addrType;

        if (IPAddress.TryParse(node.Host, out var ip))
        {
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                addrType = 0x01;
                addrBytes = ip.GetAddressBytes();
            }
            else
            {
                addrType = 0x04;
                addrBytes = ip.GetAddressBytes();
            }
        }
        else
        {
            addrType = 0x03;
            var domainBytes = System.Text.Encoding.UTF8.GetBytes(node.Host);
            addrBytes = new byte[1 + domainBytes.Length];
            addrBytes[0] = (byte)domainBytes.Length;
            Buffer.BlockCopy(domainBytes, 0, addrBytes, 1, domainBytes.Length);
        }

        var networkPort = IPAddress.HostToNetworkOrder((short)node.Port);
        var portBytes = BitConverter.GetBytes(networkPort);

        var header = new byte[16 + 1 + 1 + addrBytes.Length + 2];
        Buffer.BlockCopy(uuidBytes, 0, header, 0, 16);
        header[16] = 0x01; // TCP command
        header[17] = addrType;
        Buffer.BlockCopy(addrBytes, 0, header, 18, addrBytes.Length);
        Buffer.BlockCopy(portBytes, 0, header, 18 + addrBytes.Length, 2);

        // 修改点：全部 ExtraParams 写入 Header 相关字段
        if (extra is Dictionary<string, string> dict)
        {
            var flow = dict.GetValueOrDefault("flow") ?? "";
            dict["flow"] = flow;
            var isTls = dict.GetValueOrDefault("tls") == "tls" || dict.GetValueOrDefault("tls_enabled") == "true";
            var isReality = dict.GetValueOrDefault("tls") == "reality" || dict.GetValueOrDefault("reality_enabled") == "true";
            dict["tls_enabled"] = (isTls || isReality).ToString().ToLowerInvariant();
            dict["reality_enabled"] = isReality.ToString().ToLowerInvariant();
        }

        return header;
    }

    /// <summary>
    /// 
    /// </summary>
    private static Guid ParseOrRandomUuid( string? s )
        => Guid.TryParse(s, out var id) ? id : Guid.NewGuid();

    private static async Task<(bool, TimeSpan, Stream?)> HandleXHttpAsync(
        HiddifyConfigsCLI.src.Core.NodeInfo node, IPAddress address, int timeoutSec,
        IReadOnlyDictionary<string, string> extra, bool skipCertVerify,
        Stopwatch sw, CancellationTokenSource cts )
    {
        var xhttpPath = extra.GetValueOrDefault("xhttp_path") ?? "/";
        var xhttpHost = extra.GetValueOrDefault("xhttp_host") ?? node.Host;
        var xhttpMethod = (extra.GetValueOrDefault("xhttp_method") ?? "GET").ToUpperInvariant();
        var xhttpHeaders = extra
            .Where(k => k.Key.StartsWith("xhttp_header_"))
            .ToDictionary(k => k.Key["xhttp_header_".Length..], k => k.Value);

        var handler = new HttpClientHandler();
        if (skipCertVerify)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        using var httpClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        foreach (var (key, val) in xhttpHeaders)
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation(key, val);

        var requestUri = new UriBuilder
        {
            Scheme = (extra.GetValueOrDefault("security") ?? "tls") == "tls" ? "https" : "http",
            Host = node.Host,
            Port = node.Port,
            Path = xhttpPath.Split('?')[0],
            Query = xhttpPath.Contains('?') ? xhttpPath.Split('?', 2)[1] : ""
        }.Uri;

        var request = new HttpRequestMessage(new HttpMethod(xhttpMethod), requestUri);
        request.Headers.Host = xhttpHost;

        var uuidXHTTP = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.Password ?? "");
        var vlessHeader = BuildVlessHeader(node, address, uuidXHTTP, extra);
        request.Content = new ByteArrayContent(vlessHeader);

        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            if (!response.IsSuccessStatusCode)
            {
                LogHelper.Warn($"[XHTTP] {node.Host}:{node.Port} | HTTP 状态码: {response.StatusCode}");
                sw.Stop();
                return (false, sw.Elapsed, null);
            }

            using var respStream = await response.Content.ReadAsStreamAsync(cts.Token);
            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await respStream.ReadAsync(buf.AsMemory(0, 1), cts.Token);
                sw.Stop();
                LogHelper.Info($"[XHTTP] {node.Host}:{node.Port} | 握手成功");
                return (read > 0, sw.Elapsed, null);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[XHTTP] {node.Host}:{node.Port} | 握手失败: {ex.Message}");
            sw.Stop();
            return (false, sw.Elapsed, null);
        }
    }

    /// <summary>
    /// WebSocket 处理（保证全部 ExtraParams 使用）
    /// </summary>
    private static async Task HandleWebSocketAsync(
        HiddifyConfigsCLI.src.Core.NodeInfo node,
        Stream stream,
        IReadOnlyDictionary<string, string> extra,
        string transportType,
        string security,
        string sni,
        int timeoutSec,
        RunOptions opts,
        Stopwatch sw,
        CancellationTokenSource cts )
    {
        // 提取 WebSocket 相关参数
        var wsPath = extra.GetValueOrDefault("ws_path")
                   ?? extra.GetValueOrDefault("path") ?? "/"; // 路径
        var hostHeader = extra.GetValueOrDefault("host") ?? node.Host; // Host 头
        sni = extra.GetValueOrDefault("sni") ?? hostHeader;           // TLS SNI，可覆盖默认 Host

        var wsUri = new UriBuilder
        {
            Scheme = security == "tls" ? "wss" : "ws",
            Host = node.Host,
            Port = node.Port,
            Path = wsPath.Split('?')[0],
            Query = wsPath.Contains('?') ? wsPath.Split('?', 2)[1] : ""
        }.Uri;

        using var ws = new ClientWebSocket();
        ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
        ws.Options.SetRequestHeader("Host", hostHeader);

        // 遍历 ExtraParams 中所有 ws_header_ 前缀字段，全部设置为请求头
        foreach (var kv in extra.Where(kv => kv.Key.StartsWith("ws_header_")))
        {
            var headerName = kv.Key["ws_header_".Length..];
            ws.Options.SetRequestHeader(headerName, kv.Value);
        }

        // 连接 WebSocket
        await ws.ConnectAsync(wsUri, cts.Token);

        // 发送简单 Ping 测试
        await ws.SendAsync(new byte[] { 0x9, 0x0 }, WebSocketMessageType.Binary, true, cts.Token);
        await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Test", cts.Token);

        LogHelper.Debug($"[WebSocket] {node.Host}:{node.Port} | Path={wsPath} HostHeader={hostHeader}");

        // 调用 WebSocketTester 测试完整性
        var wsTestResult = await WebSocketTester.TestAsync(
            stream,
            hostHeader,
            wsPath,
            opts,
            cts.Token
        );

        if (!wsTestResult)
        {
            LogHelper.Warn($"[WebSocket] {node.Host}:{node.Port} | 隧道测试失败");
            throw new Exception("WebSocket handshake failed"); // 上层捕获
        }

        sw.Stop();
        LogHelper.Info($"[WebSocket] {node.Host}:{node.Port} | 握手成功");
    }

    /// <summary>
    /// gRPC 处理（保证全部 ExtraParams 使用）
    /// </summary>
    private static async Task<(bool, TimeSpan, Stream?)> HandleGrpcAsync(
        HiddifyConfigsCLI.src.Core.NodeInfo node,
        IPAddress address,
        IReadOnlyDictionary<string, string> extra,
        string security,
        CancellationTokenSource cts,
        Stopwatch sw )
    {
        var grpcService = extra.GetValueOrDefault("grpc_service") ?? "vless"; // gRPC 服务名
        var grpcPath = $"/{grpcService}";

        try
        {
            using var handler = new HttpClientHandler();
            if (security == "tls")
                handler.ServerCertificateCustomValidationCallback = ( sender, cert, chain, errors ) => true;

            using var httpClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

            var grpcUri = new UriBuilder
            {
                Scheme = security == "tls" ? "https" : "http",
                Host = node.Host,
                Port = node.Port,
                Path = grpcPath
            }.Uri;

            // 构造 VLESS 头部 payload
            var uuidgRPC = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.Password ?? "");
            byte[] grpcPayload = new byte[5]; // 前缀长度 5
            using var content = new ByteArrayContent(grpcPayload);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc");

            var request = new HttpRequestMessage(HttpMethod.Post, grpcUri)
            {
                Content = content,
                Version = HttpVersion.Version20
            };

            // 遍历 ExtraParams 中所有 grpc_header_ 前缀字段，全部加入请求头
            foreach (var kv in extra.Where(kv => kv.Key.StartsWith("grpc_header_")))
            {
                var headerName = kv.Key["grpc_header_".Length..];
                request.Headers.TryAddWithoutValidation(headerName, kv.Value);
            }

            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);

            if (!response.IsSuccessStatusCode)
            {
                LogHelper.Warn($"[gRPC] {node.Host}:{node.Port} | HTTP 状态码: {response.StatusCode}");
                sw.Stop();
                return (false, sw.Elapsed, null);
            }

            // 读取首个字节确保流可用
            using var respStream = await response.Content.ReadAsStreamAsync(cts.Token);
            var bufgRPC = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await respStream.ReadAsync(bufgRPC.AsMemory(0, 1), cts.Token);
                sw.Stop();
                LogHelper.Info($"[gRPC] {node.Host}:{node.Port} | 握手成功");
                return (read > 0, sw.Elapsed, null);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bufgRPC);
            }
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[gRPC] {node.Host}:{node.Port} | 握手失败: {ex.Message}");
            sw.Stop();
            return (false, sw.Elapsed, null);
        }
    }
}
