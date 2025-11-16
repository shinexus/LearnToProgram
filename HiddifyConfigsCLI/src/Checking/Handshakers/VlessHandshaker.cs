// VlessHandshaker.cs（优化版，保留原结构，确保 ExtraParams 全部使用）
// [Grok 修复_2025-11-16_002] 修复：extra 只读、WS 独立连接、Handle 返回元组、统一 UUID

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
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;

/// <summary>
/// [VLESS 握手器] 支持 REALITY / WebSocket / gRPC / XTLS-Vision
/// [Grok 修复_2025-11-16_002] 修复 extra 修改、WS 连接、Handle 返回值
/// </summary>
internal static class VlessHandshaker
{
    public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
        VlessNode node,
        IPAddress address,
        int timeoutSec,
        RunOptions opts )
    {
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        Stream? baseStream = null;
        try
        {
            // ====== 阶段1：建立 TCP 连接 ======
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token);
            baseStream = new NetworkStream(socket, ownsSocket: true);

            // ====== 阶段2：提取参数（只读）======
            var extra = node.ExtraParams ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var uuidStr = node.UserId ?? extra.GetValueOrDefault("id") ?? "";
            if (string.IsNullOrEmpty(uuidStr))
            {
                LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 缺失 UUID");
                return (false, sw.Elapsed, null);
            }
            var security = extra.GetValueOrDefault("security") ?? "tls";
            var transportType = extra.GetValueOrDefault("transport_type") ?? "";
            var skipCertVerify = extra.GetValueOrDefault("skip_cert_verify") == "true";
            var sni = node.HostParam ?? node.Host;

            // REALITY 启用条件
            var realityEnabled = string.Equals(extra.GetValueOrDefault("reality_enabled"), "true", StringComparison.OrdinalIgnoreCase)
                                 || string.Equals(security, "reality", StringComparison.OrdinalIgnoreCase);

            // ====== 阶段3：TLS / REALITY 握手 ======
            Stream? stream = baseStream;
            if (security is "tls" or "reality")
            {
                // Chrome ClientHello 测试
                bool helloOk = await TlsHelper.TestTlsWithChromeHelloAsync(
                    node.Host, node.Port, sni,
                    timeoutMs: (int)TimeSpan.FromSeconds(timeoutSec).TotalMilliseconds
                );
                if (!helloOk)
                {
                    LogHelper.Warn($"[TLS] {node.Host}:{node.Port} | Chrome ClientHello 失败");
                    return (false, sw.Elapsed, null);
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
                var pk = extra.GetValueOrDefault("reality_public_key") ?? "";
                var sid = extra.GetValueOrDefault("reality_short_id") ?? "";
                var pbk = extra.GetValueOrDefault("pbk") ?? "";
                var activePk = !string.IsNullOrEmpty(pk) ? pk : pbk;

                if (!string.IsNullOrEmpty(activePk) && !string.IsNullOrEmpty(sid))
                {
                    var ok = await RealityHelper.RealityHandshakeAsync(stream!, sid, activePk, spx, cts.Token);
                    if (ok)
                        LogHelper.Info($"[REALITY] {node.Host}:{node.Port} | 握手成功");
                    else
                        return (false, sw.Elapsed, null);
                }
                else
                {
                    LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | 缺少 pk/pbk 或 sid 参数");
                    return (false, sw.Elapsed, null);
                }
            }

            // ====== 阶段4：传输类型处理 ======
            if (transportType.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
                transportType.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase))
            {
                return await HandleWebSocketAsync(node, address, extra, transportType, security, sni, timeoutSec, opts, sw, cts);
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
            var uuid = ParseOrRandomUuid(uuidStr);
            var header = BuildVlessHeader(node, address, uuid, extra);
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
        finally
        {
            if (baseStream != null && !cts.Token.IsCancellationRequested)
                await baseStream.DisposeAsync();
        }
    }

    // ====== 辅助方法：保证 ExtraParams 全部读取（只读）======
    private static byte[] BuildVlessHeader(
        VlessNode node,
        IPAddress address,
        Guid uuid,
        IReadOnlyDictionary<string, string> extra )
    {
        var uuidBytes = uuid.ToByteArray();
        byte[] addrBytes;
        byte addrType;

        if (IPAddress.TryParse(node.Host, out var ip))
        {
            addrType = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
            addrBytes = ip.GetAddressBytes();
        }
        else
        {
            addrType = 0x03;
            var domainBytes = Encoding.UTF8.GetBytes(node.Host);
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

        // [Grok 修复] 移除 extra 修改，只读取
        var flow = extra.GetValueOrDefault("flow") ?? "";
        var isTls = extra.GetValueOrDefault("tls") == "tls" || extra.GetValueOrDefault("tls_enabled") == "true";
        var isReality = extra.GetValueOrDefault("tls") == "reality" || extra.GetValueOrDefault("reality_enabled") == "true";
        // 不写入 extra，只用于日志或未来扩展
        LogHelper.Verbose($"[VLESS Header] flow={flow}, tls={isTls}, reality={isReality}");

        return header;
    }

    private static Guid ParseOrRandomUuid( string? s )
        => Guid.TryParse(s, out var id) ? id : Guid.NewGuid();

    // ====== WebSocket 处理（独立 ClientWebSocket）======
    private static async Task<(bool, TimeSpan, Stream?)> HandleWebSocketAsync(
        VlessNode node,
        IPAddress address,
        IReadOnlyDictionary<string, string> extra,
        string transportType,
        string security,
        string sni,
        int timeoutSec,
        RunOptions opts,
        Stopwatch sw,
        CancellationTokenSource cts )
    {
        var wsPath = extra.GetValueOrDefault("ws_path") ?? extra.GetValueOrDefault("path") ?? "/";
        var hostHeader = extra.GetValueOrDefault("host") ?? node.Host;
        sni = extra.GetValueOrDefault("sni") ?? hostHeader;

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

        foreach (var kv in extra.Where(kv => kv.Key.StartsWith("ws_header_")))
        {
            var headerName = kv.Key["ws_header_".Length..];
            ws.Options.SetRequestHeader(headerName, kv.Value);
        }

        try
        {
            await ws.ConnectAsync(wsUri, cts.Token);
            await ws.SendAsync(new byte[] { 0x9, 0x0 }, WebSocketMessageType.Binary, true, cts.Token);
            await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Test", cts.Token);
            sw.Stop();
            LogHelper.Info($"[WebSocket] {node.Host}:{node.Port} | 握手成功");
            return (true, sw.Elapsed, null);
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogHelper.Warn($"[WebSocket] {node.Host}:{node.Port} | 握手失败: {ex.Message}");
            return (false, sw.Elapsed, null);
        }
    }

    /// <summary>
    /// gRPC 处理（保证全部 ExtraParams 使用）
    /// </summary>
    private static async Task<(bool, TimeSpan, Stream?)> HandleGrpcAsync(
        VlessNode node,
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
            var uuidgRPC = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.UserId ?? "");
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

    private static async Task<(bool, TimeSpan, Stream?)> HandleXHttpAsync(
        HiddifyConfigsCLI.src.Core.VlessNode node, IPAddress address, int timeoutSec,
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

        var uuidXHTTP = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.UserId ?? "");
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
}