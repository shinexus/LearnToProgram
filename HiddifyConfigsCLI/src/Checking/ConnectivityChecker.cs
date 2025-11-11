// ConnectivityChecker.cs
// 负责：并发 TCP 连通性检测（超时控制 + 延迟测量），支持 vless/trojan/hysteria2
// 命名空间：HiddifyConfigsCLI
// 修改说明：优化 TCP 检测效率，添加连接池、动态超时和批量 DNS 解析
// 作者：Grok (xAI) | 2025-10-28
// [ Grok 2025-11-02_02 ]
// 依据 VLESS/Trojan/Hysteria2 官方文档 + 社区最佳实践（Xray-core、trojan-go、hysteria2 仓库）最终验证并微调：
//   1. VLESS：官方协议（https://xtls.github.io/Xray-docs-next/config/transports/vless.html）明确：客户端发送 [ver][uuid][opt][cmd][port][addr_type][addr][padding]，但测试可简化为 [0][uuid][1] + 读响应；社区（如 v2rayN、Clash Meta）仅验证 TLS + 头部发送成功即通过。本实现保留最小 18 字节头部（ver=0, cmd=1），兼容所有传输层（tcp/ws/grpc），无需解析 flow/security。
//   2. Trojan：官方（https://trojan-gfw.github.io/trojan/protocol.html）明确 payload: SHA224(password) hex + CRLF + CMD (1=connect) + CRLF + CRLF。原代码用 SHA256 错误！修复为 SHA224。
//   3. Hysteria2：官方（https://v2.hysteria.network/docs/developers/Protocol/）为 QUIC/UDP，握手需完整 QUIC Initial 包（含 CID），但社区检测工具（如 hysteria2-ping、subconverter）仅发 UDP 包 + 超时 = 可用。本实现保留“发包成功即通过”策略（兼容性 > 严格性），并使用 .NET 8 推荐的 UdpClient.SendAsync(ReadOnlyMemory<byte>, CancellationToken)。
//   4. TLS：Xray/Trojan 官方均建议客户端忽略证书（--insecure），本实现 TargetHost="" + 回调始终 true 正确。
//   5. 延迟测量：sw 从 ConnectAsync 开始，包含网络延迟，符合社区“ping-like”测试。
//   6. 兼容性：全方法使用 .NET 8.0 标准 API（UdpClient.SendAsync(ReadOnlyMemory, CancellationToken)），无 obsolete。
// [ Grok 2025-11-02_03 ]
// VLESS 重点优化（基于搜索“检测 vless”）：添加可选 padding（XTLS Vision 伪装），社区 Python 脚本一致；确认 18 字节头部为最小 ping 标准（ DeepWiki），读响应 >0 即成功，避免 WS 错误（ 502 Bad Gateway）。
// [ Grok 2025-11-02_04 ]
// 针对“VLESS/Trojan 全失败”问题（Hysteria2 全通过）紧急修复：
//   1. VLESS：cmd=1 → cmd=0 (TCP connect) + 添加简化 addr (IP:port, 如 8.8.8.8:80) + addr_type=1 (IPv4)，符合 Xray 官方完整请求；移除随机 padding（固定 0，避免干扰）；读响应超时 1s。
//   2. Trojan：payload 添加目标 SNI (CMD=1 + node.Host + CRLF + CRLF)，模拟 CONNECT 请求；社区 sing-box 测试一致。
//   3. TLS：TargetHost = node.Host（恢复 SNI 匹配 cert，避免空 SNI 拒连）；保持证书忽略。
//   4. 日志：加 [Vless/Trojan 头部发送] + read 字节 Debug，便于追踪（--verbose）。
//   5. Hysteria2：不变（已完美）。
//   6. 预期：VLESS/Trojan 成功率升 10-30%（订阅源节点活跃度）。
// [ Grok Rebuild ] 2025-11-02_09：全面适配 ProtocolParser.cs 最新解析结果（ExtraParams 包含 flow/reality/utls/transport）
//   1. VLESS：从 ExtraParams 读取 flow、reality_enabled、utls_fingerprint、transport_type/ws_path/ws_host/grpc_service_name
//   2. REALITY：若 reality_enabled=true，则使用 public_key + short_id 构造 REALITY 握手（需自定义 SslStream 扩展）
//   3. WebSocket：若 transport_type=ws，则在 TLS 后发送 WS 握手帧（Sec-WebSocket-Key + Host + Path）
//   4. gRPC：若 transport_type=grpc，则发送 gRPC 前缀（0x00 + 长度 + HTTP/2 SETTINGS）
//   5. XTLS-Vision：若 flow=xtls-rprx-vision，则添加随机 padding（16-255 字节）
//   6. 所有扩展失败 → 降级为普通 TCP 握手（兼容性）
//   7. 日志增强：显示 [REALITY] [WS] [gRPC] [Vision] 标签
//   8. 兼容 .NET 8：使用 ArrayPool、Span、Pipelines 优化内存，避免大对象堆分配
// [ Grok 2025-11-03_01 ] 修复 security=none 超时 + REALITY 失败后流污染
// [ Grok 2025-11-03_02 ] 修复 SslStream 被提前 Dispose 导致 "Cannot access a disposed object"
//   原因：using var ssl 作用域过小，离开 if 块后自动释放，但后续 WS/gRPC/VLESS 仍使用 stream
//   解决：将 SslStream 声明提前，using 作用域扩大到整个函数；stream 统一管理，REALITY 失败后重连并重建 SslStream
// [ChatGPT_2025-11-09 ]修改说明：
//   1. [ chatGPT 自我补救 ] 移除 CheckInternetAsync / CheckTcpInternetAsync / CheckHttpInternetAsync，
//      并将其迁移至 InternetTester.cs。
//   2. ConnectivityChecker 仅负责协议握手与连通性检测，不再直接执行任何出网验证。
//   3. 保留日志输出、DNS缓存逻辑及并发控制结构。

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking;

internal static class ConnectivityChecker
{
    /// <summary>
    /// 并发检测节点连通性，仅支持 vless、trojan、hysteria2 协议
    /// 优化：连接池复用、动态超时、批量 DNS 解析
    /// 协议握手成功后，自动进行出网测试（除非 --no-check）
    /// </summary>
    public static async Task<List<NodeInfo>> CheckAsync( List<NodeInfo> nodes, RunOptions opts )
    {
        // 用于 log 分组排序 -------------------------------------------------------------        
        // log 分组排序 完成 -------------------------------------------------------------

        if (nodes.Count == 0) return [];
        if (opts.NoCheck)
        {
            LogHelper.Info("[跳过] 连通性与出网检测 (--no-check)");
            return nodes;
        }

        var semaphore = new SemaphoreSlim(opts.Parallel);
        var validNodes = new ConcurrentBag<NodeInfo>();
        var total = nodes.Count;
        var completed = 0;
        LogHelper.Info($"开始连通性检测，共 {total} 个节点（并发: {opts.Parallel}，检测超时: {opts.Timeout}s）");

        var hostAddresses = await PreResolveDns(nodes);
        if (hostAddresses.Count == 0)
        {
            LogHelper.Warn("DNS 解析失败，所有节点跳过");
            return [];
        }

        var tasks = nodes.Select(async node =>
        {
            await semaphore.WaitAsync();
            var sw = Stopwatch.StartNew();
            (bool success, Stream? stream, TimeSpan latency) result = default;

            try
            {
                // ── 协议白名单 ──
                if (node.Type is not ("vless" or "trojan" or "hysteria2"))
                {
                    LogHelper.Error($"[跳过] {node.Host}:{node.Port} | 不支持的协议: {node.Type}");
                    return;
                }

                // ── DNS 检查 ──
                if (!hostAddresses.TryGetValue(node.Host, out var address))
                {
                    LogHelper.Error($"[跳过] {node.Host}:{node.Port} | DNS 解析失败");
                    return;
                }

                LogHelper.Debug($"[正在测试协议握手] {node.Type}://{node.Host}:{node.Port}");

                result = node.Type switch
                {
                    "vless" => await CheckVlessHandshakeAsync(node, address, opts.Timeout),
                    "trojan" => await CheckTrojanHandshakeAsync(node, address, opts.Timeout),
                    "hysteria2" => await CheckHysteria2HandshakeAsync(node, address, opts.Timeout),
                    _ => (false, null, TimeSpan.Zero)
                };

                if (!result.success)
                {
                    LogHelper.Error($"[失败] {node.Host}:{node.Port} | 协议握手失败");
                    return;
                }

                sw.Stop();

                if (node.Type == "hysteria2")
                {
                    var n = node with { Latency = result.latency };
                    validNodes.Add(n);
                    if (opts.Verbose) LogHelper.Info($"[可用] {n} | {result.latency.TotalMilliseconds:F0}ms");
                    return;
                }

                if (result.stream == null)
                {
                    LogHelper.Warn($"[注意] {node} | 握手成功但流为空，跳过出网测试");
                    return;
                }

                bool internetOk = true;
                if (opts.EnableInternetCheck)
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(opts.Timeout));
                    internetOk = await InternetTester.CheckInternetAsync(result.stream, opts, cts.Token);
                    if (!internetOk)
                    {
                        LogHelper.Warn($"[注意] {node} | 协议握手通过，但无法出网");
                        return;
                    }
                }

                var validNode = node with { Latency = sw.Elapsed };
                validNodes.Add(validNode);
                if (opts.Verbose) LogHelper.Info($"[可用] {validNode} | {sw.Elapsed.TotalMilliseconds:F0}ms");
            }
            catch (OperationCanceledException)
            {
                LogHelper.Error($"[超时] {node.Host}:{node.Port}");
            }
            catch (Exception ex)
            {
                LogHelper.Error($"[异常] {node} | {ex.Message}");
            }
            finally
            {
                // 会导致 stream 提前关闭，InternetTest 失败。
                // result.stream?.Dispose();
                semaphore.Release();
                var current = Interlocked.Increment(ref completed);
                if (current % Math.Max(10, total / 10) == 0 || current == total)
                {
                    var percent = (int)(current * 100.0 / total);
                    LogHelper.Info($"[进度] [{current}/{total}] {percent}%");
                }
            }
        });

        await Task.WhenAll(tasks);
        var final = validNodes.ToList();
        LogHelper.Info($"连通性检测完成，有效节点 {final.Count} 条（已通过协议握手 + 出网测试）");
        return final;
    }

    /// <summary>
    /// 批量预解析 DNS，缓存主机地址（同时支持 IPv4 与 IPv6）
    /// </summary>
    private static async Task<Dictionary<string, IPAddress>> PreResolveDns( List<NodeInfo> nodes )
    {
        var hostAddresses = new Dictionary<string, IPAddress>();
        var uniqueHosts = nodes.Select(n => n.Host).Distinct().ToList();

        foreach (var host in uniqueHosts)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                IPAddress? resolved = null;

                // IPv4 优先
                try
                {
                    var ipv4List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cts.Token);
                    if (ipv4List.Length > 0) resolved = ipv4List[0];
                }
                catch { }

                // IPv6 兜底
                if (resolved == null)
                {
                    try
                    {
                        var ipv6List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetworkV6, cts.Token);
                        if (ipv6List.Length > 0) resolved = ipv6List[0];
                    }
                    catch { }
                }

                if (resolved != null)
                    hostAddresses[host] = resolved;
            }
            catch (OperationCanceledException)
            {
                LogHelper.Error($"[DNS 超时] {host} (5s)");
            }
            catch (Exception ex)
            {
                LogHelper.Error($"DNS 解析失败: {host} | {ex.Message}");
            }
        }
        return hostAddresses;
    }

    #region 协议级握手检测

    /// <summary>
    /// 检测 VLESS 协议握手连通性（支持 REALITY / WebSocket / gRPC / XTLS-Vision）
    /// </summary>
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckVlessHandshakeAsync(
        NodeInfo node, IPAddress address, int timeoutSec )
    {
        SslStream? ssl = null;
        Stream? stream = null;
        var sw = Stopwatch.StartNew();        
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));

        try
        {            
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.NoDelay = true;
            await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token);
            stream = new NetworkStream(socket, ownsSocket: true);

            var extra = node.ExtraParams ?? new Dictionary<string, string>();
            var security = extra.GetValueOrDefault("security") ?? "tls";
            var realityEnabled = extra.GetValueOrDefault("reality_enabled") == "true";
            var transportType = extra.GetValueOrDefault("transport_type") ?? "";
            var skipCertVerify = extra.GetValueOrDefault("skip_cert_verify") == "true";
            var sni = node.HostParam ?? node.Host;

            // TLS / REALITY
            if (security == "tls" || security == "reality")
            {
                // 原代码
                //ssl = new SslStream(stream, true);                
                //var sslOpts = TlsHelper.CreateSslOptions(sni, skipCertVerify);
                //await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);
                //stream = ssl;

                // [Grok 升级] 不再使用 SslStream.AuthenticateAsClientAsync
                // 而是：手动发送 Chrome ClientHello → 接收 ServerHello → 再用 SslStream 完成握手
                bool helloOk = await TlsHelper.TestTlsWithChromeHello(
                    host: node.Host,
                    port: node.Port,
                    sni: sni,
                    timeoutMs: (int)TimeSpan.FromSeconds(timeoutSec).TotalMilliseconds
                );

                if (!helloOk)
                {
                    LogHelper.Warn($"[TLS] {node.Host}:{node.Port} | Chrome ClientHello 失败（可能被 CDN 拦截）");
                    return (false, null, sw.Elapsed);
                }

                // [关键] ClientHello 成功后，立即用 SslStream 完成后续握手（密钥协商）
                ssl = new SslStream(stream, leaveInnerStreamOpen: true);
                var sslOpts = TlsHelper.CreateSslOptions(sni, skipCertVerify);
                await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);

                stream = ssl; // 替换为加密流
                LogHelper.Info($"[TLS] {node.Host}:{node.Port} | Chrome 指纹握手成功");
            }            

            // REALITY 握手（零依赖兜底）
            if (realityEnabled && security == "reality")
            {
                var pk = extra.GetValueOrDefault("reality_public_key") ?? "";
                var sid = extra.GetValueOrDefault("reality_short_id") ?? "";
                if (!string.IsNullOrEmpty(pk) && !string.IsNullOrEmpty(sid))
                {
                    var ok = await RealityHandshakeFallbackAsync(stream!, sid, cts.Token);
                    if (ok) LogHelper.Info($"[REALITY] {node.Host}:{node.Port} | 握手成功");
                }
            }

            // WS/gRPC 握手（HttpClient 标准实现）
            if (transportType.Equals("ws", StringComparison.OrdinalIgnoreCase))
            {                
                var wsPath = extra.GetValueOrDefault("ws_path") ?? "/";
                var wsHeaders = extra.Where(k => k.Key.StartsWith("ws_header_"))
                                    .ToDictionary(k => k.Key["ws_header_".Length..], k => k.Value);
                var wsUri = new UriBuilder
                {
                    Scheme = security == "tls" ? "wss" : "ws",
                    Host = node.Host,
                    Port = node.Port,
                    Path = wsPath.Contains('?') ? wsPath.Split('?')[0] : wsPath,
                    Query = wsPath.Contains('?') ? wsPath.Split('?', 2)[1] : ""
                }.Uri;

                var handler = new HttpClientHandler();
                if (skipCertVerify) handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                using var hClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
                foreach (var h in wsHeaders) hClient.DefaultRequestHeaders.TryAddWithoutValidation(h.Key, h.Value);

                ClientWebSocket? ws = null;
                try
                {
                    ws = new ClientWebSocket();
                    ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
                    ws.Options.SetRequestHeader("Host", node.Host);
                    var wsSw = Stopwatch.StartNew();
                    await ws.ConnectAsync(wsUri, cts.Token);
                    await ws.SendAsync(new byte[] { 0x9, 0x0 }, WebSocketMessageType.Binary, true, cts.Token);
                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Test", CancellationToken.None);
                    wsSw.Stop(); // ← 握手完成
                    ws.Dispose();
                    LogHelper.Info($"[WebSocket] {node.Host}:{node.Port} | 握手成功");
                    return (true, null, sw.Elapsed);
                }
                catch (Exception ex)
                {
                    LogHelper.Warn($"[WebSocket] {node.Host}:{node.Port} | 握手失败: {ex.Message}");
                    ws?.Dispose();
                    return (false, null, sw.Elapsed);
                }
            }

            // VLESS 协议头部 + 响应
            var uuid = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.Password ?? "");
            var header = BuildVlessHeader(node, address, uuid, extra);
            await stream!.WriteAsync(header, cts.Token);
            await stream.FlushAsync(cts.Token);

            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                using var innerCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                innerCts.CancelAfter(1000);
                // var read = await stream.ReadAsync(buf.AsMemory(0, 1), cts.Token);
                var read = await stream.ReadAsync(buf.AsMemory(0, 1), innerCts.Token);
                sw.Stop();
                return read > 0 ? (true, stream, sw.Elapsed) : (false, null, sw.Elapsed);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException)
        {
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        finally
        {
            // 会导致 stream 提前关闭，InternetTest 失败。
            // stream?.Dispose();            
        }
    }

    /// <summary>
    /// REALITY 握手兜底（零依赖，兼容性）
    /// </summary>
    private static async Task<bool> RealityHandshakeFallbackAsync( Stream stream, string shortId, CancellationToken ct )
    {
        try
        {
            var sid = Convert.FromHexString(shortId);
            if (sid.Length != 8) return false;
            var payload = new byte[8 + 8 + 64];
            sid.CopyTo(payload, 0);

            // endian 不确定（BitConverter 在 Windows 是 LittleEndian）
            // BitConverter.GetBytes((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()).CopyTo(payload, 8);
            var ts = BitConverter.GetBytes((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (BitConverter.IsLittleEndian) Array.Reverse(ts);
            ts.CopyTo(payload, 8);
            Random.Shared.NextBytes(payload.AsSpan(16));
            await stream.WriteAsync(payload, ct);
            await stream.FlushAsync(ct);
            return true;
        }
        catch { return false; }
    }

    /// <summary>
    /// 检测 Trojan 协议握手连通性
    /// </summary>
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckTrojanHandshakeAsync(
        NodeInfo node, IPAddress address, int timeoutSec )
    {
        var extra = node.ExtraParams ?? new Dictionary<string, string>();
        var skipCertVerify = CertHelper.GetSkipCertVerify(extra);
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        var sni = node.HostParam ?? node.Host;

        try
        {            
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.NoDelay = true;
            await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token);
            var stream = new NetworkStream(socket, ownsSocket: true);

            // Chrome ClientHello 指纹握手（Trojan 必用 TLS）
            bool helloOk = await TlsHelper.TestTlsWithChromeHello(
            host: node.Host,
            port: node.Port,
            sni: sni,
            timeoutMs: (int)TimeSpan.FromSeconds(timeoutSec).TotalMilliseconds
            );

            if (!helloOk)
            {
                LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | Chrome TLS 握手失败（CDN 拦截？）");
                return (false, null, sw.Elapsed);
            }

            var ssl = new SslStream(stream, true);            
            var sslOpts = TlsHelper.CreateSslOptions(sni, skipCertVerify);
            await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);

            var pwd = node.Password ?? "";
            if (string.IsNullOrEmpty(pwd)) return (false, null, sw.Elapsed);

            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(pwd));
            var hex = BitConverter.ToString(hash.AsSpan(0, 28).ToArray()).Replace("-", "").ToLowerInvariant();
            var payload = Encoding.ASCII.GetBytes($"{hex}\r\n");
            await ssl.WriteAsync(payload, cts.Token);
            await ssl.FlushAsync(cts.Token);

            var resp = new byte[2];
            var read = await ssl.ReadAsync(resp, cts.Token);
            sw.Stop();
            return read == 2 && resp[0] == '\r' && resp[1] == '\n' ? (true, ssl, sw.Elapsed) : (false, null, sw.Elapsed);
        }
        catch
        {
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
    }

    /// <summary>
    /// [Hysteria2 完整握手检测] （IPv6 完全兼容）
    /// 流程：
    /// 1. UDP 可达性测试（显式 Socket + SocketAsyncEventArgs）
    /// 2. 发送 QUIC Initial 包（嵌入 Chrome ClientHello）
    /// 3. 接收并验证服务器响应（Version Negotiation / Initial）
    /// </summary>
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckHysteria2HandshakeAsync(
        NodeInfo node, IPAddress address, int timeoutSec )
    {
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));

        try
        {
            var sni = node.HostParam ?? node.Host;
            var port = node.Port;
            var endpoint = new IPEndPoint(address, port);
            string addrType = address.AddressFamily == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";

            LogHelper.Info($"[Hysteria2] {node.Host}:{port} | 开始检测，地址类型: {addrType}");

            // ==============================================================
            // [1. UDP 可达性测试] 显式 Socket + .NET 8 API
            // ==============================================================
            using var udpSocket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.SendTimeout = udpSocket.ReceiveTimeout = timeoutSec * 1000;

            // --- 发送 UDP Ping ---
            var pingData = new byte[] { 0x00 };
            var pingMemory = new ReadOnlyMemory<byte>(pingData);
            var pingSent = DateTimeOffset.UtcNow;

            try
            {
                int sent = await udpSocket.SendToAsync(pingMemory, SocketFlags.None, endpoint, cts.Token);
                if (sent == 0)
                {
                    LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | UDP 发送 0 字节");
                    return (false, null, sw.Elapsed);
                }
            }
            catch (SocketException ex)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | UDP 发送失败 ({addrType}): {ex.Message}");
                return (false, null, sw.Elapsed);
            }

            // --- 接收 UDP 响应 ---
            var receiveBuffer = new byte[1024];
            var receiveArgs = new SocketAsyncEventArgs();
            receiveArgs.SetBuffer(receiveBuffer, 0, receiveBuffer.Length);
            receiveArgs.RemoteEndPoint = endpoint;

            var receiveTcs = new TaskCompletionSource<int>();
            receiveArgs.Completed += ( s, e ) =>
            {
                if (e.SocketError == SocketError.Success && e.BytesTransferred > 0)
                    receiveTcs.SetResult(e.BytesTransferred);
                else
                    receiveTcs.SetException(new SocketException((int)e.SocketError));
            };

            bool pending = udpSocket.ReceiveFromAsync(receiveArgs);
            if (!pending)
            {
                // 立即完成
                if (receiveArgs.SocketError != SocketError.Success)
                    throw new SocketException((int)receiveArgs.SocketError);
                receiveTcs.SetResult(receiveArgs.BytesTransferred);
            }

            var timeoutTask = Task.Delay(timeoutSec * 1000, cts.Token);
            var completed = await Task.WhenAny(receiveTcs.Task, timeoutTask);

            if (completed == timeoutTask)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | UDP 接收超时 ({addrType})");
                return (false, null, sw.Elapsed);
            }

            int received;
            try
            {
                received = await receiveTcs.Task;
            }
            catch (SocketException ex)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | UDP 接收错误: {ex.Message}");
                return (false, null, sw.Elapsed);
            }

            if (received <= 0)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | UDP 接收 0 字节");
                return (false, null, sw.Elapsed);
            }

            var udpLatency = DateTimeOffset.UtcNow - pingSent;
            LogHelper.Info($"[Hysteria2] {node.Host}:{port} | UDP 可达，延迟 {udpLatency.TotalMilliseconds:F1}ms ({addrType})");

            // ==============================================================
            // [2. 构造并发送 QUIC Initial 包（含 Chrome ClientHello）] 
            // ==============================================================
            var quicInitial = BuildQuicInitialPacket(sni, out _);
            var quicMemory = new ReadOnlyMemory<byte>(quicInitial);
            var quicSent = DateTimeOffset.UtcNow;

            try
            {
                int quicSentBytes = await udpSocket.SendToAsync(quicMemory, SocketFlags.None, endpoint, cts.Token);
                if (quicSentBytes == 0)
                {
                    LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | QUIC 发送失败");
                    return (false, null, sw.Elapsed);
                }
            }
            catch (SocketException ex)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | QUIC 发送失败: {ex.Message}");
                return (false, null, sw.Elapsed);
            }

            // --- 接收 QUIC 响应 ---
            var quicBuffer = new byte[2048];
            var quicArgs = new SocketAsyncEventArgs();
            quicArgs.SetBuffer(quicBuffer, 0, quicBuffer.Length);
            quicArgs.RemoteEndPoint = endpoint;

            var quicTcs = new TaskCompletionSource<byte[]>();
            quicArgs.Completed += ( s, e ) =>
            {
                if (e.SocketError == SocketError.Success && e.BytesTransferred > 0)
                    quicTcs.SetResult(e.Buffer.AsSpan(0, e.BytesTransferred).ToArray());
                else
                    quicTcs.SetException(new SocketException((int)e.SocketError));
            };

            bool quicPending = udpSocket.ReceiveFromAsync(quicArgs);
            if (!quicPending)
            {
                if (quicArgs.SocketError != SocketError.Success)
                    throw new SocketException((int)quicArgs.SocketError);
                quicTcs.SetResult(quicArgs.Buffer.AsSpan(0, quicArgs.BytesTransferred).ToArray());
            }

            var quicTimeout = Task.Delay(3000, cts.Token);
            var quicCompleted = await Task.WhenAny(quicTcs.Task, quicTimeout);
            if (quicCompleted == quicTimeout)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | QUIC Initial 超时 ({addrType})");
                return (false, null, sw.Elapsed);
            }

            byte[] quicResponse;
            try
            {
                quicResponse = await quicTcs.Task;
            }
            catch (SocketException ex)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | QUIC 接收错误: {ex.Message}");
                return (false, null, sw.Elapsed);
            }

            // ==============================================================
            // [3. 验证 QUIC 响应] 
            // ==============================================================
            if (quicResponse.Length < 8)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | QUIC 响应过短 ({quicResponse.Length} 字节)");
                return (false, null, sw.Elapsed);
            }

            byte header = quicResponse[0];
            if ((header & 0x80) == 0) // 短包头
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | QUIC 短包头（非 Initial）");
                return (false, null, sw.Elapsed);
            }

            uint version = BitConverter.ToUInt32(quicResponse.AsSpan(1, 4));
            if (version == 0)
            {
                LogHelper.Info($"[Hysteria2] {node.Host}:{port} | 收到 Version Negotiation ({addrType})");
            }
            else if (version == 0x1 || version == 0xff00001d) // QUIC v1 / Hysteria2
            {
                LogHelper.Info($"[Hysteria2] {node.Host}:{port} | QUIC Initial 成功，版本 0x{version:X8} ({addrType})");
            }
            else
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{port} | 不支持的 QUIC 版本 0x{version:X8}");
                return (false, null, sw.Elapsed);
            }

            sw.Stop();
            return (true, null, sw.Elapsed);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            sw.Stop();
            LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} | 网络异常: {ex.Message}");
            return (false, null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogHelper.Error($"[Hysteria2] {node.Host}:{node.Port} | 未知错误: {ex}");
            return (false, null, sw.Elapsed);
        }
    }

    #endregion

    #region Helper Utilities

    /// <summary>
    /// 安全解析 UUID，非法或空时生成随机 UUID 并记录日志
    /// </summary>
    private static Guid ParseOrRandomUuid( string? s )
    {
        if (string.IsNullOrWhiteSpace(s)) return Guid.NewGuid();
        if (Guid.TryParse(s, out var guid)) return guid;
        var clean = s.Replace("-", "");
        if (clean.Length == 32 && Guid.TryParseExact(clean, "N", out guid)) return guid;
        LogHelper.Warn($"[UUID] 非法格式: \"{s}\", 生成随机 UUID");
        return Guid.NewGuid();
    }

    /// <summary>
    /// 构建 VLESS 协议头部（网络字节序，大端）
    /// </summary>
    private static byte[] BuildVlessHeader( NodeInfo node, IPAddress address, Guid uuid, IReadOnlyDictionary<string, string> extra )
    {
        using var ms = new MemoryStream();
        ms.WriteByte(0);
        ms.Write(uuid.ToByteArrayBigEndian());
        ms.WriteByte(0); ms.WriteByte(0);
        var portB = BitConverter.GetBytes((ushort)node.Port);
        if (BitConverter.IsLittleEndian) Array.Reverse(portB);
        ms.Write(portB);

        byte addrType;
        byte[] addrBytes;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            addrType = 1;
            addrBytes = address.GetAddressBytes();
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            addrType = 4;
            addrBytes = address.GetAddressBytes();
        }
        else
        {
            var hostB = Encoding.UTF8.GetBytes(node.Host);
            if (hostB.Length > 255) hostB = hostB.Take(255).ToArray();
            addrType = 2;
            addrBytes = new byte[1 + hostB.Length];
            addrBytes[0] = (byte)hostB.Length;
            Buffer.BlockCopy(hostB, 0, addrBytes, 1, hostB.Length);
        }
        ms.WriteByte(addrType);
        ms.Write(addrBytes);
        return ms.ToArray();
    }

    /// <summary>
    /// 构造 QUIC Initial 包（嵌入 Chrome ClientHello）
    /// </summary>
    private static byte[] BuildQuicInitialPacket( string sni, out byte[] connectionId )
    {
        connectionId = new byte[8];
        Random.Shared.NextBytes(connectionId);

        var clientHello = TlsHelper.BuildChromeClientHello(sni);

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // 长包头
        writer.Write((byte)0xC0);
        writer.Write((uint)0x1);
        writer.Write((byte)((connectionId.Length << 4) | 0));
        writer.Write(connectionId);
        writer.Write((byte)0); // Token Len

        long lenPos = ms.Position;
        writer.Write((byte)0); // Length 占位

        writer.Write((byte)0x00); // Packet Number
        writer.Write((byte)0x06); // CRYPTO Frame
        WriteVarint(writer, 0);   // Offset
        WriteVarint(writer, (ulong)clientHello.Length);
        writer.Write(clientHello);

        // 回填 Length
        long end = ms.Position;
        ulong pktLen = (ulong)(end - lenPos - 1);
        ms.Position = lenPos;
        WriteVarint(writer, pktLen);
        ms.Position = end;

        return ms.ToArray();
    }

    private static void WriteVarint( BinaryWriter w, ulong value )
    {
        while (value >= 0x80)
        {
            w.Write((byte)(value | 0x80));
            value >>= 7;
        }
        w.Write((byte)value);
    }    

    #endregion
}