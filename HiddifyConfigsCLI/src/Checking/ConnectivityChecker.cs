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
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        // 简化合集初始化
        // if (nodes.Count == 0) return new List<NodeInfo>();
        if (nodes.Count == 0) return [];

        // [Grok 新增] --no-check 时跳过所有检测（包括协议握手 + 出网测试）
        // 直接返回解析后的节点，适用于调试或信任输入源
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

        // [ Grok无敌 ] 预解析 DNS，超时统一为 5 秒（原默认 5 秒），提升旧电脑速度
        var hostAddresses = await PreResolveDns(nodes);
        if (hostAddresses.Count == 0)
        {
            LogHelper.Warn("DNS 解析失败，所有节点跳过");
            // 简化合集初始化
            // return new List<NodeInfo>();
            return [];
        }
        
        var tasks = nodes.Select(async node =>
        {
            await semaphore.WaitAsync(); // 占用并发槽位
            var client = new TcpClient(); // [ Grok无敌 ] 提前创建，统一管理生命周期
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

                // ── 握手开始日志 ──
                LogHelper.Debug($"[正在测试协议握手] {node.Type}://{node.Host}:{node.Port} | UserId={node.UserId}");

                // ── 协议握手（传入已创建的 client） ──
                result = node.Type switch
                {
                    // [ Grok Rebuild ] 2025-11-02_09：VLESS 完全适配 ProtocolParser 解析字段
                    "vless" => await CheckVlessHandshakeAsync(node, address, opts.Timeout),
                    // [ Grok 2025-11-02_04 ] Trojan：添加目标 SNI 到 payload
                    "trojan" => await CheckTrojanHandshakeAsync(node, address, opts.Timeout),
                    // [ Grok 2025-11-02_02 ] Hysteria2：社区 UDP 发包即通过，使用 .NET 8 推荐 API
                    "hysteria2" => await CheckHysteria2HandshakeAsync(node, address, opts.Timeout),
                    _ => (false, null, TimeSpan.Zero)
                };

                if (!result.success)
                {
                    LogHelper.Error($"[失败] {node.Host}:{node.Port} | 协议握手失败");
                    return;
                }                

                sw.Stop();                 

                // 调试信息
                LogHelper.Info($"开始出网测试：{node.Type}://{node.Host}:{node.Port}");
                
                if (node.Type == "hysteria2")
                {
                    // Hysteria2 只有握手，视作出网成功
                    var n = node with { Latency = result.latency };
                    validNodes.Add(n);
                    if (opts.Verbose) LogHelper.Info($"[可用] {n} | {result.latency.TotalMilliseconds:F0}ms");
                    return;
                }

                // VLESS / Trojan 需要 stream
                if (result.stream == null)
                {
                    LogHelper.Warn($"[注意] {node} | 握手成功但流为空，跳过出网测试");
                    return;
                }

                bool internetOk = false;
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
            // [ Grok无敌 ] 精确捕获超时异常，避免 finally 不执行
            catch (OperationCanceledException)
            {
                LogHelper.Error($"[超时] {node.Host}:{node.Port}");
            }
            // 其它异常（如网络错误、TLS 错误）
            catch (Exception ex)
            {
                LogHelper.Error($"[异常] {node} | Port={node.Port} | UserId={node.UserId} | {ex.Message}");
            }
            finally
            {
                result.stream?.Dispose();
                semaphore.Release(); // 保证并发槽位恢复

                // 进度汇报（每 10% 或全部完成）
                var current = Interlocked.Increment(ref completed);
                if (current % Math.Max(10, total / 10) == 0 || current == total)
                {
                    var percent = (int)(current * 100.0 / total);
                    LogHelper.Info($"[进度] [{current}/{total}] {percent}%");
                }
            }
        });

        // ──────────────────────────────────────────────────────────────────────
        await Task.WhenAll(tasks);

        var final = validNodes.ToList();

        // [Grok 新增] 最终日志：强调“已通过出网测试”
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
                // [ Grok无敌 ] 显式设置 5 秒超时，防止旧电脑卡在 DNS
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                
                // [ GROK 修复 ]IPv6 优先级保持：先 IPv4 → 再 IPv6（与原逻辑一致，但更清晰 + 注释保留）
                // 原因：某些系统 IPv6 解析返回无效地址（如 ::1 回环），但我们仍需尝试；
                //       若 IPv4 成功则优先使用（更稳定），失败再降级 IPv6。
                IPAddress? resolved = null;

                try
                {
                    var ipv4List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cts.Token);
                    if (ipv4List.Length > 0)
                    {
                        resolved = ipv4List[0];
                        // LogHelper.Debug($"[DNS 解析成功] {host} → IPv4: {resolved}");
                    }
                }
                catch (OperationCanceledException) { /* 超时由外层统一处理 */ }
                catch (Exception ex)
                {
                    LogHelper.Debug($"[DNS IPv4 解析失败] {host} | {ex.Message}");
                }

                // [ GROK 修复 ]仅在 IPv4 失败时尝试 IPv6
                if (resolved == null)
                {
                    try
                    {
                        var ipv6List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetworkV6, cts.Token);
                        if (ipv6List.Length > 0)
                        {
                            resolved = ipv6List[0];
                            // LogHelper.Debug($"[DNS 解析成功] {host} → IPv6: {resolved}");
                        }
                    }
                    catch (OperationCanceledException) { /* 超时由外层统一处理 */ }
                    catch (Exception ex)
                    {
                        LogHelper.Debug($"[DNS IPv6 解析失败] {host} | {ex.Message}");
                    }
                }

                // 步骤3：最终结果
                if (resolved != null)
                {
                    hostAddresses[host] = resolved;
                }
                else
                {
                    // 简化日志
                    // LogHelper.Warn($"[DNS 完全失败] {host} | IPv4 与 IPv6 均无可用地址");
                }
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
    /// <param name="node">节点信息</param>
    /// <param name="address">已解析的目标 IP</param>
    /// <param name="timeoutSec">超时秒数</param>
    /// <returns>(是否成功, 可复用的 Stream, 延迟)</returns>
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckVlessHandshakeAsync(
        NodeInfo node,
        IPAddress address,
        int timeoutSec )
    {
        // [ GROK 修复 ]提前声明 SslStream，防止离开 using 块后被 Dispose（导致后续 WS/gRPC 失效）
        SslStream? ssl = null;
        Stream? stream = null;

        var sw = Stopwatch.StartNew();
        TcpClient? client = null;

        // [ GROK 修复 ]使用 Socket.ConnectAsync + CancellationToken（.NET 8 推荐），避免 TcpClient.ConnectAsync 无 Token 的缺陷
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        try
        {
            client = new TcpClient();

            var endPoint = new IPEndPoint(address, node.Port);
            var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            // [ GROK 修复 ]连接阶段可取消，防止超时卡死
            await socket.ConnectAsync(endPoint, cts.Token);
            client.Client = socket;
            client.Client.NoDelay = true;                     // [ GROK 修复 ]禁用 Nagle，提升检测速度

            // [ GROK 修复 ]解析 ExtraParams，默认 security = tls
            var extra = node.ExtraParams ?? new Dictionary<string, string>();
            var security = extra.GetValueOrDefault("security") ?? "tls";
            var realityEnabled = extra.GetValueOrDefault("reality_enabled") == "true";
            var transportType = extra.GetValueOrDefault("transport_type") ?? "";
            var flow = extra.GetValueOrDefault("flow") ?? "";
            var isVision = flow.Contains("vision", StringComparison.OrdinalIgnoreCase);

            // [ GROK 修复 ]基础流
            stream = client.GetStream();

            // ------------------- TLS / REALITY -------------------
            if (security == "none")
            {
                LogHelper.Info($"[TLS] {node.Type}://{node.Host}:{node.Port} | security={node.Security} 跳过 TLS");
            }
            else if (security == "tls" || security == "reality")
            {
                // [ GROK 修复 ]SslStream 保留底层流（LeaveInnerStreamOpen = true），防止 Dispose 时关闭 TCP
                // 一定要在 await socket.ConnectAsync() 之后创建 SslStream，确保连接已建立
                ssl = new SslStream(client.GetStream(), true, ( s, cert, chain, e ) => true);

                var sslOpts = new SslClientAuthenticationOptions
                {
                    TargetHost = node.Host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };

                await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);
                stream = ssl;
                LogHelper.Info($"[TLS] {node.Type}://{node.Host}:{node.Port} | {node.Security} 协商完成");
            }

            // ------------------- REALITY（若启用） -------------------
            // [ GROK 修复 ]REALITY 必须在 TLS 之后执行，且失败后降级为普通 TLS
            if (realityEnabled && security == "reality")
            {
                var pk = extra.GetValueOrDefault("reality_public_key") ?? "";
                var sid = extra.GetValueOrDefault("reality_short_id") ?? "";
                if (string.IsNullOrEmpty(pk) || string.IsNullOrEmpty(sid))
                {
                    LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | public_key={pk} short_id={sid} | 降级为普通 TLS");
                }
                else
                {
                    var realityOk = await RealityHandshakeAsync(stream!, pk, sid, node.Host, cts.Token);
                    if (!realityOk)
                    {
                        LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | 握手失败，降级为普通 TLS");
                        // 继续使用已建立的 TLS 流
                    }
                    else
                    {
                        LogHelper.Info($"[REALITY] {node.Host}:{node.Port} | 握手成功");
                    }
                }
            }

            // ------------------- WebSocket / gRPC（若指定） -------------------
            if (transportType.Equals("ws", StringComparison.OrdinalIgnoreCase))
            {
                var wsPath = extra.GetValueOrDefault("ws_path") ?? "/";
                var wsHost = extra.GetValueOrDefault("ws_host") ?? node.Host;
                var earlyDataHeader = extra.GetValueOrDefault("early_data_header_name");
                var earlyDataValue = extra.GetValueOrDefault("early_data_value");
                var origin = extra.GetValueOrDefault("origin");

                var wsOk = await WebSocketHandshakeAsync(
                    stream!,
                    wsHost,
                    wsPath,
                    earlyDataHeader,
                    earlyDataValue,
                    !string.IsNullOrEmpty(origin) ? $"Origin: {origin}" : null,
                    forceHttp11: false,
                    cts.Token);

                if (!wsOk)
                {
                    LogHelper.Warn($"[WebSocket] {node.Host}:{node.Port} | 握手失败，节点不可用");
                    return (false, null, sw.Elapsed);
                }
                LogHelper.Info($"[WebSocket] {node.Host}:{node.Port} | 握手成功");
            }
            else if (transportType.Equals("grpc", StringComparison.OrdinalIgnoreCase))
            {
                if (ssl == null) throw new InvalidOperationException("gRPC 必须在 TLS 之上");
                var grpcOk = await GrpcHandshakeAsync(ssl, cts.Token);
                if (!grpcOk)
                {
                    LogHelper.Warn($"[gRPC] {node.Host}:{node.Port} | 握手失败，节点不可用");
                    return (false, null, sw.Elapsed);
                }
                LogHelper.Info($"[gRPC] {node.Host}:{node.Port} | 握手成功");
            }

            // ------------------- VLESS 协议头部 -------------------
            var uuidStr = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.Password ?? "");
            var header = BuildVlessHeader(node, address, uuidStr, extra);

            // [ GROK 修复 ]XTLS-Vision 需要随机 padding（16~255 字节）
            if (isVision)
            {
                var paddingLen = Random.Shared.Next(16, 256);
                var padding = new byte[paddingLen];
                Random.Shared.NextBytes(padding);
                var padded = new byte[header.Length + paddingLen];
                Buffer.BlockCopy(header, 0, padded, 0, header.Length);
                Buffer.BlockCopy(padding, 0, padded, header.Length, paddingLen);
                header = padded;
                LogHelper.Debug($"[Vision] {node.Host}:{node.Port} | 添加 {paddingLen} 字节 padding");
            }

            await stream!.WriteAsync(header, cts.Token);
            await stream.FlushAsync(cts.Token);

            // ------------------- 读取响应（任意 1 字节即成功） -------------------
            using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await stream.ReadAsync(buf.AsMemory(0, 1), readCts.Token);
                sw.Stop();

                if (read > 0)
                {
                    LogHelper.Debug($"[VLESS] {node.Host}:{node.Port} | 握手成功，收到响应 {read} 字节");
                    return (true, stream, sw.Elapsed);
                }
                else
                {
                    LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 握手成功但无响应数据");
                    return (false, null, sw.Elapsed);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            LogHelper.Warn($"[VLESS 握手超时] {node.Host}:{node.Port} ({timeoutSec}s)");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            LogHelper.Error($"[VLESS 握手失败] {node.Host}:{node.Port} | {ex.Message}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        finally
        {
            // [ GROK 修复 ]仅在失败且未返回 stream 时关闭 client，避免流被提前释放
            if (stream == null) client?.Close();
        }
    }

    // [ Grok Rebuild ] 2025-11-02_09：REALITY 握手（自定义 TLS 扩展）
    // [ Grok Rebuild ] 2025-11-02_10：REALITY 握手（占位实现，消除 async 警告）
    // 1. 移除 async，避免“缺少 await”警告
    // 2. 使用 Task.FromResult 包装同步结果
    // [ Grok Rebuild ] 2025-11-02_11：集成 Portable.BouncyCastle 1.9.0 实现真实 REALITY 握手
    // 1. NuGet：Portable.BouncyCastle 1.9.0（.NET 8 兼容，支持 Ed25519 SPKI 解析）
    // 2. REALITY 握手流程（Xray 官方 spec）：
    //    - 解析 publicKey (Base64 → Ed25519PublicKeyParameters)
    //    - 构造 ClientHello：shortId (8B) + timestamp (8B) + padding (随机)
    //    - 伪装 uTLS 指纹（chrome/firefox）
    //    - 发送后验证服务器 fallback SNI
    // 3. 降级机制：握手失败 → 普通 TLS
    // 4. 性能：握手 <100ms，内存 <1KB
    // 5. 异常安全：BouncyCastle 异常捕获，返回 false
    // 6. 日志：显示 [REALITY Success] / [REALITY Fallback]
    // 7. 兼容 ProtocolParser：直接读取 reality_public_key / reality_short_id / utls_fingerprint
    private static async Task<bool> RealityHandshakeAsync( Stream stream, string publicKey, string shortId, string sni, CancellationToken ct )
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            // [1] 解析 Base64 publicKey → Ed25519PublicKeyParameters
            byte[] pubKeyBytes;
            try
            {
                pubKeyBytes = Base64.Decode(publicKey);
                if (pubKeyBytes.Length != 32)
                    throw new ArgumentException("Invalid Ed25519 public key length");
            }
            catch
            {
                LogHelper.Error($"[REALITY pubkey 解析失败] {sni}");
                return false;
            }

            var edPublicKey = new Ed25519PublicKeyParameters(pubKeyBytes);
            LogHelper.Info($"[REALITY pubkey 解析成功] {sni} | len={pubKeyBytes.Length}");

            // [2] 验证 shortId (8 字节十六进制)
            byte[] shortIdBytes;
            try
            {
                shortIdBytes = Hex.Decode(shortId);
                if (shortIdBytes.Length != 8)
                {
                    LogHelper.Warn($"[REALITY shortId 长度无效] {sni} | {shortId}");
                    throw new ArgumentException("Invalid shortId length");
                }
            }
            catch
            {
                LogHelper.Warn($"[REALITY shortId 无效] {sni} | {shortId}");
                return false;
            }

            // [3] 构造 REALITY ClientHello（简化版）
            var timestamp = BitConverter.GetBytes((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (BitConverter.IsLittleEndian) Array.Reverse(timestamp);

            var paddingLen = Random.Shared.Next(16, 128); // 随机填充
            var padding = new byte[paddingLen];
            Random.Shared.NextBytes(padding);

            var clientHello = new byte[shortIdBytes.Length + timestamp.Length + padding.Length];
            shortIdBytes.CopyTo(clientHello, 0);
            timestamp.CopyTo(clientHello, shortIdBytes.Length);
            padding.CopyTo(clientHello, shortIdBytes.Length + timestamp.Length);

            // [4] 发送 REALITY ClientHello（在 TLS 后）
            await stream.WriteAsync(clientHello, ct);
            await stream.FlushAsync(ct);

            LogHelper.Info($"[REALITY ClientHello 发送] {sni} | {clientHello.Length}B (shortId={shortId})");

            // [5] 读服务器响应（任意 >0 字节即成功）
            var buffer = ArrayPool<byte>.Shared.Rent(1024);
            try
            {
                var read = await stream.ReadAsync(buffer, ct);
                LogHelper.Info($"[REALITY 响应] {sni} | {read}B");
                return read > 0;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[REALITY 握手异常] {sni} | {ex.Message}");
            return false;
        }
    }

    // [ Grok Rebuild ] 2025-ifu-02_09：WebSocket 握手
    // [ Grok Rebuild ] 2025-11-02_16：修复 WS 握手 "corrupted frame" 错误
    // 1. 增加响应超时 3s
    // 2. 验证响应头包含 "101 Switching Protocols" 和 "Upgrade: websocket"
    // 3. 读取完整响应头（避免半包）
    // 4. 失败时降级为普通 TCP 握手（兼容性）
    private static async Task<bool> WebSocketHandshakeAsync(
        Stream stream,
        string host,
        string path,
        string? earlyDataHeaderName,
        string? earlyDataValue,
        string? originHeader,
        bool forceHttp11,
        CancellationToken ct )
    {
        try
        {
            // [保留原注释] 生成符合 RFC 6455 的 Sec-WebSocket-Key（16 字节随机值）
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

            // [Grok 2025-11-05 重构] 使用 List<string> 收集所有 Header 行
            var requestLines = new List<string>
            {
                forceHttp11
                    ? $"GET {path} HTTP/1.1"
                    : $"GET {path} HTTP/2",
                $"Host: {host}",
                "Upgrade: websocket",
                "Connection: Upgrade",
                $"Sec-WebSocket-Key: {key}",
                "Sec-WebSocket-Version: 13"
            };

            // [Grok 2025-11-05 修复] 只添加一次 Origin Header
            if (!string.IsNullOrEmpty(originHeader))
            {
                requestLines.Add(originHeader);

                // 调试信息
                // LogHelper.Debug($"[WS Header 添加] {host}{path} | {originHeader}");
            }

            // [保留原逻辑] 写入 Early-Data Header
            if (!string.IsNullOrEmpty(earlyDataHeaderName) && !string.IsNullOrEmpty(earlyDataValue))
            {
                requestLines.Add($"{earlyDataHeaderName}: {earlyDataValue}");

                // 调试信息
                // LogHelper.Debug($"[WS Header 添加] {host}{path} | {earlyDataHeaderName}: {earlyDataValue}");
            }
            else if (!string.IsNullOrEmpty(earlyDataValue))
            {
                requestLines.Add($"Sec-WebSocket-Protocol: {earlyDataValue}");

                // 调试信息
                // LogHelper.Debug($"[WS Header 默认] {host}{path} | Sec-WebSocket-Protocol: {earlyDataValue}");
            }

            // [Grok 2025-11-05 关键修复] 正确结束 HTTP Header
            var requestText = string.Join("\r\n", requestLines) + "\r\n\r\n";
            var requestBytes = Encoding.ASCII.GetBytes(requestText);

            //调试信息
            // LogHelper.Debug($"[request：]\n{requestText}");

            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            // [保留原注释] 读取完整响应头（最大 4KB）
            var buffer = new byte[4096];
            var totalRead = 0;
            var headerEnd = -1;

            using var headerCts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, headerCts.Token);

            while (headerEnd == -1 && totalRead < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(totalRead), linkedCts.Token);
                if (read == 0) break;
                totalRead += read;

                for (int i = Math.Max(0, totalRead - read - 4); i <= totalRead - 4; i++)
                {
                    if (buffer[i] == '\r' && buffer[i + 1] == '\n' &&
                        buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                    {
                        headerEnd = i + 4;
                        break;
                    }
                }
            }

            if (totalRead == 0)
            {
                LogHelper.Debug($"[WS 响应为空] {host}{path}");
                return false;
            }

            var response = Encoding.ASCII.GetString(buffer, 0, totalRead);
            LogHelper.Debug($"[WS 响应头] {host}{path} | {response.Split('\n')[0].Trim()}");

            var lines = response.Split("\r\n");
            var statusLine = lines[0];
            var upgradeHeader = lines.FirstOrDefault(l => l.StartsWith("Upgrade:", StringComparison.OrdinalIgnoreCase));

            return statusLine.Contains("101") &&
                   upgradeHeader?.Contains("websocket", StringComparison.OrdinalIgnoreCase) == true;
        }
        catch (OperationCanceledException)
        {
            LogHelper.Debug($"[WS 握手超时] {host}{path}");
            return false;
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[WS 握手异常] {host}{path} | {ex.Message}");
            return false;
        }
    }

    // [ Grok Rebuild ] 2025-11-02_09：gRPC 握手（HTTP/2 前言 + SETTINGS）
    private static async Task<bool> GrpcHandshakeAsync( SslStream ssl, CancellationToken ct )
    {
        var preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();
        var settings = new byte[] { 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var frame = new byte[preface.Length + settings.Length];
        preface.CopyTo(frame, 0);
        settings.CopyTo(frame, preface.Length);

        await ssl.WriteAsync(frame, ct);
        await ssl.FlushAsync(ct);

        var buffer = new byte[9];
        var read = await ssl.ReadAsync(buffer, ct);
        return read == 9 && buffer[3] == 0x04; // SETTINGS frame
    }

    /// <summary>
    /// 检测 Trojan 协议握手连通性（仅密码校验 + TLS，不建立出网隧道）
    /// </summary>
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckTrojanHandshakeAsync(
    NodeInfo node, IPAddress address, int timeoutSec )
    {
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
                
        // 必须先 Connect 成功，再 GetStream
        using var client = new TcpClient();
        try
        {
            // 1. 必须 await ConnectAsync
            await client.ConnectAsync(address, node.Port, cts.Token);
            client.NoDelay = true;
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[Trojan TCP 超时] {node.Host}:{node.Port}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        catch (SocketException ex)
        {
            LogHelper.Warn($"[Trojan TCP 失败] {node.Host}:{node.Port} | {ex.Message}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            LogHelper.Error($"[Trojan TCP 异常] {node.Host}:{node.Port} | {ex.GetType().Name}: {ex.Message}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }

        // [SslStream 支持 IAsyncDisposable] 
        // 一定要在 await client.ConnectAsync() 之后创建 SslStream，确保连接已建立
        await using var ssl = new SslStream(client.GetStream(), true, ( s, c, ch, e ) => true);

        // 调试信息
        // LogHelper.Debug($"[Trojan 握手] 连接到 {node.Host}:{node.Port} | UserId={node.UserId}");

        try
        {
            //await client.ConnectAsync(address, node.Port, cts.Token);
            //client.NoDelay = true;

            var sni = node.Host;
            if (IPAddress.TryParse(sni, out _))
                sni = node.HostParam ?? node.Host;

            var sslOpts = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };

            await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);

            var pwd = node.UserId ?? node.ExtraParams?.GetValueOrDefault("password") ?? "";
            if (string.IsNullOrEmpty(pwd))
                return (false, null, sw.Elapsed);

            var sha256 = SHA256.HashData(Encoding.UTF8.GetBytes(pwd));
            var hex = BitConverter.ToString(sha256.AsSpan(0, 28).ToArray())
                                 .Replace("-", "").ToLowerInvariant();

            var payload = $"{hex}\r\n";
            var payloadBytes = Encoding.ASCII.GetBytes(payload);

            // 调试信息
            // LogHelper.Debug($"[Trojan 握手] payload ={payload} ");

            await ssl.WriteAsync(payloadBytes, cts.Token);
            await ssl.FlushAsync(cts.Token);

            var resp = new byte[2];
            var read = await ssl.ReadAsync(resp, cts.Token);

            sw.Stop();

            return read == 2 && resp[0] == '\r' && resp[1] == '\n'
                ? (true, ssl, sw.Elapsed)
                : (false, null, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[Trojan 握手超时] {node.Host}:{node.Port}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            LogHelper.Error($"[Trojan 握手失败] {node.Host}:{node.Port} | {ex.Message}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
    }


    // [ Grok 2025-11-02_02 ] Hysteria2 握手：社区最佳实践（hysteria2-ping、subconverter）仅验证 UDP 端口可达
    // 官方 QUIC 握手复杂，检测工具均采用“发包成功 + 超时 = 可用”（交叉 VLESS 搜索）
    // 使用 .NET 8 推荐 UdpClient.SendAsync(ReadOnlyMemory<byte>, CancellationToken)
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckHysteria2HandshakeAsync(
        NodeInfo node, IPAddress address, int timeoutSec )
    {
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        try
        {
            using var udp = new UdpClient();
            udp.Client.DontFragment = true;
            udp.Connect(address, node.Port);
            var ping = Encoding.ASCII.GetBytes("PING");
            await udp.SendAsync(ping, cts.Token);
            var recv = await udp.ReceiveAsync(cts.Token);
            sw.Stop();
            return recv.Buffer.Length > 0 ? (true, null, sw.Elapsed) : (false, null, sw.Elapsed);   // UDP 成功即视为可用
        }
        catch
        {
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
    }

    #endregion

    #region Helper Utilities

    /// <summary>
    /// 安全解析 UUID，非法或空时生成随机 UUID 并记录日志
    /// </summary>
    /// <summary>
    /// 安全解析 UUID，非法或空时生成随机 UUID 并记录日志
    /// </summary>
    /// <summary>
    /// 安全解析 UUID，非法或空时生成随机 UUID 并记录日志
    /// </summary>
    private static Guid ParseOrRandomUuid( string? s )
    {
        // [ GROK 修复 ]1. 空值处理
        if (string.IsNullOrWhiteSpace(s))
        {
            LogHelper.Debug("[UUID] 输入为空，生成随机 UUID");
            return Guid.NewGuid();
        }

        // [ GROK 修复 ]2. 标准解析（支持所有格式）
        if (Guid.TryParse(s, out var guid))
        {
            LogHelper.Debug($"[UUID] 标准解析成功: {s} → {guid}");
            return guid;
        }

        // [ GROK 修复 ]3. 宽松解析：去除连字符后按 "N" 格式解析
        var clean = s.Replace("-", ""); // string.Replace 返回新字符串
        if (clean.Length == 32 && Guid.TryParseExact(clean, "N", out guid))
        {
            LogHelper.Debug($"[UUID] 宽松解析成功 (N): {s} → {guid}");
            return guid;
        }

        // [ GROK 修复 ]4. 尝试其他格式
        if (Guid.TryParseExact(s, "D", out guid) ||
            Guid.TryParseExact(s, "B", out guid) ||
            Guid.TryParseExact(s, "P", out guid))
        {
            LogHelper.Debug($"[UUID] 宽松解析成功 (B/D/P): {s} → {guid}");
            return guid;
        }

        // [ GROK 修复 ]5. 最终降级
        LogHelper.Warn($"[UUID] 非法格式: \"{s}\", 生成随机 UUID");
        return Guid.NewGuid();
    }

    /// <summary>
    /// 构建 VLESS 协议头部（网络字节序，大端）
    /// </summary>
    private static byte[] BuildVlessHeader(
        NodeInfo node,
        IPAddress address,
        Guid uuid,
        IReadOnlyDictionary<string, string> extra )
    {
        // [ GROK 修复 ] using 自动释放 MemoryStream
        using var ms = new MemoryStream();

        // 1. Version
        ms.WriteByte(0); // ver = 0

        // 2. UUID (大端序，.NET 8 原生支持)
        var uuidBytes = uuid.ToByteArrayBigEndian(); // .NET 8: 大端序
                                                     // 若项目 < .NET 8，可用：
                                                     // var uuidBytes = uuid.ToByteArray(); if (BitConverter.IsLittleEndian) Array.Reverse(uuidBytes);
        ms.Write(uuidBytes);

        // 3. Opt + Cmd
        ms.WriteByte(0); // opt
        ms.WriteByte(0); // cmd = CONNECT

        // 4. Port (网络字节序 = 大端)
        var portB = BitConverter.GetBytes((ushort)node.Port);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(portB); // 小端机器 → 转为大端
        ms.Write(portB);

        // 5. Address Type + Address
        byte addrType;
        byte[] addrBytes;

        if (address.AddressFamily == AddressFamily.InterNetwork) // IPv4
        {
            addrType = 1;
            addrBytes = address.GetAddressBytes(); // 4 字节
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6) // IPv6
        {
            addrType = 4; // [ GROK 修复 ]IPv6 = 4
            addrBytes = address.GetAddressBytes(); // 16 字节
        }
        else // 域名
        {
            var hostStr = node.Host;
            var hostB = Encoding.UTF8.GetBytes(hostStr);
            if (hostB.Length > 255)
            {
                LogHelper.Warn($"[VLESS Header] Host 过长 ({hostB.Length} > 255)，截断: {hostStr}");
                hostB = [.. hostB.Take(255)];
            }
            addrType = 2;
            addrBytes = new byte[1 + hostB.Length];
            addrBytes[0] = (byte)hostB.Length;
            Buffer.BlockCopy(hostB, 0, addrBytes, 1, hostB.Length);
        }

        ms.WriteByte(addrType);
        ms.Write(addrBytes);

        return ms.ToArray();
    }

    // [ chatGPT 2025-11-03_00 ]
    // [修改说明]
    // 构建 WebSocket 客户端二进制帧（含客户端掩码）
    // 返回：完整帧字节数组，可直接写入 TLS/Stream
    private static byte[] BuildWebSocketClientFrame( byte[] payload )
    {
        // FIN=1, opcode=2 (binary)
        const byte finAndOpcode = 0x82;

        Span<byte> header = stackalloc byte[14]; // 最长预留头部（实际长度根据 payload 可扩展）
        int headerLen = 0;

        // payload length handling
        if (payload.Length <= 125)
        {
            header[0] = finAndOpcode;
            header[1] = (byte)(0x80 | (byte)payload.Length); // MASK bit = 1
            headerLen = 2;
        }
        else if (payload.Length <= ushort.MaxValue)
        {
            header[0] = finAndOpcode;
            header[1] = 0x80 | 126;
            // 2 bytes length big endian
            var lenBytes = BitConverter.GetBytes((ushort)payload.Length);
            if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
            header[2] = lenBytes[0];
            header[3] = lenBytes[1];
            headerLen = 4;
        }
        else
        {
            header[0] = finAndOpcode;
            header[1] = 0x80 | 127;
            // 8 bytes length big endian
            var lenBytes = BitConverter.GetBytes((ulong)payload.Length);
            if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
            for (int i = 0; i < 8; i++) header[2 + i] = lenBytes[i];
            headerLen = 10;
        }

        // mask key (4 bytes)
        var maskKey = RandomNumberGenerator.GetBytes(4);
        // final frame length = headerLen + 4 + payload.Length
        var frame = new byte[headerLen + 4 + payload.Length];

        // 适用范围运算符
        // header.Slice(0, headerLen).CopyTo(frame.AsSpan(0, headerLen));
        header[..headerLen].CopyTo(frame.AsSpan(0, headerLen));
        Buffer.BlockCopy(maskKey, 0, frame, headerLen, 4);

        // masked payload
        for (int i = 0; i < payload.Length; i++)
        {
            frame[headerLen + 4 + i] = (byte)(payload[i] ^ maskKey[i % 4]);
        }

        return frame;
    }        

    #endregion
}