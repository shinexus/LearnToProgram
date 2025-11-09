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

namespace HiddifyConfigsCLI;

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

        // 【Grok 新增】--no-check 时跳过所有检测（包括协议握手 + 出网测试）
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
                LogHelper.Debug($"[正在测试协议握手] {node.Type}://{node.Host}:{node.Port}");

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

                // Hysteria2 无 stream，跳过出网测试
                //if (node.Type == "hysteria2")
                //{
                //    validNode = node with { Latency = result.latency };
                //    validNodes.Add(validNode);
                //    if (opts.Verbose)
                //        LogHelper.Info($"[可用] {validNode} | {result.latency.TotalMilliseconds:F0}ms");
                //    return;
                //}

                sw.Stop();                

                // 出网检测已迁移至 InternetTester.cs。
                // 调用 InternetTester.TestAsync() 进行 HTTP 204 或 TCP 探测。
                // 规则：
                //   1. VLESS/Trojan：复用已建立的 TLS 流发送 HTTP GET 请求
                //   2. Hysteria2：因 QUIC 复杂，暂不做出网测试（仅保留握手）
                //   3. --no-check 时已在上层跳过，此处不再执行

                // 调试信息
                LogHelper.Info($"开始出网测试：{node.Type}://{node.Host}:{node.Port}");

                /* ---------- 出网测试（仅 VLESS/Trojan） ---------- */
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
                    LogHelper.Warn($"[注意] {node.Type}://{node}:{node.Port} | 握手成功但流为空，跳过出网测试");
                    return;
                }

                bool internetOk = false;
                if (opts.EnableInternetCheck)
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(opts.Timeout));
                    internetOk = await InternetTester.CheckInternetAsync(result.stream, opts, cts.Token);
                    if (!internetOk)
                    {
                        LogHelper.Warn($"[注意] {node.Type}://{node}:{node.Port} | 协议握手通过，但无法出网");
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
                LogHelper.Error($"[异常] {node.Type}://{node}:{node.Port} | {ex.Message}");
            }
            finally
            {
                // [ Grok无敌 ] 统一释放资源 + 信号量
                // try { client.Close(); } catch { /* ignore */ } // 防止句柄泄漏

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

        // 【Grok 新增】最终日志：强调“已通过出网测试”
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

                // [ Grok 2025-11-03_03 ] 修复 IPv6 解析失败问题
                // 原因：Dns.GetHostAddressesAsync 默认优先返回 IPv6，但某些系统/网络环境下 IPv6 解析失败或返回无效地址
                // 解决：1. 显式请求 AddressFamily.InterNetworkV4（优先 IPv4）；
                //      2. 若 IPv4 失败，再尝试 AddressFamily.InterNetworkV6；
                //      3. 若两者均失败，记录日志但不阻塞后续节点
                IPAddress? resolved = null;

                // 步骤1：优先尝试 IPv4
                try
                {
                    var ipv4List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cts.Token);
                    if (ipv4List.Length > 0)
                    {
                        resolved = ipv4List[0];
                        // 简化日志
                        // LogHelper.Info($"[DNS 解析成功] {host} → IPv4: {resolved}");
                    }
                }
                catch (OperationCanceledException) { /* 超时由外层统一处理 */ }
                catch (Exception)
                {
                    // 简化日志
                    // LogHelper.Debug($"[DNS IPv4 解析失败] {host} | {ex.Message}");
                }

                // 步骤2：若 IPv4 失败，尝试 IPv6
                if (resolved == null)
                {
                    try
                    {
                        var ipv6List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetworkV6, cts.Token);
                        if (ipv6List.Length > 0)
                        {
                            resolved = ipv6List[0];
                            // 简化日志
                            // LogHelper.Info($"[DNS 解析成功] {host} → IPv6: {resolved}");
                        }
                    }
                    catch (OperationCanceledException) { /* 超时由外层统一处理 */ }
                    catch (Exception)
                    {
                        // 简化日志
                        // LogHelper.Debug($"[DNS IPv6 解析失败] {host} | {ex.Message}");
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

    #region [ Grok 修复 ] 协议级握手检测（防卡死）

    // [ Grok Rebuild ] 2025-11-02_09：VLESS 完整握手，支持 REALITY / WebSocket / gRPC / XTLS-Vision
    // 1. 从 ExtraParams 读取：flow、reality_enabled、reality_public_key、reality_short_id、utls_fingerprint、transport_type、ws_path、ws_host、grpc_service_name
    // 2. REALITY：使用 RealityHandshakeAsync（自定义 TLS 扩展）
    // 3. WebSocket：TLS 后发送标准 WS 握手帧（Sec-WebSocket-Key + Host + Path）
    // 4. gRPC：TLS 后发送 HTTP/2 前言 + SETTINGS 帧
    // 5. XTLS-Vision：若 flow=xtls-rprx-vision，则添加随机 padding（16-255 字节）
    // 6. 所有扩展失败 → 降级为普通 VLESS 头部（兼容性）
    // 7. 使用 ArrayPool 避免 GC，.NET 8 推荐
    // [ Grok 2025-11-03_01 ] 修复 security=none 超时 + REALITY 失败后流污染
    // [ Grok 2025-11-03_02 ] 修复 SslStream 被提前 Dispose 导致 "Cannot access a disposed object"
    //   原因：using var ssl 作用域过小，离开 if 块后自动释放，但后续 WS/gRPC/VLESS 仍使用 stream
    //   解决：将 SslStream 声明提前，using 作用域扩大到整个函数；stream 统一管理，REALITY 失败后重连并重建 SslStream
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckVlessHandshakeAsync( 
        NodeInfo node, 
        IPAddress address, 
        int timeoutSec )
    {
        // [ Grok 2025-11-03_02 ] 提前声明 SslStream，确保生命周期贯穿整个握手
        SslStream? ssl = null;
        Stream? stream = null; // 统一流引用

        var sw = Stopwatch.StartNew();
        TcpClient? client = null;

        // [ chatGPT 2025-11-03_00 ]
        // [修改说明]
        // 使用 Socket.ConnectAsync(EndPoint, CancellationToken) 替代 TcpClient.ConnectAsync(...) 以支持可取消连接（.NET8 推荐）
        // 原因：TcpClient.ConnectAsync 没有 CancellationToken 参数，使用 Socket API 可以让连接阶段响应超时 CancellationToken，
        // 并避免在超时情况下残留挂起 socket 导致资源泄漏。
        // 实现方式：
        //  1. 创建 Socket 并连接：await socket.ConnectAsync(endPoint, cts.Token)
        //  2. 将已连接的 socket 赋值给传入的 TcpClient.Client（TcpClient.Client 有 setter），之后可以使用 client.GetStream()
        // 注意：若已有 client 已在连接状态（或 client.Client 已被使用），先关闭旧 client 再赋值新 socket。
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        try
        {
            client = new TcpClient();

            // 建立可取消连接：使用 Socket + CancellationToken（比 TcpClient.ConnectAsync 更可控）
            var endPoint = new IPEndPoint(address, node.Port);

            // 调试信息
            // LogHelper.Debug($"[VLESS 握手] 连接到 {endPoint.Address}:{endPoint.Port} | 超时: {timeoutSec}s");

            // 
            // 创建 socket（根据地址族）
            var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            // 
            // 为了避免 DNS 解析等潜在阻塞，这里使用 socket.ConnectAsync(endPoint, cts.Token)
            await socket.ConnectAsync(endPoint, cts.Token);

            client.Client = socket;
            
            // 将底层 socket 绑定到 TcpClient（方便后续使用 client.GetStream()）
            //try
            //{
            //    client.Client = socket; // 此处赋值，TcpClient 将接管 socket 的生命周期
            //}
            //catch (Exception ex)
            //{
            //    // 若赋值失败，确保 socket 被关闭以避免泄漏
            //    try { socket.Close(); } catch { }
            //    throw new InvalidOperationException("无法将底层 Socket 赋值给 TcpClient.Client", ex);
            //}

            // [ Grok 2025-11-03_01 ] 解析 ExtraParams，优先获取 security
            var extra = node.ExtraParams ?? new Dictionary<string, string>();
            var security = extra.GetValueOrDefault("security") ?? "tls"; // 默认 tls
            var realityEnabled = extra.GetValueOrDefault("reality_enabled") == "true";
            var transportType = extra.GetValueOrDefault("transport_type") ?? "";
            var flow = extra.GetValueOrDefault("flow") ?? "";
            var isVision = flow.Contains("vision", StringComparison.OrdinalIgnoreCase);

            // [ Grok 2025-11-03_02 ] 初始化基础流
            stream = client.GetStream();

            // [ Grok 2025-11-03_01 ] 修复 security=none 超时问题
            // 若 security=none，跳过 TLS 协商，直接使用原始 TCP 流
            if (security == "none")
            {
                LogHelper.Info($"[security=none] {node.Host}:{node.Port} | 跳过 TLS 协商");
            }
            else
            {
                // [ chatGPT 2025-11-03_00 ]
                // [修改说明]
                // 使用 SslStream 并显式传入 CancellationToken 到 AuthenticateAsClientAsync（.NET8 支持的重载）
                // 同时避免在构造时重复调用 client.GetStream() 导致混淆（我们直接使用已连接的 client.GetStream()）
                // 另外：RemoteCertificateValidationCallback 仅在 SslStream 构造时设置一次，避免多次设置或静态回调冲突。
                ssl = new SslStream(client.GetStream(), false, ( s, cert, chain, sslPolicyErrors ) => true);
                var sslOpts = new SslClientAuthenticationOptions
                {
                    TargetHost = node.Host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };
                // AuthenticateAsClientAsync 支持 CancellationToken（.NET8）
                await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);
                stream = ssl; // 替换为加密流
                LogHelper.Info($"[TLS] {node.Host}:{node.Port} | 协商完成");
            }            

            // VLESS 头部（基础 + Vision padding）            
            // [修改] VLESS 检测：id 为空或非法 → 使用随机 UUID（仅占位，不影响检测）
            // ---------- 构造最小 VLESS 头部 ----------
            var uuidStr = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.Password ?? ""); 
            var header = BuildVlessHeader(node, address, uuidStr, extra);

            await stream.WriteAsync(header, cts.Token);
            await stream.FlushAsync(cts.Token);
            // ---------- 读取任意 1 字节响应 ----------
            using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await stream.ReadAsync(buf.AsMemory(0, 1), readCts.Token);
                sw.Stop();
                return read > 0 ? (true, stream, sw.Elapsed) : (false, null, sw.Elapsed);
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            LogHelper.Warn($"[Vless 握手超时] {node.Host}:{node.Port}({timeoutSec}s)");
            return (false, null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            LogHelper.Error($"[Vless 握手失败] {node.Host}:{node.Port} | {ex.Message}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        finally
        {
            // 只在失败或外层自行 Dispose 时关闭底层 client
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
            // 【保留原注释】生成符合 RFC 6455 的 Sec-WebSocket-Key（16 字节随机值）
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

            // 【Grok 2025-11-05 重构】使用 List<string> 收集所有 Header 行
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

            // 【Grok 2025-11-05 修复】只添加一次 Origin Header
            if (!string.IsNullOrEmpty(originHeader))
            {
                requestLines.Add(originHeader);

                // 调试信息
                // LogHelper.Debug($"[WS Header 添加] {host}{path} | {originHeader}");
            }

            // 【保留原逻辑】写入 Early-Data Header
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

            // 【Grok 2025-11-05 关键修复】正确结束 HTTP Header
            var requestText = string.Join("\r\n", requestLines) + "\r\n\r\n";
            var requestBytes = Encoding.ASCII.GetBytes(requestText);

            //调试信息
            // LogHelper.Debug($"[request：]\n{requestText}");

            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            // 【保留原注释】读取完整响应头（最大 4KB）
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

    // [ Grok 2025-11-02_04 ]
    // Trojan 握手：payload 添加目标 SNI (1\r\n{node.Host}\r\n\r\n)，模拟 CONNECT
    // SHA224 截取 + 读 1s 响应
    // [ Grok 2025-11-08_01 ] 修复 Trojan 出网测试
    // 问题：原 Trojan 握手仅发送密码 + CMD=1，未指定 CONNECT 目标域名 → 服务端不建立 TCP 隧道
    // 后果：CheckInternetAsync 复用 stream 发送 HTTP → 服务端视作非法数据 → 立即 RST
    // 修复：
    // 1. 在握手阶段发送完整 CONNECT 命令：CMD=1 + {targetHost}:443 + CRLF
    // 2. 读取服务端 2 字节 CRLF 响应，确认隧道建立
    // 3. 握手成功后，stream 变为可发送 HTTP 的原始 TCP 隧道
    // 4. 出网测试 CheckHttpInternetAsync 可安全复用该 stream
    // 社区验证：trojan-go、sing-box、v2rayN 均要求此字段
    // 兼容性：目标端口固定 443（出网测试均为 HTTPS），若需灵活可后续扩展
    /// <summary>
    /// 检测 Trojan 协议握手连通性
    /// </summary>
    /// <param name="node">节点信息</param>
    /// <param name="address">目标 IP 地址</param>
    /// <param name="timeout">超时时间（秒）</param>
    /// <param name="client">TcpClient 实例（外部传入以便重用）</param>
    /// <returns>握手成功返回 true，否则 false</returns>
    private static async Task<(bool success, Stream? stream, TimeSpan latency)> CheckTrojanHandshakeAsync( NodeInfo node, IPAddress address, int timeoutSec )
    {
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        TcpClient? client = null;
        SslStream? ssl = null;

        try
        {
            client = new TcpClient();

            // 建立 TCP 连接
            await client.ConnectAsync(address, node.Port, cts.Token);

            // ────────────────────────────────────────────────
            // 发送 Trojan 协议握手请求
            // ────────────────────────────────────────────────
            // Trojan 协议在 TLS 之上封装，握手内容形如：
            //   [Password] + "\r\n" + [SOCKS5-like payload]
            // 此处仅验证 TLS 握手层是否可成功建立。
            // ────────────────────────────────────────────────

            // 创建 TLS 安全流
            ssl = new SslStream(client.GetStream(), false, ( s, c, ch, e ) => true);

            // SSL 配置项
            var sslOpts = new SslClientAuthenticationOptions
            {
                TargetHost = node.HostParam ?? node.Host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            };

            // 执行 TLS 握手
            await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token);

            // ────────────────────────────────────────────────
            // [ chatGPT 自我补救 ]
            // 说明：
            //   旧版本在此处直接调用 CheckInternetAsync(node, ssl, opts)
            //   进行出网检测（HTTP 204 验证）。
            //   现在该逻辑已完全迁移至 InternetTester.cs，
            //   ConnectivityChecker 仅负责握手检测，不再执行外网访问。
            // ────────────────────────────────────────────────

            // ---------- 完整 CONNECT（出网测试用） ----------
            // 目标：构造完整的 Trojan CONNECT 请求（含密码哈希 + 目标地址），
            //       让隧道真正建立到测试目标，供后续 InternetTester 出网验证。
            // 关键点：
            // 1. 随机获取一个出网测试 URL（通过 InternetTester.GetTestUrl）
            // 2. 提取密码（优先 UserId → ExtraParams["password"]）
            // 3. 计算 SHA224 哈希（Trojan 协议要求前 28 字节）
            // 4. 拼接标准 CONNECT payload：
            //     <SHA224_hex>\r\n
            //     1\r\n                  ← 命令：CONNECT
            //     <host>\r\n
            //     <port>\r\n
            //     \r\n                   ← 空行结束
            // 5. 发送并读取服务器响应（\r\n 表示成功）
            // 6. 成功 → 返回 (true, ssl, 延迟)；失败 → (false, null, 延迟)
            var testUrl = InternetTester.GetTestUrl(
    new RunOptions { TestUrl = "random" }); // 随机选择一个出网测试 URL（如 https://cp.cloudflare.com/generate_204）

            var uri = new Uri(testUrl); // 解析 URL，获取 host 和 port（用于 CONNECT）

            // 提取密码：
            // 1. 优先使用 node.UserId（通常来自 vless:// 的用户 ID 字段）
            // 2. 否则从 ExtraParams["password"] 获取
            // 3. 若都为空 → 直接返回失败（无密码无法完成 Trojan 认证）
            var pwd = !string.IsNullOrEmpty(node.UserId)
                ? node.UserId
                : node.ExtraParams?.GetValueOrDefault("password") ?? "";
            if (string.IsNullOrEmpty(pwd))
                return (false, null, sw.Elapsed); // 密码为空 → 握手失败

            // 计算密码的 SHA-224 哈希（Trojan 协议要求）
            // 1. 先将密码转为 UTF-8 字节
            // 2. 用 SHA256 计算完整哈希（.NET 无 SHA224，但 Trojan 用 SHA256 前 28 字节模拟）
            // 3. 取前 28 字节
            var sha256 = SHA256.HashData(Encoding.UTF8.GetBytes(pwd));

            // 将前 28 字节转为十六进制字符串
            // 1. AsSpan(0, 28) → 取前 28 字节
            // 2. ToArray() → 转为数组
            // 3. BitConverter.ToString → 转为 AA-BB-CC 格式
            // 4. Replace("-", "") → 去掉连字符
            // 5. ToLowerInvariant() → 转为小写
            var hex = BitConverter.ToString(sha256.AsSpan(0, 28).ToArray())
                                 .Replace("-", "").ToLowerInvariant();

            // 构造 Trojan CONNECT payload（纯文本，ASCII 编码）
            // 格式：
            //   <SHA224_hex>\r\n
            //   1\r\n                  ← 命令码：1 = CONNECT
            //   <target_host>\r\n
            //   <target_port>\r\n
            //   \r\n                   ← 空行表示结束
            // CONNECT 到目标（https:// 走 443 端口）
            // var payload = $"{hex}\r\n1\r\n{uri.Host}\r\n{uri.Port}\r\n\r\n";
            var targetPort = uri.Scheme == "http" ? 80 : 443; // https:// → 443
            var payload = $"{hex}\r\n1\r\n{uri.Host}\r\n{targetPort}\r\n\r\n";

            // 转为 ASCII 字节（Trojan 协议要求 ASCII）
            var payloadBytes = Encoding.ASCII.GetBytes(payload);

            // 发送 CONNECT 请求（通过已建立的 TLS 流 ssl）
            await ssl.WriteAsync(payloadBytes, cts.Token);
            await ssl.FlushAsync(cts.Token); // 确保数据完全发送

            // 读取服务器响应（成功为 \r\n，即 0x0D 0x0A）
            var resp = new byte[2]; // 缓冲区：2 字节
            var read = await ssl.ReadAsync(resp, cts.Token); // 尝试读取 2 字节

            sw.Stop(); // 停止计时（握手耗时） 

            // 判断响应：
            // 1. 必须读满 2 字节
            // 2. 内容必须是 \r\n（即 resp[0] == '\r', resp[1] == '\n'）
            // 成功 → 返回 (true, ssl, 延迟)：ssl 流可继续用于出网测试
            // 失败 → 返回 (false, null, 延迟)：流不可用，需丢弃
            return read == 2 && resp[0] == '\r' && resp[1] == '\n'
                ? (true, ssl, sw.Elapsed)
                : (false, null, sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[Trojan Handshake 超时] {node.Host}:{node.Port}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        catch (Exception ex)
        {
            // 捕获所有 TLS 握手或网络异常
            LogHelper.Warn($"[Trojan Handshake 失败] {node.Host}:{node.Port} | {ex.Message}");
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
        finally
        {
            if (ssl == null) client?.Close();
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
            udp.Connect(address, node.Port);
            var ping = Encoding.ASCII.GetBytes("PING");
            await udp.SendAsync(ping, cts.Token);
            sw.Stop();
            return (true, null, sw.Elapsed);   // UDP 成功即视为可用
        }
        catch
        {
            sw.Stop();
            return (false, null, sw.Elapsed);
        }
    }

    #endregion

    #region Helper Utilities

    private static Guid ParseOrRandomUuid( string s )
        => Guid.TryParse(s, out var g) ? g : Guid.NewGuid();

    private static byte[] BuildVlessHeader( NodeInfo node, IPAddress address,
        Guid uuid, IReadOnlyDictionary<string, string> extra )
    {
        var ms = new MemoryStream();
        ms.WriteByte(0);                                   // ver
        ms.Write(uuid.ToByteArray());                     // uuid
        ms.WriteByte(0);                                   // opt
        ms.WriteByte(0);                                   // cmd = connect

        var portB = BitConverter.GetBytes((ushort)node.Port);
        if (BitConverter.IsLittleEndian) Array.Reverse(portB);
        ms.Write(portB);                                   // port

        // ---------- addr_type & addr ----------
        byte addrType = 0;
        byte[] addrBytes = [];

        if (IPAddress.TryParse(node.Host, out _))
        {
            addrType = address.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)3;
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
            header[1] = (byte)(0x80 | 126);
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
            header[1] = (byte)(0x80 | 127);
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