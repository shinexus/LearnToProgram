using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigs
{
    /// <summary>
    /// ConnectivityChecker：负责批量检测主机可达性。
    /// 支持 IPv4、IPv6、域名，优先尝试域名解析（TLS SNI 支持），失败后尝试 IP。
    /// 支持 VLESS、Trojan（TCP 测试）、Hysteria2（UDP 测试）。
    /// 兼容 .NET Framework 4.7.2。
    /// </summary>
    public static class ConnectivityChecker
    {
        /// <summary>
        /// 批量检测主机列表的可达性。
        /// 根据 Protocol 选择测试方式：VLESS/Trojan 使用 TCP，Hysteria2 使用 UDP。
        /// 优先尝试域名连接（支持 TLS SNI），失败后尝试 IP 地址。
        /// 返回检测结果，包括响应时间。
        /// </summary>
        /// <param name="hosts">主机信息列表，包含 Host、Port、HostParam、Encryption、Security、Protocol 和 ExtraParams</param>
        /// <param name="timeoutMs">超时时间（毫秒），默认 1500</param>
        /// <param name="maxConcurrency">最大并发数，默认 25</param>
        /// <param name="cancellationToken">取消操作的令牌</param>
        /// <param name="progress">进度日志</param>
        /// <returns>检测结果列表</returns>
        public static async Task<List<ConnectivityResult>> CheckHostsBatchAsync(
            IEnumerable<(string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)> hosts,
            int timeoutMs = 1500,
            int maxConcurrency = 25,
            CancellationToken cancellationToken = default,
            IProgress<string> progress = null )
        {
            // ✅ 防御性编程：确保 hosts 不为 null
            if (hosts == null)
                throw new ArgumentNullException(nameof(hosts), "传入的主机列表 hosts 为空。");

            // ✅ 过滤 Host 为空的记录，防止 NullReferenceException
            hosts = hosts
                .Where(h => !string.IsNullOrWhiteSpace(h.Host))
                .Select(h => (
                    Host: h.Host,
                    Port: h.Port,
                    HostParam: h.HostParam,
                    Encryption: h.Encryption,
                    Security: h.Security,
                    Protocol: h.Protocol,
                    ExtraParams: h.ExtraParams ?? new Dictionary<string, string>() // 保证不为空
                ))
                .ToList();

            if (!hosts.Any())
            {
                progress?.Report("[检测] ⚠️ 主机列表为空或全部无效，跳过检测。");
                LogHelper.WriteError("[检测] 警告：传入的主机列表为空或全部无效。");
                return new List<ConnectivityResult>();
            }

            // 新增：初始化结果列表和并发控制
            var results = new List<ConnectivityResult>();
            var tasks = new List<Task<ConnectivityResult>>();
            var semaphore = new SemaphoreSlim(maxConcurrency);

            //
            int hostIndex = 0;
            string reportNum = "";

            foreach (var (host, port, hostParam, encryption, security, protocol, extraParams) in hosts)
            {
                hostIndex++;
                reportNum = $"[{hostIndex}/{hosts.Count()}]";

                // 新增：等待并发控制信号量
                await semaphore.WaitAsync(cancellationToken);
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        // 新增：规范化主机名并初始化结果对象
                        string normalizedHost = host.Trim('[', ']').ToLowerInvariant();
                        var result = new ConnectivityResult
                        {
                            Host = normalizedHost,
                            Port = port,
                            HostParam = hostParam,
                            Encryption = encryption,
                            Security = security,
                            Protocol = protocol,
                            ExtraParams = extraParams,
                            Timestamp = DateTime.UtcNow
                        };

                        // 新增：根据 Protocol 和 Security 选择连接方式
                        string connectHost = security == "tls" ? (string.IsNullOrEmpty(hostParam) ? normalizedHost : hostParam) : normalizedHost;

                        // === 1️⃣ 处理 XTLS（VLESS 专用） ===
                        // 新增：XTLS 不支持，记录警告并返回不可达
                        if (security == "xtls")
                        {
                            progress?.Report(reportNum+$"[{protocol}] ⚠️ {connectHost}:{port} 不支持 security=xtls");
                            result.IsReachable = false;
                            return result;
                        }

                        // === 2️⃣ Hysteria2 使用 UDP 测试 ===
                        // 新增：Hysteria2 协议使用 UDP 测试
                        if (protocol == "Hysteria2")
                        {
                            // 简化日志
                            // progress?.Report(reportNum + $"[{protocol}] 尝试 UDP {connectHost}:{port} (host={hostParam}, security={security})");
                            var (isReachable, responseTimeMs) = await CheckUdpAsync(connectHost, port, timeoutMs, cancellationToken);
                            result.IsReachable = isReachable;
                            result.ResponseTimeMs = responseTimeMs;

                            if (isReachable)
                            {
                                // 简化日志
                                //progress?.Report(reportNum + $"[{protocol}] ✅ {connectHost}:{port} 可达 (UDP, host={hostParam}, security={security}, 耗时 {responseTimeMs} ms)");
                            }
                            else
                            {
                                // 简化日志
                                // progress?.Report($"[{protocol}] ❌ {connectHost}:{port} 不可达 (UDP, host={hostParam}, security={security})");
                            }
                            return result;
                        }

                        // === 3️⃣ VLESS/Trojan 使用 TCP 测试 ===
                        // 原有注释：尝试域名连接（TLS SNI）
                        if (security == "tls" && !IPAddress.TryParse(normalizedHost, out var ipAddress))
                        {
                            // 简化日志
                            // progress?.Report(reportNum+$"[{protocol}] 尝试域名 {connectHost}:{port} (host={hostParam}, security={security})");

                            using (var tcp = new TcpClient())
                            {
                                try
                                {
                                    var connectTask = tcp.ConnectAsync(connectHost, port);
                                    var timeoutTask = Task.Delay(timeoutMs, cancellationToken);
                                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                                    if (completedTask == connectTask && tcp.Connected)
                                    {
                                        result.IsReachable = true;
                                        result.ResponseTimeMs = (long)(DateTime.UtcNow - result.Timestamp).TotalMilliseconds;
                                        // 简化日志
                                        // progress?.Report(reportNum + $"[{protocol}] ✅ {connectHost}:{port} 可达 (host={hostParam}, security={security}, 耗时 {result.ResponseTimeMs} ms)");
                                        return result;
                                    }
                                }
                                catch (SocketException se)
                                {
                                    LogHelper.WriteError($"[{protocol}] 尝试域名失败：{connectHost}:{port}，Socket 错误代码：{se.SocketErrorCode}, 消息：{se.Message}");

                                }
                            }
                        }

                        // 原有注释：回退到 IP 连接
                        try
                        {
                            // 原有注释：使用单参数 GetHostAddressesAsync，兼容 .NET Framework 4.7.2
                            // 新增：支持取消和超时
                            var dnsTask = Dns.GetHostAddressesAsync(normalizedHost);
                            var timeoutTask = Task.Delay(timeoutMs, cancellationToken);
                            var completedTask = await Task.WhenAny(dnsTask, timeoutTask);

                            if (completedTask == timeoutTask)
                            {
                                throw new OperationCanceledException("DNS 解析超时或取消");
                            }

                            var ipAddresses = await dnsTask;
                            foreach (var ip in ipAddresses)
                            {
                                // 简化日志
                                // progress?.Report($"[{protocol}] 尝试 IP {ip}:{port} (host={hostParam}, security={security})");
                                
                                using (var tcp = new TcpClient(ip.AddressFamily))
                                {
                                    var connectTask = tcp.ConnectAsync(ip, port);
                                    timeoutTask = Task.Delay(timeoutMs, cancellationToken);
                                    completedTask = await Task.WhenAny(connectTask, timeoutTask);

                                    if (completedTask == connectTask && tcp.Connected)
                                    {
                                        result.IsReachable = true;
                                        result.ResponseTimeMs = (long)(DateTime.UtcNow - result.Timestamp).TotalMilliseconds;
                                        result.IPAddress = ip;
                                        // 简化日志
                                        // progress?.Report(reportNum + $"[{protocol}] ✅ {ip}:{port} 可达 (host={hostParam}, security={security}, 耗时 {result.ResponseTimeMs} ms)");
                                        return result;
                                    }
                                }
                            }
                        }
                        catch(SocketException se)
                        {
                            // 新增：记录 Socket 错误到 LogHelper
                            //progress?.Report(reportNum + $"[{protocol}] ❌ {connectHost}:{port} 失败 (host={hostParam}, security={security}): Socket 错误代码：{se.SocketErrorCode}");
                            LogHelper.WriteError($"[{protocol}] IP检测失败：{connectHost}:{port}，Socket 错误代码：{se.SocketErrorCode}, 消息：{se.Message}");
                        }
                        catch (Exception ex)
                        {
                            // 新增：记录错误到 LogHelper
                            progress?.Report(reportNum + $"[{protocol}] ❌ {connectHost}:{port} 失败 (host={hostParam}, security={security}): {ex.Message}");
                            LogHelper.WriteError($"[{protocol}] IP检测失败：{connectHost}:{port}，错误：{ex.Message}");
                        }

                        // 新增：TCP 测试失败，返回不可达
                        result.IsReachable = false;
                        // 简化日志
                        // progress?.Report($"[{protocol}] ❌ {connectHost}:{port} 不可达 (host={hostParam}, security={security})");
                        return result;
                    }
                    finally
                    {
                        // 新增：释放信号量
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            // 新增：等待所有任务完成并返回结果
            results.AddRange(await Task.WhenAll(tasks));
            return results;
        }

        /// <summary>
        /// 执行 UDP 连接测试，用于 Hysteria2 协议。
        /// 发送空数据包并等待响应，记录响应时间。
        /// </summary>
        /// <param name="host">主机名或 IP</param>
        /// <param name="port">端口</param>
        /// <param name="timeoutMs">超时时间（毫秒）</param>
        /// <param name="cancellationToken">取消操作的令牌</param>
        /// <returns>测试结果（是否可达，响应时间）</returns>
        private static async Task<(bool IsReachable, long? ResponseTimeMs)> CheckUdpAsync( string host, int port, int timeoutMs, CancellationToken cancellationToken )
        {
            // 新增：使用 UdpClient 进行 UDP 测试
            using (var udp = new UdpClient())
            {
                var start = DateTime.UtcNow;
                try
                {
                    // 新增：解析主机名到 IP 地址
                    var ipAddresses = await Dns.GetHostAddressesAsync(host);
                    foreach (var ip in ipAddresses)
                    {
                        try
                        {
                            // 新增：发送空数据包
                            await udp.SendAsync(new byte[0], 0, ip.ToString(), port);
                            udp.Client.ReceiveTimeout = timeoutMs;

                            // 新增：等待响应
                            var receiveTask = udp.ReceiveAsync();
                            var timeoutTask = Task.Delay(timeoutMs, cancellationToken);
                            var completedTask = await Task.WhenAny(receiveTask, timeoutTask);

                            if (completedTask == receiveTask)
                            {
                                // 新增：计算响应时间
                                var timeMs = (long)(DateTime.UtcNow - start).TotalMilliseconds;
                                return (true, timeMs);
                            }
                        }                        
                        catch
                        {
                            // 新增：忽略单个 IP 的错误，继续尝试下一个
                            continue;
                        }
                    }
                }
                catch (SocketException se)
                {
                    // 新增：记录 UDP 测试的 Socket 错误
                    LogHelper.WriteError($"[Hysteria2] UDP 测试 Socket 错误：{host}:{port}，错误代码：{se.SocketErrorCode}, 消息：{se.Message}");                    
                }
                catch (Exception ex)
                {
                    // 新增：记录 UDP 测试错误
                    LogHelper.WriteError($"[Hysteria2] UDP 测试失败：{host}:{port}，错误：{ex.Message}");
                }
            }
            // 新增：测试失败，返回不可达
            return (false, null);
        }
    }

    /// <summary>
    /// 表示主机可达性检测结果。
    /// </summary>
    public class ConnectivityResult
    {
        public string Host { get; set; }
        public int Port { get; set; }
        // 原有注释：新增：存储 Trojan 的 sni（HostParam）和 security
        // 新增：存储 Protocol 和 ExtraParams
        public string HostParam { get; set; }
        public string Encryption { get; set; }
        public string Security { get; set; }
        public string Protocol { get; set; }
        public Dictionary<string, string> ExtraParams { get; set; }
        public bool IsReachable { get; set; }
        public long? ResponseTimeMs { get; set; }
        public IPAddress IPAddress { get; set; }
        public DateTime Timestamp { get; set; }
    }
}