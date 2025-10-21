using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigs
{
    public class ConnectivityResult
    {
        public string Host { get; set; }
        public int Port { get; set; }
        public bool IsReachable { get; set; }
        public long? ResponseTimeMs { get; set; }
    }

    public static class ConnectivityChecker
    {
        /// <summary>
        /// 批量检测多个主机端口的可达性。
        /// 自动适配 IPv4 / IPv6，记录 TCP 连接耗时。
        /// </summary>
        public static async Task<List<ConnectivityResult>> CheckHostsBatchAsync(
            IEnumerable<(string Host, int Port)> hosts,
            int timeoutMs = 1500,
            int maxConcurrency = 25,
            CancellationToken cancellationToken = default,
            IProgress<string> progress = null)
        {
            var results = new List<ConnectivityResult>();
            using (var semaphore = new SemaphoreSlim(maxConcurrency))
            {
                var tasks = new List<Task>();

                foreach (var (host, port) in hosts)
                {
                    await semaphore.WaitAsync(cancellationToken);

                    tasks.Add(Task.Run(async () =>
                    {
                        //var result = new ConnectivityResult { Host = host, Port = port };
                        //var sw = Stopwatch.StartNew();
                        // 规范化主机名：移除方括号并小写
                        string normalizedHost = host.Trim('[', ']').ToLowerInvariant();
                        var result = new ConnectivityResult { Host = normalizedHost, Port = port };
                        var sw = Stopwatch.StartNew();

                        try
                        {
                            // Step 1: 尝试解析主机为 IP 地址
                            IPAddress ipAddress;
                            if (!IPAddress.TryParse(host, out ipAddress))
                            {
                                // 若不是纯 IP，则解析 DNS
                                var addresses = await Dns.GetHostAddressesAsync(host);
                                ipAddress = addresses.FirstOrDefault();
                                if (ipAddress == null)
                                    throw new Exception("无法解析主机地址");
                            }

                            // Step 2: 根据地址族创建对应的 TcpClient
                            using (var tcp = new TcpClient(ipAddress.AddressFamily))
                            {
                                var connectTask = tcp.ConnectAsync(ipAddress, port);
                                var completed = await Task.WhenAny(connectTask, Task.Delay(timeoutMs, cancellationToken));

                                if (completed == connectTask && tcp.Connected)
                                {
                                    result.IsReachable = true;
                                    sw.Stop();
                                    result.ResponseTimeMs = sw.ElapsedMilliseconds;
                                    progress?.Report($"✅ {host}:{port} 可达，耗时 {result.ResponseTimeMs} ms");
                                }
                                else
                                {
                                    result.IsReachable = false;
                                    sw.Stop();
                                    result.ResponseTimeMs = null;
                                    progress?.Report($"❌ {host}:{port} 不可达（超时 {timeoutMs} ms）");
                                }
                            }
                        }
                        catch (SocketException ex)
                        {
                            sw.Stop();
                            result.IsReachable = false;
                            progress?.Report($"❌ {host}:{port} Socket 异常：{ex.Message}");
                            LogHelper.WriteError($"❌ {host}:{port} Socket 异常：{ex.Message}");
                        }
                        catch (Exception ex)
                        {
                            sw.Stop();
                            result.IsReachable = false;
                            progress?.Report($"❌ {host}:{port} 检测异常：{ex.Message}");
                            LogHelper.WriteError($"❌ {host}:{port} 检测异常：{ex.Message}");
                        }
                        finally
                        {
                            lock (results)
                                results.Add(result);
                            semaphore.Release();
                        }
                    }, cancellationToken));
                }

                await Task.WhenAll(tasks);
            }

            return results;
        }
    }
}