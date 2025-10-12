using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace HiddifyConfigs
{
    public class DoParse
    {
        /// <summary>
        /// 异步处理 URL 列表，下载内容并提取 vmess 协议链接。来自Grok。
        /// </summary>
        /// <param name="filePath">URL 列表文件路径</param>
        /// <param name="sb">记录去重后的可 ping 通的非 vmess:// 链接</param>
        /// <param name="logInfo">记录处理日志</param>
        /// <param name="vmessList">存储 vmess:// 链接</param>
        /// <param name="nonVmessList">存储可 ping 通的非 vmess:// 链接（用于保存文件）</param>
        /// <param name="cancellationToken">取消操作的令牌</param>
        /// <param name="progress">报告处理进度</param>
        /// <param name="status">报告处理状态</param>
        /// <param name="proxy">HTTP 代理设置</param>
        public async Task ProcessUrlsAsync(string filePath, StringBuilder sb, StringBuilder logInfo, List<string> vmessList, List<string> nonVmessList, CancellationToken cancellationToken, IProgress<int> progress = null, IProgress<string> status = null, IWebProxy proxy = null)
        {
            var urls = File.ReadAllLines(filePath, Encoding.UTF8)
                .Select(u => u.Trim())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Distinct()
                .ToList();            

            int totalUrls = urls.Count;
            int processedUrls = 0;

            var handler = new HttpClientHandler();
            if (proxy != null)
            {
                handler.Proxy = proxy;
                handler.UseProxy = true;
                logInfo.AppendLine($"使用代理: {proxy}");
            }
            else
            {
                handler.UseProxy = false; // 明确不使用代理
                logInfo.AppendLine("不使用代理，直接连接。");
            }

            using (var httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) })
            {
                foreach (var url in urls)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    processedUrls++;
                    status?.Report($"正在处理 URL {processedUrls}/{totalUrls}: {url}");
                    progress?.Report(totalUrls > 0 ? (processedUrls * 100 / totalUrls) : 0);

                    if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                    {
                        logInfo.AppendLine($"无效的 URL: {url}");
                        continue;
                    }
                    try
                    {
                        logInfo.AppendLine($"正在处理 {url} ...");
                        using (var response = await httpClient.GetAsync(url, cancellationToken))
                        {
                            response.EnsureSuccessStatusCode(); // 确保响应成功
                            string content = await response.Content.ReadAsStringAsync(); // 移除 cancellationToken
                            var lines = content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var line in lines)
                            {
                                
                                if (line.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
                                {
                                    vmessList.Add(line);
                                }
                                else if (!string.IsNullOrWhiteSpace(line))
                                {
                                    string host = ExtractHostFromLine(line);

                                    /*
                                    if (!string.IsNullOrEmpty(host) && PingHost(host))
                                    {
                                        nonVmessList.Add(line);
                                        logInfo.AppendLine($"Host {host} 可达，添加链接: {line}");
                                    }
                                    */

                                    // 使用异步Ping
                                    bool pingSuccess = await PingHostAsync(host); // 异步 ping，不阻塞 UI
                                    if (!string.IsNullOrEmpty(host) && pingSuccess)
                                    {
                                        nonVmessList.Add(line);
                                        logInfo.AppendLine($"Host {host} 可达，添加链接: {line}");
                                    }
                                    else
                                    {
                                        logInfo.AppendLine($"Host {host} 不可达或无法提取，跳过链接: {line}");
                                    }                                    
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        logInfo.AppendLine($"URL: {url}, 读取失败: {ex.Message}");
                    }
                }
            }
            // 将去重后的可 ping 通的非 vmess:// 链接写入 sb (用于显示)
            var deduplicatedNonVmess = nonVmessList.Distinct().ToList();
            if (deduplicatedNonVmess.Any())
            {
                foreach (var line in deduplicatedNonVmess)
                {
                    sb.AppendLine(line);
                }
            }
        }

        /// <summary>
        /// 保存非 vmess 链接到 mix_raw.txt 文件。
        /// </summary>
        /// <param name="nonVmessList">非 vmess 链接列表</param>
        /// <param name="logInfo">记录保存结果的日志</param>
        public void SaveNonVmessList(List<string> nonVmessList, StringBuilder logInfo)
        {
            string mixFile = Path.Combine(Application.StartupPath, "mix_raw.txt");
            try
            {
                // 确保目录存在
                string directory = Path.GetDirectoryName(mixFile);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                // 写入去重后的非 vmess 链接（覆盖文件，相当于清空）
                var deduplicatedLines = nonVmessList.Distinct().ToList();
                if (deduplicatedLines.Count > 0)
                {
                    File.WriteAllLines(mixFile, deduplicatedLines, Encoding.UTF8);
                    logInfo.AppendLine($"成功写入 {deduplicatedLines.Count} 条非 vmess 链接到 {mixFile}");
                }
                else
                {
                    File.WriteAllText(mixFile, string.Empty, Encoding.UTF8);
                    logInfo.AppendLine("没有找到有效的非 vmess 链接，文件已清空。");
                }
            }
            catch (Exception ex)
            {
                logInfo.AppendLine($"写入mix_raw.txt失败: {ex.Message}");
                MessageBox.Show($"写入mix_raw.txt失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 保存 vmess 链接到 vmess_raw.txt 文件。
        /// </summary>
        /// <param name="vmessList">vmess 链接列表</param>
        /// <param name="logInfo">记录保存结果的日志</param>
        public void SaveVmessList(List<string> vmessList, StringBuilder logInfo)
        {
            string vmessFile = Path.Combine(Application.StartupPath, "vmess_raw.txt");
            try
            {
                // 确保目录存在
                string directory = Path.GetDirectoryName(vmessFile);
                if (!Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // 写入去重后的 vmess 链接（覆盖文件，相当于清空）
                if (vmessList.Count > 0)
                {
                    File.WriteAllLines(vmessFile, vmessList.Distinct(), Encoding.UTF8);
                    logInfo.AppendLine($"成功写入 {vmessList.Count} 条 vmess 链接到 {vmessFile}");
                }
                else
                {
                    File.WriteAllText(vmessFile, string.Empty, Encoding.UTF8);
                    logInfo.AppendLine("没有找到有效的 vmess 链接，文件已清空。");
                }
            }
            catch (Exception ex)
            {
                logInfo.AppendLine($"写入vmess_raw.txt失败: {ex.Message}");
                MessageBox.Show($"写入vmess_raw.txt失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Ping 主机（支持 IPv4/IPv6）。
        /// </summary>
        /// <param name="host">要 ping 的主机地址</param>
        /// <returns>是否 ping 通</returns>
        public bool PingHost(string host)
        {
            try
            {
                using (var ping = new System.Net.NetworkInformation.Ping())
                {
                    var reply = ping.Send(host, 2000);
                    return reply.Status == System.Net.NetworkInformation.IPStatus.Success;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 异步 Ping 主机（支持 IPv4/IPv6）。
        /// </summary>
        /// <param name="host">要 ping 的主机地址</param>
        /// <returns>是否 ping 通</returns>
        public async Task<bool> PingHostAsync(string host)
        {
            try
            {
                using (var ping = new Ping())
                {
                    var reply = await ping.SendPingAsync(host, 2000);
                    return reply.Status == IPStatus.Success;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Ping 主机并返回详细信息。
        /// </summary>
        /// <param name="host">要 ping 的主机地址</param>
        /// <returns>元组，包含是否成功和详细信息</returns>
        public (bool Success, string Info) PingHostWithInfo(string host)
        {
            try
            {
                using (var ping = new System.Net.NetworkInformation.Ping())
                {
                    var reply = ping.Send(host, 2000);
                    if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                    {
                        return (true, $"Ping 成功，TTL={reply.Options?.Ttl ?? 0}，耗时={reply.RoundtripTime}ms");
                    }
                    else
                    {
                        return (false, $"Ping 失败，状态={reply.Status}");
                    }
                }
            }
            catch (Exception ex)
            {
                return (false, $"Ping 异常：{ex.Message}");
            }
        }

        /// <summary>
        /// 提取协议链接中的主机部分（支持域名/IP/IPv6）。
        /// </summary>
        /// <param name="line">协议链接</param>
        /// <returns>主机地址或 null</returns>
        public string ExtractHostFromLine(string line)
        {
            var match = System.Text.RegularExpressions.Regex.Match(line, @"@(.*?)(:|/|\?|#)");
            return match.Success ? match.Groups[1].Value : null;
        }
    }
}