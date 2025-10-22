using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigs
{
    /// <summary>
    /// 感谢 Grok 提供的 DoParse 解析思路与代码框架。
    /// 感谢 chatGPT 协助完善异步处理与日志记录。
    /// 
    /// DoParse 负责整个解析流程：
    /// 1. 从文件读取 URL 列表；
    /// 2. 过滤无效或注释行；
    /// 3. 交给 ProtocolParser 提取 Host/Port；
    /// 4. 使用 ConnectivityChecker 检测主机可达性；
    /// 5. 保存可达的非 Base64 链接；
    /// 6. 全部检测完成后调用 ResultProcessor 进行全局排序与去重。
    /// </summary>
    public class DoParse
    {
        /// <summary>
        /// 异步处理 URL 文件。
        /// </summary>
        public async Task ProcessUrlsAsync(
            string filePath,
            StringBuilder logInfo,
            List<string> validList,                    // 存储可达的链接
            CancellationToken cancellationToken,
            IProgress<int> progress = null,
            IProgress<string> status = null,
            IWebProxy proxy = null,
            IProgress<string> logProgress = null)
        {
            string log;

            // === 1️⃣ 读取文件并过滤空行与注释 ===
            var allLines = File.ReadAllLines(filePath, Encoding.UTF8);
            var urls = allLines
                .Select(u => u.Trim())
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .Where(u => !IsComment(u))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (urls.Count < allLines.Length)
            {
                log = $"去重 URLs：从 {allLines.Length} 条减少到 {urls.Count} 条";
                logInfo.AppendLine(log);
                logProgress?.Report(log);
            }

            int totalUrls = urls.Count;
            int processed = 0;

            // === 2️⃣ 配置 HttpClient ===
            var handler = new HttpClientHandler
            {
                Proxy = proxy,
                UseProxy = proxy != null
            };

            log = proxy is WebProxy webProxy
                ? $"代理设置：{webProxy.Address.Host}:{webProxy.Address.Port}"
                : "代理设置：无";
            logInfo.AppendLine(log);
            logProgress?.Report(log);

            using (var httpClient = new HttpClient(handler))
            {
                httpClient.Timeout = TimeSpan.FromSeconds(30);
                httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0 Safari/537.36");                

                log = "User-Agent 已设置: Chrome/128";
                logInfo.AppendLine(log);
                logProgress?.Report(log);

                // === 累积所有检测结果（供 ResultProcessor 使用） ===
                var allResults = new List<(string Line, string Host, int Port, long? ResponseTimeMs)>();

                // === 3️⃣ 循环处理每个 URL ===
                foreach (var url in urls)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    processed++;
                    status?.Report($"正在处理 {processed}/{totalUrls}: {url}");
                    progress?.Report((int)((processed / (double)totalUrls) * 100));

                    if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                    {
                        log = $"无效的 URL: {url}";
                        logInfo.AppendLine(log);
                        logProgress?.Report(log);
                        LogHelper.WriteError($"无效的 URL：{url}");
                        continue;
                    }

                    try
                    {
                        log = $"正在请求： {url} ...";
                        logInfo.AppendLine(log);
                        logProgress?.Report(log);

                        using (var response = await httpClient.GetAsync(url, cancellationToken))
                        {
                            response.EnsureSuccessStatusCode();
                            string content = await response.Content.ReadAsStringAsync();

                            // 分行读取内容
                            var lines = content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                            var hostPortList = new List<(string Line, string Host, int Port)>();

                            foreach (var line in lines)
                            {
                                
                                // === 跳过 Base64 链接 ===
                                if (Base64LinkDecoder.IsBase64Format(line))
                                {
                                    log = $"跳过 Base64 编码链接: {line}";
                                    logInfo.AppendLine(log);
                                    logProgress?.Report(log);
                                    continue;
                                }

                                // 仅处理明文的 vmess/ss/ssr 协议
                                if (line.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase) ||
                                    line.StartsWith("ss://", StringComparison.OrdinalIgnoreCase) ||
                                    line.StartsWith("ssr://", StringComparison.OrdinalIgnoreCase))
                                {
                                    var parsed = ProtocolParser.ExtractHostAndPort(line);
                                    if (parsed == null)
                                    {
                                        log = $"跳过无法解析的链接: {line}";
                                        logInfo.AppendLine(log);
                                        logProgress?.Report(log);
                                        LogHelper.WriteError($"跳过无法解析的链接：{line}");
                                        continue;
                                    }

                                    hostPortList.Add((line, parsed.Value.Host, parsed.Value.Port));
                                    continue; // 明文三种协议处理完成
                                }

                                // 其他协议
                                var otherParsed = ProtocolParser.ExtractHostAndPort(line);
                                if (otherParsed == null)
                                {
                                    log = $"跳过无法解析的链接: {line}";
                                    logInfo.AppendLine(log);
                                    logProgress?.Report(log);
                                    LogHelper.WriteError($"跳过无法解析的链接：{line}");
                                    continue;
                                }

                                hostPortList.Add((line, otherParsed.Value.Host, otherParsed.Value.Port));
                            }

                            // === 4️⃣ 批量检测主机可达性 ===
                            var results = await ConnectivityChecker.CheckHostsBatchAsync(
                                hostPortList.Select(h => (h.Host, h.Port)),
                                timeoutMs: 1500,
                                maxConcurrency: 20,
                                cancellationToken,
                                logProgress);

                            // === 累积检测结果（不排序、不去重）===
                            foreach (var r in results.Where(r => r.IsReachable))
                            {
                                //修正 IPv6 匹配问题：忽略中括号
                                //var match = hostPortList.FirstOrDefault(
                                //    h => string.Equals(
                                //        h.Host.Trim('[', ']'),
                                //        r.Host.Trim('[', ']'),
                                //        StringComparison.OrdinalIgnoreCase)
                                //        && h.Port == r.Port);
                                var match = hostPortList.FirstOrDefault(h => h.Host == r.Host && h.Port == r.Port);
                                if (!string.IsNullOrEmpty(match.Line))
                                {
                                    allResults.Add((match.Line, match.Host, match.Port, r.ResponseTimeMs));
                                    log = $"✅ {match.Host}:{match.Port} 可达 ({r.ResponseTimeMs ?? 0} ms)";
                                    logInfo.AppendLine(log);
                                    logProgress?.Report(log);
                                }

                                var (Line, Host, Port) = hostPortList.FirstOrDefault(h => h.Host == r.Host && h.Port == r.Port);
                                if (!string.IsNullOrEmpty(Line))
                                {
                                    // allResults.Add((Line, Host, Port, r.ResponseTimeMs));
                                    allResults.Add((match.Line, match.Host, match.Port, r.ResponseTimeMs));

                                    // 输出详细耗时
                                    log = $"✅ {match.Host}:{match.Port} 可达 ({r.ResponseTimeMs ?? 0} ms)";
                                    logInfo.AppendLine(log);
                                    logProgress?.Report(log);
                                }
                            }

                            //string summary = $"检测完成：共检测 {results.Count} 条主机，可达 {results.Count(r => r.IsReachable)} 条。";
                            //logInfo.AppendLine(summary);
                            //logProgress?.Report(summary);
                            int reachable = results.Count(r => r.IsReachable);
                            string summary = $"检测完成：共检测 {results.Count} 条主机，可达 {reachable} 条。";
                            if (reachable > 0)
                            {
                                double avg = results.Where(r => r.IsReachable && r.ResponseTimeMs.HasValue)
                                                    .Average(r => r.ResponseTimeMs.Value);
                                summary += $" 平均延迟 {avg:F0} ms。";
                            }

                            logInfo.AppendLine(summary);
                            logProgress?.Report(summary);
                        }
                    }
                    //catch (OperationCanceledException)
                    //{
                    //    logProgress?.Report("操作已取消。");
                    //    throw;
                    //}
                    catch (TaskCanceledException)
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            log = $"操作已取消。";
                            logProgress?.Report(log);
                            throw;
                        }
                        else
                        {
                            // 请求超时
                            log = $"请求超时（30秒）: {url}";
                            logInfo.AppendLine(log);
                            logProgress?.Report(log);
                            continue; // 继续处理下一个 URL
                        }
                    }
                    catch (Exception ex)
                    {
                        log = $"URL 处理失败: {url}，错误: {ex.Message}";
                        logInfo.AppendLine(log);
                        logProgress?.Report(log);
                        LogHelper.WriteError($"URL 处理失败：{url}", ex);
                    }
                }

                // === 5️⃣ 全局结果处理（排序 + 去重）===
                var processedResults = ResultProcessor.ProcessResults(allResults, logInfo, logProgress);

                validList.Clear();
                validList.AddRange(processedResults.Select(r => r.Line));

                logInfo.AppendLine($"全局排序与去重完成：{validList.Count} 条可达链接。");
                logProgress?.Report($"全局排序与去重完成：{validList.Count} 条可达链接。");
            }
        }

        /// <summary>
        /// 判断一行是否是注释。
        /// </summary>
        private bool IsComment(string line)
        {
            line = line.Trim();
            return line.StartsWith("#") || line.StartsWith("//") ||
                   (line.StartsWith("/*") && line.EndsWith("*/"));
        }
    }
}