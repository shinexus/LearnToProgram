using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigs
{
    /// <summary>
    /// DoParse：从 urls.txt 读取 URL，下载内容，提取协议链接（如 vless://, trojan://），解析出 Host、Port 等信息。
    /// 支持 http:// 和 https:// 的 URL，支持代理，兼容 .NET Framework 4.7.2。
    /// 感谢 Grok 和 xAI 提供的强大支持，让代码重构和调试更加高效！
    /// 感谢 chatGPT 协助完善异步处理与日志记录。
    /// </summary>
    internal static class DoParse
    {
        /// <summary>
        /// 从 urls.txt 读取 URL，下载内容，提取协议链接，调用 ProtocolParser 解析。
        /// 返回解析后的主机信息列表，包含原始链接、主机、端口、HostParam、Encryption、Security、Protocol 和额外参数。
        /// </summary>
        /// <param name="filePath">urls.txt 的路径</param>
        /// <param name="logInfo">日志信息，记录每个阶段的处理结果</param>
        /// <param name="cancellationToken">取消操作的令牌</param>
        /// <param name="proxy">可选的代理设置</param>
        /// <param name="logProgress">可选的进度日志</param>
        /// <returns>解析后的主机信息列表</returns>
        public static async Task<List<(string Line, string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)>> ProcessUrlsAsync(
            string filePath,
            StringBuilder logInfo,
            CancellationToken cancellationToken = default,
            IWebProxy proxy = null,
            IProgress<string> logProgress = null )
        {
            // 新增：初始化返回结果列表，用于存储解析后的协议链接信息
            var hostPortList = new List<(string Line, string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)>();

            // === 1️⃣ 读取 urls.txt ===
            // 原有注释：读取 urls.txt，移除空行和注释（# 或 // 或 /* */ 开头），去重
            logInfo.AppendLine("[读取] 开始读取 urls.txt");
            logProgress?.Report("[读取] 开始读取 urls.txt");
            string[] urls;
            try
            {
                // 新增：读取文件并过滤注释和空行
                urls = File.ReadAllLines(filePath)
                    .Select(line => line.Trim())
                    .Where(line => !string.IsNullOrEmpty(line) &&
                                   !line.StartsWith("#") &&
                                   !line.StartsWith("//") &&
                                   !line.StartsWith("/*"))
                    .Distinct()
                    .ToArray();

                // 新增：记录去重后的 URL 数量
                string readLog = $"[读取] 去重 URLs：从 {File.ReadAllLines(filePath).Length} 条减少到 {urls.Length} 条";
                logInfo.AppendLine(readLog);
                logProgress?.Report(readLog);
            }
            catch (Exception ex)
            {
                // 原有注释：记录读取文件的错误
                string error = $"[读取] 无法读取 {filePath}: {ex.Message}";
                logInfo.AppendLine(error);
                logProgress?.Report(error);
                LogHelper.WriteError(error);
                return hostPortList; // 返回空列表
            }

            // === 2️⃣ 配置 HttpClient ===
            // 新增：配置 HttpClient，支持代理、超时和 User-Agent
            var handler = new HttpClientHandler
            {
                UseProxy = proxy != null,
                Proxy = proxy,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            using (var httpClient = new HttpClient(handler))
            {
                // 原有注释：设置超时时间为 30 秒，模拟 Chrome 浏览器的 User-Agent
                httpClient.Timeout = TimeSpan.FromSeconds(30);
                httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36");

                // === 3️⃣ 下载并提取协议链接 ===
                // 新增：遍历 URLs，下载内容，提取协议链接
                foreach (var url in urls)
                {
                    // 原有注释：忽略无效 URL
                    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https"))
                    {
                        string invalidUrl = $"[下载] 跳过无效 URL: {url}";
                        logInfo.AppendLine(invalidUrl);
                        logProgress?.Report(invalidUrl);
                        continue;
                    }

                    // 新增：记录下载开始
                    string downloadLog = $"[下载] 开始下载: {url}";
                    logInfo.AppendLine(downloadLog);
                    logProgress?.Report(downloadLog);

                    string content;
                    try
                    {
                        // 原有注释：下载 URL 内容
                        // 新增：修复 GetStringAsync 不支持 CancellationToken 的问题，使用 GetAsync
                        using (var response = await httpClient.GetAsync(uri, cancellationToken))
                        {
                            // 新增：确保响应成功
                            response.EnsureSuccessStatusCode();
                            content = await response.Content.ReadAsStringAsync();
                        }
                    }
                    catch (Exception ex)
                    {
                        // 原有注释：记录下载失败的错误
                        string error = $"[下载] 下载 {url} 失败: {ex.Message}";
                        logInfo.AppendLine(error);
                        logProgress?.Report(error);
                        LogHelper.WriteError(error);
                        continue;
                    }

                    // 原有注释：提取协议链接（vless://, trojan://, hysteria2:// 等）
                    // 新增：支持 hysteria2:// 协议
                    var lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(line => line.Trim())
                        .Where(line => !string.IsNullOrEmpty(line) &&
                                       !Base64LinkDecoder.IsBase64Format(line) &&
                                       Regex.IsMatch(line, @"^(vless|trojan|hysteria2)://", RegexOptions.IgnoreCase))
                        .ToArray();

                    // 新增：记录提取的协议链接数量
                    string extractLog = $"[下载] 从 {url} 提取 {lines.Length} 条协议链接";
                    logInfo.AppendLine(extractLog);
                    logProgress?.Report(extractLog);

                    // === 4️⃣ 解析协议链接 ===
                    // 新增：调用 ProtocolParser 解析每条协议链接
                    foreach (var line in lines)
                    {
                        var parsed = ProtocolParser.ExtractHostAndPort(line);
                        if (parsed.HasValue)
                        {
                            var (host, port, hostParam, encryption, security, protocol, extraParams) = parsed.Value;
                            // 新增：存储解析结果，包括原始链接和额外参数
                            hostPortList.Add((line, host, port, hostParam, encryption, security, protocol, extraParams));

                            // 新增：记录解析成功的日志
                            string parseLog = $"[解析] 成功解析 {protocol}: {host}:{port} (host={hostParam}, encryption={encryption}, security={security}" +
                                              (extraParams != null && extraParams.Any() ? $", extra={string.Join(", ", extraParams.Select(kv => $"{kv.Key}={kv.Value}"))}" : "") + ")";
                            logInfo.AppendLine(parseLog);
                            logProgress?.Report(parseLog);
                        }
                        else
                        {
                            // 原有注释：记录无法解析的链接
                            string parseError = $"[解析] 无法解析链接: {line}";
                            logInfo.AppendLine(parseError);
                            logProgress?.Report(parseError);
                            LogHelper.WriteError(parseError);
                        }
                    }
                }
            }

            // 新增：记录解析完成的日志
            string completeLog = $"[解析] 总计解析 {hostPortList.Count} 条有效链接（VLESS: {hostPortList.Count(x => x.Protocol == "VLESS")}, Trojan: {hostPortList.Count(x => x.Protocol == "Trojan")}, Hysteria2: {hostPortList.Count(x => x.Protocol == "Hysteria2")})";
            logInfo.AppendLine(completeLog);
            logProgress?.Report(completeLog);

            // 新增：返回解析结果，供 ConnectivityChecker 和 ResultProcessor 使用
            return hostPortList;
        }
    }
}