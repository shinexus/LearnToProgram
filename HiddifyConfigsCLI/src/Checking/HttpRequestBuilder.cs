// src/Checking/HttpRequestBuilder.cs
// 从 InternetTester.cs 拆分类，负责构造 HTTP GET 四连发请求字节
// 支持多种 fingerprint 和随机 header 洗牌
// [ChatGPT 审查修改]：原 BuildFourHttpGetRequestBytes 方法迁移至此

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking
{
    internal static class HttpRequestBuilder
    {
        /// <summary>
        /// 构建 HTTP GET 四连发请求字节
        /// [ChatGPT 审查修改]：迁移自 InternetTester.cs
        /// </summary>
        public static byte[][] BuildFourHttpGetRequestBytes( string host, int port, string path, string? userAgent = null )
        {
            host = host ?? throw new ArgumentNullException(nameof(host));
            if (port < 1 || port > 65535) throw new ArgumentOutOfRangeException(nameof(port));

            path = string.IsNullOrEmpty(path) ? "/" : (path.StartsWith("/") ? path : "/" + path);
            var escapedPath = Uri.EscapeDataString(path).Replace("%2F", "/");

            userAgent ??= "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

            var hostHeader = $"Host: {host}{(port is not 80 and not 443 ? $":{port}" : "")}\r\n";
            var baseGet = $"GET {escapedPath} HTTP/1.1\r\n";

            static string[] CreateUltimateHeaders( string ua, string getLine, string hostHdr )
            {
                var allHeaders = new List<string>
                {
                    $"User-Agent: {ua}\r\n",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                    "Accept-Encoding: gzip, deflate, br, zstd\r\n",
                    "Accept-Language: en-US,en;q=0.9\r\n",
                    "Sec-Fetch-Site: none\r\n",
                    "Sec-Fetch-Mode: navigate\r\n",
                    "Sec-Fetch-User: ?1\r\n",
                    "Sec-Fetch-Dest: document\r\n",
                    "Upgrade-Insecure-Requests: 1\r\n",
                    "Connection: close\r\n"
                };

                var rnd = Random.Shared;
                for (int i = allHeaders.Count - 1; i > 0; i--)
                {
                    int j = rnd.Next(i + 1);
                    (allHeaders[i], allHeaders[j]) = (allHeaders[j], allHeaders[i]);
                }

                var list = new List<string> { getLine, hostHdr };
                list.AddRange(allHeaders);
                return list.ToArray();
            }

            var fingerprints = new List<string[]>
            {
                // GFW 最严格版
                new[]
                {
                    baseGet,
                    hostHeader,
                    $"User-Agent: {userAgent}\r\n",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n",
                    "Accept-Encoding: gzip, deflate, br, zstd\r\n",
                    "Accept-Language: en-US,en;q=0.9\r\n",
                    "Sec-Fetch-Site: none\r\n",
                    "Sec-Fetch-Mode: navigate\r\n",
                    "Sec-Fetch-User: ?1\r\n",
                    "Sec-Fetch-Dest: document\r\n",
                    "Priority: u=0, i\r\n",
                    "DNT: 1\r\n",
                    "Upgrade-Insecure-Requests: 1\r\n",
                    "Connection: close\r\n"
                },
                // 欧盟 DE 标准版
                new[]
                {
                    baseGet,
                    hostHeader,
                    $"User-Agent: {userAgent}\r\n",
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n",
                    "Accept-Encoding: gzip, deflate, br, zstd\r\n",
                    "Accept-Language: en-US,en;q=0.9,de;q=0.8\r\n",
                    "Sec-Fetch-Site: none\r\n",
                    "Sec-Fetch-Mode: navigate\r\n",
                    "Sec-Fetch-User: ?1\r\n",
                    "Sec-Fetch-Dest: document\r\n",
                    "Upgrade-Insecure-Requests: 1\r\n",
                    "Connection: close\r\n"
                },
                // 社区最佳实践版
                new[]
                {
                    baseGet,
                    hostHeader,
                    $"User-Agent: {userAgent}\r\n",
                    "Accept: */*\r\n",
                    "Accept-Encoding: gzip, deflate, br\r\n",
                    "Accept-Language: en-US,en;q=0.9\r\n",
                    "Connection: close\r\n"
                },
                // 终极保险版
                CreateUltimateHeaders(userAgent, baseGet, hostHeader)
            };

            return fingerprints.Select(fp =>
            {
                var sb = new StringBuilder(256);
                foreach (var line in fp) sb.Append(line);
                sb.Append("\r\n");
                return Encoding.UTF8.GetBytes(sb.ToString());
            }).ToArray();
        }
    }
}