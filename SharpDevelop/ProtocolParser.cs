using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace HiddifyConfigs
{
    /// <summary>
    /// ProtocolParser：统一处理各种明文协议链接。
    /// 负责从链接中提取出 Host 和 Port。
    /// （例如 vless://、ss://、ssr://、trojan://、hysteria2://、wireguard:// 等）
    /// 
    /// ⚠️ 注意：
    /// - 不处理 Base64 编码形式（DoParse 已经提前过滤）
    /// - 尽量支持各种写法，包括 IPv6、额外参数、@ 符号重复等情况
    /// - 兼容 .NET Framework 4.7.2
    /// </summary>
    internal static class ProtocolParser
    {
        /// <summary>
        /// 从一条协议链接中提取 Host 和 Port。
        /// 如果解析失败，则返回 null。
        /// 统一移除方括号并将主机名转换为小写（ToLowerInvariant）。
        /// 使用 IPAddress.TryParse 验证 IPv6 地址合法性。
        /// 优化正则表达式，合并带/不带方括号的 IPv6 地址处理。
        /// </summary>
        public static (string Host, int Port)? ExtractHostAndPort(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return null;

            line = line.Trim();

            // === 1️⃣ 优先尝试 URI 解析 ===
            try
            {
                if (Uri.TryCreate(line, UriKind.Absolute, out var uri))
                {
                    if (!string.IsNullOrEmpty(uri.Host) && uri.Port > 0)
                        return (uri.Host.ToLowerInvariant(), uri.Port); // 规范化主机名
                }
            }
            catch
            {
                // 忽略 URI 解析异常，继续尝试正则解析
            }

            // === 2️⃣ SSR 明文格式（如 ssr://user:pass@1.2.3.4:443）===
            if (line.StartsWith("ssr://", StringComparison.OrdinalIgnoreCase))
            {
                string data = line.Substring(6);
                int atIndex = data.LastIndexOf('@');
                if (atIndex >= 0 && atIndex < data.Length - 1)
                    data = data.Substring(atIndex + 1);

                int lastColon = data.LastIndexOf(':');
                if (lastColon > 0 && lastColon < data.Length - 1)
                {
                    //string host = data.Substring(0, lastColon).Trim();
                    //if (int.TryParse(data.Substring(lastColon + 1).Trim(), out int port))
                    //    return (host, port);
                    string host = data.Substring(0, lastColon).Trim().Trim('[', ']').ToLowerInvariant();
                    if (int.TryParse(data.Substring(lastColon + 1).Trim(), out int port))
                        return (host, port);
                }

                return null;
            }

            // === 3️⃣ 常见协议的明文 Host:Port 区段（适用于 trojan、ss、vless、hysteria 等）===
            //int atIdx = line.LastIndexOf('@');
            //if (atIdx >= 0 && atIdx < line.Length - 1)
            //{
            //    string hostPortPart = line.Substring(atIdx + 1);

            //    // 去掉 ? / # 参数段
            //    int qIndex = hostPortPart.IndexOfAny(new[] { '?', '#', '/' });
            //    if (qIndex > 0)
            //        hostPortPart = hostPortPart.Substring(0, qIndex);

            //    hostPortPart = hostPortPart.Trim();

            //    // IPv4 或普通域名
            //    var ipv4Match = Regex.Match(hostPortPart, @"^([0-9a-zA-Z\.\-]+):(\d+)$");
            //    if (ipv4Match.Success)
            //    {
            //        string host = ipv4Match.Groups[1].Value.ToLowerInvariant();
            //        if (int.TryParse(ipv4Match.Groups[2].Value, out int port))
            //            return (host, port);
            //    }

            //    // IPv6 格式（带或不带方括号）
            //    // 统一去除方括号并小写
            //    // 处理带方括号的 IPv6:Port
            //    var ipv6Match = Regex.Match(hostPortPart, @"^(?:\[([0-9a-fA-F:]+)\]|([0-9a-fA-F:]+)):(\d+)$");
            //    if (ipv6Match.Success)
            //    {
            //        string host = (ipv6Match.Groups[1].Success ? ipv6Match.Groups[1].Value : ipv6Match.Groups[2].Value).ToLowerInvariant();
            //        if (IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
            //        {
            //            if (int.TryParse(ipv6Match.Groups[3].Value, out int port))
            //                return (host, port);
            //        }
            //    }

            //    // 通用格式
            //    // 处理无方括号的 IPv6:Port（多个冒号）
            //    int lastColon = hostPortPart.LastIndexOf(':');
            //    if (lastColon > 0 && lastColon < hostPortPart.Length - 1)
            //    {
            //        string hostPart = hostPortPart.Substring(0, lastColon).Trim('[', ']').ToLowerInvariant();
            //        string portStr = hostPortPart.Substring(lastColon + 1);
            //        if (IPAddress.TryParse(hostPart, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
            //        {
            //            if (int.TryParse(portStr, out int port))
            //                return (hostPart, port);
            //        }
            //    }
            //}
            // === 3️⃣ 常见协议的明文 Host:Port 区段（适用于 trojan、ss、vless、hysteria 等）===
            // 支持：IPv4、域名、带方括号的 IPv6、无方括号的 IPv6、连续 @ 符号
            var match = Regex.Match(line, @"^[a-zA-Z0-9]+://(?:[^@]*@)*((?:[0-9a-zA-Z\.\-]+|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)):(\d+)(?:[?/#].*)?$");
            if (match.Success)
            {
                string host = match.Groups[1].Value.Trim('[', ']').ToLowerInvariant();
                if (int.TryParse(match.Groups[2].Value, out int port))
                {
                    // 验证主机名是否合法（IPv4、IPv6 或域名）
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                        return (host, port);
                }
            }

            // === 4️⃣ hysteria2 / wireguard 等直接 Host:Port ===
            // 直接匹配 Host:Port 格式
            var genericMatch = Regex.Match(line, @"(?:\[([0-9a-fA-F:]+)\]|([0-9a-fA-F:]+|[a-zA-Z0-9\.\-]+)):(\d+)");
            if (genericMatch.Success)
            {
                string host = (genericMatch.Groups[1].Success ? genericMatch.Groups[1].Value : genericMatch.Groups[2].Value).ToLowerInvariant();
                if (int.TryParse(genericMatch.Groups[3].Value, out int port))
                {
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                        return (host, port);
                }
            }

            // === 5️⃣ 全部失败 ===
            return null;
        }
    }

    /// <summary>
    /// Base64LinkDecoder：用于识别是否为 Base64 编码形式的链接。
    /// 我们只做检测，不解码。
    /// 
    /// 检查链接是否为 Base64 格式：
    /// - vmess:// + base64
    /// - ss:// + base64
    /// - ssr:// + base64
    /// - trojan:// + base64(JSON)
    /// </summary>
    internal static class Base64LinkDecoder
    {
        public static bool IsBase64Format(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return false;

            // 支持的协议前缀
            string[] prefixes = { "vmess://", "ss://", "ssr://", "trojan://" };
            string prefix = null;
            foreach (var p in prefixes)
            {
                if (line.StartsWith(p, StringComparison.OrdinalIgnoreCase))
                {
                    prefix = p;
                    break;
                }
            }
            if (prefix == null)
                return false;
                        
            // 去掉协议头和片段 (# 之后的内容)
            string data = line.Substring(prefix.Length).Split('#')[0].Trim();

            // 明文情况：包含 @ 和 :port 的，不是 Base64
            if (data.Contains("@") && Regex.IsMatch(data, @":\d+"))
                return false;

            // 明文情况：包含 [IPv6]:port 的，不是 Base64
            if (Regex.IsMatch(data, @"\[.*?\]:\d+"))
                return false;

            // 明文情况：无方括号 IPv6:port（多个冒号）
            if (Regex.IsMatch(data, @"^([0-9a-fA-F:]+):\d+$") && data.Count(c => c == ':') >= 2)
                return false;

            // Base64 情况：字符仅限字母、数字、+/=_-，长度较长（>10）
            if (Regex.IsMatch(data, @"^[A-Za-z0-9\+/_\-]+=*$") && data.Length > 10)
                return true;

            return false;
        }
    }
}