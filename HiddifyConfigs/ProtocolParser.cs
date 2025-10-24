using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Web;

namespace HiddifyConfigs
{
    /// <summary>
    /// ProtocolParser：统一处理各种明文协议链接。
    /// 负责从链接中提取出 Host、Port、HostParam（VLESS host 或 Trojan sni 或 Hysteria2 sni）、Encryption、Security、Protocol 和额外参数。
    /// （例如 vless://、ss://、ssr://、trojan://、hysteria2://、wireguard:// 等）
    /// 
    /// ⚠️ 注意：
    /// - 不处理 Base64 编码形式（DoParse 已经提前过滤）
    /// - 尽量支持各种写法，包括 IPv6、额外参数、@ 符号重复等情况
    /// - 兼容 .NET Framework 4.7.2
    /// - 新增：支持 Trojan 的 sni、security 解析
    /// - 新增：支持 Hysteria2 的 sni、insecure、obfs 等参数解析
    /// </summary>
    internal static class ProtocolParser
    {
        /// <summary>
        /// 从一条协议链接中提取 Host、Port、HostParam、Encryption、Security、Protocol 和 ExtraParams。
        /// 如果解析失败，则返回 null。
        /// 统一移除方括号并将主机名转换为小写（ToLowerInvariant）。
        /// 使用 IPAddress.TryParse 验证 IPv6 地址合法性。
        /// </summary>
        /// <param name="line">协议链接（如 vless://, trojan://, hysteria2://）</param>
        /// <returns>解析结果，包含主机、端口、HostParam、Encryption、Security、Protocol 和额外参数</returns>
        public static (string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)? ExtractHostAndPort( string line )
        {
            // 新增：验证输入非空
            if (string.IsNullOrWhiteSpace(line))
            {
                LogHelper.WriteError($"[解析] 链接为空或无效: {line}");
                return null;
            }

            line = line.Trim();

            // === 1️⃣ 协议解析 ===
            // 原有注释：新增：优先处理 trojan:// 链接，调用 ParseTrojan
            // 新增：支持 hysteria2:// 链接，调用 ParseHysteria2
            if (line.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
            {
                return ParseTrojan(line);
            }
            if (line.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
            {
                return ParseVless(line);
            }
            if (line.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase))
            {
                return ParseHysteria2(line);
            }

            // === 2️⃣ 优先尝试 URI 解析（其他协议） ===
            // 新增：尝试使用 Uri 解析通用协议格式
            try
            {
                if (Uri.TryCreate(line, UriKind.Absolute, out var uri))
                {
                    if (!string.IsNullOrEmpty(uri.Host) && uri.Port > 0)
                    {
                        string host = uri.Host.Trim('[', ']').ToLowerInvariant();
                        if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            // 新增：其他协议返回默认值，Protocol 基于 URI Scheme
                            return (host, uri.Port, host, "none", "none", uri.Scheme.ToUpperInvariant(), new Dictionary<string, string>());
                        }
                    }
                }
            }
            catch
            {
                // 原有注释：忽略 URI 解析异常，继续尝试正则解析
                LogHelper.WriteError($"[解析] URI 解析失败: {line}");
            }

            // === 3️⃣ SSR 明文格式（如 ssr://user:pass@1.2.3.4:443）===
            // 新增：处理 ssr:// 链接，返回 Protocol=SSR
            if (line.StartsWith("ssr://", StringComparison.OrdinalIgnoreCase))
            {
                string data = line.Substring(6);
                int atIndex = data.LastIndexOf('@');
                if (atIndex >= 0 && atIndex < data.Length - 1)
                    data = data.Substring(atIndex + 1);

                int lastColon = data.LastIndexOf(':');
                if (lastColon > 0 && lastColon < data.Length - 1)
                {
                    string host = data.Substring(0, lastColon).Trim('[', ']').ToLowerInvariant();
                    if (int.TryParse(data.Substring(lastColon + 1).Trim(), out int port))
                    {
                        // if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                        // 使用丢弃变量简化代码
                        if (IPAddress.TryParse(host, out _) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            return (host, port, host, "none", "none", "SSR", new Dictionary<string, string>());
                        }
                    }
                }
                LogHelper.WriteError($"[解析] SSR 链接解析失败: {line}");
                return null;
            }

            // === 4️⃣ 常见协议的明文 Host:Port 区段（适用于 ss、wireguard 等）===
            // 新增：处理通用协议格式，返回 Protocol=Scheme
            var match = Regex.Match(line, @"^[a-zA-Z0-9]+://(?:[^@]*@)*((?:[0-9a-zA-Z\.\-]+|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)):(\d+)(?:[?/#].*)?$");
            if (match.Success)
            {
                string host = match.Groups[1].Value.Trim('[', ']').ToLowerInvariant();
                if (int.TryParse(match.Groups[2].Value, out int port))
                {
                    // if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    // 使用丢弃变量简化代码
                    if (IPAddress.TryParse(host, out _) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        // 新增：提取协议类型（如 ss, wireguard）
                        string protocol = line.Substring(0, line.IndexOf("://")).ToUpperInvariant();
                        return (host, port, host, "none", "none", protocol, new Dictionary<string, string>());
                    }
                }
            }

            // === 5️⃣ 通用 Host:Port 格式（无协议前缀） ===
            // 新增：处理简单 host:port 格式，默认 Protocol=Unknown
            var genericMatch = Regex.Match(line, @"(?:\[([0-9a-fA-F:]+)\]|([0-9a-fA-F:]+|[a-zA-Z0-9\.\-]+)):(\d+)");
            if (genericMatch.Success)
            {
                string host = (genericMatch.Groups[1].Success ? genericMatch.Groups[1].Value : genericMatch.Groups[2].Value).ToLowerInvariant();
                if (int.TryParse(genericMatch.Groups[3].Value, out int port))
                {
                    // if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    // 使用丢弃变量简化代码
                    if (IPAddress.TryParse(host, out _) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        return (host, port, host, "none", "none", "Unknown", new Dictionary<string, string>());
                    }
                }
            }

            // === 6️⃣ 全部失败 ===
            // 新增：记录解析失败的日志
            LogHelper.WriteError($"[解析] 无法解析协议链接: {line}");
            return null;
        }

        /// <summary>
        /// 解析 trojan:// 链接，提取 Host、Port、HostParam（sni）、Encryption（固定 none）、Security 和 ExtraParams。
        /// 支持 URI 解析和查询参数（sni、security）。
        /// 返回规范化主机名（小写，无方括号）。
        /// 如果解析失败，返回 null。
        /// </summary>
        /// <param name="line">Trojan 协议链接</param>
        /// <returns>解析结果</returns>
        private static (string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)? ParseTrojan( string line )
        {
            // 新增：验证输入非空
            if (string.IsNullOrWhiteSpace(line))
            {
                LogHelper.WriteError($"[解析] Trojan 链接为空: {line}");
                return null;
            }

            try
            {
                // 原有注释：新增：使用 URI 解析 trojan:// 链接
                if (Uri.TryCreate(line, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host) && uri.Port > 0)
                {
                    // 新增：解析查询参数
                    var query = HttpUtility.ParseQueryString(uri.Query);
                    string host = uri.Host.Trim('[', ']').ToLowerInvariant();
                    string hostParam = query["sni"]?.Trim('[', ']').ToLowerInvariant() ?? host; // 默认使用 host
                    string security = query["security"]?.ToLowerInvariant() ?? "tls"; // 默认 tls

                    // 新增：验证主机名（IPv4、IPv6、域名）
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        // 新增：验证 hostParam 合法性
                        if (string.IsNullOrEmpty(hostParam) || IPAddress.TryParse(hostParam, out var ipParam) || Regex.IsMatch(hostParam, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            // 新增：存储所有查询参数到 ExtraParams
                            var extraParams = query.AllKeys.ToDictionary(k => k, k => query[k]);
                            return (host, uri.Port, hostParam, "none", security, "Trojan", extraParams);
                        }
                    }
                }
            }
            catch
            {
                // 原有注释：新增：忽略 URI 解析异常，fallback 到正则解析
                LogHelper.WriteError($"[解析] Trojan URI 解析失败: {line}");
            }

            // 原有注释：新增：正则匹配 trojan://...@host:port?params
            var match = Regex.Match(line, @"^trojan://(?:[^@]*@)*((?:[0-9a-zA-Z\.\-]+|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)):(\d+)(?:[?/#].*)?$");
            if (match.Success)
            {
                string host = match.Groups[1].Value.Trim('[', ']').ToLowerInvariant();
                if (int.TryParse(match.Groups[2].Value, out int port))
                {
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        // 新增：解析查询参数
                        string hostParam = host;
                        string security = "tls";
                        var extraParams = new Dictionary<string, string>();
                        if (line.Contains("?"))
                        {
                            var queryString = line.Substring(line.IndexOf('?') + 1).Split('#')[0];
                            var query = HttpUtility.ParseQueryString(queryString);
                            hostParam = query["sni"]?.Trim('[', ']').ToLowerInvariant() ?? host;
                            security = query["security"]?.ToLowerInvariant() ?? "tls";
                            extraParams = query.AllKeys.ToDictionary(k => k, k => query[k]);
                        }

                        // 新增：验证 hostParam 合法性
                        if (string.IsNullOrEmpty(hostParam) || IPAddress.TryParse(hostParam, out var ipParam) || Regex.IsMatch(hostParam, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            return (host, port, hostParam, "none", security, "Trojan", extraParams);
                        }
                    }
                }
            }

            // 新增：记录解析失败
            LogHelper.WriteError($"[解析] Trojan 链接解析失败: {line}");
            return null;
        }

        /// <summary>
        /// 解析 vless:// 链接，提取 Host、Port、HostParam（host）、Encryption、Security 和 ExtraParams。
        /// 支持 URI 解析和查询参数（encryption、host、security）。
        /// 返回规范化主机名（小写，无方括号）。
        /// 如果解析失败，返回 null。
        /// </summary>
        /// <param name="line">VLESS 协议链接</param>
        /// <returns>解析结果</returns>
        private static (string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)? ParseVless( string line )
        {
            // 原有注释：新增：验证输入非空
            if (string.IsNullOrWhiteSpace(line))
            {
                LogHelper.WriteError($"[解析] VLESS 链接为空: {line}");
                return null;
            }

            line = line.Trim();

            // 原有注释：新增：尝试 URI 解析，优先处理规范格式
            try
            {
                if (Uri.TryCreate(line, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host) && uri.Port > 0)
                {
                    // 新增：提取查询参数
                    var query = HttpUtility.ParseQueryString(uri.Query);
                    string host = uri.Host.Trim('[', ']').ToLowerInvariant();
                    string hostParam = query["host"]?.Trim('[', ']').ToLowerInvariant() ?? host; // 默认使用 host
                    string encryption = query["encryption"]?.ToLowerInvariant() ?? "none"; // 默认 none
                    string security = query["security"]?.ToLowerInvariant() ?? "tls"; // 默认 tls

                    // 新增：验证主机名（IPv4、IPv6、域名）
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        // 新增：验证 hostParam 合法性
                        if (string.IsNullOrEmpty(hostParam) || IPAddress.TryParse(hostParam, out var ipParam) || Regex.IsMatch(hostParam, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            // 新增：存储所有查询参数到 ExtraParams
                            var extraParams = query.AllKeys.ToDictionary(k => k, k => query[k]);
                            return (host, uri.Port, hostParam, encryption, security, "VLESS", extraParams);
                        }
                    }
                }
            }
            catch
            {
                // 原有注释：新增：忽略 URI 解析异常，fallback 到正则解析
                LogHelper.WriteError($"[解析] VLESS URI 解析失败: {line}");
            }

            // 原有注释：新增：正则匹配 vless://...@host:port?params
            var match = Regex.Match(line, @"^vless://(?:[^@]*@)*((?:[0-9a-zA-Z\.\-]+|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)):(\d+)(?:[?/#].*)?$");
            if (match.Success)
            {
                string host = match.Groups[1].Value.Trim('[', ']').ToLowerInvariant();
                if (int.TryParse(match.Groups[2].Value, out int port))
                {
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        // 新增：解析查询参数
                        string hostParam = host;
                        string encryption = "none";
                        string security = "tls";
                        var extraParams = new Dictionary<string, string>();
                        if (line.Contains("?"))
                        {
                            var queryString = line.Substring(line.IndexOf('?') + 1).Split('#')[0];
                            var query = HttpUtility.ParseQueryString(queryString);
                            hostParam = query["host"]?.Trim('[', ']').ToLowerInvariant() ?? host;
                            encryption = query["encryption"]?.ToLowerInvariant() ?? "none";
                            security = query["security"]?.ToLowerInvariant() ?? "tls";
                            extraParams = query.AllKeys.ToDictionary(k => k, k => query[k]);
                        }

                        // 新增：验证 hostParam 合法性
                        if (string.IsNullOrEmpty(hostParam) || IPAddress.TryParse(hostParam, out var ipParam) || Regex.IsMatch(hostParam, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            return (host, port, hostParam, encryption, security, "VLESS", extraParams);
                        }
                    }
                }
            }

            // 原有注释：新增：解析失败返回 null
            LogHelper.WriteError($"[解析] VLESS 链接解析失败: {line}");
            return null;
        }

        /// <summary>
        /// 解析 hysteria2:// 链接，提取 Host、Port、HostParam（sni）、Encryption（固定 none）、Security 和 ExtraParams。
        /// 支持 URI 解析和查询参数（sni、insecure、obfs、obfs-password 等）。
        /// 返回规范化主机名（小写，无方括号）。
        /// 如果解析失败，返回 null。
        /// </summary>
        /// <param name="line">Hysteria2 协议链接</param>
        /// <returns>解析结果</returns>
        private static (string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)? ParseHysteria2( string line )
        {
            // 新增：验证输入非空
            if (string.IsNullOrWhiteSpace(line))
            {
                LogHelper.WriteError($"[解析] Hysteria2 链接为空: {line}");
                return null;
            }

            try
            {
                // 新增：尝试 URI 解析，优先处理规范格式
                if (Uri.TryCreate(line, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host) && uri.Port > 0)
                {
                    // 新增：提取查询参数
                    var query = HttpUtility.ParseQueryString(uri.Query);
                    string host = uri.Host.Trim('[', ']').ToLowerInvariant();
                    string hostParam = query["sni"]?.Trim('[', ']').ToLowerInvariant() ?? host; // 默认使用 host
                    string security = query["insecure"] == "1" ? "none" : "tls"; // 默认 tls

                    // 新增：验证主机名（IPv4、IPv6、域名）
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        // 新增：验证 hostParam 合法性
                        if (string.IsNullOrEmpty(hostParam) || IPAddress.TryParse(hostParam, out var ipParam) || Regex.IsMatch(hostParam, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            // 新增：存储所有查询参数到 ExtraParams（包括 obfs, alpn 等）
                            var extraParams = query.AllKeys.ToDictionary(k => k, k => query[k]);
                            return (host, uri.Port, hostParam, "none", security, "Hysteria2", extraParams);
                        }
                    }
                }
            }
            catch
            {
                // 新增：忽略 URI 解析异常，fallback 到正则解析
                LogHelper.WriteError($"[解析] Hysteria2 URI 解析失败: {line}");
            }

            // 新增：正则匹配 hysteria2://...@host:port?params
            var match = Regex.Match(line, @"^hysteria2://(?:[^@]*@)*((?:[0-9a-zA-Z\.\-]+|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+)):(\d+)(?:[?/#].*)?$");
            if (match.Success)
            {
                string host = match.Groups[1].Value.Trim('[', ']').ToLowerInvariant();
                if (int.TryParse(match.Groups[2].Value, out int port))
                {
                    if (IPAddress.TryParse(host, out var ip) || Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]+$"))
                    {
                        // 新增：解析查询参数
                        string hostParam = host;
                        string security = "tls";
                        var extraParams = new Dictionary<string, string>();
                        if (line.Contains("?"))
                        {
                            var queryString = line.Substring(line.IndexOf('?') + 1).Split('#')[0];
                            var query = HttpUtility.ParseQueryString(queryString);
                            hostParam = query["sni"]?.Trim('[', ']').ToLowerInvariant() ?? host;
                            security = query["insecure"] == "1" ? "none" : "tls";
                            extraParams = query.AllKeys.ToDictionary(k => k, k => query[k]);
                        }

                        // 新增：验证 hostParam 合法性
                        if (string.IsNullOrEmpty(hostParam) || IPAddress.TryParse(hostParam, out var ipParam) || Regex.IsMatch(hostParam, @"^[a-zA-Z0-9\.\-]+$"))
                        {
                            return (host, port, hostParam, "none", security, "Hysteria2", extraParams);
                        }
                    }
                }
            }

            // 新增：记录解析失败
            LogHelper.WriteError($"[解析] Hysteria2 链接解析失败: {line}");
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
        public static bool IsBase64Format( string line )
        {
            if (string.IsNullOrWhiteSpace(line))
                return false;

            // 原有注释：支持的协议前缀
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

            // 原有注释：去掉协议头和片段 (# 之后的内容)
            string data = line.Substring(prefix.Length).Split('#')[0].Trim();

            // 原有注释：明文情况：包含 @ 和 :port 的，不是 Base64
            if (data.Contains("@") && Regex.IsMatch(data, @":\d+"))
                return false;

            // 原有注释：明文情况：包含 [IPv6]:port 的，不是 Base64
            if (Regex.IsMatch(data, @"\[.*?\]:\d+"))
                return false;

            // 原有注释：明文情况：无方括号 IPv6:port（多个冒号）
            if (Regex.IsMatch(data, @"^([0-9a-fA-F:]+):\d+$") && data.Count(c => c == ':') >= 2)
                return false;

            // 原有注释：Base64 情况：字符仅限字母、数字、+/=_-，长度较长（>10）
            if (Regex.IsMatch(data, @"^[A-Za-z0-9\+/_\-]+=*$") && data.Length > 10)
                return true;

            return false;
        }
    }
}