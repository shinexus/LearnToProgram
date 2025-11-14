// ProtocolParser.cs
// 负责：从 vless://、trojan://、hysteria2:// 等协议链接或 JSON/YAML 配置中解析结构化字段
// 命名空间：HiddifyConfigsCLI.src.Parsing
// [Grok Rebuild] 2025-11-14：统一入口，JSON/YAML 也走 ProtocolParser，最终生成 NodeInfo
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.ComponentModel;
using System.Net;
using System.Web;
using System.Text.Json;

namespace HiddifyConfigsCLI.src.Parsing;

/// <summary>
/// 协议链接解析器：将 vless://、trojan:// 等链接或 JSON/YAML 转为 NodeInfo 结构
/// </summary>
internal static class ProtocolParser
{
    /// <summary>
    /// 解析任意协议或配置为 NodeInfo 结构
    /// </summary>
    /// <param name="line">完整协议链接（如 vless://...）或 JSON/YAML 行</param>
    /// <returns>成功返回 NodeInfo，失败返回 null</returns>
    public static NodeInfo? Parse( string line )
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        // ---------- 检测是否为 JSON/YAML 格式 ----------
        if (line.TrimStart().StartsWith("{") && line.TrimEnd().EndsWith("}"))
        {
            // JSON 格式 → 委托给 JsonOptsParser
            return JsonOptsParser.ParseJsonLine(line);
        }

        if (line.TrimStart().StartsWith("---") || line.TrimStart().StartsWith("- "))
        {
            // YAML 格式 → 委托给 YmlOptsParser
            return YmlOptsParser.ParseYmlLine(line);
        }

        // ---------- 普通协议链接处理 ----------
        try
        {
            var uri = new Uri(line, UriKind.Absolute);
            var scheme = uri.Scheme.ToLowerInvariant();

            return scheme switch
            {
                "vless"     => ParseVless(uri),
                "trojan"    => ParseTrojan(uri),
                "hysteria2" => ParseHysteria2(uri),
                "tuic"      => ParseTuic(uri),
                "wireguard" => ParseWireGuard(uri),
                "socks5"    => ParseSocks5(uri),
                _ => null
            };
        }
        catch (Exception ex) when (ex is UriFormatException or InvalidOperationException)
        {
            LogHelper.Debug($"[协议解析] 链接格式错误，已跳过: {line} | 错误: {ex.Message}");
            return null;
        }
    }

    #region VLESS 解析
    private static NodeInfo? ParseVless( Uri uri )
    {
        var query = ParseQuery(uri.Query ?? "");
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 443;

        if (string.IsNullOrWhiteSpace(host))
        {
            LogHelper.Debug($"[VLESS 节点丢弃] Host 为空: {uri}");
            return null;
        }

        if (port < 1 || port > 65535)
        {
            LogHelper.Debug($"[VLESS 节点丢弃] Port 非法: {port}");
            return null;
        }

        string? hostParam = null;
        if (query.TryGetValue("sni", out var sni) && IsValidHost(sni)) hostParam = sni;
        else if (query.TryGetValue("peer", out var peer) && IsValidHost(peer)) hostParam = peer;

        var encryption = query.GetValueOrDefault("encryption") ?? "none";
        var security = (query.GetValueOrDefault("security") ?? "none").ToLowerInvariant();

        var skipCertVerify = query.GetValueOrDefault("allowInsecure") == "1" ||
                             query.GetValueOrDefault("skip-cert-verify") == "true";
        query["skip_cert_verify"] = skipCertVerify.ToString().ToLowerInvariant();

        var transportType = query.GetValueOrDefault("type")?.ToLowerInvariant() ?? "";
        query["transport_type"] = transportType;

        // ---------- JSON 嵌套字段解析，保持兼容性 ----------
        if (transportType == "ws") JsonOptsParser.ParseWsOpts(query);
        else if (transportType == "grpc") JsonOptsParser.ParseGrpcOpts(query);
        else if (transportType == "xhttp") JsonOptsParser.ParseXhttpOpts(query);
        JsonOptsParser.ParseReality(query);

        if (query.TryGetValue("pbk", out var pbk) && !string.IsNullOrEmpty(pbk))
        {
            query["pbk"] = pbk;
            query["reality_enabled"] = "true";
        }

        var spx = query.GetValueOrDefault("spx") ?? "";
        query["spx"] = spx;

        var flow = query.GetValueOrDefault("flow") ?? "";
        query["flow"] = flow;

        var isTls = security == "tls" || query.GetValueOrDefault("tls") == "tls";
        var isReality = security == "reality" || query.GetValueOrDefault("tls") == "reality" ||
                        query.ContainsKey("pbk");

        query["tls_enabled"] = (isTls || isReality).ToString().ToLowerInvariant();
        query["reality_enabled"] = isReality.ToString().ToLowerInvariant();

        var fp = query.GetValueOrDefault("fp") ?? query.GetValueOrDefault("fingerprint") ?? "";
        query["utls_fingerprint"] = fp;

        var readOnlyExtra = query.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase);

        return NodeInfo.Create(
            OriginalLink: uri.ToString(),
            Type: "vless",
            Host: host,
            Port: port,
            HostParam: hostParam,
            Encryption: encryption,
            Security: security,
            ExtraParams: readOnlyExtra
        );
    }
    #endregion

    #region Trojan 解析
    /// <summary>
    /// 解析 Trojan 协议链接
    /// 兼容：密码错误格式、SNI 兜底（www.cloudflare.com）、WS Host 复用
    /// 提前验证 UserId/Password，无 try-catch
    /// </summary>
    private static NodeInfo? ParseTrojan( Uri uri )
    {
        // --------------- 局部帮助函数：安全解码（HTML -> URL，最多两次 URL 解码） ---------------
        static string SafeDecode( string? raw )
        {
            if (string.IsNullOrEmpty(raw)) return string.Empty;

            // 1) HTML 解码，处理 &amp; 等实体
            var htmlDecoded = System.Net.WebUtility.HtmlDecode(raw);

            // 2) 一次 URL 解码（防御式）
            string once;
            try { once = Uri.UnescapeDataString(htmlDecoded); }
            catch { once = htmlDecoded; }

            // 3) 若仍包含 '%'，尝试第二次解码（兼容双重编码，如 %253c -> %3c -> <）
            if (once.Contains('%'))
            {
                try
                {
                    var twice = Uri.UnescapeDataString(once);
                    if (!string.IsNullOrEmpty(twice)) return twice;
                }
                catch
                {
                    // 忽略二次解码失败，返回一次解码结果
                }
            }

            return once;
        }

        // --------------- 基本 Host/Port 校验 ---------------
        var host = uri.Host;
        var port = uri.Port;

        if (string.IsNullOrWhiteSpace(host) || port < 1 || port > 65535)
        {
            LogHelper.Debug($"[Trojan 节点丢弃] Host 或 Port 非法: {host}:{port}");
            return null;
        }

        // --------------- 解析并解码 query（防止 &amp; 以及编码问题） ---------------
        // uri.Query 包含开头的 '?'，SafeDecode 会处理 HTML 实体与 URL 编码
        var decodedQueryString = SafeDecode(uri.Query ?? string.Empty);
        // 你的项目里应该已有 ParseQuery(string) 方法：它将 ?a=b&c=d 解析为字典
        var query = ParseQuery(decodedQueryString);

        // --------------- 用户名与密码解析（兼容 password-only 与 user:password） ---------------
        string? userId = null;
        string? password = null;

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            // 先解码 userinfo（可能是双重编码或包含 HTML 实体）
            var decodedUserInfo = SafeDecode(uri.UserInfo);

            // 如果包含 ':' 且左右都不为空，认为是 user:password 格式；否则把整个字段当作 password（更兼容常见 trojan 链接）
            if (decodedUserInfo.Contains(':'))
            {
                var parts = decodedUserInfo.Split(new[] { ':' }, 2);
                if (!string.IsNullOrEmpty(parts[0]) && !string.IsNullOrEmpty(parts[1]))
                {
                    userId = parts[0];
                    password = parts[1];
                }
                else
                {
                    // 例如 ":password" 或 "user:"，当作 password 处理
                    userId = null;
                    password = decodedUserInfo;
                }
            }
            else
            {
                // 常见写法：trojan://PASSWORD@host:port
                userId = null;
                password = decodedUserInfo;
            }

            // 防御性过滤：若 password 明显是被屏蔽/占位符（如包含表情或注明来源），则视为无效
            if (!string.IsNullOrEmpty(password))
            {
                var p = password;
                if (p.Contains("🔒") || p.IndexOf("By ", StringComparison.OrdinalIgnoreCase) >= 0
                    || p.IndexOf("EbraSha", StringComparison.OrdinalIgnoreCase) >= 0
                    || p.IndexOf("ByEbraSha", StringComparison.OrdinalIgnoreCase) >= 0
                    || string.IsNullOrWhiteSpace(p))
                {
                    LogHelper.Warn($"[Trojan 解析] 检测到被屏蔽/占位的密码（或非法占位符），已忽略: {host}:{port}");
                    password = null;
                }
            }

            // 修复：密码误含端口（仅当 password 完全为数字字符串且等于端口时才修复）
            if (!string.IsNullOrEmpty(password) && int.TryParse(password, out var parsedPort) && parsedPort == port)
            {
                LogHelper.Warn($"[Trojan 解析] 检测到密码包含端口 {parsedPort}，已修正为 null");
                password = null;
            }
        }

        // --------------- 提前验证凭据逻辑（调整后） ---------------
        // 说明：
        //  - userId 在 Trojan 场景中并不总是提供，因此仅在存在时才校验其合法性
        //  - password 对 Trojan 是必须的：若缺失/非法则丢弃该节点
        if (!string.IsNullOrEmpty(userId))
        {
            if (!IsValidCredential(userId))
            {
                LogHelper.Debug($"[Trojan 节点丢弃] UserId 无效: {host}:{port} | UserId={userId}");
                return null;
            }
        }

        if (string.IsNullOrEmpty(password))
        {
            LogHelper.Debug($"[Trojan 节点丢弃] Password 缺失或为空: {host}:{port}");
            return null;
        }
        if (!IsValidCredential(password))
        {
            LogHelper.Debug($"[Trojan 节点丢弃] Password 无效: {host}:{port} | password={password}");
            return null;
        }

        // --------------- SNI 优先级处理：sni > peer > ws host > 兜底 ---------------
        string? hostParam = null;

        // 从 query 中安全读取并解码 sni/peer/host（注意一些源会把 sni 填为占位符）
        static string? GetQueryDecoded( Dictionary<string, string> q, string key )
        {
            if (q.TryGetValue(key, out var v)) return string.IsNullOrEmpty(v) ? null : v;
            return null;
        }

        // 读取并判断是否为被屏蔽占位（如果是则忽略）
        string? TryUseSni( string? raw )
        {
            if (string.IsNullOrEmpty(raw)) return null;
            var decoded = SafeDecode(raw);
            // 若包含明显的占位/注记文本，认为被屏蔽
            if (decoded.Contains("🔒") || decoded.IndexOf("By ", StringComparison.OrdinalIgnoreCase) >= 0
                || decoded.IndexOf("EbraSha", StringComparison.OrdinalIgnoreCase) >= 0)
                return null;
            return decoded;
        }

        if (query.TryGetValue("sni", out var sniRaw))
        {
            var sniDecoded = TryUseSni(sniRaw);
            if (!string.IsNullOrEmpty(sniDecoded) && IsValidHost(sniDecoded)) hostParam = sniDecoded;
        }

        if (string.IsNullOrEmpty(hostParam) && query.TryGetValue("peer", out var peerRaw))
        {
            var peerDecoded = TryUseSni(peerRaw);
            if (!string.IsNullOrEmpty(peerDecoded) && IsValidHost(peerDecoded)) hostParam = peerDecoded;
        }

        // WebSocket 场景下常用 host 参数来作为 Host header / SNI 的替代
        if (string.IsNullOrEmpty(hostParam) && query.TryGetValue("host", out var wsHostRaw))
        {
            var wsHostDecoded = TryUseSni(wsHostRaw);
            if (!string.IsNullOrEmpty(wsHostDecoded) && IsValidHost(wsHostDecoded))
            {
                hostParam = wsHostDecoded;
                LogHelper.Info($"[Trojan 解析] 使用 WS host 作为 SNI: {wsHostDecoded}");
            }
        }

        // 兜底 SNI（如果都没有合适的），使用一个常见的可用值以增大通过率（可根据策略调整）
        if (string.IsNullOrEmpty(hostParam) || !IsValidHost(hostParam))
        {
            hostParam = "www.cloudflare.com";
            LogHelper.Verbose($"[Trojan 解析] SNI 兜底为: {hostParam}");
        }

        // --------------- 处理 ExtraParams：把解码后的 query 放入 ExtraParams（包含 alpn 等） ---------------
        // 先把 query 里的键值全部解码并整理为不区分大小写的字典
        var safeQuery = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in query)
        {
            if (kvp.Key == null) continue;
            var k = SafeDecode(kvp.Key);
            var v = SafeDecode(kvp.Value);
            if (!string.IsNullOrEmpty(k))
            {
                // 覆盖策略：后来的同名参数覆盖前面（合理）
                safeQuery[k] = v;
            }
        }

        // 如果存在 alpn 且为 URL 编码形式（例如 http%2F1.1），SafeDecode 已处理为 "http/1.1"
        if (safeQuery.TryGetValue("alpn", out var alpnVal) && !string.IsNullOrWhiteSpace(alpnVal))
        {
            LogHelper.Info($"[Trojan 解析] ALPN 设置为: {alpnVal} for {host}:{port}");
            // 保持在 ExtraParams 里，后续在 TlsHelper.CreateSslOptions 中会读取并设置
        }

        // 把最终的 safeQuery（解码后的）作为 ExtraParams，NodeInfo.Create 会做只读处理
        var extraParams = safeQuery.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase);

        // --------------- 构造并返回 NodeInfo（使用静态工厂以保证验证） ---------------
        try
        {
            return NodeInfo.Create(
                OriginalLink: uri.ToString(),
                Type: "trojan",
                Host: host,
                Port: port,
                HostParam: hostParam,
                Encryption: "none",
                Security: "tls",
                UserId: userId,
                Password: password,
                ExtraParams: extraParams
            );
        }
        catch (ArgumentException ex)
        {
            // 如果 NodeInfo.Create 因 Host/Port 等抛异常，则记录并返回 null
            LogHelper.Debug($"[Trojan 解析] NodeInfo 创建失败: {ex.Message} | 原链: {uri}");
            return null;
        }
    }
    #endregion

    #region 其他协议
    /// <summary>
    /// [Hysteria2 协议解析器] （完整字段映射）
    /// 提前验证 password
    /// </summary>
    private static NodeInfo? ParseHysteria2( Uri uri )
    {
        var query = ParseQuery(uri.Query);
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 443;
        var password = uri.UserInfo;

        // 
        if (string.IsNullOrWhiteSpace(host) || port < 1 || port > 65535)
        {
            LogHelper.Debug($"[Hysteria2 节点丢弃] Host 或 Port 非法: {host}:{port}");
            return null;
        }
        if (!IsValidCredential(password))
        {
            LogHelper.Debug($"[Hysteria2 节点丢弃] Password 无效: {password}");
            return null;
        }

        var hostParam = query.GetValueOrDefault("sni", uri.Host);
        if (!IsValidHost(hostParam))
        {
            LogHelper.Debug($"[Hysteria2 节点丢弃] SNI 无效: {hostParam}");
            return null;
        }

        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in query)
            extra[kv.Key] = kv.Value;

        bool skipCert = query.TryGetValue("insecure", out var val) &&
                        (val == "1" || val.Equals("true", StringComparison.OrdinalIgnoreCase)) ||
                        query.TryGetValue("skip-cert-verify", out val) &&
                        (val == "1" || val.Equals("true", StringComparison.OrdinalIgnoreCase));
        if (skipCert) extra["skip_cert_verify"] = "true";

        if (query.TryGetValue("obfs", out var obfs) && !string.IsNullOrEmpty(obfs))
        {
            extra["obfs"] = obfs;
            if (query.TryGetValue("obfs-password", out var obfsPass))
                extra["obfs_password"] = obfsPass;
        }

        if (query.TryGetValue("transport", out var transport) && !string.IsNullOrEmpty(transport))
            extra["transport_type"] = transport;

        var readOnlyExtra = extra.ToDictionary(k => k.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);

        return NodeInfo.Create(
            OriginalLink: uri.ToString(),
            Type: "hysteria2",
            Host: host,
            Port: port,
            HostParam: hostParam,
            Password: password,
            Security: "tls",
            ExtraParams: readOnlyExtra
        );
    }

    /// <summary>
    /// 解析 Tuic 协议链接
    /// 提前验证
    /// </summary>
    private static NodeInfo? ParseTuic( Uri uri )
    {
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port < 1 || uri.Port > 65535)
        {
            LogHelper.Debug($"[Tuic 节点丢弃] Host 或 Port 非法: {uri.Host}:{uri.Port}");
            return null;
        }

        var userInfo = uri.UserInfo.Split(':', 2);
        var userId = userInfo.Length > 0 ? userInfo[0] : null;
        var password = userInfo.Length > 1 ? userInfo[1] : null;

        if (!IsValidCredential(userId) || !IsValidCredential(password))
        {
            LogHelper.Debug($"[Tuic 节点丢弃] 凭据无效");
            return null;
        }

        return NodeInfo.Create(
            OriginalLink: uri.ToString(),
            Type: "tuic",
            Host: uri.Host,
            Port: uri.Port,
            UserId: userId,
            Password: password,
            ExtraParams: ParseQuery(uri.Query)
        );
    }

    /// <summary>
    /// 解析 WireGuard 协议链接
    /// </summary>
    private static NodeInfo? ParseWireGuard( Uri uri )
    {
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port < 1 || uri.Port > 65535)
            return null;

        var privateKey = uri.UserInfo;
        if (!IsValidCredential(privateKey))
            return null;

        return NodeInfo.Create(
            OriginalLink: uri.ToString(),
            Type: "wireguard",
            Host: uri.Host,
            Port: uri.Port,
            PrivateKey: privateKey,
            PublicKey: ParseQuery(uri.Query).GetValueOrDefault("publickey"),
            ExtraParams: ParseQuery(uri.Query)
        );
    }

    /// <summary>
    /// 解析 SOCKS5 协议链接
    /// </summary>
    private static NodeInfo? ParseSocks5( Uri uri )
    {
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port < 1 || uri.Port > 65535)
            return null;

        var userInfo = uri.UserInfo.Split(':', 2);
        var userId = userInfo.Length > 0 ? userInfo[0] : null;
        var password = userInfo.Length > 1 ? userInfo[1] : null;

        return NodeInfo.Create(
            OriginalLink: uri.ToString(),
            Type: "socks5",
            Host: uri.Host,
            Port: uri.Port,
            UserId: userId,
            Password: password,
            ExtraParams: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        );
    }
    #endregion

    #region 验证工具
    /// <summary>
    /// 验证凭据是否合法（非空、非纯空格、长度 ≤ 256）
    /// </summary>
    private static bool IsValidCredential( string? value )
    {
        return !string.IsNullOrWhiteSpace(value) && value.Length <= 256;
    }

    /// <summary>
    /// 验证 Host/SNI 是否合法（非空、非纯IP、长度合理）
    /// </summary>
    private static bool IsValidHost( string? value )
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253)
            return false;
        if (IPAddress.TryParse(value, out _))
            return false; // 禁止纯IP作为SNI
        return true;
    }
    #endregion

    #region 查询参数解析
    /// <summary>
    /// 解析 URL 查询字符串为不区分大小写的字典
    /// </summary>
    private static Dictionary<string, string> ParseQuery( string query )
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query)) return dict;

        var cleaned = query.TrimStart('?').Replace('+', ' ');

        foreach (var pair in cleaned.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length != 2) continue;

            string SafeDecode( string? raw )
            {
                if (string.IsNullOrEmpty(raw)) return string.Empty;
                var htmlDecoded = System.Net.WebUtility.HtmlDecode(raw);
                string once;
                try { once = Uri.UnescapeDataString(htmlDecoded); }
                catch { once = htmlDecoded; }
                if (once.Contains('%'))
                {
                    try { var twice = Uri.UnescapeDataString(once); if (!string.IsNullOrEmpty(twice)) return twice; } catch { }
                }
                return once;
            }

            var key = SafeDecode(parts[0]);
            var value = SafeDecode(parts[1]);
            if (!string.IsNullOrEmpty(key)) dict[key] = value;
        }

        return dict;
    }
    #endregion
}