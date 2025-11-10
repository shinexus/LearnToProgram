// ProtocolParser.cs
// 负责：从 vless://、trojan://、hysteria2:// 等协议链接中解析结构化字段
// 命名空间：HiddifyConfigsCLI.src.Parsing
// [Grok Rebuild] 2025-11-10_06：精简主流程，JSON 解析外包至 JsonOptsParser
// 说明：
//   - 仅负责 URI → 字典 基础解析
//   - ws-opts / grpc-opts / reality 等嵌套 JSON 由 JsonOptsParser 解析
//   - 所有注释已清理、补充、统一为中文详尽说明
using System.Net;
using System.Web;

namespace HiddifyConfigsCLI.src.Parsing;

/// <summary>
/// 协议链接解析器：将 vless://、trojan:// 等链接转为 NodeInfo 结构
/// </summary>
internal static class ProtocolParser
{
    /// <summary>
    /// 解析任意协议链接为 NodeInfo 结构
    /// </summary>
    /// <param name="link">完整协议链接（如 vless://...）</param>
    /// <returns>成功返回 NodeInfo，失败返回 null</returns>
    public static NodeInfo? Parse( string link )
    {
        try
        {
            var uri = new Uri(link, UriKind.Absolute);
            var scheme = uri.Scheme.ToLowerInvariant();

            return scheme switch
            {
                "vless" => ParseVless(uri),
                "trojan" => ParseTrojan(uri),
                "hysteria2" => ParseHysteria2(uri),
                "tuic" => ParseTuic(uri),
                "wireguard" => ParseWireGuard(uri),
                "socks5" => ParseSocks5(uri),
                _ => null
            };
        }
        catch (Exception ex) when (ex is UriFormatException or InvalidOperationException)
        {
            LogHelper.Debug($"[协议解析] 链接格式错误，已跳过: {link} | 错误: {ex.Message}");
            return null;
        }
    }

    #region VLESS 解析
    /// <summary>
    /// 解析 VLESS 协议链接
    /// 支持：Reality、XTLS-Vision、WS/gRPC、skip-cert-verify、early-data 等
    /// </summary>
    private static NodeInfo ParseVless( Uri uri )
    {
        // 1. 基础字段解析
        var query = ParseQuery(uri.Query ?? "");
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 443;

        // 2. SNI / Peer 优先级解析
        string? hostParam = null;
        if (query.TryGetValue("sni", out var sni)) hostParam = sni;
        else if (query.TryGetValue("peer", out var peer)) hostParam = peer;

        // 3. 加密与安全策略
        var encryption = query.GetValueOrDefault("encryption") ?? "none";
        var security = (query.GetValueOrDefault("security") ?? "none").ToLowerInvariant();

        // 4. skip-cert-verify 解析（兼容 allowInsecure=1）
        var skipCertVerify = query.GetValueOrDefault("allowInsecure") == "1" ||
                             query.GetValueOrDefault("skip-cert-verify") == "true";
        query["skip_cert_verify"] = skipCertVerify.ToString().ToLowerInvariant();

        // 5. 传输类型识别
        var transportType = query.GetValueOrDefault("type")?.ToLowerInvariant() ?? "";
        query["transport_type"] = transportType;

        // 6. 【关键】JSON 嵌套字段外包解析
        if (transportType == "ws") JsonOptsParser.ParseWsOpts(query);
        else if (transportType == "grpc") JsonOptsParser.ParseGrpcOpts(query);
        JsonOptsParser.ParseReality(query); // Reality 全局解析

        // 7. Flow 与 TLS 状态
        var flow = query.GetValueOrDefault("flow") ?? "";
        query["flow"] = flow;
        var isTls = security == "tls" || query.GetValueOrDefault("tls") == "tls";
        var isReality = security == "reality" || query.GetValueOrDefault("tls") == "reality";
        query["tls_enabled"] = (isTls || isReality).ToString().ToLowerInvariant();
        query["reality_enabled"] = isReality.ToString().ToLowerInvariant();

        // 8. uTLS 指纹
        var fp = query.GetValueOrDefault("fp") ?? query.GetValueOrDefault("fingerprint") ?? "";
        query["utls_fingerprint"] = fp;

        // 9. 返回只读字典
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
    /// </summary>
    private static NodeInfo ParseTrojan( Uri uri )
    {
        var host = uri.Host;
        var port = uri.Port;
        var query = ParseQuery(uri.Query);

        // 1. 用户名与密码解析
        string? userId = null, password = null;
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            var parts = uri.UserInfo.Split(':', 2);
            userId = parts[0];
            password = parts.Length > 1 ? parts[1] : null;

            // 修复：密码误含端口（如 :12345@host:12345）
            if (int.TryParse(password, out var parsedPort) && parsedPort == port)
            {
                LogHelper.Warn($"[Trojan 解析] 检测到密码包含端口 {parsedPort}，已修正为 null");
                password = null;
            }
        }

        // 2. SNI 优先级：sni > peer > ws_host > 兜底
        string? hostParam = null;
        if (query.TryGetValue("sni", out var sni)) hostParam = sni;
        else if (query.TryGetValue("peer", out var peer)) hostParam = peer;
        else if (query.TryGetValue("host", out var wsHost) && !IPAddress.TryParse(wsHost, out _))
        {
            hostParam = wsHost;
            LogHelper.Info($"[Trojan 解析] 使用 WS host 作为 SNI: {wsHost}");
        }

        // 3. 兜底 SNI（防止 HandshakeFailure）
        if (string.IsNullOrEmpty(hostParam) || IPAddress.TryParse(hostParam, out _))
        {
            hostParam = "www.cloudflare.com";
            LogHelper.Verbose($"[Trojan 解析] SNI 兜底为: {hostParam}");
        }

        var extraParams = query.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase);
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
            LogHelper.Debug($"[Trojan 节点丢弃] 参数无效: {ex.Message}");
            return null;
        }
    }
    #endregion

    #region 其他协议（简洁实现）
    /// <summary>
    /// 解析 Hysteria2 协议链接
    /// </summary>
    private static NodeInfo ParseHysteria2( Uri uri ) => NodeInfo.Create(
        OriginalLink: uri.ToString(),
        Type: "hysteria2",
        Host: uri.Host,
        Port: uri.Port > 0 ? uri.Port : 443,
        HostParam: ParseQuery(uri.Query).GetValueOrDefault("sni"),
        Security: "tls",
        ExtraParams: ParseQuery(uri.Query)
    );

    /// <summary>
    /// 解析 Tuic 协议链接
    /// </summary>
    private static NodeInfo ParseTuic( Uri uri )
    {
        var userInfo = uri.UserInfo.Split(':', 2);
        return NodeInfo.Create(
            OriginalLink: uri.ToString(),
            Type: "tuic",
            Host: uri.Host,
            Port: uri.Port,
            UserId: userInfo.Length > 0 ? userInfo[0] : null,
            Password: userInfo.Length > 1 ? userInfo[1] : null,
            ExtraParams: ParseQuery(uri.Query)
        );
    }

    /// <summary>
    /// 解析 WireGuard 协议链接
    /// </summary>
    private static NodeInfo ParseWireGuard( Uri uri ) => NodeInfo.Create(
        OriginalLink: uri.ToString(),
        Type: "wireguard",
        Host: uri.Host,
        Port: uri.Port,
        PrivateKey: uri.UserInfo,
        PublicKey: ParseQuery(uri.Query).GetValueOrDefault("publickey"),
        ExtraParams: ParseQuery(uri.Query)
    );

    /// <summary>
    /// 解析 SOCKS5 协议链接
    /// </summary>
    private static NodeInfo ParseSocks5( Uri uri )
    {
        var userInfo = uri.UserInfo.Split(':', 2);
        return NodeInfo.Create(
            OriginalLink: uri.ToString(),
            Type: "socks5",
            Host: uri.Host,
            Port: uri.Port,
            UserId: userInfo.Length > 0 ? userInfo[0] : null,
            Password: userInfo.Length > 1 ? userInfo[1] : null,
            ExtraParams: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        );
    }
    #endregion

    #region 查询参数解析
    /// <summary>
    /// 解析 URL 查询字符串为不区分大小写的字典
    /// 支持：+ 转空格、URL 解码、重复键取最后一个
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
            var key = Uri.UnescapeDataString(parts[0]);
            var value = Uri.UnescapeDataString(parts[1]);
            dict[key] = value; // 重复键覆盖
        }
        return dict;
    }
    #endregion
}