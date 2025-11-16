// ProtocolParser.cs
// 负责：从 vless://、trojan://、hysteria2:// 等协议链接中解析结构化字段
// 命名空间：HiddifyConfigsCLI.src.Parsing
// [Grok Rebuild] 2025-11-12：全提前验证，零 try-catch，性能极致
// [ChatGPT Rebuild] Phase 3：自动识别 JSON/YAML/URL Query 并分发解析器
// 说明：
//   - 所有 NodeInfo.Create 前验证参数合法性
//   - 非法字段直接丢弃 + 详细日志
//   - JSON 嵌套字段外包至 JsonOptsParser，YAML 外包至 YmlOptsParser
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Parsing;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Web;

namespace HiddifyConfigsCLI.src.Parsing;

/// <summary>
/// 协议链接解析器：将 vless://、trojan:// 等链接转为 NodeInfo 结构
/// 本文件为 Phase3 重建版：
///  - 自动识别整行 JSON/YAML 并交给对应解析器（JsonOptsParser / YmlOptsParser）
///  - 对 URL 查询中嵌入 JSON/YAML 的情况进行解码并展开字段
///  - 返回 NodeInfo?（与现有检测链路兼容）
/// 修改处已用中文注释标注说明
/// </summary>
internal static class ProtocolParser
{
    /// <summary>
    /// 解析任意协议链接或整行配置为 NodeInfo 结构
    /// 支持输入形式：
    ///  - 完整协议 URL（如 vless://...）
    ///  - 整行 JSON（以 { 开头并以 } 结尾）
    ///  - 整行 YAML（以 --- 或 key: 开头等，做简单检测）
    /// </summary>
    /// <param name="lineOrLink">链接或整行配置文本</param>
    /// <returns>成功返回 NodeInfo，失败返回 null</returns>
    public static NodeInfoBase? Parse( string lineOrLink )
    {
        if (string.IsNullOrWhiteSpace(lineOrLink))
            return null;

        var trimmed = lineOrLink.Trim();

        // --------------------------
        // 1) 自动识别：整行 JSON
        // --------------------------
        // 【修改说明】新增对整行 JSON 的检测：如果整行是 JSON，就直接交给 JsonOptsParser.ParseJsonLine 处理。
        //            ParseJsonLine 会把 JSON 展开为字段并创建 NodeInfo（之前我们已实现该方法）
        if (trimmed.StartsWith("{") && trimmed.EndsWith("}"))
        {
            // 直接委托 JSON 行解析器；解析器负责详细日志与字段校验
            LogHelper.Verbose("[ProtocolParser] 识别到整行 JSON，交由 JsonOptsParser 解析");
            try
            {
                return JsonOptsParser.ParseJsonLine(trimmed);
            }
            catch (Exception ex)
            {
                LogHelper.Debug($"[ProtocolParser] Json 行解析失败: {ex.Message}");
                return null;
            }
        }

        // --------------------------
        // 2) 自动识别：整行 YAML（简单启发式）
        // --------------------------
        // 【修改说明】YAML 的识别为启发式：以 "---" 开头，或包含 ":" 且有换行、或以 "type:" 开头等
        if (trimmed.StartsWith("---") || trimmed.StartsWith("type:") || (trimmed.Contains("\n") && trimmed.Contains(":")))
        {
            LogHelper.Verbose("[ProtocolParser] 识别到整行 YAML，交由 YmlOptsParser 解析");
            try
            {
                return YmlOptsParser.ParseYmlLine(trimmed);
            }
            catch (Exception ex)
            {
                LogHelper.Debug($"[ProtocolParser] YAML 行解析失败: {ex.Message}");
                return null;
            }
        }

        // --------------------------
        // 3) 常规 URL 情况（如 vless://、trojan://、...）
        // --------------------------
        // 如果它是一个 URL（包含 scheme://），尝试用 Uri 解析（大部分链接为此类）
        try
        {
            // 如果是像 "vless://..." 或 "trojan://..." 的标准协议链接
            if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Scheme))
            {
                var scheme = uri.Scheme.ToLowerInvariant();

                // 特殊处理：Query 内可能包含 json=... / yaml=... 的情形
                // 如果包含 json= 则把 json 解码并交给 JsonOptsParser 展开后再继续解析（在 ParseVless / ParseTrojan 中使用）
                // 为兼容性我们把 ParseQuery 结果传到各个 ParseXxx 中，ParseXxx 内部会调用 JsonOptsParser / YmlOptsParser

                /**
                 * return scheme switch
                {
                    "vless" => ParseVless(uri),
                    "trojan" => ParseTrojan(uri),
                    "hysteria2" => ParseHysteria2(uri),
                    "tuic" => ParseTuic(uri),
                    "wireguard" => ParseWireGuard(uri),
                    "socks5" => ParseSocks5(uri),
                    // 若是未识别的 scheme，则尝试把 Query 当作 JSON/YAML 或以 http(s) 开头的远程配置
                    _ =>
                    {
                        LogHelper.Debug($"[ProtocolParser] 未知 scheme: {scheme}，已跳过");
                        return null;
                    }
                };
                 * 
                 */
                return scheme switch
                {
                    "vless" => ParseVless(uri),
                    "trojan" => ParseTrojan(uri),
                    "hysteria2" => ParseHysteria2(uri),
                    "tuic" => ParseTuic(uri),
                    "wireguard" => ParseWireGuard(uri),
                    "socks5" => ParseSocks5(uri),
                    _ => HandleUnknownScheme(scheme) // 调用处理未知 scheme 的函数
                };

            }
            else
            {
                // 既不是整行 JSON/YAML，也不能作为绝对 Uri 解析 —— 可能是裸的 base64 / vless://base64 等（DoParse 应该已处理）
                LogHelper.Debug($"[ProtocolParser] 非 URL 且非 JSON/YAML 行，跳过: {trimmed[..Math.Min(80, trimmed.Length)]}...");
                return null;
            }
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[ProtocolParser] 解析失败: {ex.Message}");
            return null;
        }
    }

    // 单独处理未知 scheme 的函数
    private static NodeInfoBase? HandleUnknownScheme( string scheme )
    {
        LogHelper.Debug($"[ProtocolParser] 未知 scheme: {scheme}，已跳过");
        return null; // 返回 null，避免多行大括号
    }

    // ============================================================
    // 以下为各协议解析实现（基于你之前的 ParseVless/ParseTrojan 等）
    // 修改说明：内部会调用 ParseQuery(uri.Query)，并额外处理 query 中嵌入的 json= / yaml= 字段（解码并展开）
    // ============================================================

    #region VLESS 解析
    private static NodeInfoBase? ParseVless( Uri uri )
    {
        // 解析 query（含 HTML / 双重 URL 解码）
        var query = ParseQuery(uri.Query ?? "");

        // ------------ 新增：如果 query 中有 json 或 yaml 字段，则展开并合并到 query 中 --------------
        if (query.TryGetValue("json", out var jsonRaw) && !string.IsNullOrWhiteSpace(jsonRaw))
        {
            JsonOptsParser.ParseJsonConfig(jsonRaw, query);
        }
        if (query.TryGetValue("yaml", out var yamlRaw) && !string.IsNullOrWhiteSpace(yamlRaw))
        {
            YmlOptsParser.ParseYamlConfig(yamlRaw, query);
        }

        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 443;

        // Host 不能为空
        if (string.IsNullOrWhiteSpace(host))
        {
            LogHelper.Debug($"[VLESS 节点丢弃] Host 为空: {uri}");
            return null;
        }
        // Port 范围
        if (port < 1 || port > 65535)
        {
            LogHelper.Debug($"[VLESS 节点丢弃] Port 非法: {port}");
            return null;
        }

        // [Grok 修复_2025-11-16_005] 提取 uri.UserInfo 中的 UUID
        string userId = "";
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            var parts = uri.UserInfo.Split('@');
            userId = parts[0]; // 第一个 @ 前为 UUID
            if (!Guid.TryParse(userId, out _))
            {
                LogHelper.Warn($"[VLESS] UUID 格式错误: {userId} | 链接: {uri}");
                userId = "";
            }
        }

        // 备选 UUID：query["id"] 或 query["userId"]
        if (string.IsNullOrEmpty(userId))
        {
            userId = query.GetValueOrDefault("id") ?? query.GetValueOrDefault("userId") ?? "";
        }

        // [Grok 修复] 提取 #remark
        string remark = uri.Fragment.TrimStart('#');
        if (string.IsNullOrEmpty(remark) && uri.UserInfo.Contains('@'))
        {
            // 兼容 vless://UUID@remark@host:port
            var parts = uri.UserInfo.Split('@');
            if (parts.Length > 1) remark = parts[1];
        }

        // 2. SNI / Peer 优先级解析
        string? hostParam = null;
        if (query.TryGetValue("sni", out var sni) && IsValidHost(sni)) hostParam = sni;
        else if (query.TryGetValue("peer", out var peer) && IsValidHost(peer)) hostParam = peer;

        // 3. 加密与安全策略
        var encryption = query.GetValueOrDefault("encryption") ?? "none";
        var security = (query.GetValueOrDefault("security") ?? "none").ToLowerInvariant();

        // 4. skip-cert-verify 解析
        var skipCertVerify = query.GetValueOrDefault("allowInsecure") == "1" ||
                             query.GetValueOrDefault("skip-cert-verify") == "true";
        query["skip_cert_verify"] = skipCertVerify.ToString().ToLowerInvariant();

        // 5. 传输类型识别
        var transportType = query.GetValueOrDefault("type")?.ToLowerInvariant()
                            ?? query.GetValueOrDefault("transport")?.ToLowerInvariant() ?? "";
        query["transport_type"] = transportType;

        // 6. JSON/YAML 嵌套字段外包解析
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
                        query.ContainsKey("pbk") || query.ContainsKey("reality_public_key") || query.ContainsKey("reality_short_id");
        query["tls_enabled"] = (isTls || isReality).ToString().ToLowerInvariant();
        query["reality_enabled"] = isReality.ToString().ToLowerInvariant();

        var fp = query.GetValueOrDefault("fp")
                 ?? query.GetValueOrDefault("fingerprint")
                 ?? query.GetValueOrDefault("utls.fingerprint")
                 ?? query.GetValueOrDefault("utls_fingerprint")
                 ?? "";
        if (!string.IsNullOrEmpty(fp))
            query["utls_fingerprint"] = fp;

        // 9. 规范化安全参数
        if (query.TryGetValue("early_data_header_name", out var edh) && !string.IsNullOrEmpty(edh))
            query["early_data_header_name"] = edh;
        if (query.TryGetValue("packet_encoding", out var pe) && !string.IsNullOrEmpty(pe))
            query["packet_encoding"] = pe;
        if (query.TryGetValue("grpc.service", out var gsvc) && !string.IsNullOrEmpty(gsvc))
            query["grpc_service"] = gsvc;
        if (query.TryGetValue("ws.max_early_data", out var med) && !string.IsNullOrEmpty(med))
            query["ws_max_early_data"] = med;

        // 增强 VLESS 字段映射
        if (query.TryGetValue("transport_path", out var path) && !string.IsNullOrEmpty(path))
            query["ws_path"] = Uri.UnescapeDataString(path);
        if (query.TryGetValue("transport_headers_Host", out var wsHost) && !string.IsNullOrEmpty(wsHost))
            query["ws_header_host"] = wsHost;
        if (query.TryGetValue("transport_early_data_header_name", out var edhn) && !string.IsNullOrEmpty(edhn))
            query["early_data_header_name"] = edhn;
        if (query.TryGetValue("tls_utls_fingerprint", out var utlsFp) && !string.IsNullOrEmpty(utlsFp))
            query["fingerprint"] = utlsFp;

        var readOnlyExtra = query.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase);

        return new VlessNode
        {
            OriginalLink = uri.ToString(),
            Type = "vless",
            Host = host,
            Port = port,
            Remark = remark, // [Grok 新增] 从 # 或 UserInfo 提取
            Security = security,
            HostParam = hostParam ?? host,
            Fingerprint = query.GetValueOrDefault("utls_fingerprint"),
            Alpn = query.TryGetValue("alpn", out var alpn) ? alpn : null,
            PublicKey = query.GetValueOrDefault("reality_public_key"),
            ShortId = query.GetValueOrDefault("reality_short_id"),
            SpiderX = spx,
            UserId = userId, // [Grok 修复] 优先 uri.UserInfo
            Flow = flow,
            Path = query.GetValueOrDefault("ws_path"),
            HostHeader = query.GetValueOrDefault("ws_header_host"),
            MaxEarlyData = query.TryGetValue("ws_max_early_data", out var medStr) && int.TryParse(medStr, out var medVal) ? medVal : null,
            EarlyDataHeaderName = query.GetValueOrDefault("early_data_header_name"),
            GrpcServiceName = query.GetValueOrDefault("grpc_service"),
            QuicSecurity = query.GetValueOrDefault("quic_security"),
            QuicKey = query.GetValueOrDefault("quic_key"),
            ExtraParams = readOnlyExtra
        };
    }
    #endregion

    #region Trojan 解析
    private static NodeInfoBase? ParseTrojan( Uri uri )
    {
        // 局部 SafeDecode 保留（同你之前的实现）
        static string SafeDecode( string? raw )
        {
            if (string.IsNullOrEmpty(raw)) return string.Empty;
            var htmlDecoded = System.Net.WebUtility.HtmlDecode(raw);
            string once;
            try { once = Uri.UnescapeDataString(htmlDecoded); }
            catch { once = htmlDecoded; }
            if (once.Contains('%'))
            {
                try
                {
                    var twice = Uri.UnescapeDataString(once);
                    if (!string.IsNullOrEmpty(twice)) return twice;
                }
                catch { }
            }
            return once;
        }

        var host = uri.Host;
        var port = uri.Port;

        if (string.IsNullOrWhiteSpace(host) || port < 1 || port > 65535)
        {
            LogHelper.Debug($"[Trojan 节点丢弃] Host 或 Port 非法: {host}:{port}");
            return null;
        }

        // 解析并解码 query
        var decodedQueryString = SafeDecode(uri.Query ?? string.Empty);
        var query = ParseQuery(decodedQueryString);

        // 若 query 中嵌入 json/yaml，则展开合并
        if (query.TryGetValue("json", out var jr) && !string.IsNullOrEmpty(jr)) JsonOptsParser.ParseJsonConfig(jr, query);
        if (query.TryGetValue("yaml", out var yr) && !string.IsNullOrEmpty(yr)) YmlOptsParser.ParseYamlConfig(yr, query);

        // 用户凭据解析（userinfo）
        string? userId = null;
        string? password = null;
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            var decodedUserInfo = SafeDecode(uri.UserInfo);
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
                    userId = null;
                    password = decodedUserInfo;
                }
            }
            else
            {
                userId = null;
                password = decodedUserInfo;
            }

            if (!string.IsNullOrEmpty(password))
            {
                var p = password;
                if (p.Contains("🔒") || p.IndexOf("By ", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    LogHelper.Warn($"[Trojan 解析] 检测到被屏蔽/占位的密码（或非法占位符），已忽略: {host}:{port}");
                    password = null;
                }
            }

            if (!string.IsNullOrEmpty(password) && int.TryParse(password, out var parsedPort) && parsedPort == port)
            {
                LogHelper.Warn($"[Trojan 解析] 检测到密码包含端口 {parsedPort}，已修正为 null");
                password = null;
            }
        }

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

        // SNI 优先级：sni > peer > host（ws host）
        string? hostParam = null;
        static string? GetQueryDecoded( Dictionary<string, string> q, string key )
        {
            if (q.TryGetValue(key, out var v)) return string.IsNullOrEmpty(v) ? null : v;
            return null;
        }
        string? TryUseSni( string? raw )
        {
            if (string.IsNullOrEmpty(raw)) return null;
            var decoded = SafeDecode(raw);
            if (decoded.Contains("🔒") || decoded.IndexOf("By ", StringComparison.OrdinalIgnoreCase) >= 0)
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

        if (string.IsNullOrEmpty(hostParam) && query.TryGetValue("host", out var wsHostRaw))
        {
            var wsHostDecoded = TryUseSni(wsHostRaw);
            if (!string.IsNullOrEmpty(wsHostDecoded) && IsValidHost(wsHostDecoded))
            {
                hostParam = wsHostDecoded;
                LogHelper.Info($"[Trojan 解析] 使用 WS host 作为 SNI: {wsHostDecoded}");
            }
        }

        if (string.IsNullOrEmpty(hostParam) || !IsValidHost(hostParam))
        {
            hostParam = "www.cloudflare.com";
            LogHelper.Verbose($"[Trojan 解析] SNI 兜底为: {hostParam}");
        }

        // safeQuery：解码后并归一化到字典
        var safeQuery = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in query)
        {
            if (kvp.Key == null) continue;
            var k = SafeDecode(kvp.Key);
            var v = SafeDecode(kvp.Value);
            if (!string.IsNullOrEmpty(k))
            {
                safeQuery[k] = v;
            }
        }

        // 最终 ExtraParams
        var extraParams = safeQuery.ToDictionary(kvp => kvp.Key, kvp => kvp.Value, StringComparer.OrdinalIgnoreCase);

        try
        {
            return new TrojanNode
            {
                OriginalLink = uri.ToString(),      // Trojan 原始链接
                Type = "trojan",                    // 协议类型
                Host = host,                        // 主机地址
                Port = port,                        // 端口号
                HostParam = hostParam,              // SNI / Peer（可选）
                Encryption = "none",                // 加密方式（设置为 "none"）
                Security = "tls",                   // 安全协议（默认为 "tls"）
                UserId = userId ?? "",              // 用户标识（可能为空）
                Password = password ?? "",          // 密码（可能为空）
                                                    // 这里的 ExtraParams 用于存储其他查询参数，提供更多自定义支持
                ExtraParams = extraParams,          // 额外的参数集合
                Fingerprint = query.GetValueOrDefault("fingerprint"),  // utls_fingerprint（可选）
                Alpn = query.GetValueOrDefault("alpn"), // ALPN 协议（可选）
                Path = query.GetValueOrDefault("path"), // WebSocket 路径（可选）
                HostHeader = query.GetValueOrDefault("ws_host"), // WebSocket HostHeader（可选）
                MaxEarlyData = query.TryGetValue("ws_max_early_data", out var med) && int.TryParse(med, out var maxData) ? maxData : null, // 最大提前数据（可选）
                EarlyDataHeaderName = query.GetValueOrDefault("early_data_header_name"), // HTTP 早期数据头名称（可选）
                GrpcServiceName = query.GetValueOrDefault("grpc_service"), // gRPC 服务名称（可选）
                PacketEncoding = query.GetValueOrDefault("packet_encoding") // 数据包编码（可选）
            };
        }
        catch (ArgumentException ex)
        {
            LogHelper.Debug($"[Trojan 解析] NodeInfo 创建失败: {ex.Message} | 原链: {uri}");
            return null;
        }
    }
    #endregion


    #region Hysteria2 解析（完整修复版）
    /// <summary>
    /// 解析 hysteria2:// 协议链接
    /// 支持：query 中嵌入 json= / yaml=、insecure/skip-cert-verify、obfs、带宽限制等
    /// </summary>
    private static NodeInfoBase? ParseHysteria2( Uri uri )
    {
        // [Grok 修复_2025-11-15_005] 
        // 目标：零字段重复、强类型优先、ExtraParams 仅存未知字段
        // 流程：1. 解析 query → 2. 展开 json/yaml → 3. 提取强类型字段并移除 → 4. 剩余进 ExtraParams

        // --------------------- 1. 基础解析 ---------------------
        var query = ParseQuery(uri.Query ?? "");

        // --------------------- 2. 展开嵌套 JSON/YAML ---------------------
        // 支持 ?json={...} 或 ?yaml=... 嵌入完整配置
        if (query.TryGetValue("json", out var jsonRaw) && !string.IsNullOrWhiteSpace(jsonRaw))
        {
            JsonOptsParser.ParseJsonConfig(jsonRaw, query);
            query.Remove("json"); // 展开后移除原字段
        }
        if (query.TryGetValue("yaml", out var yamlRaw) && !string.IsNullOrWhiteSpace(yamlRaw))
        {
            YmlOptsParser.ParseYamlConfig(yamlRaw, query);
            query.Remove("yaml");
        }

        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 443;
        var password = uri.UserInfo;

        // --------------------- 3. 基础校验 ---------------------
        if (string.IsNullOrWhiteSpace(host) || port < 1 || port > 65535)
        {
            LogHelper.Debug($"[Hysteria2 节点丢弃] Host 或 Port 非法: {host}:{port}");
            return null;
        }
        if (!IsValidCredential(password))
        {
            LogHelper.Debug($"[Hysteria2 节点丢弃] Password 无效或缺失: {password}");
            return null;
        }

        // --------------------- 4. SNI 提取（优先 sni > host） ---------------------
        string? hostParam = null;
        if (query.TryGetValue("sni", out var sniVal) && IsValidHost(sniVal))
        {
            hostParam = sniVal;
            query.Remove("sni");
        }
        else
        {
            hostParam = host; // 兜底使用 Host
        }

        // --------------------- 5. 强类型字段提取（并从 query 移除） ---------------------
        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Obfs
        string? obfs = null;
        if (query.TryGetValue("obfs", out var obfsVal) && !string.IsNullOrWhiteSpace(obfsVal))
        {
            obfs = obfsVal;
            query.Remove("obfs");
        }
        string? obfsPassword = null;
        if (query.TryGetValue("obfs-password", out var opVal) && !string.IsNullOrWhiteSpace(opVal))
        {
            obfsPassword = opVal;
            query.Remove("obfs-password");
        }

        // 带宽限制
        int? upMbps = null;
        if (query.TryGetValue("up_mbps", out var upStr) && int.TryParse(upStr, out var up))
        {
            upMbps = up;
            query.Remove("up_mbps");
        }
        int? downMbps = null;
        if (query.TryGetValue("down_mbps", out var downStr) && int.TryParse(downStr, out var down))
        {
            downMbps = down;
            query.Remove("down_mbps");
        }

        // 禁用 UDP
        bool? disableUdp = null;
        if (query.TryGetValue("disable_udp", out var duStr) &&
            (duStr == "1" || duStr.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            disableUdp = true;
            query.Remove("disable_udp");
        }

        // ALPN
        string? alpn = null;
        if (query.TryGetValue("alpn", out var alpnVal) && !string.IsNullOrWhiteSpace(alpnVal))
        {
            alpn = alpnVal;
            query.Remove("alpn");
        }

        // uTLS 指纹
        string? fingerprint = null;
        if (query.TryGetValue("fingerprint", out var fpVal) && !string.IsNullOrWhiteSpace(fpVal))
        {
            fingerprint = fpVal;
            query.Remove("fingerprint");
        }

        // 跳过证书验证
        bool skipCertVerify = false;
        if (query.TryGetValue("insecure", out var insecureVal) &&
            (insecureVal == "1" || insecureVal.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            skipCertVerify = true;
            query.Remove("insecure");
        }
        if (query.TryGetValue("skip-cert-verify", out var scvVal) &&
            (scvVal == "1" || scvVal.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            skipCertVerify = true;
            query.Remove("skip-cert-verify");
        }

        // 传输类型
        string? transportType = "udp";
        if (query.TryGetValue("transport", out var transVal) && !string.IsNullOrWhiteSpace(transVal))
        {
            transportType = transVal;
            query.Remove("transport");
        }

        // --------------------- 6. 剩余字段进入 ExtraParams ---------------------
        foreach (var kvp in query)
        {
            if (!string.IsNullOrEmpty(kvp.Key))
            {
                extra[kvp.Key] = kvp.Value;
            }
        }

        // --------------------- 7. 创建节点（强类型 + 扩展） ---------------------
        try
        {
            return new Hysteria2Node
            {
                // ── 基类字段 ──
                OriginalLink = uri.ToString(),
                Type = "hysteria2",
                Host = host,
                Port = port,
                Remark = string.Empty,
                Transport = transportType ?? "udp",

                // ── 认证 ──
                Password = password,

                // ── TLS ──
                HostParam = hostParam, // SNI
                SkipCertVerify = skipCertVerify,
                Alpn = alpn,
                Fingerprint = fingerprint,

                // ── 混淌 ──
                Obfs = obfs,
                ObfsPassword = obfsPassword,

                // ── 带宽 ──
                UpMbps = upMbps,
                DownMbps = downMbps,

                // ── 传输控制 ──
                DisableUdp = disableUdp,

                // ── 扩展字段（仅未知）──
                ExtraParams = extra
            };
        }
        catch (Exception ex) when (ex is ArgumentException || ex is NullReferenceException)
        {
            LogHelper.Debug($"[Hysteria2 解析] 创建节点失败: {ex.Message} | 原链: {uri}");
            return null;
        }
    }
    #endregion

    #region 其它协议（保留原实现风格，做少量增强）
    private static NodeInfoBase? ParseTuic( Uri uri )
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

        return new TuicNode
        {
            OriginalLink = uri.ToString(),
            Type = "tuic",
            Host = uri.Host,
            Port = uri.Port,
            UserId = userId,
            Password = password,
            ExtraParams = ParseQuery(uri.Query)
        };
    }

    private static NodeInfoBase? ParseWireGuard( Uri uri )
    {
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port < 1 || uri.Port > 65535)
            return null;

        var privateKey = uri.UserInfo;
        if (!IsValidCredential(privateKey))
            return null;

        return new WireguardNode
        {
            OriginalLink = uri.ToString(),
            Type = "wireguard",
            Host = uri.Host,
            Port = uri.Port,
            PrivateKey = privateKey,
            PublicKey = ParseQuery(uri.Query).GetValueOrDefault("publickey"),
            ExtraParams = ParseQuery(uri.Query)
        };
    }

    private static NodeInfoBase? ParseSocks5( Uri uri )
    {
        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port < 1 || uri.Port > 65535)
            return null;

        var userInfo = uri.UserInfo.Split(':', 2);
        var userId = userInfo.Length > 0 ? userInfo[0] : null;
        var password = userInfo.Length > 1 ? userInfo[1] : null;

        return new Socks5Node
        {
            OriginalLink = uri.ToString(),
            Type = "socks5",
            Host = uri.Host,
            Port = uri.Port,
            Username = userId,
            Password = password,
            ExtraParams = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };
    }
    #endregion

    #region 验证工具（复用/保留）
    private static bool IsValidCredential( string? value )
        => !string.IsNullOrWhiteSpace(value) && value.Length <= 256;

    private static bool IsValidHost( string? value )
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253) return false;
        if (IPAddress.TryParse(value, out _)) return false; // 禁止纯 IP 作为 SNI
        return true;
    }
    #endregion

    #region 查询参数解析（复用原 ParseQuery，保持 HTML + 双重 URL 解码）
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
                    try
                    {
                        var twice = Uri.UnescapeDataString(once);
                        if (!string.IsNullOrEmpty(twice)) return twice;
                    }
                    catch { }
                }
                return once;
            }

            var key = SafeDecode(parts[0]);
            var value = SafeDecode(parts[1]);
            if (!string.IsNullOrEmpty(key))
            {
                dict[key] = value;
            }
        }

        return dict;
    }
    #endregion
}
