// JsonOptsParser.cs
// 负责：解析 ws-opts、grpc-opts、reality、utls、quic 等 JSON 嵌套字段
// 负责：解析 JSON 字符串配置（URL 参数中的 JSON 或完整 JSON 行）
// 命名空间：HiddifyConfigsCLI.src.Parsing
// [Grok 重构_2025-11-15_010] 内联版：校验前置、usedKeys.Add 提前、switch 表达式合法

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Text.Json;

namespace HiddifyConfigsCLI.src.Parsing;

internal static class JsonOptsParser
{
    //──────────────────────────────────────────────────────────────
    // 入口函数：解析 JSON（来自 ?json=xxx 或整行 JSON 配置）
    //──────────────────────────────────────────────────────────────
    public static void ParseJsonConfig( string json, Dictionary<string, string> query )
    {
        if (string.IsNullOrWhiteSpace(json))
            return;
        try
        {
            using var doc = JsonDocument.Parse(json);
            ExtractJsonElement("", doc.RootElement, query);
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[JSON 配置解析失败] {ex.Message} | 内容: {json}");
        }
    }

    //──────────────────────────────────────────────────────────────
    // JSON 递归提取：将所有字段扁平化写入 query（嵌套字段自动展开）
    //──────────────────────────────────────────────────────────────
    private static void ExtractJsonElement( string prefix, JsonElement element, Dictionary<string, string> query )
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                {
                    string childKey = string.IsNullOrEmpty(prefix)
                        ? prop.Name
                        : $"{prefix}_{prop.Name}";
                    ExtractJsonElement(childKey, prop.Value, query);
                }
                break;
            case JsonValueKind.Array:
                query[prefix] = element.ToString();
                break;
            case JsonValueKind.String:
                query[prefix] = element.GetString() ?? "";
                break;
            case JsonValueKind.Number:
                query[prefix] = element.GetRawText();
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
                query[prefix] = element.GetBoolean() ? "true" : "false";
                break;
            case JsonValueKind.Null:
                break;
        }
    }

    //──────────────────────────────────────────────────────────────
    // 子模块：WS 配置解析
    //──────────────────────────────────────────────────────────────
    public static void ParseWsOpts( Dictionary<string, string> query )
    {
        if (query.TryGetValue("ws_path", out var p))
            query["transport"] = "ws";
        if (query.TryGetValue("ws_headers_Host", out var host))
            query["ws_header_host"] = host;
    }

    //──────────────────────────────────────────────────────────────
    // 子模块：gRPC 配置解析
    //──────────────────────────────────────────────────────────────
    public static void ParseGrpcOpts( Dictionary<string, string> query )
    {
        if (query.TryGetValue("grpc_serviceName", out var svc))
            query["grpc_service"] = svc;
        if (query.TryGetValue("grpc_authority", out var authority))
            query["grpc_authority"] = authority;
    }

    //──────────────────────────────────────────────────────────────
    // 子模块：XHTTP 配置解析
    //──────────────────────────────────────────────────────────────
    public static void ParseXhttpOpts( Dictionary<string, string> query )
    {
        if (query.TryGetValue("xhttp_headers", out var h))
            query["xhttp_headers"] = h;
    }

    //──────────────────────────────────────────────────────────────
    // 子模块：Reality 解析
    //──────────────────────────────────────────────────────────────
    public static void ParseReality( Dictionary<string, string> query )
    {
        if (query.Keys.Any(k => k.StartsWith("reality_", StringComparison.OrdinalIgnoreCase)))
            query["reality_enabled"] = "true";
    }

    //──────────────────────────────────────────────────────────────
    // 主入口：解析单行 JSON 配置并返回具体 NodeInfo
    //──────────────────────────────────────────────────────────────
    /// <summary>
    /// 解析单行 JSON 配置并返回具体 NodeInfo 实例
    /// [Grok 重构_2025-11-15_010]：内联 new，校验前置，switch 表达式合法
    /// </summary>
    public static NodeInfoBase? ParseJsonLine( string jsonLine )
    {
        if (string.IsNullOrWhiteSpace(jsonLine))
            return null;

        try
        {
            // Step 1: 解析 JSON → query
            var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ParseJsonConfig(jsonLine, query);

            // Step 2: 提取核心字段 + 基础校验
            if (!query.TryGetValue("type", out var typeStr) || string.IsNullOrWhiteSpace(typeStr))
            {
                LogHelper.Debug("[ParseJsonLine] 缺失 type 字段");
                return null;
            }
            var type = typeStr.ToLowerInvariant();

            if (!query.TryGetValue("host", out var host) || string.IsNullOrWhiteSpace(host))
            {
                LogHelper.Debug("[ParseJsonLine] 缺失 host 字段");
                return null;
            }

            if (!query.TryGetValue("port", out var portStr) || !int.TryParse(portStr, out var port) || port < 1 || port > 65535)
            {
                LogHelper.Debug($"[ParseJsonLine] Port 非法: {portStr}");
                return null;
            }

            // Step 3: 提取通用字段
            query.TryGetValue("remark", out var remark);
            query.TryGetValue("sni", out var sni);
            query.TryGetValue("alpn", out var alpn);
            query.TryGetValue("fingerprint", out var fp);

            // Step 4: 初始化 usedKeys
            var usedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "type", "host", "port", "remark", "sni", "alpn", "fingerprint"
            };

            // Step 5: 不支持的 type 提前拦截（避免 switch 中使用 {}）
            if (type is not ("vless" or "trojan" or "hysteria2" or "tuic" or "wireguard" or "socks5"))
            {
                LogHelper.Debug($"[ParseJsonLine] 不支持的 type: {type}");
                return null;
            }

            // Step 6: 协议分支（内联 + 校验前置）
            return type switch
            {
                "vless" => BuildVlessNode(query, host, port, remark, sni, alpn, fp, usedKeys, jsonLine),
                "trojan" => BuildTrojanNode(query, host, port, remark, sni, alpn, fp, usedKeys, jsonLine),
                "hysteria2" => BuildHysteria2Node(query, host, port, remark, sni, usedKeys, jsonLine),
                "tuic" => BuildTuicNode(query, host, port, usedKeys, jsonLine),
                "wireguard" => BuildWireguardNode(query, host, port, usedKeys, jsonLine),
                "socks5" => BuildSocks5Node(query, host, port, usedKeys, jsonLine),
                _ => null // 防御性（不可能到达）
            };
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[ParseJsonLine 失败] {ex.Message} | 内容: {jsonLine}");
            return null;
        }
    }

    #region 内联节点构建方法（与 YmlOptsParser 完全一致）

    private static NodeInfoBase? BuildVlessNode(
        Dictionary<string, string> query, string host, int port, string? remark,
        string? sni, string? alpn, string? fp,
        HashSet<string> usedKeys, string originalLink )
    {
        query.TryGetValue("userId", out var userId);
        if (!string.IsNullOrWhiteSpace(userId)) usedKeys.Add("userId");

        query.TryGetValue("flow", out var flow);
        if (!string.IsNullOrWhiteSpace(flow)) usedKeys.Add("flow");

        var node = new VlessNode
        {
            OriginalLink = originalLink,
            Type = "vless",
            Host = host,
            Port = port,
            Remark = remark ?? "",
            HostParam = sni,
            Alpn = alpn,
            Fingerprint = fp,
            UserId = userId ?? "",
            Flow = flow ?? ""
        };

        node.ExtraParams = BuildExtraParams(query, usedKeys);
        return node;
    }

    private static NodeInfoBase? BuildTrojanNode(
        Dictionary<string, string> query, string host, int port, string? remark,
        string? sni, string? alpn, string? fp,
        HashSet<string> usedKeys, string originalLink )
    {
        if (!query.TryGetValue("password", out var password) || string.IsNullOrWhiteSpace(password))
        {
            LogHelper.Debug("[Trojan JSON] 缺失 password");
            return null;
        }
        usedKeys.Add("password");

        var node = new TrojanNode
        {
            OriginalLink = originalLink,
            Type = "trojan",
            Host = host,
            Port = port,
            Remark = remark ?? "",
            HostParam = sni,
            Alpn = alpn,
            Fingerprint = fp,
            Password = password
        };

        node.ExtraParams = BuildExtraParams(query, usedKeys);
        return node;
    }

    private static NodeInfoBase? BuildHysteria2Node(
        Dictionary<string, string> query, string host, int port, string? remark,
        string? sni, HashSet<string> usedKeys, string originalLink )
    {
        if (!query.TryGetValue("password", out var password) || string.IsNullOrWhiteSpace(password))
        {
            LogHelper.Debug("[Hysteria2 JSON] 缺失 password");
            return null;
        }
        usedKeys.Add("password");

        var node = new Hysteria2Node
        {
            OriginalLink = originalLink,
            Type = "hysteria2",
            Host = host,
            Port = port,
            Remark = remark ?? "",
            Password = password,
            HostParam = sni
        };

        if (query.TryGetValue("obfs", out var obfs) && !string.IsNullOrWhiteSpace(obfs))
        {
            node.Obfs = obfs;
            usedKeys.Add("obfs");
        }
        if (query.TryGetValue("obfs-password", out var op) && !string.IsNullOrWhiteSpace(op))
        {
            node.ObfsPassword = op;
            usedKeys.Add("obfs-password");
        }
        if (query.TryGetValue("up_mbps", out var upStr) && int.TryParse(upStr, out var up))
        {
            node.UpMbps = up;
            usedKeys.Add("up_mbps");
        }
        if (query.TryGetValue("down_mbps", out var downStr) && int.TryParse(downStr, out var down))
        {
            node.DownMbps = down;
            usedKeys.Add("down_mbps");
        }
        if (query.TryGetValue("disable_udp", out var du) &&
            (du == "1" || du.Equals("true", StringComparison.OrdinalIgnoreCase)))
        {
            node.DisableUdp = true;
            usedKeys.Add("disable_udp");
        }

        node.ExtraParams = BuildExtraParams(query, usedKeys);
        return node;
    }

    private static NodeInfoBase? BuildTuicNode(
        Dictionary<string, string> query, string host, int port,
        HashSet<string> usedKeys, string originalLink )
    {
        if (!query.TryGetValue("userId", out var userId) || string.IsNullOrWhiteSpace(userId))
        {
            LogHelper.Debug("[Tuic JSON] 缺失 userId");
            return null;
        }
        if (!query.TryGetValue("password", out var password) || string.IsNullOrWhiteSpace(password))
        {
            LogHelper.Debug("[Tuic JSON] 缺失 password");
            return null;
        }
        usedKeys.Add("userId");
        usedKeys.Add("password");

        var node = new TuicNode
        {
            OriginalLink = originalLink,
            Type = "tuic",
            Host = host,
            Port = port,
            UserId = userId,
            Password = password
        };

        node.ExtraParams = BuildExtraParams(query, usedKeys);
        return node;
    }

    private static NodeInfoBase? BuildWireguardNode(
        Dictionary<string, string> query, string host, int port,
        HashSet<string> usedKeys, string originalLink )
    {
        if (!query.TryGetValue("privateKey", out var privateKey) || string.IsNullOrWhiteSpace(privateKey))
        {
            LogHelper.Debug("[WireGuard JSON] 缺失 privateKey");
            return null;
        }
        usedKeys.Add("privateKey");

        var node = new WireguardNode
        {
            OriginalLink = originalLink,
            Type = "wireguard",
            Host = host,
            Port = port,
            PrivateKey = privateKey
        };

        node.ExtraParams = BuildExtraParams(query, usedKeys);
        return node;
    }

    private static NodeInfoBase? BuildSocks5Node(
        Dictionary<string, string> query, string host, int port,
        HashSet<string> usedKeys, string originalLink )
    {
        query.TryGetValue("userId", out var userId);
        if (!string.IsNullOrWhiteSpace(userId)) usedKeys.Add("userId");

        query.TryGetValue("password", out var password);
        if (!string.IsNullOrWhiteSpace(password)) usedKeys.Add("password");

        var node = new Socks5Node
        {
            OriginalLink = originalLink,
            Type = "socks5",
            Host = host,
            Port = port,
            Username = userId,
            Password = password
        };

        node.ExtraParams = BuildExtraParams(query, usedKeys);
        return node;
    }

    private static Dictionary<string, string> BuildExtraParams(
        Dictionary<string, string> query, HashSet<string> usedKeys )
    {
        var extra = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in query)
        {
            if (!usedKeys.Contains(kv.Key) && !string.IsNullOrEmpty(kv.Key))
            {
                extra[kv.Key] = kv.Value;
            }
        }
        return extra;
    }

    #endregion
}