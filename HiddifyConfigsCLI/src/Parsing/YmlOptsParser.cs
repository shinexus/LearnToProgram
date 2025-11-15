// YmlOptsParser.cs
// 负责：解析 YAML 格式配置内容，展开嵌套字段并写入 query 字典
// 与 JsonOptsParser 保持完全一致的结构与行为
// [Grok 重构_2025-11-15_008] 内联版：所有协议直接 new + 对象初始化器，校验前置，usedKeys.Add 提前

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Text;
using YamlDotNet.RepresentationModel;

namespace HiddifyConfigsCLI.src.Parsing;

internal static class YmlOptsParser
{
    //──────────────────────────────────────────────────────────────
    // 入口：解析 YAML 字符串为扁平化字典（写入 query）
    //──────────────────────────────────────────────────────────────
    public static void ParseYamlConfig( string yamlContent, Dictionary<string, string> query )
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
            return;
        try
        {
            var yaml = new YamlStream();
            yaml.Load(new StringReader(yamlContent));
            var root = yaml.Documents[0].RootNode;
            ExtractYamlNode("", root, query);
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[YAML 解析失败] {ex.Message} | 内容: {yamlContent}");
        }
    }

    //──────────────────────────────────────────────────────────────
    // 核心：递归提取 YAML 节点，展开并写入 query 字典
    //──────────────────────────────────────────────────────────────
    private static void ExtractYamlNode( string prefix, YamlNode node, Dictionary<string, string> query )
    {
        switch (node)
        {
            case YamlMappingNode map:
                foreach (var kv in map.Children)
                {
                    var key = ((YamlScalarNode)kv.Key).Value ?? "";
                    string childKey = string.IsNullOrEmpty(prefix)
                        ? key
                        : $"{prefix}_{key}";
                    ExtractYamlNode(childKey, kv.Value, query);
                }
                break;
            case YamlSequenceNode seq:
                // YAML 数组序列化成 JSON-like 字符串保存
                var items = seq.Children
                    .Select(x => x is YamlScalarNode s ? s.Value ?? "" : x.ToString())
                    .ToArray();
                query[prefix] = "[" + string.Join(",", items.Select(EscapeValue)) + "]";
                break;
            case YamlScalarNode scalar:
                query[prefix] = scalar.Value ?? "";
                break;
        }
    }

    private static string EscapeValue( string v )
        => v.Contains('"') ? v.Replace("\"", "\\\"") : v;

    //──────────────────────────────────────────────────────────────
    // WS 配置标准化（兼容 WS-OPTS）
    //──────────────────────────────────────────────────────────────
    public static void ParseWsOpts( Dictionary<string, string> query )
    {
        if (query.TryGetValue("ws_path", out var path))
            query["transport"] = "ws";
        if (query.TryGetValue("ws_headers_Host", out var host))
            query["ws_header_host"] = host;
    }

    //──────────────────────────────────────────────────────────────
    // gRPC 配置标准化
    //──────────────────────────────────────────────────────────────
    public static void ParseGrpcOpts( Dictionary<string, string> query )
    {
        if (query.TryGetValue("grpc_serviceName", out var svc))
            query["grpc_service"] = svc;
        if (query.TryGetValue("grpc_authority", out var authority))
            query["grpc_authority"] = authority;
    }

    //──────────────────────────────────────────────────────────────
    // XHTTP 配置
    //──────────────────────────────────────────────────────────────
    public static void ParseXhttpOpts( Dictionary<string, string> query )
    {
        if (query.TryGetValue("xhttp_headers", out var h))
            query["xhttp_headers"] = h;
    }

    //──────────────────────────────────────────────────────────────
    // Reality 配置（是否存在 reality_xxx 字段）
    //──────────────────────────────────────────────────────────────
    public static void ParseReality( Dictionary<string, string> query )
    {
        if (query.Keys.Any(k => k.StartsWith("reality_", StringComparison.OrdinalIgnoreCase)))
            query["reality_enabled"] = "true";
    }

    //──────────────────────────────────────────────────────────────
    // 主入口：解析单行 YAML 配置并返回具体 NodeInfo
    //──────────────────────────────────────────────────────────────
    /// <summary>
    /// 解析单行 YAML 配置并返回具体 NodeInfo 实例
    /// 支持：type=vless/trojan/hysteria2/tuic/wireguard/socks5
    /// [Grok 重构_2025-11-15_008]：内联 new，校验前置，usedKeys.Add 提前
    /// </summary>
    public static NodeInfoBase? ParseYmlLine( string ymlLine )
    {
        if (string.IsNullOrWhiteSpace(ymlLine))
            return null;

        try
        {
            // Step 1: 解析 YAML → query
            var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ParseYamlConfig(ymlLine, query);

            // Step 2: 提取核心字段 + 基础校验
            if (!query.TryGetValue("type", out var typeStr) || string.IsNullOrWhiteSpace(typeStr))
            {
                LogHelper.Debug("[ParseYmlLine] 缺失 type 字段");
                return null;
            }
            var type = typeStr.ToLowerInvariant();

            if (!query.TryGetValue("host", out var host) || string.IsNullOrWhiteSpace(host))
            {
                LogHelper.Debug("[ParseYmlLine] 缺失 host 字段");
                return null;
            }

            if (!query.TryGetValue("port", out var portStr) || !int.TryParse(portStr, out var port) || port < 1 || port > 65535)
            {
                LogHelper.Debug($"[ParseYmlLine] Port 非法: {portStr}");
                return null;
            }

            // Step 3: 提取通用字段
            query.TryGetValue("remark", out var remark);
            query.TryGetValue("sni", out var sni);
            query.TryGetValue("alpn", out var alpn);
            query.TryGetValue("fingerprint", out var fp);

            // Step 4: 初始化 usedKeys（防止 ExtraParams 重复）
            var usedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "type", "host", "port", "remark", "sni", "alpn", "fingerprint"
            };

            // Step 5: 协议分支 + 校验前置 + usedKeys.Add 提前
            if (type is not ("vless" or "trojan" or "hysteria2" or "tuic" or "wireguard" or "socks5"))
            {
                LogHelper.Debug($"[ParseYmlLine] 不支持的 type: {type}");
                return null;
            }

            return type switch
            {
                "vless" => BuildVlessNode(query, host, port, remark, sni, alpn, fp, usedKeys, ymlLine),
                "trojan" => BuildTrojanNode(query, host, port, remark, sni, alpn, fp, usedKeys, ymlLine),
                "hysteria2" => BuildHysteria2Node(query, host, port, remark, sni, usedKeys, ymlLine),
                "tuic" => BuildTuicNode(query, host, port, usedKeys, ymlLine),
                "wireguard" => BuildWireguardNode(query, host, port, usedKeys, ymlLine),
                "socks5" => BuildSocks5Node(query, host, port, usedKeys, ymlLine),
                _ => null // 防御性
            };
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[ParseYmlLine 失败] {ex.Message} | 内容: {ymlLine}");
            return null;
        }
    }

    #region 内联节点构建方法（校验前置 + usedKeys.Add 提前）

    public static NodeInfoBase? BuildVlessNode(
        Dictionary<string, string> query, string host, int port, string? remark,
        string? sni, string? alpn, string? fp,
        HashSet<string> usedKeys, string originalLink )
    {
        // 校验 userId（可选，但若存在则记录）
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
        // 校验 password（必填）
        if (!query.TryGetValue("password", out var password) || string.IsNullOrWhiteSpace(password))
        {
            LogHelper.Debug("[Trojan YAML] 缺失 password");
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
        // 校验 password（必填）
        if (!query.TryGetValue("password", out var password) || string.IsNullOrWhiteSpace(password))
        {
            LogHelper.Debug("[Hysteria2 YAML] 缺失 password");
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

        // Hysteria2 专用字段（可选）
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
        // 校验 userId + password（必填）
        if (!query.TryGetValue("userId", out var userId) || string.IsNullOrWhiteSpace(userId))
        {
            LogHelper.Debug("[Tuic YAML] 缺失 userId");
            return null;
        }
        if (!query.TryGetValue("password", out var password) || string.IsNullOrWhiteSpace(password))
        {
            LogHelper.Debug("[Tuic YAML] 缺失 password");
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
        // 校验 privateKey（必填）
        if (!query.TryGetValue("privateKey", out var privateKey) || string.IsNullOrWhiteSpace(privateKey))
        {
            LogHelper.Debug("[WireGuard YAML] 缺失 privateKey");
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
        // userId / password 可选
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

    /// <summary>
    /// 构建 ExtraParams：仅包含未使用的字段
    /// </summary>
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

    // 单独处理未知 scheme 的函数
    private static NodeInfoBase? HandleUnknownScheme( string scheme )
    {
        // LogHelper.Debug($"[ParseYmlLine] 不支持的 type: {type}");
        // return null;
        LogHelper.Debug($"[ParseYmlLine] 未知 scheme: {scheme}，已跳过");
        return null; // 返回 null，避免多行大括号
    }
}