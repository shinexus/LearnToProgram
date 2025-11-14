// YmlOptsParser.cs
// 负责：解析 YAML 格式配置内容，展开嵌套字段并写入 query 字典
// 与 JsonOptsParser 保持完全一致的结构与行为
// [ChatGPT Rebuild] 2025-11-14

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

    /// <summary>
    /// 解析单行 YAML 配置并返回 NodeInfo
    /// </summary>
    /// <param name="ymlLine">完整 YAML 配置行</param>
    /// <returns>成功返回 NodeInfo，失败返回 null</returns>
    public static NodeInfo? ParseYmlLine( string ymlLine )
    {
        if (string.IsNullOrWhiteSpace(ymlLine))
            return null;

        try
        {
            // 临时 query 字典，用于扁平化字段
            var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ParseYamlConfig(ymlLine, query);

            // 提取 NodeInfo 主字段
            query.TryGetValue("type", out var type);
            query.TryGetValue("host", out var host);
            int port = query.TryGetValue("port", out var portStr) && int.TryParse(portStr, out var p) ? p : 0;
            query.TryGetValue("userId", out var userId);
            query.TryGetValue("password", out var password);

            if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(host) || port < 1 || port > 65535)
                return null;

            // 其余字段作为 ExtraParams
            var extraParams = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in query)
            {
                if (kv.Key.Equals("type", StringComparison.OrdinalIgnoreCase) ||
                    kv.Key.Equals("host", StringComparison.OrdinalIgnoreCase) ||
                    kv.Key.Equals("port", StringComparison.OrdinalIgnoreCase) ||
                    kv.Key.Equals("userId", StringComparison.OrdinalIgnoreCase) ||
                    kv.Key.Equals("password", StringComparison.OrdinalIgnoreCase))
                    continue;

                extraParams[kv.Key] = kv.Value;
            }

            return NodeInfo.Create(
                OriginalLink: ymlLine,
                Type: type!,
                Host: host!,
                Port: port,
                UserId: userId,
                Password: password,
                ExtraParams: extraParams
            );
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[ParseYmlLine 失败] {ex.Message} | 内容: {ymlLine}");
            return null;
        }
    }
}