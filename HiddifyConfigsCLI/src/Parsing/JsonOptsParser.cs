// JsonOptsParser.cs
// 负责：解析 ws-opts、grpc-opts、reality、utls、quic 等 JSON 嵌套字段
// 负责：解析 JSON 字符串配置（URL 参数中的 JSON 或完整 JSON 行）
// 命名空间：HiddifyConfigsCLI.src.Parsing
// 说明：
//   - 输入：Dictionary<string,string> query（协议解析阶段临时字典）
//   - 输出：向 query 写入标准化键（ws_path, grpc_service, utls_fingerprint 等）
//   - 仅负责“字段展开”，不负责 NodeInfo 的创建
//   - ExtraParams 的实际落地由 NodeInfo 决定
// [ChatGPT Rebuild] 2025-11-14

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
    // 示例：{ "tls": { "enabled": true, "fingerprint": "chrome" } }
    // 展开为：
    //   tls_enabled = true
    //   tls_fingerprint = chrome
    //──────────────────────────────────────────────────────────────
    private static void ExtractJsonElement( string prefix, JsonElement element, Dictionary<string, string> query )
    {
        // 调试信息
        LogHelper.Debug($"[ExtractJsonElement] Prefix: '{prefix}', ValueKind: {element.ValueKind}");

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
                // 对数组直接序列化为 JSON 字符串存入 ExtraParams
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
    // 说明：将 ws_opts.xxx 标准化为 ws_path 等字段
    //──────────────────────────────────────────────────────────────
    public static void ParseWsOpts( Dictionary<string, string> query )
    {
        if (query.TryGetValue("ws_path", out var p))
            query["transport"] = "ws";

        if (query.TryGetValue("ws_headers_Host", out var host))
            query["ws_header_host"] = host;
    }

    //──────────────────────────────────────────────────────────────
    // 子模块：gRPC 配置解析（统一标准化字段）
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
    // 子模块：Reality 解析（只判断是否存在 reality 字段）
    // 说明：具体字段如 public_key、short_id 已在 ExtractJsonElement 中展开
    //──────────────────────────────────────────────────────────────
    public static void ParseReality( Dictionary<string, string> query )
    {
        if (query.Keys.Any(k => k.StartsWith("reality_", StringComparison.OrdinalIgnoreCase)))
            query["reality_enabled"] = "true";
    }

    /// <summary>
    /// 解析单行 JSON 配置并返回 NodeInfo
    /// </summary>
    /// <param name="jsonLine">完整 JSON 配置行</param>
    /// <returns>成功返回 NodeInfo，失败返回 null</returns>
    public static NodeInfo? ParseJsonLine( string jsonLine )
    {
        if (string.IsNullOrWhiteSpace(jsonLine))
            return null;

        try
        {
            // 临时 query 字典，用于字段扁平化
            var query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ParseJsonConfig(jsonLine, query);

            // 提取 NodeInfo 主字段
            query.TryGetValue("type", out var type);
            query.TryGetValue("host", out var host);
            int port = query.TryGetValue("port", out var portStr) && int.TryParse(portStr, out var p) ? p : 0;
            query.TryGetValue("userId", out var userId);
            query.TryGetValue("password", out var password);

            if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(host) || port < 1 || port > 65535)
                return null;

            // 剩余字段都作为 ExtraParams
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
                OriginalLink: jsonLine,
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
            LogHelper.Debug($"[ParseJsonLine 失败] {ex.Message} | 内容: {jsonLine}");
            return null;
        }
    }
}
