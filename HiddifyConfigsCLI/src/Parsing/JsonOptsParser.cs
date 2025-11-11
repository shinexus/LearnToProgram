// JsonOptsParser.cs
// 负责：解析 ws-opts、grpc-opts、reality 等 JSON 嵌套字段
// 命名空间：HiddifyConfigsCLI.src.Parsing
// [Grok Rebuild] 2025-11-10_06：独立工具类，零耦合，可单元测试
// 说明：
//   - 输入：query 字典（key: 原始参数名, value: URL 编码字符串）
//   - 输出：向 query 中写入标准化键（ws_path, ws_header_host, reality_public_key 等）
//   - 所有 JSON 解析集中于此，ProtocolParser 仅调用
using HiddifyConfigsCLI.src.Logging;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Web;

namespace HiddifyConfigsCLI.src.Parsing;

/// <summary>
/// JSON 嵌套字段解析器（ws-opts / grpc-opts / reality）
/// </summary>
internal static class JsonOptsParser
{
    /// <summary>
    /// 解析 ws-opts JSON 字段
    /// 示例：?ws-opts={"path":"/ws","headers":{"Host":"example.com"},"maxEarlyData":2048}
    /// </summary>
    /// <param name="query">查询参数字典（可读写）</param>
    public static void ParseWsOpts( Dictionary<string, string> query )
    {
        // 【Grok 2025-11-10 说明】ws-opts 可能被编码为 %7B...%7D
        var wsOptsJson = query.GetValueOrDefault("ws-opts")
                         ?? query.GetValueOrDefault("ws_opts");

        if (string.IsNullOrEmpty(wsOptsJson)) return;

        try
        {
            // 【Grok 优化】先 URL 解码，再解析 JSON
            var decoded = HttpUtility.UrlDecode(wsOptsJson);
            if (string.IsNullOrEmpty(decoded)) return;

            var json = JsonNode.Parse(decoded,
                documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true })?.AsObject();
            if (json == null) return;

            // 1. 解析 path
            var path = json["path"]?.ToString() ?? "/";
            path = FixWsPath(path); // 修复多 ? 和编码问题
            query["ws_path"] = path;

            // 2. 解析 headers
            var headers = json["headers"]?.AsObject();
            if (headers != null)
            {
                foreach (var kvp in headers)
                {
                    var key = kvp.Key.Trim();
                    if (string.IsNullOrEmpty(key)) continue;
                    var value = kvp.Value?.ToString() ?? "";
                    // 标准化键：ws_header_host, ws_header_x-custom
                    query[$"ws_header_{key.ToLowerInvariant()}"] = value;
                }
            }

            // 3. 解析 early-data
            var maxEarlyData = json["maxEarlyData"]?.ToString()
                              ?? json["max_early_data"]?.ToString();
            if (!string.IsNullOrEmpty(maxEarlyData))
            {
                // 提取纯数字
                var match = RegexPatterns.DigitRegex.Match(maxEarlyData);
                query["early_data"] = match.Success ? match.Value : maxEarlyData;
            }

            // 4. 解析 earlyDataHeaderName
            var headerName = json["earlyDataHeaderName"]?.ToString()
                            ?? json["early_data_header_name"]?.ToString();
            if (!string.IsNullOrEmpty(headerName))
            {
                query["early_data_header_name"] = headerName;
            }
            else if (!string.IsNullOrEmpty(query.GetValueOrDefault("early_data")))
            {
                // 兜底：Clash Meta 默认
                query["early_data_header_name"] = "Sec-WebSocket-Protocol";
            }
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[WS-OPTS JSON 解析失败] 原始: {wsOptsJson} | 错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 解析 grpc-opts JSON 字段
    /// 示例：?grpc-opts={"grpc-service-name":"gun"}
    /// </summary>
    /// <param name="query">查询参数字典（可读写）</param>
    public static void ParseGrpcOpts( Dictionary<string, string> query )
    {
        var grpcOptsJson = query.GetValueOrDefault("grpc-opts")
                           ?? query.GetValueOrDefault("grpc_opts");

        if (string.IsNullOrEmpty(grpcOptsJson)) return;

        try
        {
            var decoded = HttpUtility.UrlDecode(grpcOptsJson);
            if (string.IsNullOrEmpty(decoded)) return;

            var json = JsonNode.Parse(decoded,
                documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true })?.AsObject();
            if (json == null) return;

            // 优先级：grpc-service-name > serviceName > servicename
            var serviceName = json["grpc-service-name"]?.ToString()
                             ?? json["serviceName"]?.ToString()
                             ?? json["servicename"]?.ToString()
                             ?? "";
            query["grpc_service_name"] = serviceName;

            // 未来扩展：其他 grpc-opts 字段
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[GRPC-OPTS JSON 解析失败] 原始: {grpcOptsJson} | 错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 解析 reality JSON 字段（可复用）
    /// 示例：?reality={"public_key":"xxx","short_id":"abc"}
    /// </summary>
    /// <param name="query">查询参数字典（可读写）</param>
    public static void ParseReality( Dictionary<string, string> query )
    {
        var realityJsonStr = query.GetValueOrDefault("reality");
        if (string.IsNullOrEmpty(realityJsonStr)) return;

        try
        {
            var decoded = HttpUtility.UrlDecode(realityJsonStr);
            if (string.IsNullOrEmpty(decoded)) return;

            var json = JsonNode.Parse(decoded,
                documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true })?.AsObject();
            if (json == null) return;

            query["reality_public_key"] = json["public_key"]?.ToString() ?? "";
            query["reality_short_id"] = json["short_id"]?.ToString() ?? "";
            // 可扩展：spiderX, fingerprint 等
        }
        catch (Exception ex)
        {
            LogHelper.Debug($"[REALITY JSON 解析失败] 原始: {realityJsonStr} | 错误: {ex.Message}");
        }
    }

    /// <summary>
    /// 修复 WebSocket 路径中的多 ? 和编码问题（复用自 ProtocolParser）
    /// </summary>
    private static string FixWsPath( string rawPath )
    {
        if (string.IsNullOrEmpty(rawPath)) return "/";

        // 1. 多 ? → &
        var qCount = rawPath.Count(c => c == '?');
        if (qCount > 1)
        {
            var firstQ = rawPath.IndexOf('?');
            var prefix = rawPath[..(firstQ + 1)];
            var suffix = rawPath[(firstQ + 1)..].Replace('?', '&');
            rawPath = prefix + suffix;
        }

        // 2. 分离 path 和 query，编码 path 主体
        var parts = rawPath.Split('?', 2);
        var pathBody = parts[0];
        var queryPart = parts.Length > 1 ? parts[1] : "";

        if (!string.IsNullOrEmpty(pathBody) && pathBody != "/")
        {
            var firstChar = pathBody[0] == '/' ? "/" : "";
            var toEncode = firstChar == "/" ? pathBody[1..] : pathBody;
            pathBody = firstChar + Uri.EscapeDataString(toEncode);
        }

        return string.IsNullOrEmpty(queryPart) ? pathBody : $"{pathBody}?{queryPart}";
    }
}