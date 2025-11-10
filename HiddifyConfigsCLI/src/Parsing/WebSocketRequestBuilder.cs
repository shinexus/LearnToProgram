/*
 * 作者：ChatGPT
 * 2025-11-05
 * 
 * WebSocketRequestBuilder 所需 ExtraParams 快速清单（仅 transportType == "ws" 时使用）
 *
 * 必填字段：
 *   ws_path                   : WebSocket 路径，来源 query["path"] 或默认 "/"。
 *                               如果 path 内含 "?ed=xxx"，需剥离仅保留路径部分。
 *   ws_host                   : Host Header，优先 query["host"]，次选 hostParam，最后回退到 uri.Host。
 *                               用于 HTTP/1.1 或 HTTP/2 Upgrade 请求的 Host。
 *
 * 可选但推荐：
 *   early_data_header_name    : Early Data Header 名称，默认 "Sec-WebSocket-Protocol" 当存在 ed 参数且未自定义。
 *   ed                        : Early Data 值，从 query["ed"] 提取数字部分（如 ed=2048）。
 *                               Cloudflare Workers 等 VLESS+WS 常用。
 *
 * 辅助字段（用于调试、日志或兼容性）：
 *   tls_enabled               : TLS 开启状态，security == "tls" 或 query["tls"] == "tls"。
 *   reality_enabled           : Reality 模式，security == "reality" 或 query["tls"] == "reality"。
 *   utls_fingerprint          : uTLS 指纹，来源 query["fp"] 或 query["fingerprint"]。
 *   flow                      : 流量控制/XTLS Flow，来源 query["flow"] 或 ""。
 *
 * 其他字段（可保留供 ConnectivityChecker 或未来扩展使用）：
 *   transport_type            : Transport 类型，固定 "ws"。
 *   packetEncoding            : 包编码方式，默认为 "none"，ConnectivityChecker 使用。
 *   hostParam                 : 节点 Host 参数，sni 或 peer。
 *   OriginalLink              : 原始 VLESS 链接，供调试或日志记录。
 *
 * 使用说明：
 *   1. WebSocketRequestBuilder 仅在 transportType == "ws" 时调用。
 *   2. ws_path 和 ws_host 是构建请求头的核心字段。
 *   3. 如果存在 ed 参数且未指定 early_data_header_name，则默认使用 "Sec-WebSocket-Protocol"。
 *   4. 所有字段统一写入 ExtraParams，便于 WebSocketRequestBuilder 读取和生成请求。
 */
using System.Security.Cryptography;
using System.Text;

namespace HiddifyConfigsCLI
{
    /// <summary>
    /// WebSocket 请求生成器（支持 VLESS + WS + Early Data）
    /// </summary>
    public static class WebSocketRequestBuilder
    {
        /// <summary>
        /// 节点类型
        /// </summary>
        public enum NodeType
        {
            CloudflareWorker,
            VPS,
            CDN
        }

        /// <summary>
        /// 生成 WebSocket 握手请求字符串
        /// </summary>
        /// <param name="host">Host 或 SNI</param>
        /// <param name="path">WebSocket 路径，可包含 query</param>
        /// <param name="earlyDataHeaderName">Early Data header 名称，例如 Sec-WebSocket-Protocol</param>
        /// <param name="earlyDataValue">Early Data 值（仅数字）</param>
        /// <param name="wsNodeType">节点类型，避免与项目中已有 nodeType 冲突</param>
        /// <returns>完整 WebSocket 握手请求字符串</returns>
        public static string BuildRequest(
            string host,
            string path,
            string? earlyDataHeaderName = null,
            string? earlyDataValue = null,
            NodeType wsNodeType = NodeType.VPS )
        {
            if (string.IsNullOrWhiteSpace(host))
                throw new ArgumentNullException(nameof(host));
            if (string.IsNullOrWhiteSpace(path))
                path = "/";

            // ------------------------------
            // [ chatGPT 自我补救 v5 ]
            // 处理 path 中多余 '?' 问题，只保留第一个 '?'，其余 '?' 转为 '&'
            // 避免服务器返回 400/421
            // ------------------------------
            if (path.Count(c => c == '?') > 1)
            {
                var first = path.IndexOf('?');
                var before = path.Substring(0, first + 1);
                var after = path.Substring(first + 1).Replace('?', '&');
                path = before + after;
            }

            // 分割 path 与 query
            var parts = path.Split('?', 2);
            // 对 path 前缀编码，保留首 '/' 避免握手失败
            if (!string.IsNullOrEmpty(parts[0]))
            {
                var firstChar = parts[0][0] == '/' ? "/" : "";
                var toEncode = firstChar == "/" ? parts[0].Substring(1) : parts[0];
                parts[0] = firstChar + Uri.EscapeDataString(toEncode);
            }
            // 拼接回 path（query 保留不编码）
            path = parts.Length > 1 ? $"{parts[0]}?{parts[1]}" : parts[0];

            // ------------------------------
            // 生成随机 Sec-WebSocket-Key
            // ------------------------------
            var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

            var sb = new StringBuilder();
            sb.AppendLine($"GET {path} HTTP/1.1");
            sb.AppendLine($"Host: {host}");
            sb.AppendLine("Upgrade: websocket");
            sb.AppendLine("Connection: Upgrade");
            sb.AppendLine($"Sec-WebSocket-Key: {key}");
            sb.AppendLine("Sec-WebSocket-Version: 13");

            // ------------------------------
            // 如果 Early Data 头存在，则添加
            // ------------------------------
            if (!string.IsNullOrWhiteSpace(earlyDataHeaderName))
            {
                var edValue = string.IsNullOrWhiteSpace(earlyDataValue) ? "0" : earlyDataValue.Trim();
                // 注意：Header 格式为 "Header-Name: ed=数字"
                sb.AppendLine($"{earlyDataHeaderName}: ed={edValue}");
            }

            // 结束头部
            sb.AppendLine();

            return sb.ToString();
        }
    }
}
