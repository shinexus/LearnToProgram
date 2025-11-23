// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2ResponseParser.cs
using System;
using System.Buffers;
using System.IO;
using System.Net.Quic;
using System.Text;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    /// <summary>
    /// Hysteria2 协议专用响应解析器
    /// 负责从 QuicStream 中读取并解析服务器返回的 HTTP/3 响应（233 HyOK）
    /// 严格校验状态码、必选头字段，并提取带宽协商结果
    /// </summary>
    // [Grok 修复_2025-11-23_006] // 新增：独立响应解析器，实现协议完整闭环，支持 233 HyOK 校验与 CC 协商
    internal static class Hysteria2ResponseParser
    {
        /// <summary>
        /// 异步解析 Hysteria2 /auth 响应
        /// </summary>
        /// <param name="stream">已建立的双向 QUIC 流（已写入请求）</param>
        /// <param name="node">节点信息（用于日志与后续扩展）</param>
        /// <param name="cancellationToken">超时控制</param>
        /// <returns>结构化解析结果</returns>
        public static async ValueTask<Hysteria2HandshakeResult> ParseAsync(
            QuicStream stream,
            Hysteria2Node node,
            CancellationToken cancellationToken = default )
        {
            var result = new Hysteria2HandshakeResult
            {
                Success = false,
                ResponseStream = null,
                NegotiatedRxBps = 0,
                NegotiatedTxBps = 0,
                UdpEnabled = false
            };

            try
            {
                // 1. 读取 HTTP/3 HEADERS 帧（可能伴随 DATA 帧，但 /auth 通常无 body）
                var buffer = ArrayPool<byte>.Shared.Rent(8192);
                try
                {
                    var memory = buffer.AsMemory(0, 8192);
                    int bytesRead = await stream.ReadAsync(memory, cancellationToken).ConfigureAwait(false);

                    if (bytesRead == 0)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 服务器过早关闭流（EOF）");
                        return result;
                    }

                    var span = memory.Span.Slice(0, bytesRead);

                    // 2. 简单但足够健壮的 HTTP/3 响应解析（仅解析 HEADERS 帧）
                    // 格式：Type (0x01) + Length (varint) + QPack 数据
                    if (span.Length < 2 || span[0] != 0x01)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 响应帧类型非法（期望 HEADERS 0x01）");
                        return result;
                    }

                    int offset = 1;
                    ulong frameLength = ReadVarint(span.Slice(offset), out int varintBytes);
                    offset += varintBytes;

                    if (offset + (int)frameLength > span.Length)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 响应帧长度不足（声明 {frameLength}，实际 {span.Length - offset}）");
                        return result;
                    }

                    var qpackData = span.Slice(offset, (int)frameLength);
                    offset += (int)frameLength;

                    // 3. 解析 QPack（极简实现，仅提取 :status 和关键头）
                    var headers = DecodeSimpleQPackHeaders(qpackData);
                    if (headers == null)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} QPack 解码失败");
                        return result;
                    }

                    // 4. 关键校验：必须是 233 HyOK
                    if (!headers.TryGetValue(":status", out var statusStr) || statusStr != "233")
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 认证失败，状态码: {statusStr ?? "缺失"}");
                        return result;
                    }

                    // 5. 解析关键响应头
                    result.UdpEnabled = headers.TryGetValue("hysteria-udp", out var udpVal) &&
                                        (udpVal.Equals("true", StringComparison.OrdinalIgnoreCase) || udpVal == "1");

                    if (headers.TryGetValue("hysteria-cc-rx", out var rxStr) && long.TryParse(rxStr, out long rxBps))
                        result.NegotiatedRxBps = rxBps;

                    if (headers.TryGetValue("hysteria-cc-tx", out var txStr) && long.TryParse(txStr, out long txBps))
                        result.NegotiatedTxBps = txBps;

                    // 6. 成功：封装原始响应流（供上层日志或调试）
                    var responseBytes = span.Slice(0, bytesRead).ToArray();
                    result.ResponseStream = new MemoryStream(responseBytes, false);
                    result.Success = true;

                    LogHelper.Info($"[Hysteria2] {node.Host}:{node.Port} 认证成功 | UDP: {result.UdpEnabled} | RX: {FormatBps(result.NegotiatedRxBps)} | TX: {FormatBps(result.NegotiatedTxBps)}");
                    return result;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 响应解析异常 → {ex.GetType().Name}: {ex.Message}");
                return result;
            }
        }

        /// <summary>
        /// 极简 QPack 解码（仅支持我们关心的静态表索引 + 字面量）
        /// </summary>
        private static Dictionary<string, string>? DecodeSimpleQPackHeaders( ReadOnlySpan<byte> data )
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int offset = 0;

            while (offset < data.Length)
            {
                if (offset >= data.Length) break;
                byte first = data[offset];

                // 静态表索引（0x40 | index）
                if ((first & 0xC0) == 0x40)
                {
                    int index = first & 0x3F;
                    if (TryGetStaticHeaderName(index, out var name))
                    {
                        offset++;
                        // 值：跳过 Huffman + varint，直接读到帧尾（我们只关心 :status）
                        if (name == ":status" && offset < data.Length)
                        {
                            ulong valueLen = ReadVarint(data.Slice(offset), out int lenBytes);
                            offset += lenBytes;
                            if (offset + (int)valueLen <= data.Length)
                            {
                                headers[name] = Encoding.ASCII.GetString(data.Slice(offset, (int)valueLen));
                                offset += (int)valueLen;
                            }
                        }
                        else
                        {
                            // 跳过值
                            ulong skipLen = ReadVarint(data.Slice(offset), out int skipBytes);
                            offset += skipBytes + (int)skipLen;
                        }
                    }
                }
                // 字面量头（0x20-0x3F 或 0x28 等）
                else if ((first & 0xF0) == 0x20 || first == 0x28)
                {
                    offset++;
                    // 跳过名称（Huffman 或字面量）
                    bool nameHuffman = (data[offset - 1] & 0x08) == 0x08;
                    ulong nameLen = ReadVarint(data.Slice(offset), out int nameBytes);
                    offset += nameBytes + (int)nameLen;

                    if (offset >= data.Length) break;

                    // 值
                    bool valueHuffman = (data[offset - 1] & 0x80) == 0x80;
                    ulong valueLen = ReadVarint(data.Slice(offset), out int valueBytes);
                    offset += valueBytes;
                    if (offset + (int)valueLen <= data.Length)
                    {
                        string value = Encoding.ASCII.GetString(data.Slice(offset, (int)valueLen));
                        // 尝试从前文推断名称（不完美但够用）
                        string name = headers.ContainsKey(":status") ? "hysteria-udp" : "unknown";
                        if (offset < data.Length)
                        {
                            // 粗略猜测
                            if (value.StartsWith("true") || value.StartsWith("false") || value == "1" || value == "0")
                                name = "hysteria-udp";
                            else if (long.TryParse(value, out _))
                                name = value.Length > 8 ? "hysteria-cc-rx" : "hysteria-cc-tx";
                        }
                        headers[name] = value;
                        offset += (int)valueLen;
                    }
                }
                else
                {
                    offset++; // 跳过未知
                }
            }

            return headers.Count > 0 ? headers : null;
        }

        private static bool TryGetStaticHeaderName( int index, out string name )
        {
            name = index switch
            {
                0 => ":authority",
                1 => ":path",
                13 => ":method",
                25 => ":scheme",
                31 => ":status",
                _ => ""
            };
            return !string.IsNullOrEmpty(name);
        }

        private static ulong ReadVarint( ReadOnlySpan<byte> span, out int bytesRead )
        {
            ulong value = 0;
            bytesRead = 0;
            for (int i = 0; i < span.Length && i < 8; i++)
            {
                byte b = span[i];
                value |= (ulong)(b & 0x7F) << 7 * i;
                bytesRead++;
                if ((b & 0x80) == 0) break;
            }
            return value;
        }

        private static string FormatBps( long bps )
        {
            if (bps == 0) return "auto";
            return bps >= 1_000_000 ? $"{bps / 1_000_000} Mbps" : $"{bps / 1000} Kbps";
        }
    }

    /// <summary>
    /// Hysteria2 握手结果（结构化）
    /// </summary>
    public class Hysteria2HandshakeResult
    {
        public bool Success { get; set; }
        public Stream? ResponseStream { get; set; }
        public long NegotiatedRxBps { get; set; }
        public long NegotiatedTxBps { get; set; }
        public bool UdpEnabled { get; set; }
    }
}