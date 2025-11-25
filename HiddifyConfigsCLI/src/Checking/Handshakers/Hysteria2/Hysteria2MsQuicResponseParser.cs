// Hysteria2MsQuicResponseParser.cs
// 适配 MsQuicStream（Hysteria2MsQuicStream）的 Hysteria2 /auth 响应解析器
// 假设：每次从 stream.ReadAsync 返回的数据代表一个完整的 Hysteria2 解密后 packet（你已确认为 A）
// 保留原有协议解析逻辑并做若干修复与健壮性增强（详见 [ChatGPT 审查修改] 注释）

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Buffers;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static class Hysteria2MsQuicResponseParser
    {
        /// <summary>
        /// 解析 Hysteria2 /auth 响应（针对 MsQuicStream 的实现）
        /// 约定：stream.ReadAsync(buffer, offset, count, ct) 返回的字节块视为一个完整 packet（由 MsQuicStream 保证）。
        /// </summary>
        public static async ValueTask<Hysteria2HandshakeResult> ParseAsync(
            Hysteria2MsQuicStream stream,
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

            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (node == null) throw new ArgumentNullException(nameof(node));

            // [ChatGPT 审查修改]
            // 使用 ArrayPool 大缓冲一次性读取单个 packet（假设 packet 不会超过 64KiB；如需要改更大）。
            const int RentSize = 64 * 1024;
            var buffer = ArrayPool<byte>.Shared.Rent(RentSize);
            try
            {
                // 我们只需要一个 packet（/auth 通常是单帧完成），但为了健壮性允许循环读取若干包直到解析成功或取消。
                while (!cancellationToken.IsCancellationRequested)
                {
                    int bytesRead;
                    try
                    {
                        bytesRead = await stream.ReadAsync(buffer, 0, RentSize, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 读取响应时异常: {ex.GetType().Name}: {ex.Message}");
                        return result;
                    }

                    if (bytesRead == 0)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 服务器在响应前关闭流（EOF）");
                        return result;
                    }

                    var span = new ReadOnlySpan<byte>(buffer, 0, bytesRead);

                    // 解析 HEADERS FRAME（HTTP/3 style） — 必须为 HEADERS (frame type 0x01)
                    if (span.Length < 1)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 响应过短");
                        return result;
                    }

                    // [ChatGPT 审查修改]
                    // 有些实现可能在 packet 前包含 QUIC 帧 header（type varint + length varint）。
                    // 这里做兼容性处理：读取第一个 varint，如果其值为 0x01（HEADERS）或第一个字节为 0x01 则继续。
                    int offset = 0;
                    // 读取第一个 varint（可能是 frame type）
                    ulong firstVar = ReadVarint(span.Slice(offset), out int firstVarBytes);
                    if (firstVarBytes == 0)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 无法解析 varint（frame type）");
                        return result;
                    }
                    offset += firstVarBytes;

                    // HEADERS frame type expected = 0x01
                    if (firstVar != 0x01)
                    {
                        // 有些包可能把 frame type 放在第一个字节直接表示（兼容旧实现）
                        if (span[0] != 0x01)
                        {
                            LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 响应帧类型非法（期望 HEADERS 0x01，实际 {firstVar}）");
                            return result;
                        }
                        // else 已经 handled
                    }

                    // 读取 frame length varint
                    ulong frameLength = ReadVarint(span.Slice(offset), out int lenVarBytes);
                    if (lenVarBytes == 0)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 无法解析 frame length");
                        return result;
                    }
                    offset += lenVarBytes;

                    if (offset + (int)frameLength > span.Length)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 响应帧长度不足（声明 {frameLength}，实际 {span.Length - offset}）");
                        return result;
                    }

                    var qpackData = span.Slice(offset, (int)frameLength);
                    offset += (int)frameLength;

                    // 解析 QPack（极简实现，仅提取 :status 与我们关心的几个头）
                    var headers = DecodeSimpleQPackHeaders(qpackData);
                    if (headers == null)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} QPack 解码失败");
                        return result;
                    }

                    // 校验 status == 233
                    if (!headers.TryGetValue(":status", out var statusStr) || statusStr != "233")
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 认证失败，状态码: {statusStr ?? "缺失"}");
                        return result;
                    }

                    // 解析关键 header
                    result.UdpEnabled = headers.TryGetValue("hysteria-udp", out var udpVal) &&
                                        (udpVal.Equals("true", StringComparison.OrdinalIgnoreCase) || udpVal == "1");

                    if (headers.TryGetValue("hysteria-cc-rx", out var rxStr) && long.TryParse(rxStr, out long rxBps))
                        result.NegotiatedRxBps = rxBps;

                    if (headers.TryGetValue("hysteria-cc-tx", out var txStr) && long.TryParse(txStr, out long txBps))
                        result.NegotiatedTxBps = txBps;

                    // 成功：封装原始响应以便上层调试/日志
                    var responseBytes = new byte[bytesRead];
                    span.CopyTo(responseBytes);
                    result.ResponseStream = new MemoryStream(responseBytes, writable: false);
                    result.Success = true;

                    LogHelper.Info($"[Hysteria2] {node.Host}:{node.Port} 认证成功 | UDP: {result.UdpEnabled} | RX: {FormatBps(result.NegotiatedRxBps)} | TX: {FormatBps(result.NegotiatedTxBps)}");
                    return result;
                }

                // 取消
                throw new OperationCanceledException(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 解析被取消");
                return result;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 响应解析异常 → {ex.GetType().Name}: {ex.Message}");
                return result;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        // ===========================
        // 极简 QPack 解码（适配 Hysteria2 在 HEADERS 中的常见编码）
        // 说明：这是一个轻量级、针对性实现，仅提取我们关心的头字段；不做完整 QPack/Huffman 支持。
        // ===========================
        private static Dictionary<string, string>? DecodeSimpleQPackHeaders( ReadOnlySpan<byte> data )
        {
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int offset = 0;

            while (offset < data.Length)
            {
                byte first = data[offset];

                // 静态表索引（示例：0x40 表示静态表索引）
                if ((first & 0xC0) == 0x40)
                {
                    int index = first & 0x3F;
                    offset++;

                    if (!TryGetStaticHeaderName(index, out var name))
                        continue;

                    // 读取值长度（varint）
                    ulong valueLen = ReadVarint(data.Slice(offset), out int lenBytes);
                    if (lenBytes == 0) break;
                    offset += lenBytes;

                    if (offset + (int)valueLen <= data.Length)
                    {
                        var value = Encoding.ASCII.GetString(data.Slice(offset, (int)valueLen));
                        headers[name] = value;
                        offset += (int)valueLen;
                    }
                    else
                    {
                        break;
                    }
                    continue;
                }

                // 字面量名称 / 字面量头（简化实现）
                if ((first & 0xF0) == 0x20 || first == 0x28)
                {
                    // 跳过标志字节
                    offset++;

                    // 名称长度 varint
                    ulong nameLen = ReadVarint(data.Slice(offset), out int nameBytes);
                    if (nameBytes == 0) break;
                    offset += nameBytes;

                    if (offset + (int)nameLen > data.Length) break;
                    string name = Encoding.ASCII.GetString(data.Slice(offset, (int)nameLen));
                    offset += (int)nameLen;

                    // 值长度 varint
                    ulong valueLen = ReadVarint(data.Slice(offset), out int valueBytes);
                    if (valueBytes == 0) break;
                    offset += valueBytes;

                    if (offset + (int)valueLen > data.Length) break;
                    string value = Encoding.ASCII.GetString(data.Slice(offset, (int)valueLen));
                    offset += (int)valueLen;

                    headers[name] = value;
                    continue;
                }

                // 其他未知标志：安全跳过一个字节继续解析
                offset++;
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
                _ => string.Empty
            };
            return !string.IsNullOrEmpty(name);
        }

        // [ChatGPT 审查修改]
        // 修复 varint 解析位移优先级错误（原版使用 << 7 * i 导致运算顺序问题）
        private static ulong ReadVarint( ReadOnlySpan<byte> span, out int bytesRead )
        {
            ulong value = 0;
            bytesRead = 0;
            for (int i = 0; i < span.Length && i < 10; i++)
            {
                byte b = span[i];
                value |= (ulong)(b & 0x7F) << (7 * i);
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

    // 结果结构：与 Hysteria2ResponseParser 保持一致
    public class Hysteria2HandshakeResult
    {
        public bool Success { get; set; }
        public Stream? ResponseStream { get; set; }
        public long NegotiatedRxBps { get; set; }
        public long NegotiatedTxBps { get; set; }
        public bool UdpEnabled { get; set; }
    }
}
