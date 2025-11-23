// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2RequestBuilder.cs
using HiddifyConfigsCLI.src.Core;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net.Security;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    /// <summary>
    /// Hysteria2 协议专用 HTTP/3 /auth 请求构造器
    /// 严格遵循官方协议规范（https://v2.hysteria.network/docs/developers/Protocol/）
    /// 负责生成完整的二进制请求帧（含伪头 + Headers 块 + 可选 Padding），不涉及 QUIC 传输层
    /// 支持将来无缝对接 salamander packet-level 混淆（返回前统一加密）
    /// </summary>
    // [Grok 修复_2025-11-22_001] // 重构：将请求构造从 TestAsync 中完全抽离，实现单责与可测试
    internal static class Hysteria2RequestBuilder
    {
        /// <summary>
        /// 构造标准的 Hysteria2 /auth 请求（HTTP/3 帧格式）
        /// 返回完整的字节数组，可直接写入 QuicStream
        /// </summary>
        /// <param name="node">解析后的 Hysteria2 节点信息</param>
        /// <returns>完整的请求字节数组（未经过 salamander 加密）</returns>
        public static byte[] BuildAuthRequest( Hysteria2Node node )
        {
            // 1. 准备所有 Headers（伪头必须最前，顺序固定）
            var headers = new List<KeyValuePair<string, string>>
            {
                // 伪头（Pseudo-Headers）—— HTTP/3 必须字段
                new(":method", "POST"),
                new(":scheme", "https"),
                new(":path", "/auth"),
                new(":authority", "hysteria"), // 官方固定为 hysteria，非实际域名

                // 标准头
                new("host", "hysteria"),
                new("user-agent", GetUserAgent(node)),
                new("accept", "*/*"),
                new("connection", "keep-alive"),

                // Hysteria2 必选认证头
                new("hysteria-auth", GetAuthString(node)),
                new("hysteria-udp", "true"),

                // 拥塞控制 / 带宽协商（0 表示未知，服务器会回传 auto）
                new("hysteria-cc-rx", GetCcRxValue(node)),
                new("hysteria-cc-tx", GetCcTxValue(node)),

                // 可选：随机 Padding 防止特征识别（官方推荐）
                new("hysteria-padding", GenerateRandomPadding())
            };

            // 2. 使用 QPack 手动编码（.NET 9 暂无内置 HTTP/3 编码器，手写最简实现）
            //    实际只需静态索引 + 字面量，足够覆盖所有字段
            return EncodeHeadersToHttp3Frame(headers);
        }

        /// <summary>
        /// 获取 User-Agent（优先使用节点自定义，否则使用 Chrome 最新指纹）
        /// </summary>
        private static string GetUserAgent( Hysteria2Node node )
        {
            if (!string.IsNullOrWhiteSpace(node.UserAgent))
                return node.UserAgent;

            // Chrome 131（2025-11 最新稳定版）
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
        }

        /// <summary>
        /// 生成 Hysteria-Auth 头值
        /// 官方：明文密码或 base64 编码的密钥，当前实现统一视为明文密码
        /// </summary>
        private static string GetAuthString( Hysteria2Node node )
        {
            // node.Password 为必填字段（Hysteria2 必须提供密码）
            return string.IsNullOrWhiteSpace(node.Password)
                ? ""
                : node.Password.Trim();
        }

        // <summary>
        /// 计算 hysteria-cc-rx 值（单位：bit/s）
        /// 优先使用节点声明的 DownMbps，若为 0 则发送 0（由服务器决定）
        /// </summary>
        private static string GetCcRxValue( Hysteria2Node node )
        {
            if (node.DownMbps <= 0)
                return "0";

            long bitsPerSecond = (long)(node.DownMbps * 1_000_000);
            return bitsPerSecond.ToString();
        }

        /// <summary>
        /// 新增：生成 hysteria-cc-tx（上行带宽声明）
        /// </summary>
        private static string GetCcTxValue( Hysteria2Node node )
        {
            if (node.UpMbps <= 0)
                return "0";

            long bitsPerSecond = (long)(node.UpMbps * 1_000_000);
            return bitsPerSecond.ToString();
        }

        /// <summary>
        /// 生成随机 Padding 字符串（0~256 字节可打印字符）
        /// 官方建议用于防主动探测
        /// </summary>
        private static string GenerateRandomPadding()
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = Random.Shared;
            int length = random.Next(0, 257); // 含 0
            if (length == 0) return "";

            var sb = new StringBuilder(length);
            for (int i = 0; i < length; i++)
                sb.Append(chars[random.Next(chars.Length)]);
            return sb.ToString();
        }

        /// <summary>
        /// 将 Headers 列表编码为 HTTP/3 HEADERS 帧（极简 QPack 实现）
        /// 仅使用静态表索引 + 字面量，足以覆盖 Hysteria2 所有固定字段
        /// 编码格式：Type(1) | Length(varint) | QPack 数据
        /// </summary>
        private static byte[] EncodeHeadersToHttp3Frame( List<KeyValuePair<string, string>> headers )
        {
            // 预估最大 2KB
            var buffer = ArrayPool<byte>.Shared.Rent(2048);
            try
            {
                int offset = 0;

                // 1. 帧头：HEADERS 帧 (0x01) + Length（后续填充）
                buffer[offset++] = 0x01;
                offset++; // Length 占位（varint 最多 4 字节）

                // 2. QPack 编码主体（手写静态表索引 + 字面量）
                int qpackStart = offset;

                foreach (var kv in headers)
                {
                    // 优先使用静态表索引（H3 静态表：https://www.rfc-editor.org/rfc/rfc9204.html#name-static-table）
                    // 下面仅列出我们用到的常见索引（节省字节）
                    switch (kv.Key)
                    {
                        case ":method" when kv.Value == "POST":
                            buffer[offset++] = 0x40 | 0x0D; // 静态索引 13 :method POST
                            break;

                        case ":scheme" when kv.Value == "https":
                            buffer[offset++] = 0x40 | 0x19; // 静态索引 25 :scheme https
                            break;

                        case ":path" when kv.Value == "/auth":
                            // 无直接索引，使用带 Huffman 的字面量
                            WriteLiteralWithNameRef(buffer, ref offset, nameIndex: 24, kv.Value); // 24 = :path
                            break;

                        case ":authority" when kv.Value == "hysteria":
                            WriteLiteralWithNameRef(buffer, ref offset, nameIndex: 1, kv.Value); // 1 = :authority
                            break;

                        default:
                            // 其他头使用动态表索引或字面量（这里统一用带 Huffman 的字面量）
                            WriteLiteralHeader(buffer, ref offset, kv.Key, kv.Value);
                            break;
                    }
                }

                int qpackLength = offset - qpackStart;

                // 回填 Length（varint）
                int lengthPos = 1;
                offset = 1;
                offset += WriteVarint((ulong)qpackLength, buffer.AsSpan(lengthPos));

                // 最终长度
                int totalLength = lengthPos + qpackLength;
                var result = new byte[totalLength];
                Buffer.BlockCopy(buffer, 0, result, 0, totalLength);
                return result;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        // 下面的辅助方法为极简 QPack 编码实现（仅支持我们所需场景）
        /// <summary>
        /// 写入带名称索引的字面量头字段（Literal Header Field With Name Reference）
        /// 使用静态表索引 + Huffman 编码值（本实现简化使用非 Huffman）
        /// </summary>
        private static void WriteLiteralWithNameRef( byte[] buffer, ref int offset, int nameIndex, string value )
        {
            // 0 0 1 1 xxxx xxxx | Name Index (varint) | Huffman? | Value
            // buffer[offset++] = 0x30 | (byte)(nameIndex >> 8); // 高位暂不处理（nameIndex < 128）

            // 前缀：0011 xxxx → 0x30 + 高4位索引（如果索引 < 16）
            // 如果索引 >= 16，则使用 0011 0000 + varint 编码索引
            if (nameIndex < 16)
            {
                // 索引 < 16，直接编码在前缀高4位
                buffer[offset++] = (byte)(0x30 | nameIndex);
            }
            else
            {
                // 索引 >= 16，使用可变长编码
                buffer[offset++] = 0x30; // 前缀 0011 0000
                offset += WriteVarint((ulong)(nameIndex - 16), buffer.AsSpan(offset)); // 减去已编码的 4 位空间
            }

            // 值：Huffman 标志位 + 长度 + 数据（这里使用非 Huffman）
            WriteHuffmanString(buffer, ref offset, value);
        }

        private static void WriteLiteralHeader( byte[] buffer, ref int offset, string name, string value )
        {
            // 0 0 1 0 0000 | Name Huffman + Length | Name | Value Huffman + Length | Value
            // buffer[offset++] = 0x28; // Literal header field without indexing + Huffman name & value

            // 完全字面量：0010 1000 = 0x28（带索引表不更新 + Huffman 名称和值）
            buffer[offset++] = 0x28;
            WriteHuffmanString(buffer, ref offset, name);
            WriteHuffmanString(buffer, ref offset, value);
        }

        private static void WriteHuffmanString( byte[] buffer, ref int offset, string s )
        {
            // 简化：我们全部使用非 Huffman（7-bit）
            byte[] bytes = Encoding.ASCII.GetBytes(s);
            offset += WriteVarint((ulong)bytes.Length | 0x80, buffer.AsSpan(offset)); // 高位 1 表示非 Huffman
            Buffer.BlockCopy(bytes, 0, buffer, offset, bytes.Length);
            offset += bytes.Length;
        }

        private static int WriteVarint( ulong value, Span<byte> destination )
        {
            int i = 0;
            while (value >= 0x80)
            {
                destination[i++] = (byte)(value & 0x7F | 0x80);
                value >>= 7;
            }
            destination[i++] = (byte)value;
            return i;
        }

        // 辅助方法：安全识别 .NET 官方支持的 ALPN 协议常量
        // 避免使用 new SslApplicationProtocol(string) 导致 QUIC 握手失败
        public static bool TryGetKnownProtocol( string name, out SslApplicationProtocol protocol )
        {
            protocol = name.Trim() switch
            {
                "h3" => SslApplicationProtocol.Http3,
                "http/3" => SslApplicationProtocol.Http3,
                "h2" => SslApplicationProtocol.Http2,
                "http/1.1" => SslApplicationProtocol.Http11,
                _ => default
            };

            return protocol != default;
        }
    }
}