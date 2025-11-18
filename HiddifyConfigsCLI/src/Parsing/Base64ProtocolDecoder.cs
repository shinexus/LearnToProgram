using System;
using System.Text;

namespace HiddifyConfigsCLI.src.Parsing
{
    /// <summary>
    /// Base64 协议解码器
    /// 负责：
    /// 1. 解码形如 vless://BASE64 以及 hysteria2://BASE64 的情况
    /// 2. 对整行 base64 编码的原始链接进行尝试性解码
    /// 3. 对整份文本整体 Base64 编码进行解码
    /// 4. 返回可识别协议的明文链接，否则原样返回
    ///
    /// 注意：
    /// - 本类为同步逻辑（无 async）
    /// - 在主解析管线上优先运行：
    ///   RawLine → Base64ProtocolDecoder → ProtocolRouter → ParseVless / ParseHysteria2 / ParseTrojan ...
    /// </summary>
    internal static partial class Base64ProtocolDecoder
    {
        private static readonly string[] ProtocolPrefixes =
        {
            "vless://",
            "hysteria2://"
        };

        // ==================================================================
        // 1. 单行协议 Base64 解码（核心入口）
        // ==================================================================
        public static string TryDecode( string rawInput )
        {
            if (string.IsNullOrWhiteSpace(rawInput))
                return rawInput;

            rawInput = rawInput.Trim();

            // 情况 1：形如 vless://base64 或 hysteria2://base64
            foreach (var prefix in ProtocolPrefixes)
            {
                if (rawInput.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    string b64Body = rawInput.Substring(prefix.Length);
                    string? decoded = DecodeBase64Safe(b64Body);

                    // decode 成功且生成可识别协议链接
                    if (decoded is not null && LooksLikeProtocol(decoded))
                        return decoded.Trim();

                    // decode 无效 → 原样返回
                    return rawInput;
                }
            }

            // 情况 2：整行可能是纯 Base64
            if (LooksLikeBase64(rawInput))
            {
                string? decoded = DecodeBase64Safe(rawInput);

                if (decoded is not null && LooksLikeProtocol(decoded))
                    return decoded.Trim();
            }

            return rawInput;
        }

        // ==================================================================
        // 2. 整份文本是否整体为 Base64
        // ==================================================================
        public static bool IsWholeBase64( string text )
        {
            if (string.IsNullOrWhiteSpace(text)) return false;

            var lines = text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);
            int base64Count = 0;

            foreach (var line in lines)
            {
                if (LooksLikeBase64(line.Trim()))
                    base64Count++;
            }

            // 超过 50% 行是 Base64 或整个文本去掉换行后是 Base64
            string joined = string.Concat(lines).Trim();
            return base64Count >= Math.Max(1, lines.Length / 2) || LooksLikeBase64(joined);
        }

        // ==================================================================
        // 3. 整份 Base64 文本解码
        // ==================================================================
        public static string DecodeWholeBase64( string text )
        {
            if (string.IsNullOrWhiteSpace(text))
                return string.Empty;

            var lines = text.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.RemoveEmptyEntries);
            var sb = new StringBuilder();

            foreach (var line in lines)
            {
                string trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed)) continue;

                string? decoded = DecodeBase64Safe(trimmed);
                if (decoded != null)
                    sb.AppendLine(decoded);
            }

            return sb.ToString();
        }

        // ==================================================================
        // 4. 内部辅助方法
        // ==================================================================

        /// <summary>
        /// 尝试 Base64 解码（失败返回 null，不抛异常）
        /// </summary>
        private static string? DecodeBase64Safe( string base64Text )
        {
            try
            {
                base64Text = base64Text
                    .Trim()
                    .Replace("\r", "")
                    .Replace("\n", "");

                // 自动补齐 Base64 Padding
                int mod = base64Text.Length % 4;
                if (mod != 0)
                    base64Text = base64Text.PadRight(base64Text.Length + (4 - mod), '=');

                byte[] data = Convert.FromBase64String(base64Text);
                return Encoding.UTF8.GetString(data);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 判断一个字符串是否“看起来像” base64（启发式）
        /// </summary>
        private static bool LooksLikeBase64( string text )
        {
            if (string.IsNullOrWhiteSpace(text)) return false;

            // Base64 仅允许 A-Z a-z 0-9 + / = -
            foreach (char c in text)
            {
                if (!(char.IsLetterOrDigit(c) || c == '+' || c == '/' || c == '=' || c == '-'))
                    return false;
            }

            // Base64 至少 12 字符（避免误判）
            return text.Length >= 12;
        }

        /// <summary>
        /// 判断解码后的内容是否为我们支持的协议链接
        /// </summary>
        private static bool LooksLikeProtocol( string decoded )
        {
            if (string.IsNullOrWhiteSpace(decoded)) return false;

            foreach (var prefix in ProtocolPrefixes)
            {
                if (decoded.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            // 也允许 decode 后前面有 BOM 或空格
            foreach (var prefix in ProtocolPrefixes)
            {
                if (decoded.Contains(prefix, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}