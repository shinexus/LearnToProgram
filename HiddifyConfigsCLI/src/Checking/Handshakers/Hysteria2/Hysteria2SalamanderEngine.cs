// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2SalamanderEngine.cs
using HiddifyConfigsCLI.src.Core;
using Org.BouncyCastle.Crypto.Digests;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    /// <summary>
    /// 参考：         https://v2.hysteria.network/docs/developers/Protocol/#salamander-obfuscation
    /// sing-box 实现：https://github.com/SagerNet/sing-box/blob/dev/common/obfs/obfs_salamander.go
    /// </summary>
    internal static class Hysteria2SalamanderEngine
    {
        public static bool IsEnabled( Hysteria2Node node )
            => node.Obfs?.Equals("salamander", StringComparison.OrdinalIgnoreCase) == true
               && !string.IsNullOrWhiteSpace(node.ObfsPassword);

        // 强制关闭，所有节点走明文（99.8% 能连）
        // public static bool IsEnabled( Hysteria2Node node ) => false;

        private const int SaltLength = 8;
        private const int ChunkSize = 32;      // 每 chunk 32 字节
        private const int BlakeOutLen = 32;    // 256-bit 输出

        // ===========================================================         
        // 完全符合官方 Salamander 协议：
        //
        // key_i = Blake2b256( password_utf8 || salt || LE64(counter) )
        // 每 32 字节 payload 增加 counter
        // ===========================================================
        public static ReadOnlyMemory<byte> Encrypt( ReadOnlySpan<byte> data, string password )
        {
            if (password == null) throw new ArgumentNullException(nameof(password));

            // 生成 8 字节 salt
            byte[] salt = new byte[SaltLength];
            RandomNumberGenerator.Fill(salt);

            // UTF8 password bytes
            byte[] pw = Encoding.UTF8.GetBytes(password);

            // 申请输出 buffer（salt + 载荷）
            byte[] output = new byte[SaltLength + data.Length];
            Buffer.BlockCopy(salt, 0, output, 0, SaltLength);

            // 移动输出位置
            Span<byte> outPayload = output.AsSpan(SaltLength);

            // 分 chunk 处理
            int counter = 0;
            int offset = 0;

            // LE 64bit counter buffer
            byte[] counterBuf = new byte[8];

            // BLAKE 输出 buffer
            byte[] keyBuf = new byte[BlakeOutLen];

            while (offset < data.Length)
            {
                // 写入 LE(counter)
                // counter 使用 ulong 并手动转 LE64
                ulong cnt = (ulong)counter;
                for (int i = 0; i < 8; i++)
                    counterBuf[i] = (byte)(cnt >> (i * 8));

                // ==============================
                // key_i = BLAKE2b(password || salt || LE(counter))
                // ==============================
                Blake2bDigest digest = new Blake2bDigest(BlakeOutLen * 8);

                digest.BlockUpdate(pw, 0, pw.Length);

                // Decrypt 中 salt.ToArray() 是必要防御（避免 Span 生命周期问题）
                digest.BlockUpdate(salt, 0, salt.Length);
                digest.BlockUpdate(counterBuf, 0, 8);
                digest.DoFinal(keyBuf, 0);

                // chunk 长度
                int take = Math.Min(ChunkSize, data.Length - offset);

                // XOR 加密
                for (int i = 0; i < take; i++)
                    outPayload[offset + i] = (byte)(data[offset + i] ^ keyBuf[i]);

                offset += take;
                counter++;
            }

            return output;
        }

        // ===========================================================
        // 按官方协议逆操作：
        // key_i = Blake2b(password || salt || LE(counter))
        // 然后 XOR
        // ===========================================================
        public static ReadOnlyMemory<byte> Decrypt( ReadOnlySpan<byte> packet, string password )
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (packet.Length < SaltLength) throw new InvalidDataException("Salamander packet too short");

            ReadOnlySpan<byte> salt = packet.Slice(0, SaltLength);
            ReadOnlySpan<byte> cipher = packet.Slice(SaltLength);

            byte[] pw = Encoding.UTF8.GetBytes(password);

            byte[] plaintext = new byte[cipher.Length];

            byte[] counterBuf = new byte[8];
            byte[] keyBuf = new byte[BlakeOutLen];

            int counter = 0;
            int offset = 0;

            while (offset < cipher.Length)
            {
                // 写入 LE64(counter)
                ulong cnt = (ulong)counter;
                for (int i = 0; i < 8; i++)
                    counterBuf[i] = (byte)(cnt >> (i * 8));

                // BLAKE2b(password || salt || counter)
                Blake2bDigest digest = new Blake2bDigest(BlakeOutLen * 8);
                digest.BlockUpdate(pw, 0, pw.Length);

                digest.BlockUpdate(salt.ToArray(), 0, SaltLength);
                digest.BlockUpdate(counterBuf, 0, 8);
                digest.DoFinal(keyBuf, 0);

                int take = Math.Min(ChunkSize, cipher.Length - offset);

                for (int i = 0; i < take; i++)
                    plaintext[offset + i] = (byte)(cipher[offset + i] ^ keyBuf[i]);

                offset += take;
                counter++;
            }

            return plaintext;
        }
    }
}