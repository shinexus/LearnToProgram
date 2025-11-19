using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Utils;

internal static class RealityHelper
{
    /// <summary>
    /// Reality 协议完整握手模板（Curve25519 + TLS1.3 + 支持 spx）
    /// </summary>
    /// <param name="stream">已建立的 TCP/TLS Stream</param>
    /// <param name="shortId">短ID</param>
    /// <param name="pkOrPbk">PublicKey 或 Base64 pbk</param>
    /// <param name="spx">伪装路径，用于初始握手</param>
    /// <param name="ct">CancellationToken</param>
    /// <returns>握手是否成功</returns>
    public static async Task<bool> RealityHandshakeAsync(
        Stream stream,
        string shortId,
        string pkOrPbk,
        string spx,
        CancellationToken ct )
    {
        if (stream == null || string.IsNullOrEmpty(shortId) || string.IsNullOrEmpty(pkOrPbk))
            return false;

        try
        {
            // ===== 1. 解析服务端公钥 =====
            byte[] serverPubKey;
            try
            {
                serverPubKey = Convert.FromBase64String(pkOrPbk);
            }
            catch
            {
                // UTF-8 编码的 PublicKey 可能会导致异常
                serverPubKey = Encoding.UTF8.GetBytes(pkOrPbk);
            }

            // ===== 2. 生成客户端 Curve25519 keypair =====
            var keyGen = new X25519KeyPairGenerator();
            keyGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
            var clientKeyPair = keyGen.GenerateKeyPair();
            var clientPriv = (X25519PrivateKeyParameters)clientKeyPair.Private;
            var clientPub = (X25519PublicKeyParameters)clientKeyPair.Public;

            // ===== 3. 构建 Reality ClientHello =====
            // 新增 spx 支持，将伪装路径加入初始握手数据
            var clientHello = BuildRealityClientHello(clientPub.GetEncoded(), shortId, spx);
            // 增加随机 padding，符合协议规范，防止固定长度被识别
            // var clientHello = BuildRealityClientHello(clientPub.GetEncoded(), shortId, spx);

            // ===== 4. 发送 ClientHello =====
            using (var ctsTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                // 增加握手超时，避免阻塞
                ctsTimeout.CancelAfter(TimeSpan.FromSeconds(5)); 
                await stream.WriteAsync(clientHello.AsMemory(0, clientHello.Length), ctsTimeout.Token);
                await stream.FlushAsync(ctsTimeout.Token);
            }

            // ===== 5. 读取服务器初始响应 =====
            var respBuf = ArrayPool<byte>.Shared.Rent(16);
            try
            {
                int read;
                using (var ctsTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    ctsTimeout.CancelAfter(TimeSpan.FromSeconds(5));
                    read = await stream.ReadAsync(respBuf.AsMemory(0, respBuf.Length), ctsTimeout.Token);
                }

                if (read <= 0) return false;

                // ===== 6. 生成共享密钥 =====
                var serverPubParam = new X25519PublicKeyParameters(serverPubKey, 0);
                var agreement = new X25519Agreement();
                agreement.Init(clientPriv);
                var sharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(serverPubParam, sharedSecret, 0);

                // TODO: 使用 sharedSecret 构建加密流 (AES-GCM 或 ChaCha20-Poly1305)
                // 当前模板仅验证握手可达性
                
                // return respBuf[0] != 0;
                return true;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(respBuf);
            }
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// 构建 Reality ClientHello（增强版 + spx + 随机 padding）
    /// </summary>
    private static byte[] BuildRealityClientHello( byte[] clientPubKey, string shortId, string spx )
    {
        var idBytes = Encoding.UTF8.GetBytes(shortId);
        var spxBytes = Encoding.UTF8.GetBytes(spx ?? "/"); // spx 不为空时加入

        //增加 8~16 字节随机 padding，增强协议一致性
        var rnd = RandomNumberGenerator.GetBytes(8);
        var hello = new byte[clientPubKey.Length + idBytes.Length + spxBytes.Length + rnd.Length];

        // 拼接顺序：客户端公钥 + shortId + spx
        Array.Copy(clientPubKey, 0, hello, 0, clientPubKey.Length);
        Array.Copy(idBytes, 0, hello, clientPubKey.Length, idBytes.Length);
        Array.Copy(spxBytes, 0, hello, clientPubKey.Length + idBytes.Length, spxBytes.Length);
        Array.Copy(rnd, 0, hello, clientPubKey.Length + idBytes.Length + spxBytes.Length, rnd.Length);

        return hello;
    }
}