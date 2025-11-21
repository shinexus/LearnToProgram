using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

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
    public static async Task<(bool success, Stream? encryptedStream)> RealityHandshakeAsync(
        VlessNode node,
        Stream baseStream,
        string shortId,
        string pkOrPbk,
        string spx,
        string effectiveSni,
        CancellationToken ct )
    {
        if (baseStream == null || string.IsNullOrEmpty(shortId) || string.IsNullOrEmpty(pkOrPbk))
            return (false, null);

        try
        {
            // ===== 1. 解析服务端公钥 =====
            byte[] serverPubKey;
            try
            {
                // serverPubKey = Convert.FromBase64String(pkOrPbk);
                serverPubKey = ParseRealityPublicKey(pkOrPbk);
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
            var realityClientHello = BuildRealityClientHello(clientPub.GetEncoded(), shortId, spx, effectiveSni);
            // 增加随机 padding，符合协议规范，防止固定长度被识别
            // var realityClientHello = BuildRealityClientHello(clientPub.GetEncoded(), shortId, spx);

            // ===== 4. 发送 ClientHello =====
            using (var ctsTimeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                // 增加握手超时，避免阻塞
                ctsTimeout.CancelAfter(TimeSpan.FromSeconds(5)); 
                await baseStream.WriteAsync(realityClientHello.AsMemory(0, realityClientHello.Length), ctsTimeout.Token);
                await baseStream.FlushAsync(ctsTimeout.Token);
            }

            // ===== 5. 读取服务器初始响应 =====
            //至少 48 字节：32 pub + 16 tag
            var respBuf = ArrayPool<byte>.Shared.Rent(64);
            try
            {
                // 正确使用 ValueTask：无需 int read，直接 await
                // await baseStream.ReadExactlyAsync(respBuf.AsMemory(0, 48), ct).ConfigureAwait(false);
                // 使用自定义扩展方法，返回实际读取长度
                int readBytes = await baseStream.ReadExactlyWithLengthAsync(respBuf.AsMemory(0, 48), ct);
                LogHelper.Debug($"[REALITY] {node.Host}:{node.Port} 读取 {readBytes} 字节响应");

                // 读取 32 字节服务器公钥
                var serverPubFromResp = respBuf.AsSpan(0, 32).ToArray();
                // 读取 16 字节 Poly1305 tag
                var serverTag = respBuf.AsSpan(32, 16).ToArray();                

                // ===== 6. 计算（生成）共享密钥 =====
                var serverPubParam = new X25519PublicKeyParameters(serverPubKey, 0);

                var agreement = new X25519Agreement();
                agreement.Init(clientPriv);
                var sharedSecret = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(serverPubParam, sharedSecret, 0);

                // ===== 7. HKDF 派生密钥（Xray 官方实现）=====
                var (key, iv) = HkdfDeriveKeys(sharedSecret, "REALITY");

                // ===== 8. 验证服务器响应 MAC（Poly1305）=====                
                if (!VerifyPoly1305(serverPubFromResp, key, iv, serverTag))
                {
                    LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | sid={shortId}, pbk={Convert.ToBase64String(serverPubKey)} 服务器响应验证失败（可能公钥错误或被中间人）");
                    return (false, null);
                }

                LogHelper.Info($"[REALITY] {node.Host}:{node.Port} 握手成功！共享密钥建立，准备加密通信");

                // ===== 9. 创建并返回加密流 =====
                var encryptedStream = new ChaCha20Poly1305Stream(baseStream, key, iv, isClient: true);
                return (true, encryptedStream);                
            }
            catch (EndOfStreamException)
            {
                LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | sid={shortId}, pbk={Convert.ToBase64String(serverPubKey)} 服务器响应不完整（EndOfStream）");
                return (false, null);
            }
            catch (OperationCanceledException)
            {
                LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} 握手超时（Cancellation）");
                return (false, null);
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} 读取响应异常: {ex.Message}");
                return (false, null);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(respBuf);
            }
        }
        catch (OperationCanceledException oce)
        {
            // return false;
            LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} 握手超时: {oce.Message}");
            return (false, null);
        }
        catch(Exception ex)
        {
            // return false;
            LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} 握手失败: {ex.Message}");
            return (false, null);
        }
    }

    /// <summary>
    /// 构建 Reality ClientHello（增强版 + spx + 随机 padding）
    /// 符合 Xray-core REALITY 规范的 ClientHello（含 uTLS 指纹 + 正确 SNI）
    /// </summary>
    private static byte[] BuildRealityClientHello( 
        byte[] clientPubKey, 
        string shortId, 
        string spx, 
        string effectiveSni,
        string? fingerprint = null )
    {
        if (string.IsNullOrEmpty(effectiveSni))
            effectiveSni = "www.microsoft.com"; // 保险起见

        // 1. 生成 shortId 和 spx 字节
        var shortIdBytes = Encoding.UTF8.GetBytes(shortId);
        var spxBytes = Encoding.UTF8.GetBytes(spx ?? "/"); // spx 不为空时加入

        // 2. 增加 8~16 字节随机 padding
        // var rnd = RandomNumberGenerator.GetBytes(8);
        // Xray 官方就是这么干的
        var padding = new byte[8 + RandomNumberGenerator.GetInt32(9)]; // 8~16

        // 构造 REALITY 协议头：clientPubKey + shortId + spx + padding
        var realityHeader = new byte[clientPubKey.Length + shortIdBytes.Length + spxBytes.Length + padding.Length];
        int offset = 0;
        Array.Copy(clientPubKey, 0, realityHeader, offset, clientPubKey.Length);
        offset += clientPubKey.Length;
        Array.Copy(shortIdBytes, 0, realityHeader, offset, shortIdBytes.Length);
        offset += shortIdBytes.Length;
        Array.Copy(spxBytes, 0, realityHeader, offset, spxBytes.Length);
        offset += spxBytes.Length;
        Array.Copy(padding, 0, realityHeader, offset, padding.Length);

        // 3. 关键：使用 effectiveSni 构建真实 TLS ClientHello
        var tlsClientHello = TlsHelper.BuildChromeClientHello(effectiveSni);

        // 4. 合并：REALITY 头 +真实 TLS ClientHello（关键！）
        var realityHello = new byte[realityHeader.Length + tlsClientHello.Length];
        Array.Copy(realityHeader, 0, realityHello, 0, realityHeader.Length);
        Array.Copy(tlsClientHello, 0, realityHello, realityHeader.Length, tlsClientHello.Length);

        LogHelper.Verbose($"[REALITY] ClientHello 构建成功 | SNI={effectiveSni} | 协议头={realityHeader.Length} 字节 | 总长={realityHello.Length} 字节");

        return realityHello; // ← 现在才是正确的！        
    }

    /// <summary>
    /// Reality 公钥解析（支持 URL-safe Base64 + 补齐 + 长度检查）
    /// </summary>
    public static byte[] ParseRealityPublicKey( string pkOrPbk )
    {
        if (string.IsNullOrEmpty(pkOrPbk))
            throw new ArgumentException("公钥为空", nameof(pkOrPbk));

        // 第1步：先补齐 =（关键！必须先补齐）
        int padding = (4 - pkOrPbk.Length % 4) % 4;
        var padded = pkOrPbk + new string('=', padding);  // ← 先补齐！

        // 第2步：再把 URL-safe 字符转回标准 Base64
        var standard = padded.Replace('-', '+').Replace('_', '/');

        var bytes = Convert.FromBase64String(standard);
        if (bytes.Length != 32)
            throw new InvalidOperationException($"公钥长度错误: {bytes.Length} 字节");

        return bytes;
    }

    // HKDF-SHA256 派生 key 和 iv（32 + 12）
    private static (byte[] key, byte[] iv) HkdfDeriveKeys( byte[] ikm, string saltStr )
    {
        var salt = Encoding.UTF8.GetBytes(saltStr);

        // 根据官方文档使用小写 "reality" 作为 info
        // var info = Encoding.UTF8.GetBytes("REALITY");
        var info = Encoding.UTF8.GetBytes("reality");

        var prk = new byte[32];
        var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(new Sha256Digest());
        hmac.Init(new KeyParameter(ikm));
        hmac.BlockUpdate(salt, 0, salt.Length);
        hmac.BlockUpdate(info, 0, info.Length);
        hmac.DoFinal(prk, 0);

        var okm = new byte[44]; // 32 key + 12 iv
        hmac.Init(new KeyParameter(prk));
        hmac.BlockUpdate(okm, 0, 0);
        hmac.BlockUpdate([1]);
        hmac.DoFinal(okm, 0);

        var key = new byte[32];
        var iv = new byte[12];
        Array.Copy(okm, 0, key, 0, 32);
        Array.Copy(okm, 32, iv, 0, 12);
        return (key, iv);
    }

    // Poly1305 验证服务器响应
    private static bool VerifyPoly1305( byte[] message, byte[] key, byte[] nonce, byte[] expectedTag )
    {
        var poly = new Org.BouncyCastle.Crypto.Macs.Poly1305();
        var chacha = new Org.BouncyCastle.Crypto.Engines.ChaCha7539Engine();
        chacha.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        var polyKey = new byte[32];
        chacha.ProcessBytes(new byte[32], 0, 32, polyKey, 0);

        poly.Init(new KeyParameter(polyKey));
        poly.BlockUpdate(message, 0, message.Length);
        var calculatedTag = new byte[16];
        poly.DoFinal(calculatedTag, 0);

        return ConstantTimeEquals(calculatedTag, expectedTag);
    }

    private static bool ConstantTimeEquals( byte[] a, byte[] b )
    {
        if (a.Length != b.Length) return false;
        int result = 0;
        for (int i = 0; i < a.Length; i++)
            result |= a[i] ^ b[i];
        return result == 0;
    }

    // 自定义 ReadExactlyWithLength（返回实际字节数）
    public static async ValueTask<int> ReadExactlyWithLengthAsync( this Stream stream, Memory<byte> buffer, CancellationToken ct = default )
    {
        await stream.ReadExactlyAsync(buffer, ct);
        return buffer.Length;  // 总是等于请求长度（否则已抛异常）
    }


}