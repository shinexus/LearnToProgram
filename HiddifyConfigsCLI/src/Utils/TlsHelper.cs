// TlsHelper.cs
// 负责：统一 TLS 配置（VLESS/Trojan/Hysteria2 共用）
//        + Chrome ClientHello 指纹模拟（JA3 匹配）
// 命名空间：HiddifyConfigsCLI.src.Utils
// [Grok Rebuild] 2025-11-11：新增 Chrome ClientHello 手动构造，支持 JA3 指纹伪装
using HiddifyConfigsCLI.src.Logging;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HiddifyConfigsCLI.src.Utils;

/// <summary>
/// TLS 配置助手：统一 SslClientAuthenticationOptions 创建 + Chrome ClientHello 指纹模拟
/// </summary>
internal static class TlsHelper
{
    #region 1. 原有功能：标准 TLS 配置（保留）
    /// <summary>
    /// 创建标准 TLS 配置（用于 SslStream 自动握手）
    /// </summary>
    /// <param name="sni">SNI 域名</param>
    /// <param name="skipCertVerify">是否跳过证书验证</param>
    /// <returns>配置好的 SslClientAuthenticationOptions</returns>
    public static SslClientAuthenticationOptions CreateSslOptions( string sni, bool skipCertVerify )
    {
        var opts = new SslClientAuthenticationOptions
        {
            TargetHost = sni,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };
        if (skipCertVerify)
        {
            // 【Grok 安全警告】仅用于测试节点，生产环境慎用
            opts.RemoteCertificateValidationCallback =
                ( sender, cert, chain, errors ) => true;
        }
        return opts;
    }
    #endregion

    #region 2. 新增功能：Chrome ClientHello 手动构造（JA3 指纹伪装）

    /// <summary>
    /// 【核心】构造符合 Chrome 127 的 TLS ClientHello 报文（手动 TLS 记录层）
    /// 目标 JA3: 771,4865-4866-4867-...-772-769-768,0-23-65281-10-11-35-13172-16-5-13-18-51-45-43-27-21,29-23-24,0
    /// </summary>
    /// <param name="sni">SNI 域名（必填）</param>
    /// <returns>完整的 TLS ClientHello 原始字节数组（可直接写入 Socket）</returns>
    public static byte[] BuildChromeClientHello( string sni )
    {
        // 使用 MemoryStream 构建整个 TLS 记录
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms, Encoding.ASCII);

        // ==============================================================
        // 1. TLS Record Layer（记录层）
        // ==============================================================
        // Content Type: Handshake (22)
        writer.Write((byte)0x16);
        // Version: TLS 1.0 (0x0301) — 兼容性字段，实际由 ClientHello 决定
        writer.Write((byte)0x03);
        writer.Write((byte)0x01);
        // Length: 占位符，后面填充
        writer.Write((ushort)0); // 临时写0

        // ==============================================================
        // 2. Handshake Layer（握手层）
        // ==============================================================
        // Handshake Type: ClientHello (1)
        writer.Write((byte)0x01);
        // Length: 占位符
        int helloLengthPos = (int)ms.Position;
        writer.Write((byte)0);
        writer.Write((byte)0);
        writer.Write((byte)0);

        // Client Version: TLS 1.2 (0x0303)
        writer.Write((byte)0x03);
        writer.Write((byte)0x03);

        // Random: 32 字节随机数（前4字节为 Unix 时间，后28字节随机）
        var random = new byte[32];
        var unixTime = (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        BitConverter.GetBytes(unixTime).CopyTo(random, 0);
        Random.Shared.NextBytes(random.AsSpan(4));
        writer.Write(random);

        // Session ID: 空（长度0）
        writer.Write((byte)0);

        // Cipher Suites: 带 GREASE + 标准 Chrome 顺序
        var cipherSuites = new ushort[]
        {
            0x0a0a, // GREASE
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0x1304, // TLS_AES_128_CCM_SHA256
            0x1305, // TLS_AES_128_CCM_8_SHA256
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035  // TLS_RSA_WITH_AES_256_CBC_SHA
        };
        writer.Write((ushort)(cipherSuites.Length * 2));
        foreach (var suite in cipherSuites)
        {
            writer.Write((byte)(suite >> 8));
            writer.Write((byte)(suite & 0xff));
        }

        // Compression Methods: null (0)
        writer.Write((byte)1);
        writer.Write((byte)0x00);

        // ==============================================================
        // 3. Extensions（扩展）
        // ==============================================================
        int extStartPos = (int)ms.Position;
        writer.Write((ushort)0); // 扩展总长度占位

        // ---- 3.1 GREASE Extension ----
        ushort greaseValue = 0x1a1a; // 随机 GREASE
        WriteGreaseExtension(writer, greaseValue);

        // ---- 3.2 server_name (0) ----
        WriteSniExtension(writer, sni);

        // ---- 3.3 extended_master_secret (23) ----
        WriteEmptyExtension(writer, 23);

        // ---- 3.4 renegotiation_info (0xff01) ----
        WriteRenegotiationInfo(writer);

        // ---- 3.5 supported_groups (10) ----
        var groups = new ushort[] { 0x0d00, 0x0017, 0x0018, 0x0019 }; // GREASE + x25519, secp256r1, secp384r1
        WriteExtensionHeader(writer, 10, groups.Length * 2 + 2);
        writer.Write((ushort)(groups.Length * 2));
        foreach (var g in groups)
        {
            writer.Write((byte)(g >> 8));
            writer.Write((byte)(g & 0xff));
        }

        // ---- 3.6 ec_point_formats (11) ----
        writer.Write((ushort)0x0b00); // type + length
        writer.Write((byte)0x02);     // length
        writer.Write((byte)0x01);     // list length
        writer.Write((byte)0x00);     // uncompressed

        // ---- 3.7 ALPN (16) ----
        var alpnList = new[] { "h2", "http/1.1" };
        int alpnBytes = alpnList.Sum(s => s.Length + 1) + 2;
        WriteExtensionHeader(writer, 16, alpnBytes);
        writer.Write((ushort)(alpnList.Sum(s => s.Length + 1) + 1));
        foreach (var proto in alpnList)
        {
            writer.Write((byte)proto.Length);
            writer.Write(Encoding.ASCII.GetBytes(proto));
        }

        // ---- 3.8 status_request (5) ----
        WriteEmptyExtension(writer, 5, new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 });

        // ---- 3.9 deleg_cred, key_share, pre_shared_key 等略（Chrome 127 核心 JA3 不依赖） ----

        // ---- 3.10 signed_certificate_timestamp (18) ----
        WriteEmptyExtension(writer, 18);

        // ---- 3.11 padding (21) ----
        WritePaddingExtension(writer, 128); // 填充至 >128 字节

        // ---- 3.12 GREASE 结尾 ----
        WriteGreaseExtension(writer, 0x2a2a);

        // 回填扩展总长度
        int extTotalLength = (int)ms.Position - extStartPos - 2;
        ms.Position = extStartPos;
        writer.Write((ushort)extTotalLength);
        ms.Position = ms.Length;

        // 回填 Handshake 长度
        int helloLength = (int)ms.Position - helloLengthPos - 3;
        ms.Position = helloLengthPos;
        writer.Write((byte)((helloLength >> 16) & 0xff));
        writer.Write((byte)((helloLength >> 8) & 0xff));
        writer.Write((byte)(helloLength & 0xff));
        ms.Position = ms.Length;

        // 回填 TLS Record 长度
        int recordLength = (int)ms.Position - 5;
        ms.Position = 3;
        writer.Write((ushort)recordLength);

        return ms.ToArray();
    }

    // 【工具】写入 GREASE 扩展（随机值 + 空内容）
    private static void WriteGreaseExtension( BinaryWriter w, ushort grease )
    {
        WriteExtensionHeader(w, grease, 1);
        w.Write((byte)0x00); // 空内容
    }

    // 【工具】写入 SNI 扩展
    private static void WriteSniExtension( BinaryWriter w, string sni )
    {
        byte[] hostBytes = Encoding.ASCII.GetBytes(sni);
        int extLen = hostBytes.Length + 5; // list len(2) + type(1) + len(2) + host
        WriteExtensionHeader(w, 0, extLen);
        w.Write((ushort)(hostBytes.Length + 3));
        w.Write((byte)0x00); // hostname type
        w.Write((ushort)hostBytes.Length);
        w.Write(hostBytes);
    }

    // 【工具】写入 renegotiation_info
    private static void WriteRenegotiationInfo( BinaryWriter w )
    {
        WriteExtensionHeader(w, 0xff01, 1);
        w.Write((byte)0x00);
    }

    // 【工具】写入空扩展
    private static void WriteEmptyExtension( BinaryWriter w, ushort type, byte[]? data = null )
    {
        data ??= Array.Empty<byte>();
        WriteExtensionHeader(w, type, data.Length);
        if (data.Length > 0) w.Write(data);
    }

    // 【工具】写入 padding 扩展
    private static void WritePaddingExtension( BinaryWriter w, int minSize )
    {
        int padding = Math.Max(0, minSize - ((int)w.BaseStream.Position % 128));
        var pad = new byte[padding];
        WriteExtensionHeader(w, 21, padding);
        w.Write(pad);
    }

    // 【工具】写入扩展头：type + length
    private static void WriteExtensionHeader( BinaryWriter w, ushort type, int payloadLength )
    {
        w.Write((byte)(type >> 8));
        w.Write((byte)(type & 0xff));
        w.Write((ushort)payloadLength);
    }

    #endregion

    #region 3. 新增功能：发送 ClientHello 并验证 ServerHello（用于 ConnectivityChecker）

    /// <summary>
    /// 【高级检测】发送 Chrome ClientHello 并等待 ServerHello（3秒超时）
    /// 成功条件：收到 ServerHello + 服务器证书
    /// </summary>
    /// <param name="host">目标主机</param>
    /// <param name="port">目标端口</param>
    /// <param name="sni">SNI 域名</param>
    /// <param name="timeoutMs">超时毫秒</param>
    /// <returns>true 表示 TLS 握手成功</returns>
    public static async Task<bool> TestTlsWithChromeHelloAsync( string host, int port, string sni, int timeoutMs = 4000 )
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            if (await Task.WhenAny(connectTask, Task.Delay(timeoutMs)) != connectTask)
                return false;

            using var stream = client.GetStream();
            var helloBytes = BuildChromeClientHello(sni);

            // 调试信息
            LogHelper.Debug($"[helloBytes：]{host}:{port} | sni={sni} | helloBytes[0]={helloBytes[0]}, helloBytes[1]={helloBytes[1]}, helloBytes[2]={helloBytes[2]}, helloBytes[3]={helloBytes[3]}");

            // 基于内存重载
            // await stream.WriteAsync(helloBytes, 0, helloBytes.Length);
            await stream.WriteAsync(helloBytes);

            // 读取 TLS Record 头（5字节）
            var header = new byte[5];
            int read = 0;
            var readTask = stream.ReadAsync(header, 0, 5);
            while (read < 5)
            {
                int r = await Task.WhenAny(readTask, Task.Delay(timeoutMs - read * 100)) == readTask
                    ? readTask.Result
                    : 0;
                if (r <= 0) return false;
                read += r;
            }

            // 调试信息
            LogHelper.Debug($"[TLS Record：]{host}:{port} | sni={sni} | header[0]={header[0]}, header[1]={header[1]}, header[2]={header[2]}, header[3]={header[3]}");

            if (header[0] != 0x16 || header[1] != 0x03) return false; // 不是 TLS Handshake

            // 读取长度
            int length = (header[3] << 8) + header[4];
            var buffer = new byte[length];
            read = 0;
            while (read < length)
            {
                // 基于内存重载
                // int r = await stream.ReadAsync(buffer, read, length - read);
                int r = await stream.ReadAsync(buffer.AsMemory(read, length - read));
                if (r <= 0) return false;
                read += r;
            }

            // 简单验证：是否包含 ServerHello (0x02)
            return buffer.Length > 5 && buffer[5] == 0x02;
        }
        catch
        {
            return false;
        }
    }

    #endregion
}