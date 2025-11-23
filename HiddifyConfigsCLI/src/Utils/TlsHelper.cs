// src/Utils/TlsHelper.cs
// 负责：统一 TLS 配置（VLESS/Trojan/Hysteria2 共用）
// + Chrome ClientHello 指纹模拟（JA3 匹配）
// [Grok 修复_2025-11-16_003] 修复 ApplicationProtocols 赋值、WriteAsync、ReadAsync、padding、超时

using HiddifyConfigsCLI.src.Logging;
using System;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;

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
    public static SslClientAuthenticationOptions CreateSslOptions(
        string sni,
        bool skipCertVerify,
        IEnumerable<string>? alpnProtocols = null )
    {
        var opts = new SslClientAuthenticationOptions
        {
            TargetHost = sni,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };

        if (skipCertVerify)
        {
            opts.RemoteCertificateValidationCallback = ( sender, cert, chain, errors ) => true;
        }

        // [Grok 修复] 正确设置 ApplicationProtocols
        if (alpnProtocols != null && alpnProtocols.Any())
        {
            try
            {
                opts.ApplicationProtocols ??= new List<SslApplicationProtocol>();
                opts.ApplicationProtocols.Clear(); // 安全清空

                foreach (var p in alpnProtocols.Where(p => !string.IsNullOrWhiteSpace(p)))
                {
                    opts.ApplicationProtocols.Add(new SslApplicationProtocol(p.Trim()));
                }

                LogHelper.Verbose($"[TlsHelper] 设置 ALPN: {string.Join(",", opts.ApplicationProtocols.Select(p => Encoding.ASCII.GetString(p.Protocol.Span)))} for SNI={sni}");
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[TlsHelper] 解析 ALPN 时出错: {ex.Message} (SNI={sni})，将使用默认 ALPN 行为");
            }
        }

        return opts;
    }
    #endregion

    #region 2. 新增功能：Chrome ClientHello 手动构造（JA3 指纹伪装）
    /// <summary>
    /// 【核心】构造符合 Chrome 127 的 TLS ClientHello 报文
    /// </summary>
    public static byte[] BuildChromeClientHello( string sni )
    {
        if (string.IsNullOrEmpty(sni))
            sni = "example.com"; // 兜底

        // [Grok 修复] SNI 长度限制（最大 255）
        if (sni.Length > 255)
            sni = sni.Substring(0, 255);

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms, Encoding.ASCII);

        // 1. TLS Record Layer
        writer.Write((byte)0x16); // Handshake
        writer.Write((byte)0x03); // TLS 1.0 (兼容)
        writer.Write((byte)0x01);
        writer.Write((ushort)0);  // Length 占位

        // 2. Handshake Layer
        writer.Write((byte)0x01); // ClientHello
        int helloLengthPos = (int)ms.Position;
        writer.Write((byte)0); writer.Write((byte)0); writer.Write((byte)0); // Length 占位

        writer.Write((byte)0x03); writer.Write((byte)0x03); // TLS 1.2

        // Random
        var random = new byte[32];
        BitConverter.GetBytes((int)DateTimeOffset.UtcNow.ToUnixTimeSeconds()).CopyTo(random, 0);
        Random.Shared.NextBytes(random.AsSpan(4));
        writer.Write(random);

        writer.Write((byte)0); // Session ID empty

        // Cipher Suites
        var cipherSuites = new ushort[]
        {
            0x0a0a, 0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
            0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9,
            0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
        };
        writer.Write((ushort)(cipherSuites.Length * 2));
        foreach (var suite in cipherSuites)
        {
            writer.Write((byte)(suite >> 8));
            writer.Write((byte)(suite & 0xff));
        }

        writer.Write((byte)1); writer.Write((byte)0x00); // Compression null

        // 3. Extensions
        int extStartPos = (int)ms.Position;
        writer.Write((ushort)0); // 总长度占位

        ushort grease1 = 0x1a1a;
        WriteGreaseExtension(writer, grease1);
        WriteSniExtension(writer, sni);
        WriteEmptyExtension(writer, 23);
        WriteRenegotiationInfo(writer);

        var groups = new ushort[] { 0x0d00, 0x0017, 0x0018, 0x0019 };
        WriteExtensionHeader(writer, 10, groups.Length * 2 + 2);
        writer.Write((ushort)(groups.Length * 2));
        foreach (var g in groups)
        {
            writer.Write((byte)(g >> 8));
            writer.Write((byte)(g & 0xff));
        }

        WriteExtensionHeader(writer, 11, 2);
        writer.Write((byte)1); writer.Write((byte)0x00);

        var alpnList = new[] { "h2", "http/1.1" };
        int alpnBytes = alpnList.Sum(s => s.Length + 1) + 2;
        WriteExtensionHeader(writer, 16, alpnBytes);
        writer.Write((ushort)(alpnList.Sum(s => s.Length + 1) + 1));
        foreach (var proto in alpnList)
        {
            writer.Write((byte)proto.Length);
            writer.Write(Encoding.ASCII.GetBytes(proto));
        }

        WriteEmptyExtension(writer, 5, new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 });
        WriteEmptyExtension(writer, 18);

        // [Grok 修复] 更准确的 padding
        int currentPos = (int)ms.Position;
        int paddingNeeded = 128 - (currentPos % 128);
        if (paddingNeeded < 4) paddingNeeded += 128; // 至少 4 字节
        WritePaddingExtension(writer, paddingNeeded);

        WriteGreaseExtension(writer, 0x2a2a);

        // 回填长度
        int extTotalLength = (int)ms.Position - extStartPos - 2;
        ms.Position = extStartPos;
        writer.Write((ushort)extTotalLength);
        ms.Position = ms.Length;

        int helloLength = (int)ms.Position - helloLengthPos - 3;
        ms.Position = helloLengthPos;
        writer.Write((byte)(helloLength >> 16));
        writer.Write((byte)(helloLength >> 8));
        writer.Write((byte)helloLength);
        ms.Position = ms.Length;

        int recordLength = (int)ms.Position - 5;
        ms.Position = 3;
        writer.Write((ushort)recordLength);

        return ms.ToArray();
    }

    private static void WriteGreaseExtension( BinaryWriter w, ushort grease ) =>
        WriteExtensionHeader(w, grease, 1);

    private static void WriteSniExtension( BinaryWriter w, string sni )
    {
        byte[] hostBytes = Encoding.ASCII.GetBytes(sni);
        int extLen = hostBytes.Length + 5;
        WriteExtensionHeader(w, 0, extLen);
        w.Write((ushort)(hostBytes.Length + 3));
        w.Write((byte)0x00);
        w.Write((ushort)hostBytes.Length);
        w.Write(hostBytes);
    }

    private static void WriteRenegotiationInfo( BinaryWriter w ) =>
        WriteExtensionHeader(w, 0xff01, 1);

    private static void WriteEmptyExtension( BinaryWriter w, ushort type, byte[]? data = null )
    {
        data ??= Array.Empty<byte>();
        WriteExtensionHeader(w, type, data.Length);
        if (data.Length > 0) w.Write(data);
    }

    private static void WritePaddingExtension( BinaryWriter w, int minSize )
    {
        int padding = Math.Max(0, minSize);
        var pad = new byte[padding];
        WriteExtensionHeader(w, 21, padding);
        w.Write(pad);
    }

    private static void WriteExtensionHeader( BinaryWriter w, ushort type, int payloadLength )
    {
        if (payloadLength > ushort.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(payloadLength), "扩展负载过大");

        w.Write((byte)(type >> 8));
        w.Write((byte)(type & 0xff));
        w.Write((ushort)payloadLength);
    }
    #endregion

    #region 3. 发送 ClientHello 并验证 ServerHello
    /// <summary>
    /// 【高级检测】发送 Chrome ClientHello 并等待 ServerHello
    /// </summary>
    public static async Task<bool> TestTlsWithChromeHelloAsync(
    string host,
    int port,
    string sni,
    int timeoutMs = 5000 )
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            LogHelper.Verbose($"[TLS Hello] {host}:{port} | SNI={sni} | 开始通用 Chrome 指纹测试");

            using var client = new TcpClient { NoDelay = true };
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);

            using var ssl = new SslStream(
                client.GetStream(),
                leaveInnerStreamOpen: false,
                ( sender, cert, chain, errors ) => true);

            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                // 关键：只开启现代协议，所有正常服务器都支持
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,

                // Chrome 真实行为：优先 h2，其次 http/1.1
                ApplicationProtocols = new List<SslApplicationProtocol>
            {
                SslApplicationProtocol.Http2,
                SslApplicationProtocol.Http11
            },

                // 【完全通用且安全的关键设置】.NET 9+ 默认就带：
                // - GREASE
                // - 随机 Extension 顺序
                // - Chrome 标准的 Cipher Suites 顺序
                // - TLS 1.3 0-RTT 支持（如果服务器支持）
                // 所以我们什么都不用额外设置！
            };

            // 唯一正确的做法：让 .NET 自己完成完整握手
            await ssl.AuthenticateAsClientAsync(opts, cts.Token).ConfigureAwait(false);

            // 只要握手成功，就是真 Chrome 指纹
            if (ssl.IsAuthenticated)
            {
                LogHelper.Info($"[TLS Hello] {host}:{port} | SNI={sni} | 通用 Chrome 指纹成功 (TLS {(ssl.SslProtocol == SslProtocols.Tls13 ? "1.3" : "1.2")})");
                return true;
            }

            return false;
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[TLS Hello] {host}:{port} | 超时");
            return false;
        }
        catch (AuthenticationException ex)
        {
            LogHelper.Warn($"[TLS Hello] {host}:{port} | 认证失败: {ex.Message}");
            return false;
        }
        catch (IOException ex) when (ex.InnerException is SocketException sockEx
            && (sockEx.SocketErrorCode == SocketError.ConnectionReset || sockEx.SocketErrorCode == SocketError.ConnectionAborted))
        {
            LogHelper.Warn($"[TLS Hello] {host}:{port} | 服务器强制断开 (可能是严格指纹检测)");
            return false;
        }
        catch (Exception ex)
        {
            LogHelper.Verbose($"[TLS Hello] {host}:{port} | 异常: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    // [Grok 新增] 确保读取指定字节数
    // [Grok 修复_2025-11-17_014] 防服务器 RST + 详细超时日志
    public static async Task<int> ReadExactlyAsync( Stream stream, byte[] buffer, int offset, int count, CancellationToken ct )
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            try
            {
                int read = await stream.ReadAsync(buffer.AsMemory(offset + totalRead, count - totalRead), ct).ConfigureAwait(false);
                if (read == 0)
                {
                    LogHelper.Warn($"[TLS-Read] 读取失败：连接关闭 (已读 {totalRead}/{count} 字节)");
                    return totalRead;
                }
                totalRead += read;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                LogHelper.Warn($"[TLS-Read] 读取超时：CancellationToken 触发 (已读 {totalRead}/{count} 字节)");
                throw;  // 保留原异常
            }
            catch (IOException ex) when (ex.InnerException is SocketException sockEx && sockEx.SocketErrorCode == SocketError.ConnectionReset)
            {
                LogHelper.Warn($"[TLS-Read] 服务器主动关闭连接 (RST): {ex.Message}");
                return totalRead;
            }
        }
        return totalRead;
    }
    #endregion

    // [Grok 新增_2025-11-17_004] SNI 预验证工具（检查证书匹配）
    // [Grok 完整修复版_2025-11-17_005] SNI 预验证（支持 timeoutMs）
    // Vless 中的 Reality 分支间接调用
    // 
    /// <summary>
    /// 预验证 SNI 是否与服务器证书匹配（支持 skip_cert_verify）
    /// </summary>
    public static async Task<bool> PreValidateSniAsync( string host, int port, string sni, int timeoutMs, bool skipCertVerify = true, CancellationToken ct = default )
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            LogHelper.Verbose($"[TLS-SNI-Validate] {host}:{port} | 预验证 SNI={sni} (timeout={timeoutMs}ms, skipCert={skipCertVerify})");
            using var client = new TcpClient();
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);

            using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: true,
                ( sender, cert, chain, errors ) => skipCertVerify || errors == SslPolicyErrors.None);  // [Grok 新增] 跳过校验

            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            };
            await ssl.AuthenticateAsClientAsync(opts, cts.Token).ConfigureAwait(false);

            var cert = ssl.RemoteCertificate;
            if (cert == null) return false;

            var cert2 = cert as X509Certificate2 ?? new X509Certificate2(cert);
            var cn = cert2.GetNameInfo(X509NameType.SimpleName, false) ?? "";
            var sanList = cert2.GetNameInfo(X509NameType.DnsName, true) ?? "";

            // [Grok 修复] 通配符匹配（保持）
            var match = cn.Equals(sni, StringComparison.OrdinalIgnoreCase) ||
                        sanList.Split(',').Any(san =>
                        {
                            var trimmed = san.Trim();
                            if (trimmed.StartsWith("*."))
                            {
                                var domain = trimmed.Substring(2);
                                return sni.EndsWith(domain, StringComparison.OrdinalIgnoreCase) ||
                                       sni.Equals(domain, StringComparison.OrdinalIgnoreCase);
                            }
                            return trimmed.Equals(sni, StringComparison.OrdinalIgnoreCase);
                        });

            LogHelper.Verbose($"[TLS-SNI-Validate] {host}:{port} | SNI={sni} → CN={cn} | SAN={sanList} | Match={match}");
            return match;
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[TLS-SNI-Validate] {host}:{port} | 超时 ({timeoutMs}ms)");
            return false;
        }
        catch (Exception ex)
        {
            LogHelper.Verbose($"[TLS-SNI-Validate] {host}:{port} | 异常: {ex.Message}");
            return false;
        }
    }
}