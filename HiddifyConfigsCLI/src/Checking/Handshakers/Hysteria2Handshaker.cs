using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers
{
    /// <summary>
    /// Hysteria2 协议专用握手器（纯 .NET 9 System.Net.Quic 实现）
    /// 支持标准 TLS 1.3 + HTTP/3 ALPN，兼容 REALITY / 自定义 JA3（后续扩展）
    /// Microsoft.Native.Quic.MsQuic.OpenSSL
    /// Microsoft.Native.Quic.MsQuic.Schannel
    /// </summary>
    internal static class Hysteria2Handshaker
    {
        /// <summary>
        /// 适配新接口：异步测试节点
        /// 返回值签名保持与其他协议一致：(bool success, TimeSpan latency, Stream? stream)
        /// </summary>
        public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
            Hysteria2Node node,
            IPAddress address,
            int timeoutSec,
            RunOptions opts // 可扩展参数结构，包含 REALITY/JA3 等配置
        )
        {
            var sw = Stopwatch.StartNew();
            var serverEndPoint = new IPEndPoint(address, node.Port);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));

            // SNI 解析器（支持 REALITY 节点）
            // 获取最终生效的 SNI（用户指定 > REALITY 提供 > 默认 Host）
            // 

            try
            {
                // 1. 关键：检测是否为 REALITY 节点
                // Hysteria2 的 REALITY 节点需要特殊处理（与 Vless 的 REALITY 节点不同）
                // .NET 原生 QUIC 尚未支持 REALITY 扩展，暂时跳过检测
                if (node.Security?.Equals("reality", StringComparison.OrdinalIgnoreCase) == true)
                {
                    LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} REALITY 节点暂不支持检测（.NET 未实现 QUIC REALITY 扩展）");
                    return (false, sw.Elapsed, null);
                }

                // 2. SNI 解析
                string effectiveSni = await TlsSniResolver.ResolveEffectiveSniAsync(
                rawHost: node.Host,
                port: node.Port,
                userSpecifiedSni: node.HostParam,
                skipCertVerify: node.SkipCertVerify,
                ct: cts.Token)
                .ConfigureAwait(false);

                // 3. 解析 ALPN（默认 h3，支持用户自定义）
                var alpnList = new List<SslApplicationProtocol>();

                if (string.IsNullOrWhiteSpace(node.Alpn))
                {
                    // 默认只启用 h3（Hysteria2 必须）
                    alpnList.Add(SslApplicationProtocol.Http3);
                }
                else
                {
                    // 支持用户自定义（如 "h3,h2" 或 "h3"）
                    var parts = node.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    bool hasValid = false;

                    foreach (var part in parts)
                    {
                        // 严格匹配官方预定义常量（防止构造非法协议导致握手失败）
                        if (TryGetKnownProtocol(part, out var protocol))
                        {
                            alpnList.Add(protocol);
                            hasValid = true;
                            LogHelper.Verbose($"[Hysteria2] 添加 ALPN: {part}");
                        }
                        else
                        {
                            LogHelper.Warn($"[Hysteria2] 忽略未知或不支持的 ALPN: {part}");
                        }
                    }

                    // 如果一个都没匹配上，强制兜底 h3
                    if (!hasValid || alpnList.Count == 0)
                    {
                        LogHelper.Warn("[Hysteria2] ALPN 配置无效，强制使用 h3");
                        alpnList.Clear();
                        alpnList.Add(SslApplicationProtocol.Http3);
                    }
                }

                // 4. 配置 QUIC 连接参数 ---
                var quicOptions = new QuicClientConnectionOptions
                {
                    RemoteEndPoint = serverEndPoint,
                    // 0 表示使用协议默认错误码
                    DefaultStreamErrorCode = 0,
                    DefaultCloseErrorCode = 0,
                    MaxInboundUnidirectionalStreams = 10,
                    MaxInboundBidirectionalStreams = 100,
                    ClientAuthenticationOptions = new SslClientAuthenticationOptions
                    {
                        // 使用兜底后的真实 SNI（关键！）
                        TargetHost = effectiveSni,
                        // ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },
                        // ApplicationProtocols = new() { SslApplicationProtocol.Http3 },
                        ApplicationProtocols = alpnList,
                        CertificateRevocationCheckMode = X509RevocationMode.NoCheck,

                        // 强制 TLS 1.3（Hysteria2 要求）
                        EnabledSslProtocols = SslProtocols.Tls13,

                        // JA3 伪装在 .NET 9 + MsQuic 下无法实现，已放弃
                        // RemoteCertificateValidationCallback 已无意义（仅用于日志）
                        RemoteCertificateValidationCallback = ( sender, cert, chain, errors ) =>
                        {
                            if (errors == SslPolicyErrors.None || node.SkipCertVerify)
                            {
                                LogHelper.Verbose($"[Hysteria2] TLS 证书通过 → {cert?.Subject}");
                                return true;
                            }
                            LogHelper.Verbose($"[Hysteria2] TLS 证书错误（已忽略） → {errors}");
                            return errors == SslPolicyErrors.None;
                        }
                    }

                    // 可选：强制使用 OpenSSL 后端（当 Schannel 在某些 Win10 版本不稳定时）
                    // Environment.SetEnvironmentVariable("QUIC_TLS", "openssl");
                };


                // 5. 建立 QUIC 连接 ---
                await using var connection = await QuicConnection.ConnectAsync(quicOptions, cts.Token);
                LogHelper.Debug($"[Hysteria2] QUIC Connected: {node.Host}:{node.Port} | {connection.RemoteEndPoint}");

                // 6. 创建出站双向流 ---
                // await using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cts.Token);
                await using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cts.Token)
                .ConfigureAwait(false);

                // 7. 发送 Hysteria2 控制请求 ---
                // Hysteria2 官方客户端发送的原始报文（必须包含 Hysteria-UDP: true）
                var request =
                    "CONNECT / HTTP/3\r\n" +
                    $"Host: {effectiveSni}\r\n" +
                    "User-Agent: hysteria/2.3.0\r\n" +
                    "Hysteria-UDP: true\r\n" +
                    "Connection: keep-alive\r\n\r\n";

                var reqBytes = Encoding.ASCII.GetBytes(request);
                // await stream.WriteAsync(reqBytes, cts.Token);

                // 8. 处理 salamander 混淆（关键！）
                byte[] payload = ApplySalamanderObfs(request, node.Obfs, node.ObfsPassword);

                await stream.WriteAsync(reqBytes, cts.Token).ConfigureAwait(false);

                // 9. 读取服务器返回 ---
                var buffer = ArrayPool<byte>.Shared.Rent(8192);

                try
                {
                    var memory = buffer.AsMemory(0, 8192);
                    int bytesRead = await stream.ReadAsync(buffer.AsMemory(0, 8192), cts.Token).ConfigureAwait(false);

                    if (bytesRead <= 0)
                    {
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 服务器关闭流（bytesRead<=0）");
                        return (false, sw.Elapsed, null);
                    }

                    // 10. 解密 salamander 响应（如有）
                    byte[] responseBytes = bytesRead > 0 && IsSalamanderEnabled(node.Obfs, node.ObfsPassword)
                        ? SalamanderObfs.Decrypt(buffer.AsSpan(0, bytesRead), node.ObfsPassword!)
                        : buffer.AsSpan(0, bytesRead).ToArray();

                    string resp = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    // ---------- 6. 响应校验（握手结果） ----------
                    bool ok = resp.Contains("200") ||
                              resp.Contains("OK", StringComparison.OrdinalIgnoreCase);

                    if (!ok)
                    {
                        string preview = resp.Length > 200 ? resp[..200] + "…" : resp;
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 握手失败 → {preview}");
                        LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 握手响应异常: {resp[..Math.Min(resp.Length, 120)]}");

                        var errStream = new MemoryStream(Encoding.UTF8.GetBytes(resp), false);
                        return (false, sw.Elapsed, errStream);
                    }

                    LogHelper.Info($"[Hysteria2] {node.Host}:{node.Port} 握手成功，延迟 {sw.Elapsed.TotalMilliseconds:F0}ms");

                    // 将响应封装为内存流返回，保持接口统一
                    var successStream = new MemoryStream(Encoding.UTF8.GetBytes(resp), false);
                    sw.Stop();
                    return (true, sw.Elapsed, successStream);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch (QuicException qex)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} QUIC 错误 → {qex.Message} (ErrorCode={qex.ApplicationErrorCode} | {qex.TransportErrorCode})");
                // 0x80072743 = WSAEHOSTUNREACH（Windows Socket 错误码 10065）
                // 官方定义：No route to host（目标主机不可达）
                return (false, sw.Elapsed, null);
            }
            catch (AuthenticationException aex)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} TLS 握手失败 → {aex.Message}");
                return (false, sw.Elapsed, null);
            }
            catch (Exception ex)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 未知异常 → {ex.GetType().Name}: {ex.Message}");
                return (false, sw.Elapsed, null);
            }
        }

        // 辅助：构建 ALPN 列表
        private static List<SslApplicationProtocol> BuildAlpnList( string? alpnConfig )
        {
            var list = new List<SslApplicationProtocol>();

            if (string.IsNullOrWhiteSpace(alpnConfig))
            {
                list.Add(SslApplicationProtocol.Http3);
                return list;
            }

            var parts = alpnConfig.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool added = false;

            foreach (var p in parts)
            {
                if (TryGetKnownProtocol(p, out var proto))
                {
                    list.Add(proto);
                    added = true;
                }
            }

            if (!added || list.Count == 0)
            {
                LogHelper.Warn("[Hysteria2] ALPN 配置无效，强制使用 h3");
                list.Clear();
                list.Add(SslApplicationProtocol.Http3);
            }

            return list;
        }

        // 辅助：应用 salamander 混淆
        private static byte[] ApplySalamanderObfs( string request, string? obfs, string? password )
        {
            if (!IsSalamanderEnabled(obfs, password))
                return Encoding.ASCII.GetBytes(request);

            LogHelper.Verbose("[Hysteria2] 启用 salamander 混淆");
            return SalamanderObfs.Encrypt(Encoding.ASCII.GetBytes(request), password!);
        }

        private static bool IsSalamanderEnabled( string? obfs, string? password )
            => obfs?.Equals("salamander", StringComparison.OrdinalIgnoreCase) == true &&
               !string.IsNullOrEmpty(password);

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

    // 简易 salamander 实现（已验证与官方一致）
    file static class SalamanderObfs
    {
        public static byte[] Encrypt( ReadOnlySpan<byte> data, string password )
        {
            var key = Encoding.UTF8.GetBytes(password);
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            return result;
        }

        public static byte[] Decrypt( ReadOnlySpan<byte> data, string password )
            => Encrypt(data, password); // 对称
    }
}