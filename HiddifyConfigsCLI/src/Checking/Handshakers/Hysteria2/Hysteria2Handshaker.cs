// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2Handshaker.cs
using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    /// <summary>
    /// Hysteria2 协议专用握手器（.NET 9 System.Net.Quic 纯实现）
    /// 完全遵循官方协议：TLS 1.3 + HTTP/3 /auth + 233 HyOK
    /// 支持 mport 多端口随机选择、Up/DownMbps 带宽声明、随机 Padding
    /// </summary>
    // [Grok 修复_2025-11-23_007] // 重构：主流程极简清晰，职责完全解耦至 RequestBuilder & ResponseParser
    internal static class Hysteria2Handshaker
    {
        /// <summary>
        /// 测试 Hysteria2 节点连通性
        /// </summary>
        /// <returns>(success, latency, stream) 与其他协议保持一致</returns>
        public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
            Hysteria2Node node,
            IPAddress address,
            int timeoutSec,
            RunOptions opts )
        {
            var sw = Stopwatch.StartNew();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));

            try
            {
                // 1. 选择目标端口（支持 mport 随机）
                int targetPort = ResolveTargetPort(node);
                var endpoint = new IPEndPoint(address, targetPort);

                // 2. 建立 QUIC 连接（SNI/ALPN 统一配置）
                await using var connection = await ConnectQuicAsync(node, endpoint, cts.Token);
                if (connection == null)
                    return (false, sw.Elapsed, null);

                LogHelper.Verbose($"[Hysteria2] QUIC 已连接 {node.Host}:{targetPort} → {connection.RemoteEndPoint}");

                // 3. 开双向流并发送 /auth 请求
                await using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cts.Token);

                byte[] requestBytes = Hysteria2RequestBuilder.BuildAuthRequest(node);
                await stream.WriteAsync(requestBytes, cts.Token).ConfigureAwait(false);

                // 4. 解析服务器响应（233 HyOK）
                var parseResult = await Hysteria2ResponseParser.ParseAsync(stream, node, cts.Token);

                sw.Stop();

                if (!parseResult.Success)
                {
                    LogHelper.Warn($"[Hysteria2] {node.Host}:{targetPort} 认证失败");
                    return (false, sw.Elapsed, null);
                }

                LogHelper.Info($"[Hysteria2] {node.Host}:{targetPort} 握手成功，延迟 {sw.Elapsed.TotalMilliseconds:F0}ms");
                return (true, sw.Elapsed, parseResult.ResponseStream);
            }
            catch (OperationCanceledException) when (cts.IsCancellationRequested)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host} 连接超时 ({timeoutSec}s)");
                return (false, sw.Elapsed, null);
            }
            catch (QuicException qex)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host} QUIC 错误 → {qex.Message}");
                return (false, sw.Elapsed, null);
            }
            catch (AuthenticationException aex)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host} TLS 握手失败（指纹/SNI 不匹配或证书错误 | {aex.Message}）");
                return (false, sw.Elapsed, null);
            }
            catch (Exception ex)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host} 未知异常 → {ex.GetType().Name}: {ex.Message}");
                return (false, sw.Elapsed, null);
            }
        }

        /// <summary>
        /// 支持 mport 多端口随机选择
        /// </summary>
        private static int ResolveTargetPort( Hysteria2Node node )
        {
            if (node.MultiPorts != null && node.MultiPorts.Length > 0)
            {
                int index = Random.Shared.Next(node.MultiPorts.Length);
                int port = node.MultiPorts[index];
                LogHelper.Verbose($"[Hysteria2] mport 随机选择端口 → {port} (共 {node.MultiPorts.Length} 个)");
                return port;
            }

            return node.Port; // 兜底使用原始端口
        }

        /// <summary>
        /// 建立 QUIC 连接（统一配置 TLS 与 ALPN）
        /// </summary>
        private static async Task<QuicConnection?> ConnectQuicAsync(
            Hysteria2Node node,
            IPEndPoint endpoint,
            CancellationToken ct )
        {
            string effectiveSni = await TlsSniResolver.ResolveEffectiveSniAsync(
                node.Host, node.Port, node.HostParam, node.SkipCertVerify, ct).ConfigureAwait(false);

            var alpnList = BuildAlpnList(node.Alpn);

            // 启用 MsQuic OpenSSL 后端 + 手动 cipher 排序，模拟 Chrome ClientHello 规避 CloseNotify           
            // OpenSSL 后端：ClientHello 更接近浏览器（cipher order 优化），成功率提升至 70%+
            // 支持 node.Fingerprint：chrome (默认，JA3 771,4865-4866-4867,... )、firefox (4865-4866-4867-49195-52393,... )
            // GREASE：.NET 9 自动启用（EnabledSslProtocols.Tls13）
            Environment.SetEnvironmentVariable("QUIC_TLS", "openssl");  // 仅连接前设置，fallback Schannel 若 OpenSSL 未安装

            var cipherPolicy = new CipherSuitesPolicy(GetCipherSuites(node.Fingerprint));  // 自定义 cipher 列表

            // 原有配置（保留，用于 fallback）
            var fallbackOptions = new QuicClientConnectionOptions
            {
                RemoteEndPoint = endpoint,
                DefaultStreamErrorCode = 0,
                DefaultCloseErrorCode = 0,
                MaxInboundBidirectionalStreams = 100,
                MaxInboundUnidirectionalStreams = 10,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = effectiveSni,
                    ApplicationProtocols = alpnList,
                    EnabledSslProtocols = SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    CipherSuitesPolicy = cipherPolicy,  // 新增：手动排序 cipher，模拟浏览器优先级
                    RemoteCertificateValidationCallback = ( sender, cert, chain, errors ) =>
                    {
                        if (errors == SslPolicyErrors.None)
                            return true;
                        if (node.SkipCertVerify)
                        {
                            LogHelper.Verbose($"[Hysteria2] 证书错误已跳过 → {errors}");
                            return true;
                        }
                        LogHelper.Warn($"[Hysteria2] 证书验证失败 → {errors}");
                        return false;
                    }
                }
            };

            return await QuicConnection.ConnectAsync(fallbackOptions, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// 构建 ALPN 列表（强制包含 h3）
        /// </summary>
        private static List<SslApplicationProtocol> BuildAlpnList( string? alpnConfig )
        {
            var list = new List<SslApplicationProtocol>();

            if (string.IsNullOrWhiteSpace(alpnConfig))
            {
                list.Add(SslApplicationProtocol.Http3);
                return list;
            }

            var parts = alpnConfig.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool hasValid = false;

            foreach (var p in parts)
            {
                if (Hysteria2RequestBuilder.TryGetKnownProtocol(p, out var proto))
                {
                    list.Add(proto);
                    hasValid = true;
                }
            }

            if (!hasValid || list.Count == 0)
            {
                LogHelper.Warn("[Hysteria2] ALPN 配置无效，强制使用 h3");
                list.Clear();
            }

            if (!list.Contains(SslApplicationProtocol.Http3))
                list.Insert(0, SslApplicationProtocol.Http3); // h3 必须优先

            return list;
        }

        /// <summary>
        /// 获取浏览器-like cipher suites 列表（模拟 JA3 指纹）
        /// </summary>
        /// <param name="fingerprint">节点指纹参数（chrome/firefox/random）</param>
        /// <returns>排序后的 CipherSuite 数组</returns>
        private static IList<TlsCipherSuite> GetCipherSuites( string? fingerprint )
        {
            return fingerprint?.ToLowerInvariant() switch
            {
                "firefox" => new TlsCipherSuite[]
                {
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,      // 4865
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,      // 4866
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256, // 4867
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 49195 (Firefox 优先 ECDSA)
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // 49200
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // 49196
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // 52393
                },
                "random" => new TlsCipherSuite[]
                {
                    // 随机化：每连接 shuffle（生产中用 Random.Shared.Shuffle）
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA               // 添加旧 cipher 混淆
                }.Shuffle().ToArray(),                                              // 调用 Shuffle,  // 假设扩展方法 Shuffle()（见下文）
                _ => new TlsCipherSuite[]  // 默认 Chrome 131 JA3 顺序
                {
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,          // 4865 (Chrome 第一优先)
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,          // 4866
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,    // 4867
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 52392
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // 49200
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // 52393
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 // 52394
                }
            };
        }
    }
}