// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2Handshaker.cs
using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

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
                LogHelper.Warn($"[Hysteria2] {node.Host} TLS 握手失败（指纹/SNI 不匹配或证书错误）");
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

            var options = new QuicClientConnectionOptions
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

            return await QuicConnection.ConnectAsync(options, ct).ConfigureAwait(false);
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
    }
}