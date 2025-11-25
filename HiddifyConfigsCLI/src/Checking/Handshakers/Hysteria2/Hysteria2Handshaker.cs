// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2Handshaker.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Security.Authentication;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    /// <summary>
    /// Hysteria2 协议专用握手器（.NET 9 System.Net.Quic 纯实现）
    /// 完全遵循官方协议：TLS 1.3 + HTTP/3 /auth + 233 HyOK
    /// 支持：mport 多端口随机选择、Up/DownMbps 带宽声明、随机 Padding
    /// 支持：Salamander（BouncyCastle）、cipher 伪装、mport、完整异常处理
    /// 重构：主流程解耦至 RequestBuilder & ResponseParser 等
    /// </summary>    
    internal static class Hysteria2Handshaker
    {
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
                int targetPort = Hysteria2PortResolver.Resolve(node);
                var endpoint = new IPEndPoint(address, targetPort);

                // 尝试使用 ChatGPT 修改过的 MsQuic
                // await using var connection = await Hysteria2ConnectionFactory.ConnectAsync(node, endpoint, cts.Token);
                using var connection = await Hysteria2MsQuicFactory.ConnectAsync(node, endpoint, cts.Token);

                if (connection == null)
                    return (false, sw.Elapsed, null);

                LogHelper.Verbose($"[Hysteria2] QUIC 已连接 {node.Host}:{targetPort} → {connection.ToString}");

                // await using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cts.Token);
                await using var stream = await connection.OpenBidirectionalStreamAsync(cts.Token);

                byte[] request = Hysteria2RequestBuilder.BuildAuthRequest(node);
                if (Hysteria2SalamanderEngine.IsEnabled(node))
                {
                    var encrypted = Hysteria2SalamanderEngine.Encrypt(request, node.ObfsPassword!);
                    await stream.WriteAsync(encrypted, cts.Token);
                    LogHelper.Verbose($"[Hysteria2] Salamander 加密请求 {request.Length} → {encrypted.Length} 字节");
                }
                else
                {
                    await stream.WriteAsync(request, cts.Token);
                }

                // 使用 ChatGPT 修改的 MsQuic
                // var parseResult = await Hysteria2ResponseParser.ParseAsync(stream, node, cts.Token);
                var parseResult = await Hysteria2MsQuicResponseParser.ParseAsync(stream, node, cts.Token);

                sw.Stop();

                if (!parseResult.Success)
                {
                    LogHelper.Warn($"[Hysteria2] {node.Host}:{targetPort} 认证失败");
                    return (false, sw.Elapsed, null);
                }

                LogHelper.Info($"[Hysteria2] {node.Host}:{targetPort} 握手成功，延迟 {sw.Elapsed.TotalMilliseconds:F0}ms | UDP: {parseResult.UdpEnabled}");
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
    }
}