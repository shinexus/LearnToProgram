// src/Checking/Handshakers/ProtocolHandshaker.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking.Handshakers
{
    /// <summary>
    /// 协议握手器，支持 VLESS 和 Trojan 协议的通用握手逻辑
    /// </summary>
    internal static class ProtocolHandshaker
    {
        /// <summary>
        /// 进行 TLS 握手
        /// </summary>
        private static async Task<SslStream> PerformTlsHandshakeAsync( NetworkStream networkStream, string sni, bool skipCertVerify, CancellationToken token )
        {
            var ssl = new SslStream(networkStream, leaveInnerStreamOpen: true);
            var sslOpts = TlsHelper.CreateSslOptions(sni, skipCertVerify);
            await ssl.AuthenticateAsClientAsync(sslOpts, token);
            return ssl;
        }

        /// <summary>
        /// 通用的握手流程
        /// </summary>
        public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
            NodeInfoBase node,
            IPAddress address,
            int timeoutSec,
            RunOptions opts,
            Func<Stream, CancellationToken, Task<bool>> protocolSpecificHandshake )
        {
            Stream? stream = null;
            var sw = Stopwatch.StartNew();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));

            try
            {
                using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };
                await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token);
                using var networkStream = new NetworkStream(socket, ownsSocket: true);

                // 执行协议特定的 TLS 握手
                var ssl = await PerformTlsHandshakeAsync(networkStream, node.HostParam ?? node.Host, CertHelper.GetSkipCertVerify(node.ExtraParams), cts.Token);

                // 执行协议特定的操作（如 VLESS 或 Trojan）
                var success = await protocolSpecificHandshake(ssl, cts.Token);

                sw.Stop();

                if (success)
                {
                    LogHelper.Info($"[{node.Type}] {node.Host}:{node.Port} | 握手成功");
                    return (true, sw.Elapsed, ssl);
                }

                LogHelper.Warn($"[{node.Type}] {node.Host}:{node.Port} | 验证失败");
                return (false, sw.Elapsed, ssl);
            }
            catch (OperationCanceledException)
            {
                LogHelper.Warn($"[{node.Type}] {node.Host}:{node.Port} | 超时");
                sw.Stop();
                return (false, sw.Elapsed, null);
            }
            catch (AuthenticationException ex)
            {
                LogHelper.Warn($"[{node.Type}] {node.Host}:{node.Port} | TLS认证失败: {ex.Message}");
                sw.Stop();
                return (false, sw.Elapsed, null);
            }
            catch (Exception ex)
            {
                LogHelper.Error($"[{node.Type}] {node.Host}:{node.Port} | 握手异常: {ex.Message}");
                sw.Stop();
                return (false, sw.Elapsed, null);
            }
        }
    }
}
