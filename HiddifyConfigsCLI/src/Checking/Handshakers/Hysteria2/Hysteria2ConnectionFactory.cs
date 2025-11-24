// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2ConnectionFactory.cs
using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{    
    // 中文说明：提取 QUIC 连接建立逻辑，集中处理 CipherSuitesPolicy 平台兼容性问题
    // 完全兼容 Windows / Linux / macOS，自动降级，永不抛 PlatformNotSupportedException
    internal static class Hysteria2ConnectionFactory
    {
        public static async Task<QuicConnection?> ConnectAsync( Hysteria2Node node, IPEndPoint endpoint, CancellationToken ct )
        {
            string effectiveSni = await TlsSniResolver.ResolveEffectiveSniAsync(
                node.Host, node.Port, node.HostParam, node.SkipCertVerify, ct).ConfigureAwait(false);

            var alpnList = Hysteria2AlpnBuilder.Build(node.Alpn);

            // 尝试启用 OpenSSL 后端（仅 Linux 有效）
            Environment.SetEnvironmentVariable("QUIC_TLS", "openssl");

            CipherSuitesPolicy? cipherPolicy = null;
            bool cipherSupported = false;

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
                !RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                try
                {
                    var suites = Hysteria2CipherSuiteProvider.GetSuites(node.Fingerprint);
                    if (suites.Count > 0)
                    {
                        cipherPolicy = new CipherSuitesPolicy(suites);
                        cipherSupported = true;
                    }
                }
                catch (PlatformNotSupportedException)
                {
                    LogHelper.Verbose("[Hysteria2] 当前平台不支持 CipherSuitesPolicy，降级使用默认 TLS 密码套件顺序");
                }
            }
            else
            {
                LogHelper.Verbose("[Hysteria2] Windows/macOS 不支持 CipherSuitesPolicy，使用系统默认 TLS 策略");
            }

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
                    CipherSuitesPolicy = cipherSupported ? cipherPolicy : null,
                    RemoteCertificateValidationCallback = ( sender, cert, chain, errors ) =>
                    {
                        if (errors == SslPolicyErrors.None) return true;
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

            LogHelper.Verbose(cipherSupported
                ? $"[Hysteria2] TLS 伪装启用 → OpenSSL + {node.Fingerprint ?? "chrome"} cipher 自定义顺序"
                : "[Hysteria2] TLS 伪装降级 → 使用系统默认 cipher 顺序（连通性优先）");

            return await QuicConnection.ConnectAsync(options, ct).ConfigureAwait(false);
        }
    }
}