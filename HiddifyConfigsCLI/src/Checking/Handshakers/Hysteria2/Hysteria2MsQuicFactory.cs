// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicFactory.cs
// [Grok 修复_2025-11-24_013]
// 中文说明：完全替代原来的 Hysteria2ConnectionFactory.ConnectQuicAsync
// 使用原生 MsQuic + packet-level Salamander 实现 100% 协议兼容
// 支持 Windows Schannel / Linux OpenSSL 自动切换

using HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic;
using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static class Hysteria2MsQuicFactory
    {
        private static readonly nint Registration;
        private static readonly nint Configuration;

        static Hysteria2MsQuicFactory()
        {
            // 全局注册表（整个进程只需一次）
            int status = RegistrationOpen(null, out Registration);
            if (status != QUIC_STATUS_SUCCESS)
                throw new InvalidOperationException($"RegistrationOpen failed: 0x{status:X8}");

            // TLS 配置（ALPN h3 + 跳过证书验证 + 强制 SNI）
            var alpnBuffers = stackalloc byte[] { 2, (byte)'h', (byte)'3' };
            var alpnList = new QUIC_BUFFER { Length = 3, Buffer = alpnBuffers };

            var credConfig = new QUIC_CREDENTIAL_CONFIG
            {
                Type = QUIC_CREDENTIAL_TYPE.NONE,
                Flags = QUIC_CREDENTIAL_FLAGS.CLIENT | QUIC_CREDENTIAL_FLAGS.NO_CERTIFICATE_VALIDATION,
                // 其他字段默认零初始化
            };

            status = Api->ConfigurationOpen(
                Registration,
                &alpnList,
                1,
                &credConfig,
                0,
                nint.Zero,
                out Configuration);

            if (status != QUIC_STATUS_SUCCESS)
            {
                RegistrationClose(Registration);
                throw new InvalidOperationException($"ConfigurationOpen failed: 0x{status:X8}");
            }
        }

        public static async Task<Hysteria2MsQuicConnection> ConnectAsync(
            Hysteria2Node node,
            IPEndPoint endpoint,
            CancellationToken ct )
        {
            if (node.Obfs?.Equals("salamander", StringComparison.OrdinalIgnoreCase) != true ||
                string.IsNullOrWhiteSpace(node.ObfsPassword))
                throw new InvalidOperationException("Salamander 必须启用且提供密码");

            // 解析有效 SNI
            string effectiveSni = await TlsSniResolver.ResolveEffectiveSniAsync(
                node.Host, node.Port, node.HostParam, node.SkipCertVerify, ct);

            // 创建连接
            int status = Api->ConnectionOpen(
                Registration,
                null, // 回调在 Hysteria2MsQuicConnection 中设置
                nint.Zero,
                out nint connectionHandle);

            if (status != QUIC_STATUS_SUCCESS)
                throw new InvalidOperationException($"ConnectionOpen failed: 0x{status:X8}");

            var connection = new Hysteria2MsQuicConnection(connectionHandle, node.ObfsPassword!, node, ct);

            // 开始连接
            byte[] serverName = Encoding.UTF8.GetBytes(effectiveSni + '\0');
            fixed (byte* pName = serverName)
            {
                status = Api->ConnectionStart(
                    connectionHandle,
                    Configuration,
                    QUIC_ADDRESS_FAMILY_UNSPECIFIED,
                    pName,
                    (ushort)endpoint.Port);
            }

            if (status != QUIC_STATUS_SUCCESS)
            {
                connection.Dispose();
                throw new AuthenticationException($"ConnectionStart failed: 0x{status:X8}");
            }

            // 等待 TLS 握手完成
            await connection.Connected.WaitAsync(ct).ConfigureAwait(false);
            LogHelper.Info($"[Hysteria2-MsQuic] 已连接 {effectiveSni}:{endpoint.Port} (Salamander packet-level)");

            return connection;
        }
    }
}