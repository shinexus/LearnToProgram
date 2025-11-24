// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicFactory.cs
// Grok 写的代码，我一点也不懂
// 中文说明：完全替代原来的 Hysteria2ConnectionFactory.ConnectQuicAsync
// 使用原生 MsQuic + packet-level Salamander 实现 100% 协议兼容
// 支持 Windows Schannel / Linux OpenSSL 自动切换

using HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic;
using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    // ⚠️ 这里不要加 unsafe
    internal static class Hysteria2MsQuicFactory
    {
        private static readonly AsyncLazy<GlobalResources> _global
            = new(async () => await InitializeGlobalAsync().ConfigureAwait(false));

        private sealed class GlobalResources : IDisposable
        {
            public nint Registration { get; }
            public nint Configuration { get; }
            public GlobalResources( nint r, nint c ) => (Registration, Configuration) = (r, c);
            public void Dispose()
            {
                if (Configuration != nint.Zero) ConfigurationClose(Configuration);
                if (Registration != nint.Zero) RegistrationClose(Registration);
            }
        }

        // 修正：保持 async，但不标记为 unsafe
        private static async Task<GlobalResources> InitializeGlobalAsync()
        {
            int status;
            nint reg;

            unsafe
            {
                status = RegistrationOpen(null, out reg);
            }
            if (status != QUIC_STATUS_SUCCESS)
                throw new InvalidOperationException($"RegistrationOpen failed: 0x{status:X8}");

            // 只有这里需要 unsafe
            QUIC_BUFFER alpnBuffer;
            unsafe
            {
                byte* alpn = stackalloc byte[3];
                alpn[0] = 2;
                alpn[1] = (byte)'h';
                alpn[2] = (byte)'3';
                alpnBuffer = new QUIC_BUFFER { Length = 3, Buffer = alpn };
            }

            var cred = new QUIC_CREDENTIAL_CONFIG
            {
                Type = QUIC_CREDENTIAL_TYPE.NONE,
                Flags = QUIC_CREDENTIAL_FLAGS.CLIENT | QUIC_CREDENTIAL_FLAGS.NO_CERTIFICATE_VALIDATION,
            };

            unsafe
            {
                status = ConfigurationOpen(
                    reg, &alpnBuffer, 1, &cred,
                    (uint)sizeof(QUIC_CREDENTIAL_CONFIG),
                    nint.Zero, out nint cfg);

                if (status != QUIC_STATUS_SUCCESS)
                {
                    RegistrationClose(reg);
                    throw new InvalidOperationException($"ConfigurationOpen failed: 0x{status:X8}");
                }

                LogHelper.Info("[Hysteria2-MsQuic] 全局资源初始化完成");
                return new GlobalResources(reg, cfg);
            }
        }

        // ✔ 修正：async 方法必须是安全方法
        public static async Task<Hysteria2MsQuicConnection> ConnectAsync(
            Hysteria2Node node,
            IPEndPoint endpoint,
            CancellationToken ct = default )
        {
            GlobalResources global = await _global.Value.ConfigureAwait(false);

            if (node.Obfs?.Equals("salamander", StringComparison.OrdinalIgnoreCase) is not true ||
                string.IsNullOrWhiteSpace(node.ObfsPassword))
                throw new InvalidOperationException("Salamander 必须启用且提供密码");

            string effectiveSni = await TlsSniResolver.ResolveEffectiveSniAsync(
                node.Host, node.Port, node.HostParam, node.SkipCertVerify, ct)
                .ConfigureAwait(false);

            int status = ConnectionOpen(global.Registration, null, nint.Zero, out nint connHandle);

            if (status != QUIC_STATUS_SUCCESS)
                throw new InvalidOperationException($"ConnectionOpen failed: 0x{status:X8}");

            var connection = new Hysteria2MsQuicConnection(connHandle, node.ObfsPassword!, node, ct);

            // 仅这里需要 unsafe
            unsafe
            {
                byte[] sniBytes = Encoding.UTF8.GetBytes(effectiveSni + '\0');
                fixed (byte* pSni = sniBytes)
                {
                    status = ConnectionStart(
                        connHandle,
                        global.Configuration,
                        QUIC_ADDRESS_FAMILY.UNSPECIFIED,
                        pSni,
                        (ushort)endpoint.Port);
                }
            }

            if (status != QUIC_STATUS_SUCCESS)
            {
                connection.Dispose();
                throw new AuthenticationException($"ConnectionStart failed: 0x{status:X8}");
            }

            await connection.Connected.WaitAsync(ct).ConfigureAwait(false);

            LogHelper.Info($"[Hysteria2-MsQuic] Salamander 连接成功 → {effectiveSni}:{endpoint.Port}");
            return connection;
        }
    }

    internal sealed class AsyncLazy<T>
    {
        private readonly Lazy<Task<T>> _lazy;
        public AsyncLazy( Func<Task<T>> factory ) => _lazy = new Lazy<Task<T>>(factory);
        public Task<T> Value => _lazy.Value;
    }
}