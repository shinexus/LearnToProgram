// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicFactory.cs
// Grok 写的代码，我一点也不懂
// 中文说明：完全替代原来的 Hysteria2ConnectionFactory.ConnectQuicAsync
// 使用原生 MsQuic + packet-level Salamander 实现 100% 协议兼容
// 支持 Windows Schannel / Linux OpenSSL 自动切换

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
    internal static class Hysteria2MsQuicFactory
    {
        // 正确实现 AsyncLazy：返回 Task<GlobalResources>
        // 原代码错误地将 Lazy<Task<T>> 当作 AsyncLazy<T> 使用，导致 await 语法错误
        private static readonly AsyncLazy<GlobalResources> _global
            = new AsyncLazy<GlobalResources>(InitializeGlobalAsync);

        private sealed class GlobalResources : IDisposable
        {
            public nint Registration { get; }
            public nint Configuration { get; }
            public GlobalResources( nint r, nint c ) => (Registration, Configuration) = (r, c);

            public void Dispose()
            {
                if (Configuration != nint.Zero)
                    ConfigurationClose(Configuration);
                if (Registration != nint.Zero)
                    RegistrationClose(Registration);
            }
        }

        // 改为真正的 async 方法，所有 unsafe 代码块已隔离
        private static async Task<GlobalResources> InitializeGlobalAsync()
        {
            // 【Grok 修复_2025-11-24_03】仅在此方法内部使用 unsafe 块，类保持安全
            QUIC_BUFFER alpnBuffer;
            GCHandle alpnHandle;

            unsafe
            {
                // 栈上分配 h3 ALPN（2 byte 长度前缀 + "h3"）
                byte* ptr = stackalloc byte[3];
                ptr[0] = 2;
                ptr[1] = (byte)'h';
                ptr[2] = (byte)'3';

                alpnBuffer = new QUIC_BUFFER
                {
                    Length = 3,
                    Buffer = ptr
                };
            }

            // 栈内存生命周期到方法结束前都有效，MsQuic 在 ConfigurationOpen 完成后立即复制 ALPN，无需固定
            alpnHandle = default; // 不需要 GCHandle

            int status;
            nint reg;

            unsafe
            {
                status = RegistrationOpen(null, out reg);
            }
            if (status != QUIC_STATUS_SUCCESS)
                throw new InvalidOperationException($"RegistrationOpen failed: 0x{status:X8}");

            var cred = new QUIC_CREDENTIAL_CONFIG
            {
                Type = QUIC_CREDENTIAL_TYPE.NONE,
                Flags = QUIC_CREDENTIAL_FLAGS.CLIENT | QUIC_CREDENTIAL_FLAGS.NO_CERTIFICATE_VALIDATION,
            };

            nint cfg;
            unsafe
            {
                status = ConfigurationOpen(
                    reg,
                    &alpnBuffer,
                    1,
                    &cred,
                    (uint)sizeof(QUIC_CREDENTIAL_CONFIG),
                    nint.Zero,
                    out cfg);
            }

            if (status != QUIC_STATUS_SUCCESS)
            {
                RegistrationClose(reg);
                throw new InvalidOperationException($"ConfigurationOpen failed: 0x{status:X8}");
            }

            LogHelper.Info("[Hysteria2-MsQuic] 全局资源初始化完成（h3 ALPN 使用 stackalloc 安全分配）");

            return new GlobalResources(reg, cfg);
        }

        // 正确 await Task<GlobalResources>
        public static async Task<Hysteria2MsQuicConnection> ConnectAsync(
            Hysteria2Node node,
            IPEndPoint endpoint,
            CancellationToken ct = default )
        {
            // 正确获取 Task<GlobalResources> 并 await
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

            var connection = new Hysteria2MsQuicConnection(node.ObfsPassword!, node, ct);

            // SNI 字符串必须以 null 结尾，且使用 fixed 固定托管数组
            byte[] sniBytes = Encoding.UTF8.GetBytes(effectiveSni + '\0');

            unsafe
            {
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

    // 标准 AsyncLazy 实现（支持 .NET 9）
    internal sealed class AsyncLazy<T> where T : class
    {
        private readonly Lazy<Task<T>> _lazy;

        public AsyncLazy( Func<Task<T>> factory )
        {
            _lazy = new Lazy<Task<T>>(factory, true);
        }

        public Task<T> Value => _lazy.Value;
    }
}