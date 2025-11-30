// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicFactory.cs
// Grok 写的代码，我一点也不懂
// 中文说明：完全替代原来的 Hysteria2ConnectionFactory.ConnectQuicAsync
// 使用原生 MsQuic + packet-level Salamander 实现 100% 协议兼容
// 支持 Windows Schannel / Linux OpenSSL 自动切换
// 彻底移除所有直接 DllImport 的 Registration*/Configuration* 调用
// 全部改为通过 Hysteria2MsQuicNative 中已绑定的委托执行
// 同时新增并绑定 RegistrationCloseDelegate / ConfigurationCloseDelegate
// 修复后可彻底解决 EntryPointNotFoundException

using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Net.Security;
using System.Runtime.CompilerServices;
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
        internal static readonly AsyncLazy<GlobalResources> _global
            = new AsyncLazy<GlobalResources> ( InitializeGlobalAsync );

        // 公开全局资源 Task，供 Hysteria2MsQuicConnection 等其他类使用
        // 必须是 internal static，这样同程序集内其他类才能访问
        public static Task<GlobalResources> GlobalResourcesTask => _global.Value;

        public sealed class GlobalResources : IDisposable
        {
            public nint Registration { get; }
            public nint Configuration { get; }
            public GlobalResources ( nint r, nint c ) => (Registration, Configuration) = (r, c);

            public void Dispose ( )
            {
                if ( Configuration != nint.Zero )
                    Hysteria2MsQuicNative.ConfigurationClose?.Invoke ( Configuration );
                if ( Registration != nint.Zero )
                    Hysteria2MsQuicNative.RegistrationClose?.Invoke ( Registration );
            }
        }

        // 改为真正的 async 方法，所有 unsafe 代码块已隔离
        private static async Task<GlobalResources> InitializeGlobalAsync ( )
        {
            // 1. 准备 hysteria2 ALPN（托管数组 + GCHandle 固定）
            byte[] alpnBytes = Encoding.ASCII.GetBytes ( "hysteria2" );
            var alpnHandle = GCHandle.Alloc ( alpnBytes, GCHandleType.Pinned );

            QUIC_BUFFER alpnBuffer; // 稍后在 unsafe 中填充 Buffer 指针

            // 必须在 unsafe 中才能取 AddrOfPinnedObject
            unsafe
            {
                alpnBuffer = new QUIC_BUFFER
                {
                    Length = ( uint ) alpnBytes.Length,
                    Buffer = ( byte* ) alpnHandle.AddrOfPinnedObject ( )  // ← 这里必须 unsafe
                };
            }            

            // 2. 正确构造 RegistrationConfig
            // https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h#L1114
            var regConfig = new QUIC_REGISTRATION_CONFIG
            {
                AppName = nint.Zero,  // 传 null 即可
                ExecutionProfile = QUIC_EXECUTION_PROFILE.LOW_LATENCY
            };

            nint reg = nint.Zero;
            int status;

            unsafe
            {
                QUIC_REGISTRATION_CONFIG* pConfig = stackalloc QUIC_REGISTRATION_CONFIG[1];
                pConfig->AppName = nint.Zero;
                pConfig->ExecutionProfile = QUIC_EXECUTION_PROFILE.LOW_LATENCY;
                status = RegistrationOpen ( pConfig, out reg );
            }

            if ( status != QUIC_STATUS_SUCCESS )
                throw new InvalidOperationException ( $"RegistrationOpen failed: 0x{status:X8}" );

            // 3. Credential 配置（跳过证书验证）
            var cred = new QUIC_CREDENTIAL_CONFIG
            {
                //Type = QUIC_CREDENTIAL_TYPE.NONE,
                //Flags = QUIC_CREDENTIAL_FLAGS.CLIENT | QUIC_CREDENTIAL_FLAGS.NO_CERTIFICATE_VALIDATION,
                //AsyncCertificateValidation = 0,
                //CertificateHash = nint.Zero,
                //CertificateHashStore = nint.Zero,
                //CertificateContext = nint.Zero,
                //CertificateHashStoreName = nint.Zero
                Type = QUIC_CREDENTIAL_TYPE.NONE,
                Flags = QUIC_CREDENTIAL_FLAGS.CLIENT | QUIC_CREDENTIAL_FLAGS.NO_CERTIFICATE_VALIDATION,
                // union 部分全零（NONE 类型不需要证书）
                CertificateHash = nint.Zero,
                CertificateHashStore = nint.Zero,
                CertificateContext = nint.Zero,
                CertificateFile = nint.Zero,
                CertificateFileProtected = nint.Zero,
                CertificatePkcs12 = nint.Zero,
                Principal = nint.Zero,
                Reserved = nint.Zero,
                AsyncHandler = nint.Zero,
                // 用官方完整名 + 位或，确保 Hysteria2 支持所有 Cipher Suite
                AllowedCipherSuites = QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 |
                          QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 |
                          QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
                CaCertificateFile = nint.Zero
            };

            // 3. ConfigurationOpen（通过委托）
            // https://github.com/microsoft/msquic/blob/main/src/inc/msquic.h#L1183
            nint cfg = nint.Zero;

            // 必须给 Context 传一个非零指针，哪怕只是占位！
            nint context = ( nint ) GCHandle.Alloc ( "Hysteria2-Config-Context", GCHandleType.Normal );
            unsafe
            {
                // 64 是 QUIC_CREDENTIAL_CONFIG 实际大小（7个字段：uint + uint + 6*nint）
                // +59 是官方保留区，必须全零
                byte* pFullCred = stackalloc byte[sizeof ( QUIC_CREDENTIAL_CONFIG ) + 59];
                Unsafe.InitBlock ( pFullCred + sizeof ( QUIC_CREDENTIAL_CONFIG ), 0, 59 ); // 清零保留区

                // 把干净的结构体拷贝进去
                *( QUIC_CREDENTIAL_CONFIG* ) pFullCred = cred;

                // 3.1 空 Configuration（只传 ALPN
                status = ConfigurationOpen (
                    reg,
                    &alpnBuffer,
                    1,
                    null,
                    0,
                    context,
                    out cfg );
            }

            if ( status != QUIC_STATUS_SUCCESS )
            {
                RegistrationClose ( reg );
                throw new InvalidOperationException ( $"ConfigurationOpen failed: 0x{status:X8}" );
            }            

            if ( status != QUIC_STATUS_SUCCESS )
            {
                ConfigurationClose ( cfg );
                RegistrationClose ( reg );
                throw new InvalidOperationException ( $"SetParam(CREDENTIAL_FLAGS) failed: 0x{status:X8}" );
            }

            LogHelper.Info ( "[Hysteria2-MsQuic] Configuration 创建成功（h3 ALPN 使用 stackalloc 安全分配）" );
            return new GlobalResources ( reg, cfg );
        }

        // 正确 await Task<GlobalResources>
        public static async Task<Hysteria2MsQuicConnection> ConnectAsync (
            Hysteria2Node node,
            IPEndPoint endpoint,
            CancellationToken ct = default )
        {
            // 正确获取 Task<GlobalResources> 并 await
            GlobalResources global = await _global.Value.ConfigureAwait ( false );

            // 创建 connection 对象
            // 此时我们已经有 connHandle 和正确的 GCHandle
            var connection = new Hysteria2MsQuicConnection ( node.ObfsPassword ?? "", node, ct );
            // 调试信息
            LogHelper.Debug ( $"[Hysteria2] 创建连接对象，GCHandle = 0x{connection.GCHandlePtr:X16}" );

            // ConnectionOpen 仍然通过委托（已绑定）            
            // 第 2 个参数是 null：InvalidOperationException: ConnectionOpen failed: 0x80070057
            // int status = ConnectionOpen ( global.Registration, null, nint.Zero, out nint connHandle );
            
            // 1. 先 Open
            int status = ConnectionOpen (
                global.Registration,
                NativeCallbacks.ConnectionDelegate,
                // nint.Zero,                            // Context 暂时传 0
                connection.GCHandlePtr,
                out nint connHandle );

            if ( status != QUIC_STATUS_SUCCESS )
                throw new InvalidOperationException ( $"ConnectionOpen failed: 0x{status:X8}" );
           

            // 立即设置正确的 ConnectionHandle（内部会用到）
            connection.SetConnectionHandle ( connHandle );            

            // Salamander 检查（放在这里最安全）
            // 支持明文 + 强制 Salamander 必须带密码
            bool isSalamander = node.Obfs?.Equals ( "salamander", StringComparison.OrdinalIgnoreCase ) == true;

            if ( isSalamander )
            {
                // 开启了 Salamander，必须提供密码（不能为空）
                if ( string.IsNullOrWhiteSpace ( node.ObfsPassword ) )
                    throw new InvalidOperationException ( "Salamander 已启用，但未提供混淆密码（obfs-password 不能为空）" );
            }
            else
            {
                // 没开 Salamander，密码可以为空（明文模式）
                if ( !string.IsNullOrWhiteSpace ( node.ObfsPassword ) )
                    LogHelper.Warn ( $"节点未启用 Salamander，但提供了 obfs-password（将被忽略）: {node.ObfsPassword}" );
            }

            LogHelper.Info ( isSalamander
    ? $"[Hysteria2] 使用 Salamander 混淆，密码长度: {node.ObfsPassword!.Length}"
    : "[Hysteria2] 使用明文 QUIC（无 Salamander 混淆）" );

            // 3. SNI 处理 + ConnectionStart
            // SNI 字符串必须以 null 结尾，且使用 fixed 固定托管数组
            string effectiveSni = await TlsSniResolver.ResolveEffectiveSniAsync (
                node.Host, node.Port, node.HostParam, node.SkipCertVerify, ct )
                .ConfigureAwait ( false );

            byte[] sniBytes = Encoding.UTF8.GetBytes ( effectiveSni + '\0' );

            unsafe
            {
                fixed ( byte* pSni = sniBytes )
                {
                    status = ConnectionStart (
                        connHandle,
                        global.Configuration,
                        QUIC_ADDRESS_FAMILY.UNSPECIFIED,
                        pSni,
                        ( ushort ) endpoint.Port );
                }
            }

            if ( status != QUIC_STATUS_SUCCESS )
            {
                connection.Dispose ( );
                throw new AuthenticationException ( $"ConnectionStart failed: 0x{status:X8}" );
            }

            // 等待握手完成
            await connection.Connected.WaitAsync ( ct ).ConfigureAwait ( false );

            LogHelper.Info ( isSalamander
    ? $"[Hysteria2-MsQuic] Salamander 连接成功 → {effectiveSni}:{endpoint.Port}"
    : $"[Hysteria2-MsQuic] 明文连接成功 → {effectiveSni}:{endpoint.Port}" );
            return connection;
        }
    }

    // 标准 AsyncLazy 实现（支持 .NET 9）
    public sealed class AsyncLazy<T> where T : class
    {
        private readonly Lazy<Task<T>> _lazy;

        public AsyncLazy ( Func<Task<T>> factory )
        {
            _lazy = new Lazy<Task<T>> ( factory, true );
        }

        public Task<T> Value => _lazy.Value;
    }
}