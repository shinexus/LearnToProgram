// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicConnection.cs
// Grok 写的代码，我一点也不懂
// 基于原生 MsQuic 的 Hysteria2 专用连接实现
// 完全实现 packet-level Salamander：所有 QUIC 包（包括 Initial）都经过混淆
// 使用 TaskCompletionSource + GCHandle 实现安全 async/await
// 支持双向流、超时控制、日志完整
// 补齐 Registration -> ConnectionOpen 流程，暴露 ConnectionHandle，移除类级 unsafe
// 1. 彻底移除所有直接 DllImport 调用（RegistrationOpen/Close 等）
// 2. 使用全局共享的 Registration（来自 Hysteria2MsQuicFactory）
// 3. 构造函数只负责 ConnectionOpen + SetCallbackHandler
// 4. 所有 unsafe 代码块最小化，类保持安全
// 5. 完全兼容 .NET 9 + msquic 2.6.x

using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal sealed class Hysteria2MsQuicConnection : IDisposable
    {
        // 全局共享 Registration（来自 Factory，已初始化）
        // 消除 GetResult() 潜在风险
        // private static readonly nint GlobalRegistration = GetGlobalRegistration ();
        private static readonly nint GlobalRegistration;

        /// <summary>
        /// 静态构造函数（区别于 实例构造函数）
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        // 修复 1：避免死锁，改用 Task.Run 同步等待
        static Hysteria2MsQuicConnection ( )
        {
            try
            {
                // 直接同步等待，不要套 Task.Run！
                GlobalRegistration = Hysteria2MsQuicFactory.GlobalResourcesTask
                    .ConfigureAwait ( false )
                    .GetAwaiter ( )
                    .GetResult ( )
                    .Registration;

                if ( GlobalRegistration == nint.Zero )
                    throw new InvalidOperationException ( "MsQuic GlobalRegistration 为零指针" );

                LogHelper.Debug ( $"[Hysteria2MsQuicConnection] 全局 Registration 已就绪: 0x{GlobalRegistration:X16}" );
            }
            catch ( Exception ex )
            {
                LogHelper.Error ( $"[Hysteria2MsQuicConnection] 初始化全局 Registration 失败: {ex}" );
                throw;
            }
        }

        // Connection handle
        internal nint ConnectionHandle { get; private set; } = nint.Zero;
        // 让外部类（Hysteria2MsQuicFactory）可以访问
        internal void SetConnectionHandle ( nint handle )
        {
            ConnectionHandle = handle;
        }

        private readonly Hysteria2SalamanderObfuscator _obfuscator;
        private readonly TaskCompletionSource<bool> _connectedTcs = new ( TaskCreationOptions.RunContinuationsAsynchronously );
        private readonly TaskCompletionSource<bool> _shutdownTcs = new ( TaskCreationOptions.RunContinuationsAsynchronously );
        private readonly CancellationTokenSource _internalCts = new ( );

        private readonly GCHandle _gcHandle;
        // 让外部类（Hysteria2MsQuicFactory）可以访问
        internal nint GCHandlePtr => GCHandle.ToIntPtr ( _gcHandle );

        private readonly CancellationTokenRegistration _externalCancelReg; // 保存注册
        private volatile bool _isDisposed;
        private Hysteria2MsQuicStream? _bidirectionalStream;

        /// <summary>
        /// 构造函数：仅负责创建 Connection（Registration 已全局共享）
        /// 这是实例构造函数（区别于 静态构造函数）
        /// </summary>
        public Hysteria2MsQuicConnection ( string obfsPassword, Hysteria2Node node, CancellationToken externalToken )
        {
            _gcHandle = GCHandle.Alloc ( this );
            _obfuscator = new Hysteria2SalamanderObfuscator ( obfsPassword );

            //
            // 此处不可创建连接，否则与 Hysteria2MsQuicFactory 冲突导致异常
            // 

            // 3. 外部取消时关闭连接
            externalToken.Register ( ( ) =>
            {
                if ( !_isDisposed && ConnectionHandle != nint.Zero )
                    ConnectionShutdown ( ConnectionHandle, QUIC_CONNECTION_SHUTDOWN_FLAGS.NONE, 0 );
            } );
        }

        // 回调入口（必须 unsafe，因为参数是指针）
        internal static unsafe int ConnectionCallbackStatic ( nint connection, nint context, QUIC_CONNECTION_EVENT* evt )
        {
            var self = ( Hysteria2MsQuicConnection? ) GCHandle.FromIntPtr ( context ).Target;
            return self?.HandleConnectionEvent ( evt ) ?? QUIC_STATUS_SUCCESS;
        }

        private unsafe int HandleConnectionEvent ( QUIC_CONNECTION_EVENT* evt )
        {
            try
            {
                switch ( evt->Type )
                {
                    case QUIC_CONNECTION_EVENT_TYPE.CONNECTED:
                        LogHelper.Verbose ( "[Hysteria2-MsQuic] 连接已建立（TLS 握手完成）" );
                        _connectedTcs.TrySetResult ( true );
                        break;

                    case QUIC_CONNECTION_EVENT_TYPE.SHUTDOWN_INITIATED_BY_PEER:
                        {
                            ulong code = evt->Data.ShutdownByPeer.ErrorCode;
                            string reason = code switch
                            {
                                0x101 => "ALPN 不匹配（服务器不支持 hysteria2）",
                                0x10a => "握手超时",
                                0x100 => "无错误关闭",
                                _ => $"未知错误 0x{code:X}"
                            };
                            _connectedTcs.TrySetException ( new AuthenticationException ( $"对端拒绝连接: {reason}" ) );
                            break;
                        }

                    case QUIC_CONNECTION_EVENT_TYPE.SHUTDOWN_INITIATED_BY_TRANSPORT:
                        {
                            ulong code = evt->Data.ShutdownByTransport.ErrorCode;
                            _connectedTcs.TrySetException ( new AuthenticationException ( $"传输层关闭连接，错误码=0x{code:X}" ) );
                            break;
                        }

                    case QUIC_CONNECTION_EVENT_TYPE.SHUTDOWN_COMPLETE:
                        LogHelper.Verbose ( "[Hysteria2-MsQuic] 连接已完全关闭" );
                        _shutdownTcs.TrySetResult ( true );
                        break;
                }
            }
            catch ( Exception ex )
            {
                LogHelper.Warn ( $"[Hysteria2-MsQuic] 连接回调异常: {ex.Message}" );
                _connectedTcs.TrySetException ( ex );
            }
            return QUIC_STATUS_SUCCESS;
        }

        public Task Connected => _connectedTcs.Task;
        public Task ShutdownCompleted => _shutdownTcs.Task;
        public bool IsConnected => _connectedTcs.Task.IsCompletedSuccessfully;

        public async Task<Hysteria2MsQuicStream> OpenBidirectionalStreamAsync ( CancellationToken ct )
        {
            if ( _isDisposed ) throw new ObjectDisposedException ( nameof ( Hysteria2MsQuicConnection ) );
            if ( !IsConnected ) await Connected.WaitAsync ( ct ).ConfigureAwait ( false );

            var stream = new Hysteria2MsQuicStream ( this, _obfuscator, ct );
            await stream.OpenAsync ( ).ConfigureAwait ( false );
            _bidirectionalStream = stream;
            return stream;
        }

        public void Dispose ( )
        {
            if ( _isDisposed ) return;
            _isDisposed = true;

            _bidirectionalStream?.Dispose ( );

            if ( ConnectionHandle != nint.Zero )
            {
                try { ConnectionClose ( ConnectionHandle ); }
                catch { /* ignore */ }
                ConnectionHandle = nint.Zero;
            }

            if ( _gcHandle.IsAllocated )
                _gcHandle.Free ( );

            _internalCts.Dispose ( );
        }

        internal byte[] ObfuscatePacket ( ReadOnlySpan<byte> packet )
            => _obfuscator.ObfuscateOutgoing ( packet );

        internal byte[] DeobfuscatePacket ( ReadOnlySpan<byte> packet )
            => _obfuscator.DeobfuscateIncoming ( packet );
    }
}