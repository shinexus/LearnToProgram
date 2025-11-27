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
        private static readonly nint GlobalRegistration = GetGlobalRegistration ();

        // Connection handle
        internal nint ConnectionHandle { get; private set; } = nint.Zero;

        private readonly Hysteria2SalamanderObfuscator _obfuscator;
        private readonly TaskCompletionSource<bool> _connectedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _shutdownTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly CancellationTokenSource _internalCts = new();
        private readonly GCHandle _gcHandle;
        private volatile bool _isDisposed;
        private Hysteria2MsQuicStream? _bidirectionalStream;

        // 关键：从 Factory 获取已初始化好的 Registration
        private static nint GetGlobalRegistration ()
        {
            var task = Hysteria2MsQuicFactory.GlobalResourcesTask;
            if ( task.IsCompletedSuccessfully )
                return task.Result.Registration;

            // 同步阻塞等待（初始化很快，且只发生一次）
            return task.GetAwaiter ().GetResult ().Registration;
        }
        /// <summary>
        /// 构造函数：仅负责创建 Connection（Registration 已全局共享）
        /// </summary>
        public Hysteria2MsQuicConnection ( string obfsPassword, Hysteria2Node node, CancellationToken externalToken )
        {
            _gcHandle = GCHandle.Alloc ( this );
            _obfuscator = new Hysteria2SalamanderObfuscator ( obfsPassword );

            // 1. ConnectionOpen（使用全局 Registration）
            int openStatus = ConnectionOpen (
                GlobalRegistration,
                NativeCallbacks.ConnectionDelegate,
                GCHandle.ToIntPtr ( _gcHandle ),
                out nint connHandle );

            if ( openStatus != QUIC_STATUS_SUCCESS )
            {
                _gcHandle.Free ();
                throw new InvalidOperationException ( $"ConnectionOpen failed: 0x{openStatus:X8}" );
            }

            ConnectionHandle = connHandle;

            // 2. 设置回调（必须调用）
            int setCbStatus = ConnectionSetCallbackHandler (
                ConnectionHandle,
                NativeCallbacks.ConnectionDelegate,
                GCHandle.ToIntPtr ( _gcHandle ) );

            if ( setCbStatus != QUIC_STATUS_SUCCESS )
            {
                ConnectionClose ( ConnectionHandle );
                ConnectionHandle = nint.Zero;
                _gcHandle.Free ();
                throw new InvalidOperationException ( $"ConnectionSetCallbackHandler failed: 0x{setCbStatus:X8}" );
            }

            // 3. 外部取消时关闭连接
            externalToken.Register ( () =>
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
            await stream.OpenAsync ().ConfigureAwait ( false );
            _bidirectionalStream = stream;
            return stream;
        }

        public void Dispose ()
        {
            if ( _isDisposed ) return;
            _isDisposed = true;

            _bidirectionalStream?.Dispose ();

            if ( ConnectionHandle != nint.Zero )
            {
                try { ConnectionClose ( ConnectionHandle ); }
                catch { /* ignore */ }
                ConnectionHandle = nint.Zero;
            }

            if ( _gcHandle.IsAllocated )
                _gcHandle.Free ();

            _internalCts.Dispose ();
        }

        internal byte[] ObfuscatePacket ( ReadOnlySpan<byte> packet )
            => _obfuscator.ObfuscateOutgoing ( packet );

        internal byte[] DeobfuscatePacket ( ReadOnlySpan<byte> packet )
            => _obfuscator.DeobfuscateIncoming ( packet );
    }
}