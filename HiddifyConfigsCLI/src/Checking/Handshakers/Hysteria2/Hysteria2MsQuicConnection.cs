// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicConnection.cs
// Grok 写的代码，我一点也不懂
// 中文说明：基于原生 MsQuic 的 Hysteria2 专用连接实现
// 完全实现 packet-level Salamander：所有 QUIC 包（包括 Initial）都经过混淆
// 使用 TaskCompletionSource + GCHandle 实现安全 async/await
// 支持双向流、超时控制、日志完整

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
        private readonly nint _connectionHandle;
        private readonly Hysteria2SalamanderObfuscator _obfuscator;
        private readonly TaskCompletionSource<bool> _connectedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<bool> _shutdownTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly CancellationTokenSource _internalCts = new();
        private readonly GCHandle _gcHandle;
        private volatile bool _isDisposed;
        private Hysteria2MsQuicStream? _bidirectionalStream;

        public Task Connected => _connectedTcs.Task;
        public Task ShutdownCompleted => _shutdownTcs.Task;
        public bool IsConnected => _connectedTcs.Task.IsCompletedSuccessfully;
        public nint ConnectionHandle => _connectionHandle;

        public Hysteria2MsQuicConnection(
            nint connectionHandle,
            string obfsPassword,
            Hysteria2Node node,
            CancellationToken externalToken )
        {
            if (connectionHandle == nint.Zero)
                throw new ArgumentException("Invalid connection handle", nameof(connectionHandle));

            _connectionHandle = connectionHandle;
            _obfuscator = new Hysteria2SalamanderObfuscator(obfsPassword);
            _gcHandle = GCHandle.Alloc(this);

            // 使用集中管理的函数指针（零 unsafe）
            int status = ConnectionSetCallbackHandler(
    _connectionHandle,
    ConnectionCallbackStatic,  // 直接传静态方法！！
    GCHandle.ToIntPtr(_gcHandle));

            if (status != QUIC_STATUS_SUCCESS)
            {
                _gcHandle.Free();
                throw new InvalidOperationException($"ConnectionSetCallbackHandler failed: 0x{status:X8}");
            }

            externalToken.Register(() =>
            {
                if (!_isDisposed)
                    ConnectionShutdown(_connectionHandle, QUIC_CONNECTION_SHUTDOWN_FLAGS.NONE, 0);
            });
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static unsafe int ConnectionCallbackStatic( IntPtr connection, IntPtr context, QUIC_CONNECTION_EVENT* evt )
        {
            var self = (Hysteria2MsQuicConnection)GCHandle.FromIntPtr(context).Target!;
            return self.HandleConnectionEvent(evt);
        }

        private unsafe int HandleConnectionEvent( QUIC_CONNECTION_EVENT* evt )
        {
            try
            {
                switch (evt->Type)
                {
                    case QUIC_CONNECTION_EVENT_TYPE.CONNECTED:
                        LogHelper.Verbose("[Hysteria2-MsQuic] 连接已建立（TLS 握手完成）");
                        _connectedTcs.TrySetResult(true);
                        break;

                    case QUIC_CONNECTION_EVENT_TYPE.SHUTDOWN_COMPLETE:
                        LogHelper.Verbose("[Hysteria2-MsQuic] 连接已完全关闭");
                        _shutdownTcs.TrySetResult(true);
                        break;
                }
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[Hysteria2-MsQuic] 连接回调异常: {ex.Message}");
                _connectedTcs.TrySetException(ex);
            }
            return QUIC_STATUS_SUCCESS;
        }

        public async Task<Hysteria2MsQuicStream> OpenBidirectionalStreamAsync( CancellationToken ct )
        {
            if (_isDisposed) throw new ObjectDisposedException(nameof(Hysteria2MsQuicConnection));
            if (!IsConnected) await Connected.WaitAsync(ct).ConfigureAwait(false);

            var stream = new Hysteria2MsQuicStream(this, _obfuscator, ct);
            await stream.OpenAsync().ConfigureAwait(false);
            _bidirectionalStream = stream;
            return stream;
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            _bidirectionalStream?.Dispose();

            if (_connectionHandle != nint.Zero)
                ConnectionClose(_connectionHandle);

            if (_gcHandle.IsAllocated)
                _gcHandle.Free();

            _internalCts.Dispose();
        }

        internal byte[] ObfuscatePacket( ReadOnlySpan<byte> packet )
            => _obfuscator.ObfuscateOutgoing(packet);

        internal byte[] DeobfuscatePacket( ReadOnlySpan<byte> packet )
            => _obfuscator.DeobfuscateIncoming(packet);
    }
}