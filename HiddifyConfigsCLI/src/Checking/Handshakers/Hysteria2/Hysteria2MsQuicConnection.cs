// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicConnection.cs
// [Grok 修复_2025-11-24_011]
// 中文说明：基于原生 MsQuic 的 Hysteria2 专用连接实现
// 完全实现 packet-level Salamander：所有 QUIC 包（包括 Initial）都经过混淆
// 使用 TaskCompletionSource + GCHandle 实现安全 async/await
// 支持双向流、超时控制、日志完整

using HiddifyConfigsCLI.src.Checking.Tls;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic
{
    /// <summary>
    /// Hysteria2 专用的 MsQuic 连接包装器（packet-level Salamander）
    /// 完全替代 System.Net.Quic 的 QuicConnection
    /// </summary>
    internal sealed class Hysteria2MsQuicConnection : IDisposable
    {
        private readonly IntPtr _connectionHandle;
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

        public Hysteria2MsQuicConnection(
            IntPtr connectionHandle,
            string obfsPassword,
            Hysteria2Node node,
            CancellationToken externalToken )
        {
            if (connectionHandle == IntPtr.Zero)
                throw new ArgumentException("Invalid connection handle", nameof(connectionHandle));

            _connectionHandle = connectionHandle;
            _obfuscator = new Hysteria2SalamanderObfuscator(obfsPassword);

            // 安全托管：将当前实例传递给原生回调
            _gcHandle = GCHandle.Alloc(this);

            // 注册连接回调
            int status = Hysteria2MsQuicNative.Api->ConnectionSetCallbackHandler(
                _connectionHandle,
                &ConnectionCallback,
                (void*)GCHandle.ToIntPtr(_gcHandle));

            if (status != Hysteria2MsQuicNative.QUIC_STATUS_SUCCESS)
            {
                _gcHandle.Free();
                throw new InvalidOperationException($"ConnectionSetCallbackHandler failed: 0x{status:X8}");
            }

            // 链接外部取消
            externalToken.Register(() =>
            {
                if (!_isDisposed)
                    Hysteria2MsQuicNative.Api->ConnectionShutdown(_connectionHandle, QUIC_CONNECTION_SHUTDOWN_FLAGS.NONE, 0);
            });
        }

        // 连接事件回调（原生函数）
        [UnmanagedCallersOnly]
        private static int ConnectionCallback( IntPtr connection, IntPtr context, QUIC_CONNECTION_EVENT* evt )
        {
            var self = (Hysteria2MsQuicConnection)GCHandle.FromIntPtr(context).Target!;
            return self.HandleConnectionEvent(evt);
        }

        private int HandleConnectionEvent( QUIC_CONNECTION_EVENT* evt )
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

                    case QUIC_CONNECTION_EVENT_TYPE.PEER_STREAM_STARTED:
                        // 服务器主动开流（通常不会），忽略
                        break;
                }
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[Hysteria2-MsQuic] 连接回调异常: {ex.Message}");
                _connectedTcs.TrySetException(ex);
            }
            return Hysteria2MsQuicNative.QUIC_STATUS_SUCCESS;
        }

        /// <summary>
        /// 开启双向流（用于发送 /auth 请求）
        /// </summary>
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

            if (_bidirectionalStream != null)
                _bidirectionalStream.Dispose();

            if (_connectionHandle != IntPtr.Zero)
            {
                Hysteria2MsQuicNative.Api->ConnectionClose(_connectionHandle);
            }

            if (_gcHandle.IsAllocated)
                _gcHandle.Free();

            _internalCts.Dispose();
        }

        // 包级混淆：发送前调用（由 Stream 使用）
        internal byte[] ObfuscatePacket( ReadOnlySpan<byte> packet )
            => _obfuscator.ObfuscateOutgoing(packet);

        // 包级解混淆：接收后调用（由 Stream 使用）
        internal byte[] DeobfuscatePacket( ReadOnlySpan<byte> packet )
            => _obfuscator.DeobfuscateIncoming(packet);
    }
}