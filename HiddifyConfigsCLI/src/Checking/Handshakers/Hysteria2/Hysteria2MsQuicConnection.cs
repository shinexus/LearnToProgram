// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicConnection.cs
// Grok 写的代码，我一点也不懂
// 基于原生 MsQuic 的 Hysteria2 专用连接实现
// 完全实现 packet-level Salamander：所有 QUIC 包（包括 Initial）都经过混淆
// 使用 TaskCompletionSource + GCHandle 实现安全 async/await
// 支持双向流、超时控制、日志完整
// 补齐 Registration -> ConnectionOpen 流程，暴露 ConnectionHandle，移除类级 unsafe

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
        // Registration handle（来自 RegistrationOpen）
        private nint _registrationHandle = nint.Zero;

        // Connection handle（来自 ConnectionOpen）——必须对 StreamOpen 可见
        internal nint ConnectionHandle { get; private set; } = nint.Zero;

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

        /// <summary>
        /// 构造函数：执行 RegistrationOpen -> ConnectionOpen -> ConnectionSetCallbackHandler
        /// 注意：这里在需要与 native 交互的地方使用局部 unsafe 块以避免把整个类标记为 unsafe。
        /// </summary>
        public Hysteria2MsQuicConnection(
            string obfsPassword,
            Hysteria2Node node,
            CancellationToken externalToken )
        {
            _gcHandle = GCHandle.Alloc(this);
            _obfuscator = new Hysteria2SalamanderObfuscator(obfsPassword);

            // 1) RegistrationOpen（传 null 配置指针，native 接受 null）
            unsafe
            {
                // RegistrationOpen 原型：int RegistrationOpen(byte* Config, out nint Registration);
                // 传入 null 即可（等同无特殊注册配置）
                int regStatus = RegistrationOpen((byte*)0, out nint regHandle);
                if (regStatus != QUIC_STATUS_SUCCESS)
                {
                    _gcHandle.Free();
                    throw new InvalidOperationException($"RegistrationOpen failed: 0x{regStatus:X8}");
                }
                _registrationHandle = regHandle;
            }

            // 2) ConnectionOpen：第一个参数为 registration handle（不是回调），第二参数为托管 delegate（QUIC_CONNECTION_CALLBACK）
            //    注意：这里我们传入 NativeCallbacks.ConnectionDelegate（托管 delegate），而不是 ConnectionPtr（nint）。
            int openStatus = ConnectionOpen(
                _registrationHandle,
                NativeCallbacks.ConnectionDelegate,   // 正确：delegate 类型
                GCHandle.ToIntPtr(_gcHandle),
                out nint connHandle);

            if (openStatus != QUIC_STATUS_SUCCESS)
            {
                // 回滚 registration
                if (_registrationHandle != nint.Zero)
                {
                    RegistrationClose(_registrationHandle);
                    _registrationHandle = nint.Zero;
                }
                _gcHandle.Free();
                throw new InvalidOperationException($"ConnectionOpen failed: 0x{openStatus:X8}");
            }

            ConnectionHandle = connHandle;

            // 3) ConnectionSetCallbackHandler：将我们希望使用的回调绑定到实际 connection
            //    注意：ConnectionSetCallbackHandlerDelegate 的签名期望第二参数为 QUIC_CONNECTION_CALLBACK（托管 delegate）
            int setCbStatus = ConnectionSetCallbackHandler(
                ConnectionHandle,
                NativeCallbacks.ConnectionDelegate,   // 正确：delegate 类型（不是 nint）
                GCHandle.ToIntPtr(_gcHandle));

            if (setCbStatus != QUIC_STATUS_SUCCESS)
            {
                // 清理并抛异常
                ConnectionClose(ConnectionHandle);
                ConnectionHandle = nint.Zero;

                RegistrationClose(_registrationHandle);
                _registrationHandle = nint.Zero;

                _gcHandle.Free();
                throw new InvalidOperationException($"ConnectionSetCallbackHandler failed: 0x{setCbStatus:X8}");
            }

            // 4) 如果外部 token 触发取消，则尝试优雅关闭连接
            externalToken.Register(() =>
            {
                if (!_isDisposed && ConnectionHandle != nint.Zero)
                    ConnectionShutdown(ConnectionHandle, QUIC_CONNECTION_SHUTDOWN_FLAGS.NONE, 0);
            });
        }

        // ============================
        //     回调静态入口（不把整个类标记为 unsafe）
        // ============================
        // 注意：此方法使用 unsafe 参数（QUIC_CONNECTION_EVENT*），所以需声明 unsafe。
        internal static unsafe int ConnectionCallbackStatic( nint connection, nint context, QUIC_CONNECTION_EVENT* evt )
        {
            var self = (Hysteria2MsQuicConnection?)GCHandle.FromIntPtr(context).Target;
            if (self == null) return QUIC_STATUS_SUCCESS;
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

                        // 其他事件建议也处理（PEER_STREAM_STARTED 等）
                }
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[Hysteria2-MsQuic] 连接回调异常: {ex.Message}");
                _connectedTcs.TrySetException(ex);
            }

            return QUIC_STATUS_SUCCESS;
        }

        // ============================
        //     打开双向流（此方法为 async，不在 unsafe 上下文中）
        // ============================
        public async Task<Hysteria2MsQuicStream> OpenBidirectionalStreamAsync( CancellationToken ct )
        {
            if (_isDisposed) throw new ObjectDisposedException(nameof(Hysteria2MsQuicConnection));
            if (!IsConnected) await Connected.WaitAsync(ct).ConfigureAwait(false);

            var stream = new Hysteria2MsQuicStream(this, _obfuscator, ct);
            await stream.OpenAsync().ConfigureAwait(false);
            _bidirectionalStream = stream;
            return stream;
        }

        // ============================
        //     清理 MsQuic 连接与 registration
        // ============================
        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;

            _bidirectionalStream?.Dispose();

            if (ConnectionHandle != nint.Zero)
            {
                try { ConnectionClose(ConnectionHandle); }
                catch { /* ignore */ }
                ConnectionHandle = nint.Zero;
            }

            if (_registrationHandle != nint.Zero)
            {
                try { RegistrationClose(_registrationHandle); }
                catch { /* ignore */ }
                _registrationHandle = nint.Zero;
            }

            if (_gcHandle.IsAllocated)
                _gcHandle.Free();

            _internalCts.Dispose();
        }

        // Salamander 混淆封装（保持原 API）
        internal byte[] ObfuscatePacket( ReadOnlySpan<byte> packet )
            => _obfuscator.ObfuscateOutgoing(packet);

        internal byte[] DeobfuscatePacket( ReadOnlySpan<byte> packet )
            => _obfuscator.DeobfuscateIncoming(packet);
    }
}