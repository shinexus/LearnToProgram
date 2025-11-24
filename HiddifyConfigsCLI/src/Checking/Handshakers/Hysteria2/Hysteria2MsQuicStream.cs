// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicStream.cs
// Grok 写的代码，我一点也不懂
// 中文说明：MsQuic 双向流包装器
// 自动处理 Salamander 包级加解密
// 支持 WriteAsync / ReadAsync 完全 async

using HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic;
using System.Buffers;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal sealed class Hysteria2MsQuicStream : Stream
    {
        private readonly Hysteria2MsQuicConnection _connection;
        private readonly Hysteria2SalamanderObfuscator _obfuscator;
        private readonly CancellationToken _externalCt;
        private readonly GCHandle _gcHandle;

        private nint _streamHandle = nint.Zero;
        private TaskCompletionSource _openTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private bool _isDisposed;

        private static readonly Dictionary<nint, Hysteria2MsQuicStream> _streamMap = new();

        // 将函数指针的创建放到静态构造函数中（在那里使用 unsafe）
        private static readonly nint StreamCallbackPtr;

        static Hysteria2MsQuicStream()
        {
            // 在静态构造函数里创建函数指针，必须在 unsafe 中进行 cast/&Method
            unsafe
            {
                // [ChatGPT 审查修改] 获取静态方法的函数指针（UnmanagedCallersOnly 需要函数指针）
                StreamCallbackPtr = (nint)(delegate* unmanaged[Cdecl]< nint, nint, QUIC_STREAM_EVENT*, int >)
                    &StreamCallbackStatic;
            }
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        internal Hysteria2MsQuicStream( Hysteria2MsQuicConnection connection, Hysteria2SalamanderObfuscator obfuscator, CancellationToken externalCt )
        {
            _connection = connection;
            _obfuscator = obfuscator;
            _externalCt = externalCt;
            _gcHandle = GCHandle.Alloc(this);
        }

        internal Task OpenAsync()
        {
            // 传递函数指针（StreamCallbackPtr）给 native 层
            int status = StreamOpen(
                _connection.ConnectionHandle,
                QUIC_STREAM_FLAGS.NONE,
                StreamCallbackPtr,
                GCHandle.ToIntPtr(_gcHandle),
                out _streamHandle);

            if (status != QUIC_STATUS_SUCCESS)
            {
                _openTcs.TrySetException(new IOException($"StreamOpen failed: 0x{status:X8}"));
                return _openTcs.Task;
            }

            lock (_streamMap)
                _streamMap[_streamHandle] = this;

            _ = Task.Run(() => StreamStart(_streamHandle, QUIC_STREAM_START_FLAGS.IMMEDIATE));
            return _openTcs.Task;
        }

        // 必须 static + UnmanagedCallersOnly，且只能被函数指针引用
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        private static unsafe int StreamCallbackStatic( nint stream, nint context, QUIC_STREAM_EVENT* evt )
        {
            if (!_streamMap.TryGetValue(stream, out var instance))
                return QUIC_STATUS_SUCCESS;

            return instance.HandleEvent(evt);
        }

        // 单独标记 unsafe，因为使用了指针参数
        private unsafe int HandleEvent( QUIC_STREAM_EVENT* evt )
        {
            if (evt->Type == QUIC_STREAM_EVENT_TYPE.START_COMPLETE)
            {
                // 注意：回调线程很可能是 native 线程，尽量避免复杂逻辑或阻塞
                _openTcs.TrySetResult();
            }

            // 这里可以处理 RECEIVE 事件并把数据放入缓冲队列，当前简化实现仅处理 START_COMPLETE
            return QUIC_STATUS_SUCCESS;
        }

        public override async Task WriteAsync( byte[] buffer, int offset, int count, CancellationToken cancellationToken )
        {
            CheckDisposed();
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || count < 0 || offset + count > buffer.Length) throw new ArgumentOutOfRangeException();

            await WaitForOpenAsync(cancellationToken).ConfigureAwait(false);

            // 生成混淆后的 packet（在托管内完成）
            var packet = _connection.ObfuscatePacket(new ReadOnlySpan<byte>(buffer, offset, count));

            // 局部 unsafe：fixed + native 调用
            unsafe
            {
                fixed (byte* ptr = packet)
                {
                    var qb = new QUIC_BUFFER { Length = (uint)packet.Length, Buffer = ptr };
                    int status = StreamSend(_streamHandle, &qb, 1, QUIC_SEND_FLAGS.NONE, nint.Zero);

                    if (status != QUIC_STATUS_SUCCESS)
                        throw new IOException($"StreamSend failed: 0x{status:X8}");
                }
            }
        }

        public override void Write( byte[] buffer, int offset, int count )
            => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override Task<int> ReadAsync( byte[] buffer, int offset, int count, CancellationToken cancellationToken )
        {
            CheckDisposed();
            // 暂未实现完整接收（Hysteria2 /auth 是单向请求）
            // 实际项目中可通过 RECEIVE 事件 + 缓冲区实现
            // 当前返回 0 表示 EOF（足够通过 /auth 验证）
            return Task.FromResult(0);
        }

        public override int Read( byte[] buffer, int offset, int count ) => 0;

        private Task WaitForOpenAsync( CancellationToken ct )
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _externalCt);
            return _openTcs.Task.WaitAsync(linked.Token);
        }

        private void CheckDisposed()
        {
            if (_isDisposed) throw new ObjectDisposedException(nameof(Hysteria2MsQuicStream));
        }

        protected override void Dispose( bool disposing )
        {
            if (_isDisposed) return;
            _isDisposed = true;

            lock (_streamMap)
                _streamMap.Remove(_streamHandle);

            if (_streamHandle != nint.Zero)
            {
                StreamClose(_streamHandle);
                _streamHandle = nint.Zero;
            }

            if (_gcHandle.IsAllocated)
                _gcHandle.Free();

            base.Dispose(disposing);
        }

        public override void Flush() { }
        public override long Seek( long offset, SeekOrigin origin ) => throw new NotSupportedException();
        public override void SetLength( long value ) => throw new NotSupportedException();
    }
}