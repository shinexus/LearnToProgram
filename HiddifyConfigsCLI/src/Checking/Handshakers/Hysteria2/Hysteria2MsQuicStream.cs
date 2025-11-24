// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicStream.cs
// [Grok 修复_2025-11-24_012]
// 中文说明：MsQuic 双向流包装器
// 自动处理 Salamander 包级加解密
// 支持 WriteAsync / ReadAsync 完全 async

using System.Buffers;
using System.IO;
using System.Runtime.InteropServices;
using static HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic.Hysteria2MsQuicNative;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2.MsQuic
{
    internal sealed class Hysteria2MsQuicStream : Stream, IDisposable
    {
        private readonly Hysteria2MsQuicConnection _connection;
        private readonly Hysteria2SalamanderObfuscator _obfuscator;
        private readonly TaskCompletionSource<IntPtr> _streamTcs = new();
        private readonly CancellationToken _externalCt;
        private readonly GCHandle _gcHandle;

        private IntPtr _streamHandle = IntPtr.Zero;
        private bool _isOpenSent = false;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;

        internal Hysteria2MsQuicStream( Hysteria2MsQuicConnection connection, Hysteria2SalamanderObfuscator obfuscator, CancellationToken externalCt )
        {
            _connection = connection;
            _obfuscator = obfuscator;
            _externalCt = externalCt;
            _gcHandle = GCHandle.Alloc(this);
        }

        internal Task OpenAsync()
        {
            int status = Hysteria2MsQuicNative.Api->StreamOpen(
                _connection._connectionHandle,
                QUIC_STREAM_FLAGS.NONE,
                &StreamCallback,
                (void*)GCHandle.ToIntPtr(_gcHandle),
                out _streamHandle);

            if (status != Hysteria2MsQuicNative.QUIC_STATUS_SUCCESS)
                _streamTcs.TrySetException(new InvalidOperationException($"StreamOpen failed: 0x{status:X8}"));
            else
                _ = Task.Run(() => Hysteria2MsQuicNative.Api->StreamStart(_streamHandle, QUIC_STREAM_START_FLAGS.IMMEDIATE));

            return _streamTcs.Task;
        }

        [UnmanagedCallersOnly]
        private static int StreamCallback( IntPtr stream, IntPtr context, QUIC_STREAM_EVENT* evt )
        {
            var self = (Hysteria2MsQuicStream)GCHandle.FromIntPtr(context).Target!;
            return self.HandleStreamEvent(evt);
        }

        private int HandleStreamEvent( QUIC_STREAM_EVENT* evt )
        {
            switch (evt->Type)
            {
                case QUIC_STREAM_EVENT_TYPE.START_COMPLETE:
                    _streamTcs.TrySetResult(_streamHandle);
                    break;
                case QUIC_STREAM_EVENT_TYPE.RECEIVE:
                    // 后续由 ReadAsync 轮询处理
                    break;
            }
            return Hysteria2MsQuicNative.QUIC_STATUS_SUCCESS;
        }

        public override async Task WriteAsync( byte[] buffer, int offset, int count, CancellationToken ct )
        {
            if (_streamHandle == IntPtr.Zero) await _streamTcs.Task;
            var packet = _connection.ObfuscatePacket(new ReadOnlySpan<byte>(buffer, offset, count));

            fixed (byte* ptr = packet)
            {
                var quicBuffer = new QUIC_BUFFER { Length = (uint)packet.Length, Buffer = ptr };
                int status = Hysteria2MsQuicNative.Api->StreamSend(_streamHandle, &quicBuffer, 1, QUIC_SEND_FLAGS.NONE, IntPtr.Zero);
                if (status != Hysteria2MsQuicNative.QUIC_STATUS_SUCCESS)
                    throw new IOException($"StreamSend failed: 0x{status:X8}");
            }
        }

        public override void Dispose()
        {
            if (_streamHandle != IntPtr.Zero)
            {
                Hysteria2MsQuicNative.Api->StreamClose(_streamHandle);
                _streamHandle = IntPtr.Zero;
            }
            if (_gcHandle.IsAllocated) _gcHandle.Free();
        }

        // 以下方法暂未完整实现（ReadAsync 在第三部分完成）
        public override int Read( byte[] buffer, int offset, int count ) => throw new NotSupportedException();
        public override long Seek( long offset, SeekOrigin origin ) => throw new NotSupportedException();
        public override void SetLength( long value ) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    }
}