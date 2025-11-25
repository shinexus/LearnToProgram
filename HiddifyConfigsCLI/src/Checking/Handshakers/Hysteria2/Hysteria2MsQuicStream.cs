// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/MsQuic/Hysteria2MsQuicStream.cs
// Grok 写的代码，我一点也不懂
// 中文说明：MsQuic 双向流包装器
// 自动处理 Salamander 包级加解密
// 支持 WriteAsync / ReadAsync 完全 async

using HiddifyConfigsCLI.src.Core;
using System.Buffers;
using System.Collections.Concurrent;
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
        private readonly TaskCompletionSource _openTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ConcurrentQueue<byte[]> _receiveQueue = new();
        private TaskCompletionSource<int> _readTcs = new();
        private volatile bool _isDisposed;

        private static readonly ConcurrentDictionary<nint, Hysteria2MsQuicStream> _streamMap = new();

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
            if (_isDisposed) throw new ObjectDisposedException(nameof(Hysteria2MsQuicStream));

            int status = StreamOpen(
                _connection.ConnectionHandle,
                QUIC_STREAM_FLAGS.NONE,
                StreamCallbackStatic,
                GCHandle.ToIntPtr(_gcHandle),
                out _streamHandle);

            if (status != QUIC_STATUS_SUCCESS)
            {
                _gcHandle.Free();
                _openTcs.TrySetException(new IOException($"StreamOpen failed: 0x{status:X8}"));
                return _openTcs.Task;
            }

            _streamMap[_streamHandle] = this;

            status = StreamStart(_streamHandle, QUIC_STREAM_START_FLAGS.IMMEDIATE);
            if (status != QUIC_STATUS_SUCCESS)
                _openTcs.TrySetException(new IOException($"StreamStart failed: 0x{status:X8}"));

            return _openTcs.Task;
        }

        [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
        internal static unsafe int StreamCallbackStatic( nint stream, nint context, QUIC_STREAM_EVENT* evt )
        {
            if (!_streamMap.TryGetValue(stream, out var instance))
                return QUIC_STATUS_SUCCESS;

            return instance.HandleStreamEvent(evt);
        }

        private unsafe int HandleStreamEvent( QUIC_STREAM_EVENT* evt )
        {
            try
            {
                switch (evt->Type)
                {
                    case QUIC_STREAM_EVENT_TYPE.START_COMPLETE:
                        _openTcs.TrySetResult();
                        break;

                    case QUIC_STREAM_EVENT_TYPE.RECEIVE:
                        var receive = &evt->Receive;
                        for (uint i = 0; i < receive->BufferCount; i++)
                        {
                            var bufferPtr = Marshal.ReadIntPtr(receive->Buffers, (int)(i * IntPtr.Size));
                            var quicBuffer = (QUIC_BUFFER*)bufferPtr;
                            var data = new byte[quicBuffer->Length];
                            Marshal.Copy((nint)quicBuffer->Buffer, data, 0, data.Length);

                            var plain = _connection.DeobfuscatePacket(data);
                            _receiveQueue.Enqueue(plain);
                        }
                        _readTcs.TrySetResult(_receiveQueue.Count);
                        break;
                }
            }
            catch (Exception ex)
            {
                _openTcs.TrySetException(ex);
                _readTcs.TrySetException(ex);
            }
            return QUIC_STATUS_SUCCESS;
        }

        public override async Task WriteAsync( byte[] buffer, int offset, int count, CancellationToken ct )
        {
            CheckDisposed();
            await WaitForOpenAsync(ct).ConfigureAwait(false);

            var packet = _connection.ObfuscatePacket(new ReadOnlySpan<byte>(buffer, offset, count));

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

        public override async Task<int> ReadAsync( byte[] buffer, int offset, int count, CancellationToken ct )
        {
            CheckDisposed();
            await WaitForOpenAsync(ct).ConfigureAwait(false);

            while (_receiveQueue.IsEmpty)
            {
                _readTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
                await _readTcs.Task.WaitAsync(ct).ConfigureAwait(false);
            }

            if (!_receiveQueue.TryDequeue(out var segment))
                return 0;

            int copied = Math.Min(count, segment.Length);
            segment.AsSpan(0, copied).CopyTo(buffer.AsSpan(offset));
            return copied;
        }

        public override void Write( byte[] buffer, int offset, int count )
            => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override int Read( byte[] buffer, int offset, int count )
            => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

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

            _streamMap.TryRemove(_streamHandle, out _);
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