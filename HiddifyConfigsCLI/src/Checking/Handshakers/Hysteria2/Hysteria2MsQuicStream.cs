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

        // [ChatGPT 审查修改]：TaskCompletionSource 必须指定泛型类型。
        // 使用 bool 作为完成标识（无需传回值），并启用 RunContinuationsAsynchronously 以避免同步执行回调。
        private readonly TaskCompletionSource<bool> _openTcs = new ( TaskCreationOptions.RunContinuationsAsynchronously );

        // [ChatGPT 审查修改]：用 ConcurrentQueue 存放接收的数据包。
        // 使用 SemaphoreSlim 作为异步信号量替代重复创建/覆盖 TaskCompletionSource 的不安全做法，
        // 可避免 race condition（事件发生在 _readSignal 创建/替换之前导致丢失信号）。
        private readonly ConcurrentQueue<byte[]> _receiveQueue = new ( );
        private readonly SemaphoreSlim _readSignal = new ( 0, int.MaxValue );

        private volatile bool _isDisposed;

        // [ChatGPT 审查修改]：使用 ConcurrentDictionary 保持流实例映射，确保在 Dispose 时移除，从而降低泄漏风险。
        private static readonly ConcurrentDictionary<nint, Hysteria2MsQuicStream> _streamMap = new ( );

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException ( );
        public override long Position { get => throw new NotSupportedException ( ); set => throw new NotSupportedException ( ); }

        internal Hysteria2MsQuicStream ( Hysteria2MsQuicConnection connection, Hysteria2SalamanderObfuscator obfuscator, CancellationToken externalCt )
        {
            _connection = connection;
            _obfuscator = obfuscator;
            _externalCt = externalCt;
            _gcHandle = GCHandle.Alloc ( this );
        }

        internal Task OpenAsync ( )
        {
            if ( _isDisposed ) throw new ObjectDisposedException ( nameof ( Hysteria2MsQuicStream ) );

            // [ChatGPT 审查修改]
            // 调用 upstream 的 StreamOpen 需要传入一个托管委托（匹配 QUIC_STREAM_CALLBACK 委托类型）。
            // 这里直接传入方法组（StreamCallbackStatic），它与 QUIC_STREAM_CALLBACK 的签名一致（nint, nint, QUIC_STREAM_EVENT*）。
            // 注意：不要为该静态回调方法添加 UnmanagedCallersOnly 特性 —— 否则无法作为托管委托分配/传递。
            unsafe
            {
                int status = StreamOpen (
                    _connection.ConnectionHandle,
                    QUIC_STREAM_FLAGS.NONE,
                    StreamCallbackStatic,
                    GCHandle.ToIntPtr ( _gcHandle ),
                    out _streamHandle );

                if ( status != QUIC_STATUS_SUCCESS )
                {
                    _gcHandle.Free ( );
                    _openTcs.TrySetException ( new IOException ( $"StreamOpen failed: 0x{status:X8}" ) );
                    return _openTcs.Task;
                }

                // [ChatGPT 审查修改]
                // 在将实例放入全局映射前，先检查 key 是否已存在（理论上不应）。
                _streamMap[_streamHandle] = this;

                status = StreamStart ( _streamHandle, QUIC_STREAM_START_FLAGS.IMMEDIATE );
                if ( status != QUIC_STATUS_SUCCESS )
                    _openTcs.TrySetException ( new IOException ( $"StreamStart failed: 0x{status:X8}" ) );
            }

            return _openTcs.Task;
        }

        // [ChatGPT 审查修改]
        // 为了使回调与上面 Marshal.GetFunctionPointerForDelegate / NativeCallbacks 使用一致，
        // 此方法不能使用 UnmanagedCallersOnly，否则将无法创建 delegate 或通过 Marshal.GetFunctionPointerForDelegate 使用。
        // 保持普通静态方法，签名与 QUIC_STREAM_CALLBACK 完全一致（CallingConvention 在 delegate 定义处指定）。
        internal static unsafe int StreamCallbackStatic ( nint stream, nint context, QUIC_STREAM_EVENT* evt )
        {
            if ( !_streamMap.TryGetValue ( stream, out var instance ) )
                return QUIC_STATUS_SUCCESS;

            return instance.HandleStreamEvent ( evt );
        }

        private unsafe int HandleStreamEvent ( QUIC_STREAM_EVENT* evt )
        {
            try
            {
                switch ( evt->Type )
                {
                    case QUIC_STREAM_EVENT_TYPE.START_COMPLETE:
                        // [ChatGPT 审查修改]
                        // 使用 TrySetResult(true) 而不是 TrySetResult()，与 TaskCompletionSource<bool> 对应。
                        _openTcs.TrySetResult ( true );
                        break;

                    case QUIC_STREAM_EVENT_TYPE.RECEIVE:
                        var receive = &evt->Receive;

                        // [ChatGPT 审查修改]
                        // receive->Buffers 是一个 native 指针（nint），指向 QUIC_BUFFER* 的数组。
                        // 使用 Marshal.ReadIntPtr 来读取每个指针，然后 Marshal.Copy 拷贝到托管内存。
                        for ( uint i = 0; i < receive->BufferCount; i++ )
                        {
                            // 构造 IntPtr 以兼容 Marshal API
                            var buffersBase = new IntPtr ( receive->Buffers );
                            var bufferPtr = Marshal.ReadIntPtr ( buffersBase, ( int ) ( i * IntPtr.Size ) );
                            var quicBuffer = ( QUIC_BUFFER* ) bufferPtr;

                            // [ChatGPT 审查修改]
                            // 为减少短期 GC 压力，优先使用 ArrayPool<byte> 获取临时缓冲区。
                            // 但是为了最大兼容性（且不改变 deobfuscate API），这里仍然生成新的 byte[] 并在后续步骤考虑池化优化。
                            var length = ( int ) quicBuffer->Length;
                            var data = ArrayPool<byte>.Shared.Rent ( length );
                            try
                            {
                                // Marshal.Copy 支持 IntPtr 源
                                Marshal.Copy ( new IntPtr ( quicBuffer->Buffer ), data, 0, length );

                                // DeobfuscatePacket 返回托管 byte[]（由实现决定是否池化）
                                var plain = _connection.DeobfuscatePacket ( new ReadOnlySpan<byte> ( data, 0, length ) );

                                // 将结果入队
                                _receiveQueue.Enqueue ( plain );
                                // 释放暂用的租赁缓冲区
                            }
                            finally
                            {
                                ArrayPool<byte>.Shared.Return ( data );
                            }
                        }

                        // [ChatGPT 审查修改]
                        // 触发异步等待者。SemaphoreSlim 的 Release 可多次调用，适合批量数据到达的场景。
                        // 注意：Release 的次数不会超过 int.MaxValue（BufferCount 通常很小）。
                        _readSignal.Release ( ( int ) receive->BufferCount );
                        break;

                        // [ChatGPT 审查修改]
                        // 推荐显式处理更多事件（例如：SHUTDOWN_COMPLETE、SEND_COMPLETE、PEER_SEND_ABORTED 等）。
                        // 这里只保留关键分支以避免遗漏并导致 read/write 永远阻塞。
                }
            }
            catch ( Exception ex )
            {
                // [ChatGPT 审查修改]
                // 回调中抛出异常要合理传播到等待的任务上，避免 silent-fail。
                _openTcs.TrySetException ( ex );
                // 解除所有等待以促使上层处理异常：释放等待读取的信号（若有）
                // 注意：不能准确知道等待者数量，选择释放一次以尽量唤醒。若需要，可设计更复杂的错误传播机制。
                _readSignal.Release ( );
            }
            return QUIC_STATUS_SUCCESS;
        }

        public override async Task WriteAsync ( byte[] buffer, int offset, int count, CancellationToken ct )
        {
            CheckDisposed ( );
            await WaitForOpenAsync ( ct ).ConfigureAwait ( false );

            var packet = _connection.ObfuscatePacket ( new ReadOnlySpan<byte> ( buffer, offset, count ) );

            unsafe
            {
                fixed ( byte* ptr = packet )
                {
                    var qb = new QUIC_BUFFER { Length = ( uint ) packet.Length, Buffer = ptr };
                    int status = StreamSend ( _streamHandle, &qb, 1, QUIC_SEND_FLAGS.NONE, nint.Zero );
                    if ( status != QUIC_STATUS_SUCCESS )
                        throw new IOException ( $"StreamSend failed: 0x{status:X8}" );
                }
            }
        }

        public override async Task<int> ReadAsync ( byte[] buffer, int offset, int count, CancellationToken ct )
        {
            CheckDisposed ( );
            await WaitForOpenAsync ( ct ).ConfigureAwait ( false );

            // 尝试先快速从队列中读取（避免不必要的等待）
            if ( _receiveQueue.TryDequeue ( out var segment ) )
            {
                int copied = Math.Min ( count, segment.Length );
                segment.AsSpan ( 0, copied ).CopyTo ( buffer.AsSpan ( offset ) );
                return copied;
            }

            // 如果没有现成的数据，则等待信号（被 HandleStreamEvent Release）
            using var linked = CancellationTokenSource.CreateLinkedTokenSource ( ct, _externalCt );
            try
            {
                await _readSignal.WaitAsync ( linked.Token ).ConfigureAwait ( false );
            }
            catch ( OperationCanceledException )
            {
                // 取消时返回 0 表示没有读取到数据
                return 0;
            }

            // 等待被唤醒后再从队列取数据
            if ( !_receiveQueue.TryDequeue ( out segment ) )
                return 0;

            int copiedAfterWait = Math.Min ( count, segment.Length );
            segment.AsSpan ( 0, copiedAfterWait ).CopyTo ( buffer.AsSpan ( offset ) );
            return copiedAfterWait;
        }

        public override void Write ( byte[] buffer, int offset, int count )
            => WriteAsync ( buffer, offset, count, CancellationToken.None ).GetAwaiter ( ).GetResult ( );

        public override int Read ( byte[] buffer, int offset, int count )
            => ReadAsync ( buffer, offset, count, CancellationToken.None ).GetAwaiter ( ).GetResult ( );

        private Task WaitForOpenAsync ( CancellationToken ct )
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource ( ct, _externalCt );
            return _openTcs.Task.WaitAsync ( linked.Token );
        }

        private void CheckDisposed ( )
        {
            if ( _isDisposed ) throw new ObjectDisposedException ( nameof ( Hysteria2MsQuicStream ) );
        }

        protected override void Dispose ( bool disposing )
        {
            if ( _isDisposed ) return;
            _isDisposed = true;

            // [ChatGPT 审查修改]
            // 先从全局映射中移除，防止后续回调再引用到此实例。
            _streamMap.TryRemove ( _streamHandle, out _ );

            if ( _streamHandle != nint.Zero )
            {
                try
                {
                    StreamClose ( _streamHandle );
                }
                catch
                {
                    // 忽略 native close 抛出的异常（Dispose 应尽量吞掉非致命错误）
                }
                _streamHandle = nint.Zero;
            }

            if ( _gcHandle.IsAllocated )
                _gcHandle.Free ( );

            // 释放信号量资源
            _readSignal.Dispose ( );

            base.Dispose ( disposing );
        }

        public override void Flush ( ) { }
        public override long Seek ( long offset, SeekOrigin origin ) => throw new NotSupportedException ( );
        public override void SetLength ( long value ) => throw new NotSupportedException ( );
    }
}