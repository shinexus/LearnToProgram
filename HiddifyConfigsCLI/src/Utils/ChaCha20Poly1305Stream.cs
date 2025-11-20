// src/Utils/ChaCha20Poly1305Stream.cs
// [Grok 完整修复_2025-11-20_024] .NET 6+ 必须实现 Position.set
// [Grok 终极修复_2025-11-20_025] BouncyCastle 2.4.0+ 完全兼容版
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

internal sealed class ChaCha20Poly1305Stream : Stream
{
    private readonly Stream _baseStream;
    private readonly IAeadCipher _cipher;  // ← 关键：改用 IAeadCipher！
    private readonly byte[] _buffer = new byte[65536];
    private bool _disposed;

    public ChaCha20Poly1305Stream( Stream baseStream, byte[] key, byte[] iv, bool isClient )
    {
        _baseStream = baseStream ?? throw new ArgumentNullException(nameof(baseStream));

        // [Grok 修复_2025-11-20_025] 使用新接口 IAeadCipher
        _cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        var parameters = new AeadParameters(new KeyParameter(key), 128, iv);

        _cipher.Init(isClient, parameters);
    }

    public override bool CanRead => _baseStream.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => _baseStream.CanWrite;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => _baseStream.Position;
        set => throw new NotSupportedException("ChaCha20Poly1305Stream 不支持定位");
    }

    public override long Seek( long offset, SeekOrigin origin )
        => throw new NotSupportedException();

    public override void SetLength( long value )
        => throw new NotSupportedException();

    public override int Read( byte[] buffer, int offset, int count )
        => ReadAsync(buffer, offset, count).GetAwaiter().GetResult();

    public override async Task<int> ReadAsync( byte[] buffer, int offset, int count, CancellationToken ct )
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ChaCha20Poly1305Stream));

        int read = await _baseStream.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
        if (read > 0)
        {
            var outBuf = ArrayPool<byte>.Shared.Rent(read + 16);
            try
            {
                int outLen = _cipher.ProcessBytes(buffer, offset, read, outBuf, 0);
                outLen += _cipher.DoFinal(outBuf, outLen);  // 解密 + 验证 tag
                Buffer.BlockCopy(outBuf, 0, buffer, offset, outLen);
            }
            catch (InvalidCipherTextException)
            {
                throw new IOException("ChaCha20-Poly1305 解密失败：数据被篡改或密钥错误");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(outBuf);
            }
        }
        return read;
    }

    public override void Write( byte[] buffer, int offset, int count )
        => WriteAsync(buffer, offset, count).GetAwaiter().GetResult();

    public override async Task WriteAsync( byte[] buffer, int offset, int count, CancellationToken ct )
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ChaCha20Poly1305Stream));

        var outBuf = ArrayPool<byte>.Shared.Rent(count + 16);
        try
        {
            int outLen = _cipher.ProcessBytes(buffer, offset, count, outBuf, 0);
            outLen += _cipher.DoFinal(outBuf, outLen);  // 加密 + 添加 tag
            await _baseStream.WriteAsync(outBuf, 0, outLen, ct).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(outBuf);
        }
    }

    public override void Flush() => _baseStream.Flush();
    public override Task FlushAsync( CancellationToken ct ) => _baseStream.FlushAsync(ct);

    protected override void Dispose( bool disposing )
    {
        if (!_disposed)
        {
            if (disposing)
            {
                try { _cipher.Reset(); } catch { }
            }
            _disposed = true;
        }
        base.Dispose(disposing);
    }
}