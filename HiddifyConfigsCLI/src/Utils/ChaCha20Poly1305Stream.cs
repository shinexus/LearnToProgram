// src/Utils/ChaCha20Poly1305Stream.cs
using Org.BouncyCastle.Crypto.Parameters;
using System.Buffers;

internal sealed class ChaCha20Poly1305Stream : Stream
{
    private readonly Stream _baseStream;
    private readonly IAuthenticatedCipher _encryptor;
    private readonly IAuthenticatedCipher _decryptor;
    private readonly byte[] _buffer = new byte[65536];
    private bool _disposed;

    public ChaCha20Poly1305Stream( Stream baseStream, byte[] key, byte[] iv, bool isClient )
    {
        _baseStream = baseStream;
        var cipher = new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
        var parameters = new AeadParameters(new KeyParameter(key), 128, iv);

        _encryptor = cipher;
        _decryptor = cipher;

        if (isClient)
        {
            _encryptor.Init(true, parameters);
            _decryptor.Init(false, parameters);
        }
        else
        {
            _encryptor.Init(false, parameters);
            _decryptor.Init(true, parameters);
        }
    }

    public override async Task<int> ReadAsync( byte[] buffer, int offset, int count, CancellationToken ct )
    {
        int read = await _baseStream.ReadAsync(buffer, offset, count, ct);
        if (read > 0)
            _decryptor.ProcessBytes(buffer, offset, read, buffer, offset);
        return read;
    }

    public override async Task WriteAsync( byte[] buffer, int offset, int count, CancellationToken ct )
    {
        var outBuf = ArrayPool<byte>.Shared.Rent(count + 16);
        try
        {
            int outLen = _encryptor.ProcessBytes(buffer, offset, count, outBuf, 0);
            outLen += _encryptor.DoFinal(outBuf, outLen);
            await _baseStream.WriteAsync(outBuf.AsMemory(0, outLen), ct);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(outBuf);
        }
    }

    // 其他 Stream 方法省略...
}