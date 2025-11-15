// src/Checking/Handshakers/TrojanHandshaker.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using Org.BouncyCastle.Crypto.Digests;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;

/// <summary>
/// 【Trojan 握手器】完整 Trojan 协议握手（TLS + SHA224 密码验证）
/// </summary>
internal static class TrojanHandshaker
{
    /// <summary>
    /// 检测 Trojan 协议握手连通性
    /// 返回值：success, latency, stream（若 success 且希望继续用连接则返回 SslStream；调用者在最终使用完后必须 Dispose）
    /// </summary>
    public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
        // NodeInfo node,
        TrojanNode node,
        IPAddress address,
        int timeoutSec,
        RunOptions opts )
    {
        Stream? stream = null;
        var sw = Stopwatch.StartNew();

        // 总超时 CancellationTokenSource（用于整个流程）
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        var sni = node.HostParam ?? node.Host;

        // 我们要在失败时手动释放这些资源；在成功并返回 stream 时不要释放它们
        Socket? socket = null;
        NetworkStream? networkStream = null;
        SslStream? ssl = null;
        var keepAlive = false; // 如果握手成功并返回流，设置为 true，表示不要在 finally 中释放

        try
        {
            // 建立 TCP 连接（不使用 using，因为可能需要返回 stream）
            socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };

            // ConnectAsync 支持 CancellationToken
            await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token).ConfigureAwait(false);

            // 把 socket 包装成 NetworkStream，ownsSocket: true 表示关闭 NetworkStream 时会关闭 socket
            networkStream = new NetworkStream(socket, ownsSocket: true);

            // SslStream 不要在本方法内用 using，如果成功我们要把它返回给调用者
            ssl = new SslStream(networkStream, leaveInnerStreamOpen: false);

            // TLS 配置（Cert 验证策略由 CertHelper 和 TlsHelper 决定）
            var skipCertVerify = CertHelper.GetSkipCertVerify(node.ExtraParams); // 请确保 ExtraParams 的约定正确

            // 从 ExtraParams 读取 alpn（可能是单个协议或多个以逗号分隔）
            List<string>? alpnList = null;
            if (node.ExtraParams != null && node.ExtraParams.TryGetValue("alpn", out var alpnRaw) && !string.IsNullOrWhiteSpace(alpnRaw))
            {
                // 支持 "http/1.1" 或 "h2" 或 "http/1.1,h2"
                alpnList = alpnRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            }

            // 传入 CreateSslOptions
            var sslOpts = TlsHelper.CreateSslOptions(sni, skipCertVerify, alpnList);

            // TLS 认证（注意：AuthenticateAsClientAsync 会在失败时抛出 AuthenticationException）
            await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token).ConfigureAwait(false);

            // 密码检查：Trojan 使用 SHA224(hex) + "\r\n"
            var pwd = node.Password ?? "";
            if (string.IsNullOrEmpty(pwd))
            {
                // 密码为空被视为失败；在返回前停止计时
                sw.Stop();

                // 清理资源（因为不会返回 stream）
                ssl.Dispose();
                networkStream = null; // ssl.Dispose 已经处理了内层流（leaveInnerStreamOpen=false）
                socket = null;

                LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | 密码为空");
                return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
            }

            // 计算 SHA224(hex)
            var digest = new Sha224Digest();
            var pwdBytes = Encoding.UTF8.GetBytes(pwd); // 使用 UTF8 支持非 ASCII 密码
            digest.BlockUpdate(pwdBytes, 0, pwdBytes.Length);
            var hashBytes = new byte[digest.GetDigestSize()];
            digest.DoFinal(hashBytes, 0);
            var hex = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

            var payload = Encoding.UTF8.GetBytes($"{hex}\r\n");

            // 发送密码验证
            await ssl.WriteAsync(payload.AsMemory(0, payload.Length), cts.Token).ConfigureAwait(false);
            await ssl.FlushAsync(cts.Token).ConfigureAwait(false);

            // 读取响应：trojan 服务端在密码验证后可能会立即返回 "\r\n"，也可能等待客户端发送后续请求才返回。
            // 兼容性策略：
            //  - 尝试快速读取 2 字节（短超时），如果得到 CRLF 则明确验证成功；
            //  - 如果短超时内没有数据返回（超时 / IO 异常），视为握手阶段已完成（多数实现如此），仍视为成功。
            //  - 任何读取到的数据若不是 CRLF，视为验证失败。
            var buffer = ArrayPool<byte>.Shared.Rent(2);
            try
            {
                // 创建一个短时的读取超时（例如 500ms）与总超时组合
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                readCts.CancelAfter(TimeSpan.FromMilliseconds(500));

                int read = 0;
                try
                {
                    read = await ssl.ReadAsync(buffer.AsMemory(0, 2), readCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // 短超时触发（即 500ms 内未返回）: 视为“服务端没有立即返回，但握手阶段已完成”
                    // 不把它当成错误，继续返回成功并把 ssl 返回给上层
                    sw.Stop();
                    stream = ssl;
                    keepAlive = true; // 上层负责释放
                    LogHelper.Info($"[Trojan] {node.Host}:{node.Port} | 未立即返回数据，但 TLS+密码已发送 — 视为握手成功");
                    return await Task.FromResult((true, sw.Elapsed, stream));
                }
                catch (IOException ioEx)
                {
                    // IO 异常（例如对端重置）：把它当作失败
                    sw.Stop();
                    LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | 读取响应 IO 异常: {ioEx.Message}");
                    return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
                }

                // 如果读到数据，检查是否为 CRLF（\r\n）
                if (read == 2 && buffer[0] == (byte)'\r' && buffer[1] == (byte)'\n')
                {
                    sw.Stop();
                    stream = ssl;
                    keepAlive = true; // 返回后上层负责释放
                    LogHelper.Info($"[Trojan] {node.Host}:{node.Port} | 握手成功（收到 CRLF）");
                    return await Task.FromResult((true, sw.Elapsed, stream));
                }
                else if (read > 0)
                {
                    // 收到非 CRLF 数据：视为验证失败（服务端返回了错误或其他二进制）
                    sw.Stop();
                    LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | 验证响应非 CRLF，bytesRead={read}");
                    return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
                }
                else
                {
                    // read == 0: 对端已关闭连接（视为失败）
                    sw.Stop();
                    LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | 连接已被对端关闭（读取到 0 字节）");
                    return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (OperationCanceledException)
        {
            // 超时
            sw.Stop();
            LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | 超时");
            return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
        }
        catch (AuthenticationException ex)
        {
            // TLS 验证失败（证书问题等）
            sw.Stop();
            LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | TLS 认证失败: {ex.Message}");
            return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
        }
        catch (SocketException ex)
        {
            // TCP 层问题
            sw.Stop();
            LogHelper.Warn($"[Trojan] {node.Host}:{node.Port} | TCP 连接失败: {ex.Message}");
            return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogHelper.Error($"[Trojan] {node.Host}:{node.Port} | 握手异常: {ex.Message}");
            return await Task.FromResult((false, sw.Elapsed, (Stream?)null));
        }
        finally
        {
            // 仅在失败或不需要返回 stream 时释放资源
            if (!keepAlive)
            {
                try { ssl?.Dispose(); } catch { /* ignore */ }
                try { networkStream?.Dispose(); } catch { /* ignore */ }
                try { socket?.Dispose(); } catch { /* ignore */ }
            }
            else
            {
                // 成功并返回了 ssl（stream），不要在这里释放；调用者负责释放
            }
        }
    }
}
