using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking.Handshakers
{
    internal static class Hysteria2Handshaker
    {
        /// <summary>
        /// 适配新接口：异步测试节点（纯 .NET 9 QUIC 实现）
        /// 返回值签名保持与其他协议一致：(bool success, TimeSpan latency, Stream? stream)
        /// </summary>
        public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
            HiddifyConfigsCLI.src.Core.NodeInfo node,
            IPAddress address,
            int timeoutSec,
            RunOptions opts // 可扩展参数结构，包含 REALITY/JA3 等配置
        )
        {
            var sw = Stopwatch.StartNew();
            var serverEndPoint = new IPEndPoint(address, node.Port);

            // --- 1️⃣ 配置 QUIC 连接参数 ---
            var quicOptions = new QuicClientConnectionOptions
            {
                RemoteEndPoint = serverEndPoint,
                DefaultStreamErrorCode = 0,
                DefaultCloseErrorCode = 0,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = node.Host,
                    ApplicationProtocols = new() { SslApplicationProtocol.Http3 },
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }
            };

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));

            try
            {
                // --- 2️⃣ 建立 QUIC 连接 ---
                await using var connection = await QuicConnection.ConnectAsync(quicOptions, cts.Token);
                LogHelper.Debug($"[Hysteria2] QUIC Connected: {node.Host}:{node.Port} | {connection.RemoteEndPoint}");

                // --- 3️⃣ 创建出站双向流 ---
                await using var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cts.Token);

                // --- 4️⃣ 发送 Hysteria2 控制请求 ---
                var request =
                    "CONNECT / HTTP/3\r\n" +
                    $"Host: {node.Host}\r\n" +
                    "User-Agent: hysteria/2.3.0\r\n" +
                    "Hysteria-UDP: true\r\n" +
                    "Connection: keep-alive\r\n\r\n";

                var reqBytes = Encoding.ASCII.GetBytes(request);
                await stream.WriteAsync(reqBytes, cts.Token);

                // --- 5️⃣ 读取服务器返回 ---
                var buffer = ArrayPool<byte>.Shared.Rent(4096);
                int bytesRead = await stream.ReadAsync(buffer.AsMemory(0, 4096), cts.Token);
                string resp = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                ArrayPool<byte>.Shared.Return(buffer);

                // --- 校验握手结果 ---
                if (!resp.Contains("200") && !resp.Contains("OK", StringComparison.OrdinalIgnoreCase))
                {
                    LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 握手响应异常: {resp[..Math.Min(resp.Length, 120)]}");
                    // ❗将响应封装为 MemoryStream 返回，方便上层读取
                    var respStream = new MemoryStream(Encoding.UTF8.GetBytes(resp));
                    return (false, sw.Elapsed, respStream);
                }

                LogHelper.Info($"[Hysteria2] {node.Host}:{node.Port} 握手成功 ✅");

                // --- 6️⃣ Datagram 功能暂不支持 (.NET 9 托管栈不含 SendDatagramAsync) ---
                // 可在后续使用 opts 实现应用层 Ping 或 QUIC 原始扩展

                sw.Stop();

                // ✅ 将响应封装为内存流返回，保持接口统一
                var successStream = new MemoryStream(Encoding.UTF8.GetBytes(resp));
                return (true, sw.Elapsed, successStream);
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 超时未响应");
                return (false, sw.Elapsed, null);
            }
            catch (Exception ex)
            {
                sw.Stop();
                LogHelper.Warn($"[Hysteria2] {node.Host}:{node.Port} 握手失败: {ex.Message}");
                return (false, sw.Elapsed, null);
            }
        }
    }

    /// <summary>
    /// Hysteria2 可扩展参数，可用于 REALITY/JA3 TLS 配置
    /// </summary>
    internal class Hysteria2Options
    {
        public bool UseReality { get; set; } = false;
        public string? Sni { get; set; }
        public byte[]? Ja3Fingerprint { get; set; }
        // 其他可扩展参数
    }
}