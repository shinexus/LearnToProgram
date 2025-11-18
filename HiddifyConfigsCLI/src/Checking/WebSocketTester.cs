// WebSocketTester.cs
// 负责：通过隧道检测 WebSocket / HTTP Upgrade 可用性
// 命名空间：HiddifyConfigsCLI.src.Checking
// [ chatGPT 自我补救 ]

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking;

internal static class WebSocketTester
{
    /// <summary>
    /// 通过隧道发送 WebSocket 或 HTTP Upgrade 请求检测节点是否可用
    /// 成功条件：收到 HTTP 101 Switching Protocols 响应
    /// </summary>
    /// <param name="stream">已建立的隧道流（VLESS/Trojan/Hysteria2）</param>
    /// <param name="host">目标主机（Host）</param>
    /// <param name="path">请求路径，例如 /ws</param>
    /// <param name="opts">运行选项（包含 UserAgent、Timeout 等）</param>
    /// <param name="ct">取消令牌</param>
    /// <param name="transportType">可选类型：ws / httpupgrade</param>
    /// <returns>true 表示 Upgrade 成功</returns>
    public static async Task<bool> TestAsync(
        Stream stream,
        string host,
        string path,
        RunOptions opts,
        CancellationToken ct = default,
        string transportType = "ws"
    )
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout));

        try
        {
            // ==== 构造 Upgrade 请求 ====
            string upgradeHeader =
                transportType.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase)
                    ? "h2c"
                    : "websocket";

            string secWebSocketKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

            var request = new StringBuilder();
            request.AppendLine($"GET {path} HTTP/1.1");
            request.AppendLine($"Host: {host}");
            request.AppendLine($"Upgrade: {upgradeHeader}");
            request.AppendLine("Connection: Upgrade");

            if (transportType.Equals("ws", StringComparison.OrdinalIgnoreCase))
            {
                // 仅 WebSocket 需要这些头
                request.AppendLine($"Sec-WebSocket-Key: {secWebSocketKey}");
                request.AppendLine("Sec-WebSocket-Version: 13");
            }

            request.AppendLine($"User-Agent: {opts.UserAgent}");
            request.AppendLine("Accept: */*");
            request.AppendLine(); // 空行结束头部

            byte[] requestBytes = Encoding.ASCII.GetBytes(request.ToString());

            if (opts.Verbose)
                LogHelper.Debug($"[{transportType.ToUpperInvariant()} Upgrade] → {host}{path} | {request.Length} bytes");

            await stream.WriteAsync(requestBytes, linkedCts.Token);
            await stream.FlushAsync(linkedCts.Token);

            // ==== 读取响应 ====
            var buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                int totalRead = 0;
                int headerEnd = -1;

                while (totalRead < buffer.Length && headerEnd == -1)
                {
                    int read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), linkedCts.Token);
                    if (read == 0) break;
                    totalRead += read;

                    // 查找 \r\n\r\n
                    for (int i = Math.Max(0, totalRead - read - 3); i <= totalRead - 4; i++)
                    {
                        if (buffer[i] == '\r' && buffer[i + 1] == '\n' &&
                            buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                        {
                            headerEnd = i + 4;
                            break;
                        }
                    }
                }

                if (totalRead == 0)
                {
                    LogHelper.Warn($"[{transportType.ToUpperInvariant()} 无响应] {host}{path}");
                    return false;
                }

                string response = Encoding.UTF8.GetString(buffer, 0, totalRead);
                string firstLine = response.Split('\n')[0].Trim();

                if (opts.Verbose)
                    LogHelper.Debug($"[{transportType.ToUpperInvariant()} Response] → {host}{path} | {firstLine}");

                // ==== 成功条件 ====
                bool success =
                    firstLine.Contains("101", StringComparison.OrdinalIgnoreCase) &&
                    response.Contains("Upgrade", StringComparison.OrdinalIgnoreCase);

                if (success)
                {
                    LogHelper.Info($"[{transportType.ToUpperInvariant()} Upgrade 成功] → {host}{path} | {firstLine}");
                    return true;
                }

                LogHelper.Warn($"[{transportType.ToUpperInvariant()} Upgrade 失败] → {host}{path} | {firstLine}");
                return false;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (OperationCanceledException)
        {
            LogHelper.Warn($"[{transportType.ToUpperInvariant()} Upgrade 超时] {host}{path} | {opts.Timeout}s");
            return false;
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[{transportType.ToUpperInvariant()} Upgrade 异常] {host}{path} | {ex.Message}");
            return false;
        }
    }
}