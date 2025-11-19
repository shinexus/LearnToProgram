// src/Checking/TcpTunnelChecker.cs
// 从 InternetTester.cs 拆分类，负责 TCP CONNECT 兜底检测
// [ChatGPT 审查修改]：代码迁自原 InternetTester.cs 并强化职责单一性

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Buffers;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking
{
    internal static class TcpTunnelChecker
    {
        /// <summary>
        /// [ChatGPT 审查修改]
        /// 将 InternetTester.cs 中的 TCP CONNECT 检测完全迁移到此处
        /// 负责：
        ///  - 构造 CONNECT 命令
        ///  - 发送并读取响应
        ///  - 判断是否存在 "200"（隧道建立成功）
        /// </summary>
        public static async Task<bool> CheckTcpTunnelAsync(
            Stream stream,
            RunOptions opts,
            CancellationToken ct )
        {
            var targets = new[]
            {
                "8.8.8.8:53",
                "1.1.1.1:53",
                "208.67.222.222:53",
                "114.114.114.114:53"
            };

            var shuffled = targets.OrderBy(_ => Random.Shared.Next()).Take(2);

            foreach (var target in shuffled)
            {
                var parts = target.Split(':');
                var host = parts[0];
                var port = int.Parse(parts[1]);

                var connectCmd = $"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n";
                var bytes = Encoding.UTF8.GetBytes(connectCmd);

                try
                {
                    await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
                    await stream.FlushAsync(ct).ConfigureAwait(false);

                    var respBuffer = ArrayPool<byte>.Shared.Rent(128);
                    try
                    {
                        var read = await stream.ReadAsync(respBuffer.AsMemory(0, 128), ct).ConfigureAwait(false);
                        if (read > 0)
                        {
                            var resp = Encoding.ASCII.GetString(respBuffer, 0, read);
                            if (resp.Contains("200", StringComparison.Ordinal))
                            {
                                LogHelper.Info($"[TCP 隧道成功] → {target}");
                                return true;
                            }
                        }
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(respBuffer);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    LogHelper.Debug($"[TCP CONNECT 失败] {target} | {ex.Message}");
                }
            }

            LogHelper.Warn("[TCP 隧道失败] 所有目标不可达");
            return false;
        }
    }
}