// src/Checking/HttpResponseReader.cs
// 从 InternetTester.cs 拆分类，负责读取完整 HTTP 响应头
// [ChatGPT 审查修改]：原 ReadHttpResponseHeaderAsync 方法迁移至此

using HiddifyConfigsCLI.src.Logging;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking
{
    internal static class HttpResponseReader
    {
        /// <summary>
        /// [ChatGPT 审查修改]
        /// 读取完整 HTTP 响应头（最大 64KB）
        /// 返回 (success, headerString)
        /// </summary>
        public static async Task<(bool success, string header)> ReadHttpResponseHeaderAsync( Stream stream, CancellationToken ct )
        {
            const int softLimit = 1024 * 64; // 64KB

            var ms = new MemoryStream(1024);
            var readBuffer = ArrayPool<byte>.Shared.Rent(4096);

            try
            {
                while (true)
                {
                    ct.ThrowIfCancellationRequested();

                    var read = await stream.ReadAsync(readBuffer, ct).ConfigureAwait(false);
                    if (read == 0)
                    {
                        LogHelper.Verbose("[HTTP] 服务器提前关闭连接（0 字节响应）");
                        return (false, "");
                    }

                    ms.Write(readBuffer, 0, read);

                    if (ms.Length >= 4)
                    {
                        var buffer = ms.GetBuffer();
                        int len = (int)ms.Length;
                        for (int i = Math.Max(0, len - read - 4); i <= len - 4; i++)
                        {
                            if (buffer[i] == (byte)'\r' && buffer[i + 1] == (byte)'\n' &&
                                buffer[i + 2] == (byte)'\r' && buffer[i + 3] == (byte)'\n')
                            {
                                var header = Encoding.ASCII.GetString(buffer, 0, i + 4);
                                LogHelper.Debug($"[HTTP] 收到完整响应头（{i + 4} 字节）");
                                return (true, header);
                            }
                        }
                    }

                    if (ms.Length > softLimit)
                    {
                        LogHelper.Info($"[HTTP] 响应头超大（>{softLimit / 1024}KB），标记为可疑成功");
                        return (true, "");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                LogHelper.Warn("[HTTP] 出网检测超时");
                return (false, "");
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[HTTP] 读取响应头异常: {ex.Message.Split('\n')[0]}");
                return (false, "");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(readBuffer);
                ms.Dispose();
            }
        }
    }
}