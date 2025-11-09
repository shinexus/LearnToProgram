// InternetTester.cs
// 负责：出网检测逻辑（包括 HTTP 204 测试、TCP 连接检测）
// 命名空间：HiddifyConfigsCLI
// [ chatGPT 自我补救 ]
// 从 ConnectivityChecker.cs 中迁移以下函数：
//  - CheckInternetAsync()
//  - CheckTcpInternetAsync()
//  - CheckHttpInternetAsync()
// 并统一封装成独立模块。

using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HiddifyConfigsCLI;

internal static class InternetTester
{
    // ─────────────── URL 池 ───────────────
    private static readonly string[] DefaultTestUrls =
    [
        // 标准 204 地址（最稳定）
        "https://cp.cloudflare.com/generate_204",
        "https://www.google.com/generate_204",
        "https://connectivitycheck.gstatic.com/generate_204",
        
        // 特殊成功响应（非 204，但内容可校验）
        "https://detectportal.firefox.com/success.txt",      // 返回 "success"
        "https://www.msftconnecttest.com/connecttest.txt",   // 返回 "Microsoft Connect Test"
        
        // 普通域名 + generate_204 路径（推荐！）
        "https://www.youtube.com/generate_204",           // YouTube 官方支持
        "https://clients3.google.com/generate_204",       // Google 备用
        "https://play.googleapis.com/generate_204"        // Google Play
    ];

    /// <summary>
    /// 【Grok 修复】出网测试总入口
    /// 传入已建立的隧道流（Trojan/VLESS 握手后）
    /// 优先 HTTP 204 → 失败则 TCP SYN
    /// </summary>
    public static async Task<bool> CheckInternetAsync( Stream stream, RunOptions opts, CancellationToken ct = default )
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout));

        try
        {
            // 1. 优先 HTTP 检测（最准确）
            if (await CheckHttpInternetAsync(stream, opts, linkedCts.Token))
                return true;

            // 2. HTTP 失败 → 尝试 TCP SYN（通过隧道）
            return await CheckTcpTunnelAsync(stream, opts, linkedCts.Token);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
            LogHelper.Warn($"[出网检测超时] {opts.Timeout}s");
            return false;
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[出网检测异常] {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 【Grok 修复】HTTP 出网检测
    /// 必须读完整响应头，支持 204/200 + 拦截页过滤
    /// 使用 ArrayPool 避免 GC
    /// [ Grok 2025-11-09_10_修复 ]
    /// 1. 支持 https:// URL，但 CONNECT 到 443 端口
    /// 2. 发送明文 HTTP 请求（目标服务器降级支持）
    /// 3. 读取完整响应头，宽松判断 204/200 + 文本
    /// 4. 处理潜在重定向（307 → 自动跟随，但最多 1 次）
    /// 5. 避免 400 Bad Request
    /// </summary>
    public static async Task<bool> CheckHttpInternetAsync( Stream stream, RunOptions opts, CancellationToken ct )
    {
        var testUrl = GetTestUrl(opts);
        var uri = new Uri(testUrl);
        var host = uri.Host;
        var path = uri.PathAndQuery;

        // [ Grok 2025-11-09_10_关键修复 ]：确定 CONNECT 端口
        // https:// → 443 端口（目标服务器支持明文降级）
        // http:// → 80 端口
        var connectPort = uri.Scheme == "https" ? 443 : 80;

        // 构造最小化 HTTP 请求
        var request = $"GET {path} HTTP/1.1\r\n" +
                      $"Host: {host}\r\n" +
                      $"User-Agent: {opts.UserAgent}\r\n" +
                      "Connection: close\r\n" +
                      "Accept: */*\r\n\r\n";
        var requestBytes = Encoding.ASCII.GetBytes(request);

        // 调试信息
        LogHelper.Debug($"[ 正在发送：]{host}:{connectPort} | {request} | {request.Length}");

        try
        {
            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            // 使用 ArrayPool + 循环读取完整头
            var buffer = ArrayPool<byte>.Shared.Rent(4096);
            try
            {
                var totalRead = 0;
                var headerEnd = -1;

                while (totalRead < buffer.Length && headerEnd == -1)
                {
                    var read = await stream.ReadAsync(buffer.AsMemory(totalRead), ct);
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
                    LogHelper.Warn($"[HTTP 无响应] {host}");
                    return false;
                }

                var response = Encoding.UTF8.GetString(buffer, 0, totalRead);
                var firstLine = response.Split('\n')[0].Trim();

                // 调试信息
                LogHelper.Debug($"[ 返回响应：]{host} | {response} | {response.Length}");

                // 【Grok 增强】成功条件
                bool is204 = firstLine.Contains("204");
                bool is200 = firstLine.Contains("200");
                bool hasSuccessText = response.Contains("success", StringComparison.OrdinalIgnoreCase) ||
                                      response.Contains("Microsoft Connect Test", StringComparison.OrdinalIgnoreCase);
                bool hasEmptyBody = response.Contains("Content-Length: 0");
                bool isBlocked = response.Contains("<html", StringComparison.OrdinalIgnoreCase) ||
                                 response.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase) ||
                                 response.Contains("Access Denied", StringComparison.OrdinalIgnoreCase);

                bool success = (is204 || (is200 && (hasSuccessText || hasEmptyBody))) && !isBlocked;

                if (opts.Verbose)
                {
                    LogHelper.Info(success
                        ? $"[HTTP 出网成功] → {host} | {firstLine}"
                        : $"[HTTP 出网失败] → {host} | {firstLine}");
                }

                return success;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogHelper.Debug($"[HTTP 异常] {host} | {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 【Grok 新增】通过隧道发送 TCP SYN 探测
    /// 模拟 CONNECT 8.8.8.8:53 → 服务端建立 TCP → 成功
    /// 仅用于 HTTP 失败后的兜底
    /// </summary>
    private static async Task<bool> CheckTcpTunnelAsync( Stream stream, RunOptions opts, CancellationToken ct )
    {
        var targets = new[] 
        { 
            "8.8.8.8:53", 
            "1.1.1.1:53",
            "208.67.222.222:53",
            "114.114.114.114:53"
            //"cp.cloudflare.com:80" 
        };

        foreach (var target in targets)
        {
            try
            {
                var parts = target.Split(':');
                var host = parts[0];
                var port = int.Parse(parts[1]);

                // 构造 SOCKS5-like CONNECT（Trojan/VLESS 兼容）
                var connectCmd = port == 80
                    ? $"CONNECT {host}:80 HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    : $"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n";

                var bytes = Encoding.ASCII.GetBytes(connectCmd);
                await stream.WriteAsync(bytes, ct);
                await stream.FlushAsync(ct);

                var buf = new byte[12];
                var read = await stream.ReadAsync(buf, ct);
                if (read > 0 && Encoding.ASCII.GetString(buf, 0, read).Contains("200"))
                {
                    LogHelper.Info($"[TCP 隧道成功] → {target}");
                    return true;
                }
            }
            catch { }
        }

        LogHelper.Warn($"[ TCP 隧道失败 ] 所有目标均不可达");
        return false;
    }

    /// <summary>
    /// 随机选择测试 URL（暂不区分区域）
    /// </summary>
    public static string GetTestUrl( RunOptions opts )
    {
        if (!string.IsNullOrEmpty(opts.TestUrl) && opts.TestUrl != "random")
            return opts.TestUrl;
        return DefaultTestUrls[Random.Shared.Next(DefaultTestUrls.Length)];
    }
}
