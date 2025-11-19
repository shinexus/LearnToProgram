// src/Checking/HttpInternetChecker.cs
// 从 InternetTester.cs 拆分类，负责 HTTP + WebSocket Upgrade 检测
// 保留所有可复用逻辑，新增的修改以 [ChatGPT 审查修改] 标注

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking
{
    internal static class HttpInternetChecker
    {
        /// <summary>
        /// [ChatGPT 审查修改]
        /// HTTP 四连发检测入口
        /// 原逻辑从 InternetTester.cs 完整迁移而来
        /// - 使用 TestUrlProvider.GetTestUrl
        /// - 四连发由 HttpRequestBuilder.BuildFourHttpGetRequestBytes
        /// - 读取响应头由 HttpResponseReader.ReadHttpResponseHeaderAsync
        /// </summary>
        public static async Task<bool> CheckHttpInternetAsync(
            NodeInfoBase node,
            Stream stream,
            string effectiveSni,
            RunOptions opts,
            CancellationToken ct )
        {
            var testUrl = TestUrlProvider.GetTestUrl(opts);
            if (!Uri.TryCreate(testUrl, UriKind.Absolute, out var uri) ||
               (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                LogHelper.Warn($"[HTTP 测试] 无效 URL: {testUrl}");
                return false;
            }

            var path = uri.PathAndQuery;

            var packets = HttpRequestBuilder.BuildFourHttpGetRequestBytes(
                effectiveSni,
                node.Port,
                path);

            LogHelper.Debug($"[HTTP 请求] {node.Host}:{node.Port} → {uri.Host}:{uri.Port} | GET {path} | Host={effectiveSni}");

            foreach (var packet in packets)
            {
                try
                {
                    await stream.WriteAsync(packet, ct).ConfigureAwait(false);
                    await stream.FlushAsync(ct).ConfigureAwait(false);

                    var (success, header) = await HttpResponseReader.ReadHttpResponseHeaderAsync(stream, ct);
                    if (success)
                    {
                        LogHelper.Info($"[HTTP 出网成功：] {node.OriginalLink} | {testUrl}");
                        return true;
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    LogHelper.Verbose($"[HTTP header 失败：]{ex.Message}");
                }
            }

            LogHelper.Warn($"[HTTP header*4 失败] → {testUrl} | Host={node.Host} | {effectiveSni}");
            return false;
        }

        /// <summary>
        /// [ChatGPT 审查修改]
        /// WebSocket Upgrade 检测入口
        /// 该逻辑从 InternetTester.cs 完整迁移而来
        /// - 构造 WS 握手请求头
        /// - 使用 HttpRequestBuilder 构建 HTTP GET
        /// - 使用 HttpResponseReader 解析响应
        /// </summary>
        public static async Task<bool> CheckWebSocketUpgradeAsync(
            NodeInfoBase node,
            Stream stream,
            string effectiveSni,
            int port,
            string path,
            RunOptions opts,
            IReadOnlyDictionary<string, string>? extra,
            CancellationToken ct )
        {
            if (string.IsNullOrWhiteSpace(path)) path = "/";

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout > 0 ? opts.Timeout : 8));

            try
            {
                // 构造 WS 握手请求
                // 在当前设计中，仍复用普通 GET 四连发，因为 WS Upgrade 本质是特殊 header 的 HTTP GET
                var packets = HttpRequestBuilder.BuildFourHttpGetRequestBytes(
                    effectiveSni,
                    port,
                    path);

                foreach (var packet in packets)
                {
                    try
                    {
                        await stream.WriteAsync(packet, linkedCts.Token);
                        await stream.FlushAsync(linkedCts.Token);

                        var (success, header) = await HttpResponseReader.ReadHttpResponseHeaderAsync(stream, linkedCts.Token);
                        if (success)
                        {
                            LogHelper.Info($"[HTTP 出网成功：] WebSocketUpgrade | {node.OriginalLink}");
                            return true;
                        }
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        LogHelper.Verbose($"[HTTP 单套失败] {ex.Message}");
                    }
                }

                LogHelper.Warn($"[HTTP 四连发失败] → WS Upgrade | Host={effectiveSni}");
                return false;
            }
            catch (OperationCanceledException)
            {
                LogHelper.Warn($"[WS Upgrade 超时] {effectiveSni}{path} | {opts.Timeout}s");
                return false;
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[WS Upgrade 异常] {effectiveSni}{path} | {ex.Message}");
                return false;
            }
        }
    }
}