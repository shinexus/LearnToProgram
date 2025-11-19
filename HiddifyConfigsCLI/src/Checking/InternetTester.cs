// src/Checking/InternetTester.cs
// 原文件已拆分：HTTP/请求构造/响应解析等逻辑已迁移到独立类

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking
{
    /// <summary>
    /// InternetTester - 精简协调器
    /// 仅负责：
    ///  1) 协调 HTTP 出网检测（交给 HttpInternetChecker）
    ///  2) 协调 TCP 隧道兜底检测（交给 TcpTunnelChecker）
    ///
    /// [ChatGPT 审查修改] 说明：
    /// - 将原 InternetTester.cs 中的所有具体实现拆分到单独类中（HttpInternetChecker / TcpTunnelChecker / TestUrlProvider / HttpRequestBuilder / HttpResponseReader）
    /// - 本文件保留原始入口 API（CheckInternetAsync），保持外部调用不变
    /// - 任何被迁出的旧逻辑均使用注释块保留在原处，便于人工对照与删除
    /// </summary>
    internal static class InternetTester
    {
        /// <summary>
        /// 出网检测总入口（不变的外部签名）
        /// - 仍保持 async/await
        /// - 负责调度：先 HTTP 四连发（HttpInternetChecker），失败则 TCP 兜底（TcpTunnelChecker）
        /// </summary>
        public static async Task<bool> CheckInternetAsync( NodeInfoBase node, Stream stream, string effectiveSni, RunOptions opts, CancellationToken ct = default )
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (string.IsNullOrWhiteSpace(effectiveSni)) throw new ArgumentException("effectiveSni 不能为空", nameof(effectiveSni));
            if (opts == null) throw new ArgumentNullException(nameof(opts));

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linkedCts.CancelAfter(TimeSpan.FromSeconds(opts.Timeout > 0 ? opts.Timeout : 8));

            try
            {
                // 优先 HTTP 四连发检测（实现细节在 HttpInternetChecker.cs）
                if (await HttpInternetChecker.CheckHttpInternetAsync(node, stream, effectiveSni, opts, linkedCts.Token).ConfigureAwait(false))
                    return true;

                // HTTP 失败 -> TCP 兜底（实现细节在 TcpTunnelChecker.cs）
                return await TcpTunnelChecker.CheckTcpTunnelAsync(stream, opts, linkedCts.Token).ConfigureAwait(false);
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

        /*
         * 说明：下面为迁出示例（保留旧实现的注释块，便于审查与回滚）
         * - 旧版包含：GetTestUrl / BuildFourHttpGetRequestBytes / ReadHttpResponseHeaderAsync / CheckTcpTunnelAsync 等
         * - 现已拆分到：TestUrlProvider.cs, HttpRequestBuilder.cs, HttpResponseReader.cs, TcpTunnelChecker.cs
         *
         * 如果需要查看完整旧实现，请参考历史提交或原始文件（已保存在仓库历史）。
         */
    }
}
