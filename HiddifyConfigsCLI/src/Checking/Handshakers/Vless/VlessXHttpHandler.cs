// src/Checking/Handshakers/VlessXHttpHandler.cs
// [重构版_2025-11-20]
// 功能：VLESS 节点 XHTTP 处理
// 目的：将 VlessHandshaker 中 XHTTP 相关逻辑抽离为独立类，提高可读性与可维护性

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Vless;

internal static class VlessXHttpHandler
{
    /// <summary>
    /// 处理 XHTTP 传输类型
    /// </summary>
    /// <param name="node">VLESS 节点信息</param>
    /// <param name="address">IP 地址</param>
    /// <param name="timeoutSec">超时时间（秒）</param>
    /// <param name="extra">节点额外参数</param>
    /// <param name="skipCertVerify">是否跳过 TLS 证书验证</param>
    /// <param name="sw">计时器，用于记录延迟</param>
    /// <param name="cts">取消令牌源</param>
    /// <param name="effectiveSni">有效 SNI</param>
    /// <returns>握手结果 (success, latency, stream)</returns>
    public static async Task<(bool, TimeSpan, Stream?)> HandleXHttpAsync(
        VlessNode node,
        IPAddress address,
        int timeoutSec,
        IReadOnlyDictionary<string, string> extra,
        bool skipCertVerify,
        System.Diagnostics.Stopwatch sw,
        CancellationTokenSource cts,
        string effectiveSni )
    {
        // 1. 构建路径、Host、Method
        var xhttpPath = extra.GetValueOrDefault("xhttp_path") ?? "/";
        var xhttpHost = extra.GetValueOrDefault("xhttp_host") ?? node.Host;
        var xhttpMethod = (extra.GetValueOrDefault("xhttp_method") ?? "GET").ToUpperInvariant();

        // 2. 提取自定义 header
        var xhttpHeaders = extra
            .Where(k => k.Key.StartsWith("xhttp_header_"))
            .ToDictionary(k => k.Key["xhttp_header_".Length..], k => k.Value);

        // 3. 初始化 HttpClientHandler
        var handler = new HttpClientHandler();
        if (skipCertVerify)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        using var httpClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

        // 注入自定义 header
        foreach (var (key, val) in xhttpHeaders)
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation(key, val);

        // 4. 构建请求 URI
        var requestUri = new UriBuilder
        {
            Scheme = (extra.GetValueOrDefault("security") ?? "tls") == "tls" ? "https" : "http",
            Host = node.Host,
            Port = node.Port,
            Path = xhttpPath.Split('?')[0],
            Query = xhttpPath.Contains('?') ? xhttpPath.Split('?', 2)[1] : ""
        }.Uri;

        var request = new HttpRequestMessage(new HttpMethod(xhttpMethod), requestUri);
        request.Headers.Host = xhttpHost;

        // 5. 构建 VLESS Header 并作为 Content
        var uuidXHTTP = VlessHeaderBuilder.ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.UserId ?? "");
        var vlessHeader = VlessHeaderBuilder.BuildVlessHeader(node, address, uuidXHTTP, extra);
        request.Content = new ByteArrayContent(vlessHeader);

        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                                               .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                LogHelper.Warn($"[XHTTP] {node.Host}:{node.Port} | HTTP 状态码: {response.StatusCode}");
                sw.Stop();
                return (false, sw.Elapsed, null);
            }

            // 读取返回流的第一字节，作为握手成功判定
            using var respStream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await respStream.ReadAsync(buf.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
                sw.Stop();

                node.EffectiveSni = effectiveSni;

                LogHelper.Info($"[XHTTP] {node.Host}:{node.Port} | 握手成功");
                return (read > 0, sw.Elapsed, null);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[XHTTP] {node.Host}:{node.Port} | 握手失败: {ex.Message}");
            sw.Stop();
            return (false, sw.Elapsed, null);
        }
    }
}
