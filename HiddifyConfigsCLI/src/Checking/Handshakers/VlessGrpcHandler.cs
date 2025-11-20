// src/Checking/Handshakers/VlessGrpcHandler.cs
// [重构版_2025-11-20]
// 功能：VLESS 节点 gRPC 处理
// 目的：将 VlessHandshaker 中 gRPC 相关逻辑抽离为独立类，提高可读性与可维护性

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Buffers;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;

internal static class VlessGrpcHandler
{
    /// <summary>
    /// 处理 gRPC 传输类型
    /// </summary>
    /// <param name="node">VLESS 节点信息</param>
    /// <param name="address">IP 地址</param>
    /// <param name="extra">节点额外参数</param>
    /// <param name="security">安全类型（tls/reality）</param>
    /// <param name="cts">取消令牌源</param>
    /// <param name="sw">计时器，用于记录延迟</param>
    /// <param name="effectiveSni">有效 SNI</param>
    /// <returns>握手结果 (success, latency, stream)</returns>
    public static async Task<(bool, TimeSpan, Stream?)> HandleGrpcAsync(
        VlessNode node,
        IPAddress address,
        IReadOnlyDictionary<string, string> extra,
        string security,
        CancellationTokenSource cts,
        System.Diagnostics.Stopwatch sw,
        string effectiveSni )
    {
        // 1. 构建 gRPC 路径
        var grpcService = extra.GetValueOrDefault("grpc_service") ?? "vless";
        var grpcPath = $"/{grpcService}";

        try
        {
            using var handler = new HttpClientHandler();

            // 如果使用 TLS，则跳过证书验证
            if (security == "tls")
                handler.ServerCertificateCustomValidationCallback = ( sender, cert, chain, errors ) => true;

            using var httpClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };

            var grpcUri = new UriBuilder
            {
                Scheme = security == "tls" ? "https" : "http",
                Host = node.Host,
                Port = node.Port,
                Path = grpcPath
            }.Uri;

            // 解析 UUID
            var uuidgRPC = VlessHeaderBuilder.ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.UserId ?? "");

            // 构建最小 payload
            byte[] grpcPayload = new byte[5];
            using var content = new ByteArrayContent(grpcPayload);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc");

            // 构建请求
            var request = new HttpRequestMessage(HttpMethod.Post, grpcUri)
            {
                Content = content,
                Version = HttpVersion.Version20
            };

            // 注入 gRPC 自定义 Header
            foreach (var kv in extra.Where(kv => kv.Key.StartsWith("grpc_header_")))
            {
                var headerName = kv.Key["grpc_header_".Length..];
                request.Headers.TryAddWithoutValidation(headerName, kv.Value);
            }

            // 发送请求
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                                               .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                LogHelper.Warn($"[gRPC] {node.Host}:{node.Port} | HTTP 状态码: {response.StatusCode}");
                sw.Stop();
                return (false, sw.Elapsed, null);
            }

            // 尝试读取返回流的第一字节
            using var respStream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await respStream.ReadAsync(buf.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
                sw.Stop();
                LogHelper.Info($"[gRPC] {node.Host}:{node.Port} | 握手成功");

                node.EffectiveSni = effectiveSni;

                return (read > 0, sw.Elapsed, null);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[gRPC] {node.Host}:{node.Port} | 握手失败: {ex.Message}");
            sw.Stop();
            return (false, sw.Elapsed, null);
        }
    }
}
