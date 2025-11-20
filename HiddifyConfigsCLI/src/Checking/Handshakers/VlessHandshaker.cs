// src/Checking/Handshakers/VlessHandshaker.cs
// [重构版_2025-11-20] 核心握手流程
// 拆分：TLS/REALITY → TlsRealityHelper
//       Header 构建 → VlessHeaderBuilder
//       gRPC → VlessGrpcHandler
//       XHTTP → VlessXHttpHandler
//       WS → HttpInternetChecker.CheckWebSocketUpgradeAsync
// 功能：VLESS 节点握手主逻辑
// 目的：调用独立 Handler 类，实现 TCP/TLS/REALITY/WS/gRPC/XHTTP 全流程
// 优化：可读性、性能、可维护性，保留原注释和日志

using HiddifyConfigsCLI.src.Checking;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;

internal static class VlessHandshaker
{
    /// <summary>
    /// VLESS 节点测试入口
    /// </summary>
    public static async Task<(bool success, TimeSpan latency, Stream? stream)> TestAsync(
        VlessNode node,
        IPAddress address,
        int timeoutSec,
        RunOptions opts )
    {
        bool returnStreamToCaller = false;
        var sw = Stopwatch.StartNew();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSec));
        Stream? baseStream = null;

        try
        {
            // ===== 阶段1：建立 TCP 连接 =====
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            socket.SendTimeout = timeoutSec * 1000;
            socket.ReceiveTimeout = timeoutSec * 1000;
            await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token).ConfigureAwait(false);
            baseStream = new NetworkStream(socket, ownsSocket: true);
            LogHelper.Debug($"[VLESS-TCP] {node.Host}:{node.Port} | TCP Connect 成功");

            // ===== 阶段2：提取参数 =====
            var extra = node.ExtraParams ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var uuidStr = node.UserId ?? extra.GetValueOrDefault("id") ?? "";
            if (string.IsNullOrEmpty(uuidStr))
            {
                LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 缺失 UUID");
                return (false, sw.Elapsed, null);
            }

            var transportType = extra.GetValueOrDefault("transport_type") ?? "";

            // ===== 阶段3：TLS / REALITY =====
            var stream = await TlsRealityHelper.HandleTlsRealityAsync(node, baseStream, extra, timeoutSec, cts)
                                               .ConfigureAwait(false);
            if (stream == null)
                return (false, sw.Elapsed, null);

            // ===== 阶段4：传输类型处理 =====
            var security = extra.GetValueOrDefault("security") ?? "tls";
            var effectiveSni = node.EffectiveSni ?? node.Host;
            var skipCertVerify = extra.GetValueOrDefault("skip_cert_verify") == "true";

            if (transportType.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
    transportType.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase))
            {
                // 提取 effectiveSni 和 wsPath
                // var effectiveSni = node.EffectiveSni ?? node.Host;
                var wsPath = extra.GetValueOrDefault("ws_path") ?? extra.GetValueOrDefault("path") ?? "/";

                // 调用拆分后的 VlessWsHandler
                var wsResult = await VlessWsHandler.HandleWebSocketAsync(
                    node,
                    stream!,
                    effectiveSni,
                    node.Port,
                    wsPath,
                    opts,
                    extra,
                    cts.Token
                ).ConfigureAwait(false);

                sw.Stop();
                if (wsResult)
                {
                    returnStreamToCaller = true;
                    node.EffectiveSni = effectiveSni;
                    LogHelper.Info($"[VLESS-WS] {node.Host}:{node.Port} | WebSocket 握手+出网成功 | {sw.Elapsed.TotalMilliseconds:F0}ms");
                    return (true, sw.Elapsed, stream);
                }
                else
                {
                    LogHelper.Warn($"[VLESS-WS] {node.Host}:{node.Port} | WebSocket 升级失败");
                    return (false, sw.Elapsed, null);
                }
            }
            else if (transportType.Equals("grpc", StringComparison.OrdinalIgnoreCase))
            {
                // gRPC 处理
                return await VlessGrpcHandler.HandleGrpcAsync(
                    node,
                    address,
                    extra,
                    security,
                    cts,
                    sw,
                    effectiveSni
                ).ConfigureAwait(false);
            }
            else if (transportType.Equals("xhttp", StringComparison.OrdinalIgnoreCase))
            {
                // XHTTP 处理
                return await VlessXHttpHandler.HandleXHttpAsync(
                    node,
                    address,
                    timeoutSec,
                    extra,
                    skipCertVerify,
                    sw,
                    cts,
                    effectiveSni
                ).ConfigureAwait(false);
            }

            // ===== 阶段4T：默认 TCP 直连 =====
            var uuid = Guid.TryParse(uuidStr, out var id) ? id : Guid.NewGuid();
            var header = VlessHeaderBuilder.BuildVlessHeader(node, address, uuid, extra);

            await stream.WriteAsync(header, cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);
            LogHelper.Debug($"[VLESS-TCP] {node.Host}:{node.Port} | Header 发送成功");

            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await stream.ReadAsync(buf.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
                sw.Stop();
                if (read > 0)
                {
                    returnStreamToCaller = true;
                    node.EffectiveSni = node.EffectiveSni;
                    LogHelper.Info($"[VLESS-握手成功] {node.Host}:{node.Port} | latency={sw.ElapsedMilliseconds}ms");
                    return (true, sw.Elapsed, stream);
                }
                else
                {
                    LogHelper.Warn($"[VLESS-握手失败] {node.Host}:{node.Port} | 服务器关闭连接");
                    return (false, sw.Elapsed, null);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 超时");
            return (false, sw.Elapsed, null);
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 异常: {ex.Message}");
            return (false, sw.Elapsed, null);
        }
        finally
        {
            if (baseStream != null && !returnStreamToCaller)
            {
                await baseStream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}


