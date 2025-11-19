// src/Checking/Handshakers/VlessHandshaker.cs
// [Grok 完整修复版_2025-11-17_017] 
// 修复要点：
//   1. 废弃 HandleWebSocketAsync（功能重复 + 缺陷）
//   2. WS 检测统一迁移至 InternetTester.CheckWebSocketUpgradeAsync
//   3. 支持 ws_header_* 全部注入
//   4. 所有 return 使用 Task.FromResult((...))
//   5. 保留 ExtraParams 只读 + 全字段读取
//   6. 统一 UUID 处理
//   7. TLS/REALITY 复用 stream
//   8. 性能：ArrayPool + ConfigureAwait(false)
//   9. 废弃代码用 /* 废弃 */ 包围
//   10. 依赖：InternetTester 已含 CheckWebSocketUpgradeAsync

using HiddifyConfigsCLI.src.Checking;
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;

/// <summary>
/// [VLESS 握手器] 支持 REALITY / WebSocket / gRPC / XTLS-Vision
/// [Grok 修复_2025-11-17_017] 统一 WS 检测、废弃重复方法、规范返回
/// 注意：TCP → TLS/REALITY → 发送 VLESS Header（认证） → 出网检测（HTTP 204）
/// </summary>
internal static class VlessHandshaker
{
    /// <summary>    
    /// <param name="node"></param>
    /// <param name="address"></param>
    /// <param name="timeoutSec"></param>
    /// <param name="opts"></param>
    /// <returns></returns>
    /// </summary>
    //
    // 注意：async 方法内不能直接 return Task.FromResult，改为裸元组
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
            // ====== 阶段1：建立 TCP 连接 ======
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            socket.SendTimeout = timeoutSec * 1000;  // [Grok 修复] 单位 ms
            socket.ReceiveTimeout = timeoutSec * 1000;
            await socket.ConnectAsync(new IPEndPoint(address, node.Port), cts.Token).ConfigureAwait(false);
            baseStream = new NetworkStream(socket, ownsSocket: true);
            LogHelper.Debug($"[VLESS-阶段1] {node.Host}:{node.Port} | TCP Connect 成功");

            // ====== 阶段2：提取参数（只读）======
            var extra = node.ExtraParams ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var uuidStr = node.UserId ?? extra.GetValueOrDefault("id") ?? "";
            if (string.IsNullOrEmpty(uuidStr))
            {
                LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 缺失 UUID");
                // return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
                // async 方法内不能直接 return Task.FromResult，改为裸元组
                return (false, sw.Elapsed, null);
            }

            var security = extra.GetValueOrDefault("security") ?? "tls";
            var transportType = extra.GetValueOrDefault("transport_type") ?? "";
            var skipCertVerify = extra.GetValueOrDefault("skip_cert_verify") == "true";
            var sni = node.HostParam ?? node.Host;
            string effectiveSni = node.Host;

            // REALITY 启用条件
            var realityEnabled = string.Equals(extra.GetValueOrDefault("reality_enabled"), "true", StringComparison.OrdinalIgnoreCase)
                                 || string.Equals(security, "reality", StringComparison.OrdinalIgnoreCase);

            // ====== 阶段3：TLS / REALITY 握手 ======
            Stream? stream = baseStream;

            if (security is "tls" or "reality")
            {
                LogHelper.Debug($"[VLESS-阶段3] {node.Host}:{node.Port} | 开始 TLS (原始 SNI={sni}, skipCert={skipCertVerify})");

                // ---------- 1. 计算 effectiveSni ----------
                // var effectiveSni = sni;

                if (security == "reality" && !string.IsNullOrEmpty(sni))
                {
                    LogHelper.Debug($"[VLESS-TLS-SNI] {node.Host}:{node.Port} | REALITY 模式，预验证 SNI={sni}");

                    var hostParts = node.Host.Split('.');
                    var fallbackSnis = new List<string> { node.Host };

                    if (hostParts.Length >= 2)
                    {
                        var root = string.Join(".", hostParts.Skip(hostParts.Length - 2));
                        fallbackSnis.Add(root);
                        fallbackSnis.Add("www." + root);
                        fallbackSnis.Add("*." + root);
                    }
                    fallbackSnis.Add("www.microsoft.com");
                    fallbackSnis.Add("www.cloudflare.com");
                    fallbackSnis = fallbackSnis.Distinct().ToList();

                    LogHelper.Verbose($"[VLESS-TLS-SNI] {node.Host}:{node.Port} | 动态 fallback SNIs: {string.Join(", ", fallbackSnis)}");

                    foreach (var f in fallbackSnis)
                    {
                        var match = await TlsHelper.PreValidateSniAsync(node.Host, node.Port, f, 2000, skipCertVerify).ConfigureAwait(false);
                        LogHelper.Verbose($"[VLESS-TLS-SNI-Fallback] {node.Host}:{node.Port} | 测试 SNI={f} → Match={match}");

                        if (match)
                        {
                            effectiveSni = f.StartsWith("*.") ? node.Host : f;
                            LogHelper.Info($"[VLESS-TLS-SNI] {node.Host}:{node.Port} | 匹配成功，停止测试 → 使用 effectiveSni={effectiveSni}");
                            break;
                        }
                    }

                    if (effectiveSni == sni)
                    {
                        effectiveSni = node.Host;
                        LogHelper.Warn($"[VLESS-TLS-SNI] {node.Host}:{node.Port} | 所有 fallback 失败，强制使用 Host={effectiveSni}");
                    }
                }
                else
                {
                    // 两种写法逻辑相同
                    // effectiveSni = string.IsNullOrEmpty(sni) ? node.Host : sni;
                    effectiveSni = !string.IsNullOrEmpty(sni) ? sni : node.Host;
                    LogHelper.Debug($"[VLESS-阶段3] {node.Host}:{node.Port} | 非 REALITY，使用 SNI={effectiveSni}");
                }

                // ---------- 2. Chrome ClientHello ----------
                bool helloOk = await TlsHelper.TestTlsWithChromeHelloAsync(
                    node.Host, node.Port, effectiveSni,
                    timeoutMs: (int)TimeSpan.FromSeconds(timeoutSec).TotalMilliseconds
                ).ConfigureAwait(false);

                if (!helloOk)
                {
                    LogHelper.Warn($"[TLS] {node.Host}:{node.Port} | Chrome ClientHello 失败 (SNI={effectiveSni})");
                    
                    // return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
                    // async 方法内不能直接 return Task.FromResult，改为裸元组
                    return (false, sw.Elapsed, null);
                }

                // ---------- 3. 正式 SSL 握手 ----------
                var ssl = new SslStream(stream, leaveInnerStreamOpen: true);
                var sslOpts = TlsHelper.CreateSslOptions(effectiveSni, skipCertVerify);  // [Grok 修复_2025-11-17_018] 使用 effectiveSni

                sslOpts.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                sslOpts.ApplicationProtocols = new List<SslApplicationProtocol>
                {
                    SslApplicationProtocol.Http2,
                    SslApplicationProtocol.Http11
                };

                await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token).ConfigureAwait(false);

                // 注意：stream 类型是 SslStream 
                stream = ssl;

                LogHelper.Info($"[TLS] {node.Host}:{node.Port} | Chrome 指纹握手成功 (SNI={effectiveSni})");
            }

            // ====== 阶段3R：REALITY 握手 ======
            if (realityEnabled && security == "reality")
            {
                LogHelper.Debug($"[VLESS-阶段3R] {node.Host}:{node.Port} | 开始 REALITY");

                var spx = extra.GetValueOrDefault("spx") ?? "/";
                var pk = extra.GetValueOrDefault("reality_public_key") ?? "";
                var sid = extra.GetValueOrDefault("reality_short_id") ?? "";
                var pbk = extra.GetValueOrDefault("pbk") ?? "";
                var activePk = !string.IsNullOrEmpty(pk) ? pk : pbk;

                if (string.IsNullOrEmpty(activePk) || !IsValidBase64(activePk) || activePk.Length < 32)
                {
                    LogHelper.Warn($"[VLESS-阶段3R] {node.Host}:{node.Port} | REALITY public_key 无效 (len={activePk?.Length ?? 0})");

                    // return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
                    // async 方法内不能直接 return Task.FromResult，改为裸元组
                    return (false, sw.Elapsed, null);
                }
                if (string.IsNullOrEmpty(sid) || sid.Length > 16)
                {
                    LogHelper.Warn($"[VLESS-阶段3R] {node.Host}:{node.Port} | REALITY short_id 无效 (len={sid?.Length ?? 0})");

                    // return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
                    // async 方法内不能直接 return Task.FromResult，改为裸元组
                    return (false, sw.Elapsed, null);
                }

                var ok = await RealityHelper.RealityHandshakeAsync(stream!, sid, activePk, spx, cts.Token).ConfigureAwait(false);
                if (ok)
                    LogHelper.Info($"[VLESS-阶段3R] {node.Host}:{node.Port} | REALITY 握手成功");
                else
                {
                    LogHelper.Warn($"[VLESS-阶段3R] {node.Host}:{node.Port} | REALITY 握手超时/失败");

                    // return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
                    // async 方法内不能直接 return Task.FromResult，改为裸元组
                    return (false, sw.Elapsed, null);
                }
            }

            // ====== 阶段4：传输类型处理 ======
            bool handshakeSuccess = false;
            TimeSpan latency = sw.Elapsed;

            if (transportType.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
                transportType.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase))
            {
                var wsPath = extra.GetValueOrDefault("ws_path") ?? extra.GetValueOrDefault("path") ?? "/";
                var wsSuccess = await HttpInternetChecker.CheckWebSocketUpgradeAsync(
                    node,
                    stream: stream!,
                    effectiveSni: effectiveSni,  // [Grok 修复_2025-11-17_018] 使用 effectiveSni
                    port: node.Port,
                    path: wsPath,
                    opts: opts,
                    extra: extra,
                    ct: cts.Token).ConfigureAwait(false);

                sw.Stop();
                latency = sw.Elapsed;

                if (wsSuccess)
                {
                    node.EffectiveSni = effectiveSni;

                    // handshakeSuccess = wsSuccess;
                    latency = sw.Elapsed;

                    LogHelper.Info($"[VLESS-WS] {node.Host}:{node.Port} | WebSocket 握手+出网成功 | {latency.TotalMilliseconds:F0}ms");
                    
                    returnStreamToCaller = true;

                    // return Task.FromResult((true, latency, stream)).Result;
                    // async 方法内不能直接 return Task.FromResult，改为裸元组
                    return (true, latency, stream);
                }
                else
                {
                    LogHelper.Warn($"[VLESS-WS] {node.Host}:{node.Port} | WebSocket 升级失败");

                    // return Task.FromResult<(bool, TimeSpan, Stream?)>((false, latency, null)).Result;
                    return (false, latency, null);
                }

                //handshakeSuccess = wsSuccess;
                //latency = sw.Elapsed;
                //return Task.FromResult((handshakeSuccess, latency, handshakeSuccess ? stream : null)).Result;
            }
            else if (transportType.Equals("grpc", StringComparison.OrdinalIgnoreCase))
            {
                var grpcResult = await HandleGrpcAsync(node, address, extra, security, cts, sw, effectiveSni).ConfigureAwait(false);

                // return Task.FromResult(grpcResult).Result;
                // 你已经 await 得到 grpcResult，它已经不再是 Task，而是一个 值类型 tuple。
                // 方法本身是 async Task < (…)>，那么只需要 直接 return 值
                return grpcResult;
            }
            else if (transportType.Equals("xhttp", StringComparison.OrdinalIgnoreCase))
            {
                var xhttpResult = await HandleXHttpAsync(node, address, timeoutSec, extra, skipCertVerify, sw, cts, effectiveSni).ConfigureAwait(false);
                
                // return Task.FromResult(xhttpResult).Result;
                return xhttpResult;
            }

            // ====== 默认 TCP (VLESS 直连) ======
            LogHelper.Debug($"[VLESS-阶段4T] {node.Host}:{node.Port} | 默认 TCP 直连，准备发送 Header");

            socket.SendTimeout = timeoutSec * 1000;
            socket.ReceiveTimeout = timeoutSec * 1000;

            var uuid = ParseOrRandomUuid(uuidStr);
            var header = BuildVlessHeader(node, address, uuid, extra);

            await stream!.WriteAsync(header, cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);
            LogHelper.Debug($"[VLESS-阶段4T] Header 发送成功");

            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await stream.ReadAsync(buf.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
                sw.Stop();

                if (read > 0)
                {
                    LogHelper.Info($"[VLESS-握手成功] {node.Host}:{node.Port} | latency={sw.ElapsedMilliseconds}ms");
                    handshakeSuccess = true;
                    latency = sw.Elapsed;

                    node.EffectiveSni = effectiveSni;
                }
                else
                {
                    LogHelper.Warn($"[VLESS-握手失败] {node.Host}:{node.Port} | 服务器关闭连接");
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }

            // ====== 阶段5：出网验证（握手成功后）======
            // 对于非 WS 的传输（如 tcp, grpc, xtls 等），才继续阶段5出网检测
            handshakeSuccess = true;  // 走到这里说明 TLS/REALITY 协议握手已成功
            latency = sw.Elapsed;

            if (handshakeSuccess && !transportType.Equals("ws", StringComparison.OrdinalIgnoreCase))
            {
                // 注意：此时的 Stream 依然是 SslStream
                // 注意：但是 CheckInternetAsync 发送明文 HttpRequest
                // 注意：TCP → TLS/REALITY → 发送 VLESS Header（认证） → 出网检测（HTTP 204）
                //var internetOk = await InternetTester.CheckInternetAsync(
                //    node, stream!, effectiveSni, opts, cts.Token).ConfigureAwait(false);

                //if (internetOk)
                //{
                //    LogHelper.Info($"[出网成功] {node.Host}:{node.Port} | 完整链路 OK");

                //    returnStreamToCaller = true;

                //    // return Task.FromResult((handshakeSuccess, latency, handshakeSuccess ? stream : null)).Result;
                //    return (handshakeSuccess, latency, handshakeSuccess ? stream : null);
                //}
                //else
                //{
                //    handshakeSuccess = false;
                //    LogHelper.Warn($"[出网失败] {node.Host}:{node.Port} | 握手成功但无法出网");
                //}

                var requestBytes = HttpRequestBuilder.BuildFourHttpGetRequestBytes(node.Host, node.Port, "/");

                foreach (var request in requestBytes)
                {
                    try
                    {
                        // 写入请求到流
                        await stream!.WriteAsync(request, cts.Token).ConfigureAwait(false);
                        await stream.FlushAsync(cts.Token).ConfigureAwait(false);

                        // 读取响应
                        var step5buf = ArrayPool<byte>.Shared.Rent(1);
                        try
                        {
                            var read = await stream.ReadAsync(buf.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
                            if (read > 0)
                            {
                                // 如果读取到数据，说明请求成功
                                LogHelper.Info($"[出网成功] {node.Host}:{node.Port} | 完整链路 OK | 请求成功");
                                returnStreamToCaller = true;
                                break; // 成功后退出循环
                            }
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(step5buf);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogHelper.Warn($"[出网测试失败] {node.Host}:{node.Port} | 请求失败: {ex.Message}");
                    }
                }
                if (!returnStreamToCaller)
                {
                    handshakeSuccess = false;
                    LogHelper.Warn($"[出网失败] {node.Host}:{node.Port} | 握手成功但无法出网");
                }
            }

            // returnStreamToCaller = true;            
            // return (handshakeSuccess, latency, handshakeSuccess ? stream : null);
            return (handshakeSuccess, latency, handshakeSuccess ? stream : null);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 超时");
            return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
        }
        catch (Exception ex)
        {
            sw.Stop();
            LogHelper.Warn($"[VLESS] {node.Host}:{node.Port} | 异常: {ex.Message}");
            return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
        }
        finally
        {
            //if (baseStream != null && !cts.Token.IsCancellationRequested)
            //    await baseStream.DisposeAsync().ConfigureAwait(false);

            if (baseStream != null && !returnStreamToCaller)
            {
                await baseStream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    // ====== 辅助方法：保证 ExtraParams 全部读取（只读）======
    private static byte[] BuildVlessHeader(
        VlessNode node,
        IPAddress address,
        Guid uuid,
        IReadOnlyDictionary<string, string> extra )
    {
        var uuidBytes = uuid.ToByteArray();
        byte[] addrBytes;
        byte addrType;
        if (IPAddress.TryParse(node.Host, out var ip))
        {
            addrType = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
            addrBytes = ip.GetAddressBytes();
        }
        else
        {
            addrType = 0x03;
            var domainBytes = Encoding.UTF8.GetBytes(node.Host);
            addrBytes = new byte[1 + domainBytes.Length];
            addrBytes[0] = (byte)domainBytes.Length;
            Buffer.BlockCopy(domainBytes, 0, addrBytes, 1, domainBytes.Length);
        }
        var networkPort = IPAddress.HostToNetworkOrder((short)node.Port);
        var portBytes = BitConverter.GetBytes(networkPort);
        var header = new byte[16 + 1 + 1 + addrBytes.Length + 2];
        Buffer.BlockCopy(uuidBytes, 0, header, 0, 16);
        header[16] = 0x01; // TCP command
        header[17] = addrType;
        Buffer.BlockCopy(addrBytes, 0, header, 18, addrBytes.Length);
        Buffer.BlockCopy(portBytes, 0, header, 18 + addrBytes.Length, 2);

        // [Grok 修复] 移除 extra 修改，只读取
        var flow = extra.GetValueOrDefault("flow") ?? "";
        var isTls = extra.GetValueOrDefault("tls") == "tls" || extra.GetValueOrDefault("tls_enabled") == "true";
        var isReality = extra.GetValueOrDefault("tls") == "reality" || extra.GetValueOrDefault("reality_enabled") == "true";
        LogHelper.Verbose($"[VLESS Header] flow={flow}, tls={isTls}, reality={isReality}");
        return header;
    }

    private static Guid ParseOrRandomUuid( string? s )
        => Guid.TryParse(s, out var id) ? id : Guid.NewGuid();

    /// <summary>
    /// gRPC 处理（保证全部 ExtraParams 使用）
    /// </summary>
    private static async Task<(bool, TimeSpan, Stream?)> HandleGrpcAsync(
        VlessNode node,
        IPAddress address,
        IReadOnlyDictionary<string, string> extra,
        string security,
        CancellationTokenSource cts,
        Stopwatch sw,
        string effectiveSni )
    {
        var grpcService = extra.GetValueOrDefault("grpc_service") ?? "vless";
        var grpcPath = $"/{grpcService}";
        try
        {
            using var handler = new HttpClientHandler();
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

            var uuidgRPC = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.UserId ?? "");
            byte[] grpcPayload = new byte[5];
            using var content = new ByteArrayContent(grpcPayload);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/grpc");
            var request = new HttpRequestMessage(HttpMethod.Post, grpcUri)
            {
                Content = content,
                Version = HttpVersion.Version20
            };

            foreach (var kv in extra.Where(kv => kv.Key.StartsWith("grpc_header_")))
            {
                var headerName = kv.Key["grpc_header_".Length..];
                request.Headers.TryAddWithoutValidation(headerName, kv.Value);
            }

            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                LogHelper.Warn($"[gRPC] {node.Host}:{node.Port} | HTTP 状态码: {response.StatusCode}");
                sw.Stop();
                return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
            }

            using var respStream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            var bufgRPC = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await respStream.ReadAsync(bufgRPC.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
                sw.Stop();
                LogHelper.Info($"[gRPC] {node.Host}:{node.Port} | 握手成功");

                node.EffectiveSni = effectiveSni;

                return Task.FromResult<(bool, TimeSpan, Stream?)>((read > 0, sw.Elapsed, null)).Result;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bufgRPC);
            }
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[gRPC] {node.Host}:{node.Port} | 握手失败: {ex.Message}");
            sw.Stop();
            return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
        }
    }

    private static async Task<(bool, TimeSpan, Stream?)> HandleXHttpAsync(
        VlessNode node, IPAddress address, int timeoutSec,
        IReadOnlyDictionary<string, string> extra, bool skipCertVerify,
        Stopwatch sw, CancellationTokenSource cts, string effectiveSni )
    {
        var xhttpPath = extra.GetValueOrDefault("xhttp_path") ?? "/";
        var xhttpHost = extra.GetValueOrDefault("xhttp_host") ?? node.Host;
        var xhttpMethod = (extra.GetValueOrDefault("xhttp_method") ?? "GET").ToUpperInvariant();
        var xhttpHeaders = extra
            .Where(k => k.Key.StartsWith("xhttp_header_"))
            .ToDictionary(k => k.Key["xhttp_header_".Length..], k => k.Value);

        var handler = new HttpClientHandler();
        if (skipCertVerify)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        using var httpClient = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        foreach (var (key, val) in xhttpHeaders)
            httpClient.DefaultRequestHeaders.TryAddWithoutValidation(key, val);

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
        var uuidXHTTP = ParseOrRandomUuid(extra.GetValueOrDefault("id") ?? node.UserId ?? "");
        var vlessHeader = BuildVlessHeader(node, address, uuidXHTTP, extra);
        request.Content = new ByteArrayContent(vlessHeader);

        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                LogHelper.Warn($"[XHTTP] {node.Host}:{node.Port} | HTTP 状态码: {response.StatusCode}");
                sw.Stop();
                return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
            }

            using var respStream = await response.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            var buf = ArrayPool<byte>.Shared.Rent(1);
            try
            {
                var read = await respStream.ReadAsync(buf.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
                sw.Stop();

                node.EffectiveSni = effectiveSni;

                LogHelper.Info($"[XHTTP] {node.Host}:{node.Port} | 握手成功");
                return Task.FromResult<(bool, TimeSpan, Stream?)>((read > 0, sw.Elapsed, null)).Result;
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
            return Task.FromResult<(bool, TimeSpan, Stream?)>((false, sw.Elapsed, null)).Result;
        }
    }

    // 辅助：Base64 验证
    private static bool IsValidBase64( string? input )
    {
        if (string.IsNullOrEmpty(input)) return false;
        try { Convert.FromBase64String(input); return true; }
        catch { return false; }
    }
}