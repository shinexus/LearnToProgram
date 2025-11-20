// src/Checking/Handshakers/TlsRealityHelper.cs
// [重构版_2025-11-20]
// 功能：统一处理 TLS 与 REALITY 握手
// 目的：将 VlessHandshaker 中 TLS/REALITY 相关逻辑抽离，提高复用性与可读性

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;

internal static class TlsRealityHelper
{
    /// <summary>
    /// 统一 TLS / REALITY 握手
    /// </summary>
    /// <param name="node">VLESS 节点信息</param>
    /// <param name="baseStream">TCP Stream</param>
    /// <param name="extra">节点额外参数</param>
    /// <param name="timeoutSec">超时时间（秒）</param>
    /// <param name="cts">取消令牌源</param>
    /// <returns>握手成功后的 Stream（可能是 SslStream 或 RealityStream）</returns>
    public static async Task<Stream?> HandleTlsRealityAsync(
        VlessNode node,
        Stream baseStream,
        IReadOnlyDictionary<string, string> extra,
        int timeoutSec,
        CancellationTokenSource cts )
    {
        Stream stream = baseStream;

        // 1. 提取参数
        var security = extra.GetValueOrDefault("security") ?? "tls";
        var skipCertVerify = extra.GetValueOrDefault("skip_cert_verify") == "true";
        var sni = node.HostParam ?? node.Host;
        string effectiveSni = node.Host;

        // 2. 判断是否启用 REALITY
        var realityEnabled = string.Equals(extra.GetValueOrDefault("reality_enabled"), "true", StringComparison.OrdinalIgnoreCase)
                             || string.Equals(security, "reality", StringComparison.OrdinalIgnoreCase);

        // ===== TLS 阶段 =====
        // 关键：REALITY 必须在裸 TCP 上握手，不能在 SslStream 上运行！
        if (security == "tls")
        {
            // 纯 TLS 节点：执行标准 TLS 握手
            LogHelper.Debug($"[TLS] {node.Host}:{node.Port} | 开始标准 TLS 握手 (skipCert={skipCertVerify})");

            // 使用原始传入的 SNI（或 fallback 到 Host）
            var tlsSni = !string.IsNullOrEmpty(sni) ? sni : node.Host;

            // Chrome ClientHello 指纹检测
            bool helloOk = await TlsHelper.TestTlsWithChromeHelloAsync(
node.Host, node.Port, effectiveSni,
timeoutMs: (int)TimeSpan.FromSeconds(timeoutSec).TotalMilliseconds
).ConfigureAwait(false);

            if (!helloOk)
            {
                LogHelper.Warn($"[TLS] {node.Host}:{node.Port} | Chrome ClientHello 失败 (SNI={tlsSni})");
                return null;
            }

            var ssl = new SslStream(baseStream, leaveInnerStreamOpen: true);
            var sslOpts = TlsHelper.CreateSslOptions(tlsSni, skipCertVerify);
            sslOpts.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
            sslOpts.ApplicationProtocols = new List<SslApplicationProtocol>
    {
        SslApplicationProtocol.Http2,
        SslApplicationProtocol.Http11
    };

            await ssl.AuthenticateAsClientAsync(sslOpts, cts.Token).ConfigureAwait(false);

            stream = ssl;
            LogHelper.Info($"[TLS] {node.Host}:{node.Port} | TLS 握手成功 (SNI={tlsSni})");
        }
        else if (security == "reality")
        {
            // REALITY 节点：直接在原始 TCP 流上进行 REALITY 握手（跳过 TLS）
            LogHelper.Debug($"[REALITY] {node.Host}:{node.Port} | 跳过 TLS，直接在裸 TCP 上执行 REALITY 握手");

            var spx = extra.GetValueOrDefault("spx") ?? "/";
            var pk = extra.GetValueOrDefault("reality_public_key") ?? "";
            var pbk = extra.GetValueOrDefault("pbk") ?? "";
            var sid = extra.GetValueOrDefault("reality_short_id") ?? "";
            var activePk = !string.IsNullOrEmpty(pk) ? pk : pbk;

            // 提前验证公钥合法性（支持 URL-safe Base64 + 自动补齐）
            try
            {
                _ = RealityHelper.ParseRealityPublicKey(activePk);
            }
            catch
            {
                LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | public_key 无效 (len={activePk?.Length ?? 0})");
                return null;
            }

            if (string.IsNullOrEmpty(sid) || sid.Length > 16)
            {
                LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | short_id 无效 (len={sid?.Length ?? 0})");
                return null;
            }

            var (success, encryptedStream) = await RealityHelper.RealityHandshakeAsync(
                baseStream,           // ← 关键！必须传原始 TCP 流，不能传 SslStream
                sid,
                activePk,
                spx,
                cts.Token).ConfigureAwait(false);

            if (success && encryptedStream != null)
            {
                stream = encryptedStream;
                LogHelper.Info($"[REALITY] {node.Host}:{node.Port} | REALITY 握手成功，已建立加密通道");
            }
            else
            {
                LogHelper.Warn($"[REALITY] {node.Host}:{node.Port} | REALITY 握手失败或超时");
                return null;
            }
        }
        // 其他 security（如 "none"）直接返回原始 stream
        else
        {
            LogHelper.Debug($"[PLAIN] {node.Host}:{node.Port} | 无加密，直接使用裸 TCP");
        }

        return stream;
    }

    /// <summary>
    /// REALITY 模式 SNI fallback 预验证
    /// </summary>
    private static async Task<string> PreValidateSniFallbackAsync( VlessNode node, string sni, bool skipCertVerify )
    {
        string effectiveSni = sni;
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

        LogHelper.Verbose($"[REALITY-SNI] {node.Host}:{node.Port} | fallback SNIs: {string.Join(", ", fallbackSnis)}");

        foreach (var f in fallbackSnis)
        {
            var match = await TlsHelper.PreValidateSniAsync(node.Host, node.Port, f, 2000, skipCertVerify).ConfigureAwait(false);
            LogHelper.Verbose($"[REALITY-SNI-Fallback] {node.Host}:{node.Port} | 测试 SNI={f} → Match={match}");

            if (match)
            {
                effectiveSni = f.StartsWith("*.") ? node.Host : f;
                LogHelper.Info($"[REALITY-SNI] {node.Host}:{node.Port} | 匹配成功 → 使用 effectiveSni={effectiveSni}");
                break;
            }
        }

        if (effectiveSni == sni)
        {
            effectiveSni = node.Host;
            LogHelper.Warn($"[REALITY-SNI] {node.Host}:{node.Port} | 所有 fallback 失败，强制使用 Host={effectiveSni}");
        }

        return effectiveSni;
    }

    /// <summary>
    /// Base64 校验
    /// </summary>
    private static bool IsValidBase64( string? input )
    {
        if (string.IsNullOrEmpty(input)) return false;
        try { Convert.FromBase64String(input); return true; }
        catch { return false; }
    }
}
