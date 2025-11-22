// src/Checking/Tls/TlsSniResolver.cs
using HiddifyConfigsCLI.src.Logging;
using HiddifyConfigsCLI.src.Utils;
using System.Collections.Concurrent;
using System.Net;
using YamlDotNet.Core.Tokens;

namespace HiddifyConfigsCLI.src.Checking.Tls;

/// <summary>
/// 【Grok 修复_2025-11-22_03】
/// 全局统一的智能 SNI 解析器（支持 VLESS/Trojan/Hysteria2 通用）
/// 包含：兜底逻辑 + REALITY 兼容 + 并发缓存（5分钟TTL）
/// 在 VlessHandshaker / TrojanHandshaker / Hysteria2Handshaker 中统一这样写：
/// string effectiveSni = await TlsSniResolver.ResolveEffectiveSniAsync(
/// node.Host, node.Port, node.Sni, opts.SkipCertVerify, cts.Token);
/// options.ClientAuthenticationOptions.TargetHost = effectiveSni;
/// </summary>
internal static class TlsSniResolver
{
    // 缓存：key = $"{host}:{port}", value = (effectiveSni, expireUtc)
    private static readonly ConcurrentDictionary<string, (string Sni, DateTime ExpireUtc)> _cache = new();

    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);
    private static readonly string[] GlobalFallbacks =
    {
        "www.microsoft.com",
        "www.cloudflare.com",
        "www.youtube.com"
    };

    public static async Task<string> ResolveEffectiveSniAsync(
        string rawHost,           // 节点原始 Host（可能是IP或域名）
        int port,
        string? userSpecifiedSni, // 用户在链接中指定的 sni=（可能为空）
        bool skipCertVerify,
        CancellationToken ct = default )
    {
        string cacheKey = $"{rawHost}:{port}";
        if (_cache.TryGetValue(cacheKey, out var cached) && cached.ExpireUtc > DateTime.UtcNow)
        {
            LogHelper.Verbose($"[TlsSniResolver] 缓存命中 → {cached.Sni}");
            return cached.Sni;
        }

        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. 用户指定 SNI 优先级最高
        if (!string.IsNullOrWhiteSpace(userSpecifiedSni) &&
            !IPAddress.TryParse(userSpecifiedSni.Trim(), out _))
        {
            candidates.Add(userSpecifiedSni.Trim());
        }

        // 2. 节点 Host 本身 + 根域变种
        if (!IPAddress.TryParse(rawHost, out _))
        {
            var parts = rawHost.Split('.');
            candidates.Add(rawHost);

            if (parts.Length >= 2)
            {
                string root = string.Join(".", parts.Skip(parts.Length - 2));
                candidates.Add(root);
                candidates.Add("www." + root);
                candidates.Add("*." + root);
            }
        }

        // 3. 全球兜底三件套
        foreach (var fb in GlobalFallbacks)
            candidates.Add(fb);

        foreach (var candidate in candidates)
        {
            if (ct.IsCancellationRequested) break;
            if (IPAddress.TryParse(candidate, out _)) continue;

            bool match = await TlsHelper.PreValidateSniAsync(
                rawHost, port, candidate, 2500, skipCertVerify, ct)
                .ConfigureAwait(false);

            if (match)
            {
                string final = candidate.StartsWith("*.") ? (userSpecifiedSni?.Trim() ?? candidate) : candidate;
                _cache[cacheKey] = (final, DateTime.UtcNow.Add(CacheTtl));
                LogHelper.Info($"[TlsSniResolver] 智能解析成功 → {rawHost}:{port} 使用 SNI: {final}");
                return final;
            }
        }

        // 最终强制兜底
        string fallback = GlobalFallbacks[0];
        _cache[cacheKey] = (fallback, DateTime.UtcNow.Add(CacheTtl));
        LogHelper.Warn($"[TlsSniResolver] 所有候选失败，强制使用 {fallback}");
        return fallback;
    }

    /// <summary>
    /// 清理已过期的缓存条目
    /// </summary>
    public static void ClearExpired()
    {
        // 先复制一份键集合，避免在遍历过程中修改字典导致异常
        foreach (var key in _cache.Keys.ToList())
        {
            if (_cache.TryGetValue(key, out var entry) && entry.ExpireUtc <= DateTime.UtcNow)
            {
                _cache.TryRemove(key, out _);
            }
        }
    }
}