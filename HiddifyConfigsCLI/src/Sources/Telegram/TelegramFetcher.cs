using HiddifyConfigsCLI.src.Core;
using System.Net;
using System.Text.RegularExpressions;

namespace HiddifyConfigsCLI.src.Sources.Telegram;

/// <summary>
/// Telegram RSS 抓取器（主逻辑）
/// </summary>
public class TelegramFetcher
{
    private readonly TelegramConfig _config;
    private readonly HttpClient _httpClient;
    private readonly Random _random = new();

    public TelegramFetcher( TelegramConfig config, RunOptions options )
    {
        _config = config;

        var handler = new HttpClientHandler();

        if (!string.IsNullOrWhiteSpace(options.Proxy))
        {
            if (!TryParseProxy(options.Proxy, out var proxyUri))
            {
                LogHelper.Warn($"[Telegram] 代理格式无效，已忽略: {options.Proxy}");
            }
            else
            {
                handler.Proxy = new WebProxy(proxyUri);
                handler.UseProxy = true;
                LogHelper.Info($"[Telegram] 使用代理: {options.Proxy}");
            }
        }

        _httpClient = new HttpClient(handler);
        _httpClient.DefaultRequestHeaders.Add("User-Agent", options.UserAgent);
        _httpClient.Timeout = TimeSpan.FromSeconds(config.TimeoutSeconds);
    }

    /// <summary>
    /// 抓取所有频道，返回原始链接
    /// </summary>
    public async Task<List<string>> FetchAllAsync( CancellationToken ct = default )
    {
        _config.Validate();
        var allLinks = new List<string>();
        var semaphore = new SemaphoreSlim(_config.ParallelChannels);

        var tasks = _config.Channels.Select(async channel =>
        {
            await semaphore.WaitAsync(ct);
            try
            {
                var links = await FetchChannelAsync(channel, ct);
                lock (allLinks) allLinks.AddRange(links);
                LogHelper.Info($"[Telegram] @{channel} -> {links.Count} links");
            }
            catch (Exception ex)
            {
                LogHelper.Warn($"[Telegram] @{channel} failed: {ex.Message}");
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return allLinks.Distinct().ToList();
    }

    /// <summary>
    /// 抓取单个频道
    /// </summary>
    private async Task<List<string>> FetchChannelAsync( string channel, CancellationToken ct )
    {
        var cachePath = Path.Combine(_config.CacheDir, $"{channel}.json");
        var cache = _config.EnableCache ? TelegramCache.Load(cachePath) : new TelegramCache();
        var url = $"https://t.me/s/{channel}";
        if (!string.IsNullOrEmpty(cache.LastMessageId))
            url += $"?before={cache.LastMessageId}";

        var html = await _httpClient.GetStringAsync(url, ct);
        var links = ExtractLinks(html);

        // 更新缓存
        if (links.Any() && _config.EnableCache)
        {
            var lastId = GetLastMessageId(html);
            if (!string.IsNullOrEmpty(lastId))
            {
                cache.LastMessageId = lastId;
                cache.LastFetchTime = DateTime.UtcNow;
                cache.Save(cachePath);
            }
        }

        return links;
    }

    /// <summary>
    /// 正则提取 vless/trojan/hysteria2 链接
    /// </summary>
    private static List<string> ExtractLinks( string html )
    {
        var pattern = @"(vless|trojan|hysteria2)://[^\s""'<>()]+";
        var matches = Regex.Matches(html, pattern, RegexOptions.IgnoreCase);
        return matches.Select(m => m.Value.Trim()).ToList();
    }

    /// <summary>
    /// 从 HTML 提取最后一条消息 ID
    /// </summary>
    private static string GetLastMessageId( string html )
    {
        var match = Regex.Match(html, @"data-message-id=""(\d+)""", RegexOptions.RightToLeft);
        return match.Success ? match.Groups[1].Value : string.Empty;
    }

    /// <summary>
    /// 延迟 + 随机抖动
    /// </summary>
    private async Task DelayAsync()
    {
        var delay = _config.RequestDelayMs + _random.Next(0, 500);
        await Task.Delay(delay);
    }

    /// <summary>
    /// 安全解析 host:port 格式代理
    /// </summary>
    private static bool TryParseProxy( string proxy, out Uri uri )
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(proxy)) return false;

        var parts = proxy.Split(':');
        if (parts.Length != 2) return false;

        var host = parts[0].Trim();
        var portStr = parts[1].Trim();

        if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(portStr)) return false;
        if (!int.TryParse(portStr, out var port) || port <= 0 || port > 65535) return false;

        try
        {
            uri = new UriBuilder { Scheme = "http", Host = host, Port = port }.Uri;
            return true;
        }
        catch
        {
            return false;
        }
    }
}