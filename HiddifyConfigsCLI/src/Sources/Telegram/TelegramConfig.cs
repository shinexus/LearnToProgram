using System.Text.Json.Serialization;

namespace HiddifyConfigsCLI.src.Sources.Telegram;

/// <summary>
/// Telegram 抓取模块配置类（JSON 驱动）
/// </summary>
public class TelegramConfig
{
    /// <summary>
    /// 要抓取的频道用户名列表（不含 @）
    /// </summary>
    [JsonPropertyName("channels")]
    public List<string> Channels { get; set; } = new();

    /// <summary>
    /// 每个频道最大抓取消息数（默认 50，代码锁死）
    /// </summary>
    [JsonPropertyName("maxMessagesPerChannel")]
    public int MaxMessagesPerChannel { get; set; } = 50;

    /// <summary>
    /// 请求间隔毫秒（默认 2000，含随机抖动）
    /// </summary>
    [JsonPropertyName("requestDelayMs")]
    public int RequestDelayMs { get; set; } = 2000;

    /// <summary>
    /// 并发抓取频道数（默认 5）
    /// </summary>
    [JsonPropertyName("parallelChannels")]
    public int ParallelChannels { get; set; } = 5;

    /// <summary>
    /// HTTP User-Agent
    /// </summary>
    [JsonPropertyName("userAgent")]
    public string UserAgent { get; set; } = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    /// <summary>
    /// 缓存目录
    /// </summary>
    [JsonPropertyName("cacheDir")]
    public string CacheDir { get; set; } = "cache/telegram";

    /// <summary>
    /// 是否启用缓存
    /// </summary>
    [JsonPropertyName("enableCache")]
    public bool EnableCache { get; set; } = true;

    /// <summary>
    /// HTTP 超时秒
    /// </summary>
    [JsonPropertyName("timeoutSeconds")]
    public int TimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// 验证配置
    /// </summary>
    public void Validate()
    {
        if (Channels == null || Channels.Count == 0)
            throw new InvalidOperationException("TelegramConfig: 'channels' 不能为空");
    }
}