using System.Text.Json;

namespace HiddifyConfigsCLI.src.Sources.Telegram;

/// <summary>
/// Telegram 频道缓存（last_message_id）
/// </summary>
public class TelegramCache
{
    public string LastMessageId { get; set; } = string.Empty;
    public DateTime LastFetchTime { get; set; } = DateTime.MinValue;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>
    /// 加载缓存
    /// </summary>
    public static TelegramCache Load( string cachePath )
    {
        if (!File.Exists(cachePath)) return new TelegramCache();
        var json = File.ReadAllText(cachePath);
        return JsonSerializer.Deserialize<TelegramCache>(json) ?? new TelegramCache();
    }

    /// <summary>
    /// 保存缓存
    /// </summary>
    public void Save( string cachePath )
    {
        if (cachePath == null)
            throw new ArgumentNullException(nameof(cachePath));

        var dir = Path.GetDirectoryName(cachePath);
        if (string.IsNullOrEmpty(dir))
            return; // 或者记录日志，不抛异常

        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        var json = JsonSerializer.Serialize(this, JsonOptions);
        File.WriteAllText(cachePath, json);
    }
}