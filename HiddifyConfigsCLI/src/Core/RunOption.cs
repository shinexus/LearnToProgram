using CommandLine;
using CommandLine.Text;

namespace HiddifyConfigsCLI.src.Core;

/// <summary>
/// CLI 参数选项（按属性名首字母升序排列）
/// </summary>
public class RunOptions
{
    // ────────────────────── A ──────────────────────
    [Option("http-timeout", Default = 20, HelpText = "HTTP 下载超时（秒）")]
    public int HttpTimeout { get; set; } = 20;

    // ────────────────────── I ──────────────────────
    [Option('i', "input", Default = "urls.txt", HelpText = "输入文件或远程 URL（本地路径或 http(s):// 开头）", Group = "Source")]
    public string Input { get; set; } = "urls.txt";

    [Option("info", Default = null, HelpText = "统一备注标签")]
    public string? InfoTag { get; set; } = null;

    // ────────────────────── L ──────────────────────
    [Option("log", Default = false, HelpText = "启用日志文件（cliLog.log，轮转 1MB*5）")]
    public bool EnableLog { get; set; } = false;

    // ────────────────────── M ──────────────────────
    [Option("max-lines", Default = 100, HelpText = "每个分段最大行数")]
    public int MaxLines { get; set; } = 100;

    [Option("max-parts", Default = 2, HelpText = "最大分段数量")]
    public int MaxParts { get; set; } = 2;

    // ────────────────────── N ──────────────────────
    [Option("no-check", Default = false, HelpText = "跳过连通性检测（仅解析）")]
    public bool NoCheck { get; set; } = false;

    // ────────────────────── O ──────────────────────
    [Option('o', "output", Default = "valid_links.txt", HelpText = "输出主文件路径")]
    public string Output { get; set; } = "valid_links.txt";

    // ────────────────────── P ──────────────────────
    [Option("parallel", Default = 32, HelpText = "并发检测任务数")]
    public int Parallel { get; set; } = 32;

    [Option("protocol-type", Default = "all", HelpText = "处理指定的协议（名）")]
    public string ProtocolType { get; set; } = "all";

    [Option("proxy", Required = false, HelpText = "代理地址 host:port（可选）")]
    public string? Proxy { get; set; }

    // ────────────────────── S ──────────────────────
    [Option("sort", Default = "latency", HelpText = "排序依据：latency / host / type")]
    public string Sort { get; set; } = "latency";

    // ────────────────────── T ──────────────────────
    [Option("telegram", Required = false, HelpText = "启用 Telegram 频道抓取", Group = "Source")]
    public bool EnableTelegram { get; set; }

    [Option("telegram-config", Required = false, HelpText = "Telegram 配置文件路径")]
    public string? TelegramConfigPath { get; set; }

    [Option("test-url", Default = "random", HelpText = "出网测试地址")]
    public string TestUrl { get; set; } = "random";

    [Option("timeout", Default = 5, HelpText = "TCP 检测超时（秒）")]
    public int Timeout { get; set; } = 5;

    // ────────────────────── U ──────────────────────
    [Option("user-agent", Default = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        HelpText = "HTTP 请求 User-Agent")]
    public string UserAgent { get; set; } = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

    // ────────────────────── V ──────────────────────
    [Option("verbose", Default = false, HelpText = "控制台详细输出")]
    public bool Verbose { get; set; } = false;

    // ────────────────────── 衍生属性 ──────────────────────
    /// <summary>
    /// 是否启用出网测试（--no-check 时关闭）
    /// </summary>
    public bool EnableInternetCheck => !NoCheck;

    // ────────────────────── 用例示例 ──────────────────────
    [Usage(ApplicationAlias = "HiddifyConfigsCLI")]
    public static IEnumerable<Example> Examples
    {
        get
        {
            yield return new Example("默认本地文件", new RunOptions { Input = "urls.txt" });
            yield return new Example("远程 + 并发 + 排序", new RunOptions
            {
                Input = "https://example.com/urls.txt",
                Parallel = 50,
                Sort = "latency"
            });
        }
    }
}