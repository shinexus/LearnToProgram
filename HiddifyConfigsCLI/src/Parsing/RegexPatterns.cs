// RegexPatterns.cs
// 集中管理所有 GeneratedRegex（编译时生成）
// 所有正则均无访问修饰符（默认 internal），让源生成器自动实现
// RegexPatterns.cs
// ┌────────────────────────────────────────────────────────────────────┐
// │  正则表达式统一容器（C# 12 Source Generator）                      │
// │  • 所有正则均在编译期生成，运行时零开销                           │
// │  • 每个 GeneratedRegex 必须为 static partial、无访问修饰符       │
// │  • 对外仅暴露 public static Regex 属性（线程安全、只读）          │
// └────────────────────────────────────────────────────────────────────┘

using System.Text.RegularExpressions;

namespace HiddifyConfigsCLI;

/// <summary>
/// 集中管理项目中所有 <c>GeneratedRegex</c> 的容器。<br/>
/// 每个正则都遵循「声明 → 生成 → 封装」的模式，保证：
/// <list type="bullet">
///   <item>编译期语法检查</item>
///   <item>运行时零正则编译开销</item>
///   <item>AOT / 单文件发布友好</item>
///   <item>统一命名、易于维护</item>
/// </list>
/// </summary>
public static partial class RegexPatterns
{
    //=====================================================================
    //  1. 链接提取
    //=====================================================================
    /// <summary>
    /// 提取完整的协议链接（vless://、trojan://、hysteria2://、vmess://、ss://、tuic://）。<br/>
    /// 匹配到第一个空格或双引号为止，防止截断。
    /// </summary>
    [GeneratedRegex(
        @"(vless|trojan|hysteria2|vmess|ss|tuic)://[^\s""]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    internal static partial Regex LinkRegexGenerated();

    public static Regex LinkRegex => LinkRegexGenerated();

    //=====================================================================
    //  2. 空行 / 注释行（#、//、;）
    //=====================================================================
    /// <summary>
    /// 判断一行是否为「空行」或「注释行」。<br/>
    /// 支持 <c>#</c>、<c>//</c>、<c>;</c> 开头的注释以及完全空白行。
    /// </summary>
    [GeneratedRegex(@"^\s*(#|//|;|$)", RegexOptions.Compiled)]
    internal static partial Regex CommentOrEmptyRegexGenerated();

    public static Regex CommentOrEmptyRegex => CommentOrEmptyRegexGenerated();

    //=====================================================================
    //  3. Base64 整行检测
    //=====================================================================
    /// <summary>
    /// 判断一行是否为完整的 Base64 编码（仅含 <c>A-Z a-z 0-9 + / =</c> 以及空白）。<br/>
    /// 用于过滤订阅文件中的 Base64 块。
    /// </summary>
    [GeneratedRegex(@"^[a-zA-Z0-9+/=]+\s*$", RegexOptions.Compiled)]
    internal static partial Regex Base64LineRegexGenerated();

    public static Regex Base64LineRegex => Base64LineRegexGenerated();

    //=====================================================================
    //  4. 协议结构化解析（VLESS / Trojan / Hysteria2）
    //=====================================================================
    /// <summary>解析 <c>vless://uuid@host:port?params</c> 结构，捕获 uuid、host、port、params。</summary>
    [GeneratedRegex(
        @"vless://(?<uuid>[^@]+)@(?<host>[^:]+):(?<port>\d+)\?(?<params>.*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    internal static partial Regex VlessRegexGenerated();
    public static Regex VlessRegex => VlessRegexGenerated();

    /// <summary>解析 <c>trojan://password@host:port?params</c> 结构。</summary>
    [GeneratedRegex(
        @"trojan://(?<password>[^@]+)@(?<host>[^:]+):(?<port>\d+)\?(?<params>.*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    internal static partial Regex TrojanRegexGenerated();
    public static Regex TrojanRegex => TrojanRegexGenerated();

    /// <summary>解析 <c>hysteria2://auth@host:port?params</c> 结构。</summary>
    [GeneratedRegex(
        @"hysteria2://(?<auth>[^@]+)@(?<host>[^:]+):(?<port>\d+)\?(?<params>.*)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    internal static partial Regex Hysteria2RegexGenerated();
    public static Regex Hysteria2Regex => Hysteria2RegexGenerated();

    //=====================================================================
    //  5. 快速协议前缀判断
    //=====================================================================
    /// <summary>快速判断链接是否以 <c>vmess://</c> 开头（常用于过滤）。</summary>
    [GeneratedRegex(@"^vmess://", RegexOptions.IgnoreCase)]
    internal static partial Regex VmessPrefixRegexGenerated();
    public static Regex VmessPrefixRegex => VmessPrefixRegexGenerated();

    //=====================================================================
    //  6. 通用提取
    //=====================================================================
    /// <summary>从任意协议链接中提取 <c>@host:</c> 前的 host（不含端口）。</summary>
    [GeneratedRegex(@"@(?<host>[^:]+):", RegexOptions.IgnoreCase)]
    internal static partial Regex HostExtractRegexGenerated();
    public static Regex HostExtractRegex => HostExtractRegexGenerated();

    //=====================================================================
    //  7. 参数检测
    //=====================================================================
    /// <summary>检测是否出现 <c>?ed=</c> 或 <c>&ed=</c> 参数。</summary>
    [GeneratedRegex(@"[?&]ed=", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    internal static partial Regex HasEdParamRegexGenerated();
    public static Regex HasEdParamRegex => HasEdParamRegexGenerated();

    //=====================================================================
    //  8. chatGPT 自我补救系列（path=?ed= / 多 ? 修复）
    //=====================================================================
    /// <summary>检测 <c>path=... ?ed=</c>（错误形式）。</summary>
    [GeneratedRegex(@"path=\/[^ ]*\?ed=", RegexOptions.IgnoreCase)]
    internal static partial Regex PathHasQEdRegexGenerated();
    public static Regex PathHasQEdRegex => PathHasQEdRegexGenerated();

    /// <summary>检测 <c>path=...</c> 中出现多个 <c>?</c>（需要转为 <c>&amp;</c>）。</summary>
    [GeneratedRegex(@"path=\/[^ ]*\?.*\?", RegexOptions.IgnoreCase)]
    internal static partial Regex PathMultiQueryRegexGenerated();
    public static Regex PathMultiQueryRegex => PathMultiQueryRegexGenerated();

    /// <summary>捕获完整的 <c>path=...</c> 值，用于后续替换。</summary>
    [GeneratedRegex(@"path=([^\s]+)", RegexOptions.IgnoreCase)]
    internal static partial Regex PathValueRegexGenerated();
    public static Regex PathValueRegex => PathValueRegexGenerated();

    /// <summary>捕获完整的 <c>ed=...</c> 值，后面再提取数字。</summary>
    [GeneratedRegex(@"ed=([^&\s]+)", RegexOptions.IgnoreCase)]
    internal static partial Regex EdValueFullRegexGenerated();
    public static Regex EdValueFullRegex => EdValueFullRegexGenerated();

    /// <summary>提取任意字符串中最长的连续数字串（用于 <c>ed=abc123def</c> → <c>123</c>）。</summary>
    [GeneratedRegex(@"\d+", RegexOptions.Compiled)]
    internal static partial Regex DigitRegexGenerated();
    public static Regex DigitRegex => DigitRegexGenerated();

    /// <summary>将 <c>?ed=</c> 替换为 <c>&amp;ed=</c>（仅在 <c>path=/...</c> 场景）。</summary>
    [GeneratedRegex(@"path=\/([^?\s]*)\?ed=", RegexOptions.IgnoreCase)]
    internal static partial Regex FixQEdRegexGenerated();
    public static Regex FixQEdRegex => FixQEdRegexGenerated();
}