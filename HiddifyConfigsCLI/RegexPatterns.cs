// RegexPatterns.cs
// 集中管理所有 GeneratedRegex（编译时生成）
// 所有正则均无访问修饰符（默认 internal），让源生成器自动实现

using System.Text.RegularExpressions;

namespace HiddifyConfigsCLI;

/// <summary>
/// 正则表达式容器（C# 12 GeneratedRegex 源生成）
/// </summary>
public static partial class RegexPatterns
{
    // ---------- 链接提取 ----------
    [GeneratedRegex(
        @"(vless|trojan|hysteria2|vmess|ss|tuic)://[^\s""]+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    public static partial Regex LinkRegexGenerated();
    public static Regex LinkRegex => LinkRegexGenerated();

    // ---------- 空行 / 注释（#、//、;） ----------
    [GeneratedRegex(@"^\s*(#|//|;|$)", RegexOptions.Compiled)]
    public static partial Regex CommentOrEmptyRegexGenerated();
    public static Regex CommentOrEmptyRegex => CommentOrEmptyRegexGenerated();

    // ---------- Base64 整行 ----------
    [GeneratedRegex(@"^[a-zA-Z0-9+/=]+\s*$", RegexOptions.Compiled)]
    public static partial Regex Base64LineRegexGenerated();
    public static Regex Base64LineRegex => Base64LineRegexGenerated();
}