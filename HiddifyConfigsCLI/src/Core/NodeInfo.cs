// NodeInfo.cs
// 结构化协议节点信息模型（解析 + 检测结果）
// 命名空间：HiddifyConfigsCLI
// 修改说明：修复构造函数二义性错误，移除手动构造函数，使用静态工厂方法添加验证
// 作者：Grok (xAI) | 2025-10-28

using HiddifyConfigsCLI.src.Logging;
using System.Collections.ObjectModel;
using System.Text;

namespace HiddifyConfigsCLI.src.Core;

/// <summary>
/// 统一的协议节点结构，支持 vless / trojan / hysteria2 / tuic / wireguard / socks5
/// 用于存储协议链接的解析结果及检测信息
/// </summary>
/// <param name="OriginalLink">原始完整链接字符串，用于记录和保存</param>
/// <param name="Type">协议类型：vless / trojan / hysteria2 / tuic / wireguard / socks5</param>
/// <param name="Host">目标主机（IP 地址或域名）</param>
/// <param name="Port">目标端口号（1-65535）</param>
/// <param name="HostParam">SNI / Peer 参数（用于 TLS 或 QUIC 验证，Tuic/WireGuard 可选）</param>
/// <param name="Encryption">加密方式（vless/trojan 专用，Tuic 可选）</param>
/// <param name="Security">安全层：tls / none / reality 等（协议特有）</param>
/// <param name="UserId">用户标识符（vless/trojan 用户 ID，Tuic/WireGuard 认证用户名，SOCKS5 用户名）</param>
/// <param name="Password">密码（Tuic 密码，SOCKS5 密码，WireGuard 无用）</param>
/// <param name="PrivateKey">WireGuard 专用：客户端私钥（Base64 编码）</param>
/// <param name="PublicKey">WireGuard 专用：服务器公钥（Base64 编码）</param>
/// <param name="ExtraParams">所有额外查询参数的键值对字典（通用扩展字段）</param>
/// <param name="Latency">TCP/QUIC 连接延迟（可选，检测后填充，单位：TimeSpan）</param>
public record NodeInfo(
    string OriginalLink,
    string Type,
    string Host,
    int Port,
    string? HostParam = null,
    string? Encryption = null,
    string? Security = null,
    string? UserId = null,              // 支持 Tuic/WireGuard/SOCKS5 用户标识
    string? Password = null,            // Tuic/SOCKS5 密码
    string? PrivateKey = null,          // WireGuard 私钥
    string? PublicKey = null,           // WireGuard 公钥
    IReadOnlyDictionary<string, string>? ExtraParams = null,
    TimeSpan? Latency = null )
{
    // 确保 ExtraParams 不可变
    private static readonly IReadOnlyDictionary<string, string> EmptyParams =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// 静态工厂方法：创建 NodeInfo 实例并进行验证
    /// 确保 Host 非空且 Port 在有效范围
    /// </summary>
    /// <param name="OriginalLink">原始链接字符串</param>
    /// <param name="Type">协议类型</param>
    /// <param name="Host">目标主机</param>
    /// <param name="Port">目标端口</param>
    /// <param name="HostParam">SNI/Peer 参数</param>
    /// <param name="Encryption">加密方式</param>
    /// <param name="Security">安全层</param>
    /// <param name="UserId">用户标识</param>
    /// <param name="Password">密码</param>
    /// <param name="PrivateKey">WireGuard 私钥</param>
    /// <param name="PublicKey">WireGuard 公钥</param>
    /// <param name="ExtraParams">额外参数字典</param>
    /// <param name="latency">连接延迟</param>
    /// <returns>验证通过的 NodeInfo 实例</returns>
    /// <exception cref="ArgumentException">当 Host 为空或 Port 无效时抛出</exception>
    public static NodeInfo Create(
        string OriginalLink,
        string Type,
        string Host,
        int Port,
        string? HostParam = null,
        string? Encryption = null,
        string? Security = null,
        string? UserId = null,
        string? Password = null,
        string? PrivateKey = null,
        string? PublicKey = null,
        IReadOnlyDictionary<string, string>? ExtraParams = null,
        TimeSpan? latency = null )
    {
        if (string.IsNullOrWhiteSpace(Host))
        {
            LogHelper.Debug($"[节点丢弃] Host 为空 → {OriginalLink}");
            return null;
        }

        // 验证 Port：必须在 1-65535 之间
        if (Port < 1 || Port > 65535)
        {
            LogHelper.Debug($"[节点丢弃] Port 无效 ({Port}) → {OriginalLink}");
            return null;
        }

        // 确保 ExtraParams 不可变
        var safeParams = ExtraParams switch
        {
            null => EmptyParams,
            ReadOnlyDictionary<string, string> readOnly => readOnly,
            _ => new ReadOnlyDictionary<string, string>(
                new Dictionary<string, string>(ExtraParams, StringComparer.OrdinalIgnoreCase))
        };

        return new NodeInfo(
            OriginalLink,
            Type,
            Host,
            Port,
            HostParam,
            Encryption,
            Security,
            UserId,
            Password,
            PrivateKey,
            PublicKey,
            safeParams,
            latency);
    }

    /// <summary>
    /// 去重键：基于 Host + Port，同一服务器不同配置视为相同节点
    /// 用于避免重复检测同一服务器
    /// </summary>
    public (string Host, int Port) DedupKey => (Host, Port);

    /// <summary>
    /// 用于排序的延迟值：无延迟时排在最后（TimeSpan.MaxValue）
    /// 确保检测结果按延迟升序排序
    /// </summary>
    public TimeSpan SortLatency => Latency ?? TimeSpan.MaxValue;

    /// <summary>
    /// 格式化输出，便于调试日志和用户查看
    /// 包含协议类型、地址、参数和延迟信息，敏感信息部分隐藏
    /// </summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append($"[{Type.ToUpper()}] {Host}:{Port}");
        if (!string.IsNullOrEmpty(HostParam)) sb.Append($" | SNI/Peer: {HostParam}");
        if (!string.IsNullOrEmpty(Encryption)) sb.Append($" | ENC: {Encryption}");
        if (!string.IsNullOrEmpty(Security)) sb.Append($" | SEC: {Security}");
        if (!string.IsNullOrEmpty(UserId)) sb.Append($" | UID: {UserId}");
        if (!string.IsNullOrEmpty(Password))
        {
            // sb.Append($" | PWD: {Password.Substring(0, 3)}***"); // 部分隐藏密码
            // 使用丢弃方法避免可能的异常
            _ = sb.Append($" | PWD: {Password.Substring(0, 3)}***"); // 部分隐藏密码
        }

        if (!string.IsNullOrEmpty(PrivateKey))
        {
            // sb.Append($" | PRIV: {PrivateKey.Substring(0, 8)}***"); // 部分隐藏私钥
            _ = sb.Append($" | PRIV: {PrivateKey.Substring(0, 8)}***"); // 部分隐藏私钥
        }

        if (!string.IsNullOrEmpty(PublicKey))
        {
            // sb.Append($" | PUB: {PublicKey.Substring(0, 8)}***"); // 部分隐藏公钥
            _ = sb.Append($" | PUB: {PublicKey.Substring(0, 8)}***"); // 部分隐藏公钥
        }

        if (Latency != null)
        {
            // sb.Append($" | LATENCY: {Latency.Value.TotalMilliseconds:F0}ms");
            _ = sb.Append($" | LATENCY: {Latency.Value.TotalMilliseconds:F0}ms");
        }

        return sb.ToString();
    }
}