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
    string? UserId = null,
    string? Password = null,
    string? PrivateKey = null,
    string? PublicKey = null,
    IReadOnlyDictionary<string, string>? ExtraParams = null,
    TimeSpan? Latency = null )
{
    // 复用空字典，避免重复创建
    private static readonly IReadOnlyDictionary<string, string> EmptyParams =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// 静态工厂方法：创建 NodeInfo 实例并进行验证
    /// 确保 Host 非空且 Port 在有效范围
    /// </summary>
    /// <returns>验证通过的 NodeInfo 实例</returns>
    /// <exception cref="ArgumentException">当 Host 为空或 Port 无效时抛出</exception>
    /// <remarks>
    /// 不再返回 null！改为抛出异常或返回默认无效节点
    /// 工厂方法应保证返回有效实例，避免调用方空引用检查
    /// </remarks>
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
        // Host 为空 → 抛出异常（调用方应提前过滤）
        if (string.IsNullOrWhiteSpace(Host))
            throw new ArgumentException($"Host 不能为空: {OriginalLink}", nameof(Host));

        // Port 无效 → 抛出异常
        if (Port < 1 || Port > 65535)
            throw new ArgumentException($"Port 必须在 1-65535 之间: {Port}", nameof(Port));

        // 安全处理 ExtraParams
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

        if (!string.IsNullOrEmpty(HostParam))   sb.Append($" | SNI/Peer: {HostParam}");
        if (!string.IsNullOrEmpty(Encryption))  sb.Append($" | ENC: {Encryption}");
        if (!string.IsNullOrEmpty(Security))    sb.Append($" | SEC: {Security}");
        if (!string.IsNullOrEmpty(UserId))      sb.Append($" | UID: {UserId}");

        // 安全隐藏密码（避免 Substring 越界）
        if (!string.IsNullOrEmpty(Password))
        {
            string masked = Password.Length >= 3 ? Password[..3] + "***" : "***";
            sb.Append($" | PWD: {masked}");
        }

        // 安全隐藏私钥
        if (!string.IsNullOrEmpty(PrivateKey))
        {
            string masked = PrivateKey.Length >= 8 ? PrivateKey[..8] + "***" : "***";
            sb.Append($" | PRIV: {masked}");
        }

        // 安全隐藏公钥
        if (!string.IsNullOrEmpty(PublicKey))
        {
            string masked = PublicKey.Length >= 8 ? PublicKey[..8] + "***" : "***";
            sb.Append($" | PUB: {masked}");
        }

        if (Latency.HasValue)
        {
            sb.Append($" | LATENCY: {Latency.Value.TotalMilliseconds:F0}ms");
        }

        return sb.ToString();
    }
}