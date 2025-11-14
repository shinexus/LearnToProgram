// NodeInfo.cs
// 结构化协议节点信息模型（解析 + 检测结果）
// 命名空间：HiddifyConfigsCLI.src.Core
//
// 更新说明（ChatGPT Rebuild 2025-11-14）
// ------------------------------------------------------------
// 1. 明确区分“主字段（通用协议字段）”与“扩展字段（ExtraParams）”
// 2. 所有非通用协议参数（如 utls.fingerprint、early_data_header_name、packet_encoding）
//    一律进入 ExtraParams，而不是主字段
// 3. 全面重写 summary 和 param 文档，遵循统一架构规范
// ------------------------------------------------------------

using HiddifyConfigsCLI.src.Logging;
using System.Collections.ObjectModel;
using System.Text;

namespace HiddifyConfigsCLI.src.Core;

/// <summary>
/// 统一的协议节点结构定义，用于承载解析后的节点信息以及后续检测结果。
///
/// 本结构区分：
///
/// **（A）核心主字段（所有协议通用 / 常用字段）**
/// ------------------------------------------------------------
/// - 原始链接
/// - 协议类型
/// - 服务器主机（Host）
/// - 端口（Port）
/// - HostParam（SNI / Peer）
/// - 安全层（Security）
/// - 加密方式（Encryption）
/// - 用户标识（UserId）
/// - 密码（Password）
/// - WireGuard 公私钥
///
/// **这些字段是所有协议检测和连接逻辑都需要的基础字段。**
///
///
/// **（B）扩展字段 ExtraParams（协议特性字段 / 可选字段）**
/// ------------------------------------------------------------
/// 所有非通用、协议专属、扩展性质的参数一律进入 ExtraParams：
/// - uTLS 参数（例如 utls.fingerprint）
/// - WebSocket / gRPC 特性字段（例如 early_data_header_name）
/// - XUDP / QUIC 额外字段（例如 packet_encoding）
/// - 未来扩展字段，或节点中出现的额外自定义参数
///
/// **ExtraParams 的存在使得 NodeInfo 可随协议发展无缝扩展，无需修改主结构。**
///
///
/// **（C）检测类字段**
/// ------------------------------------------------------------
/// - Latency：网络延迟（检测后填入）
///
/// NodeInfo 是一个不可变 record，通过静态工厂 Create() 构造并确保 Host/Port 合法。
/// </summary>
///
/// <param name="OriginalLink">节点的原始完整链接字符串（用于保存或导出）</param>
/// <param name="Type">协议类型（vless / trojan / hysteria2 / tuic / wireguard / socks5）</param>
/// <param name="Host">解析出的服务器地址（IP 或域名）</param>
/// <param name="Port">服务器端口号（1–65535）</param>
/// <param name="HostParam">SNI / Peer 等 Host 扩展参数，用于 TLS 或 QUIC 握手</param>
/// <param name="Encryption">协议特有的加密方式（如 none、aes-128-gcm 等）</param>
/// <param name="Security">安全层类型（如 tls、none、reality 等）</param>
/// <param name="UserId">用户标识字段（UUID/用户名等）</param>
/// <param name="Password">密码字段（密码/Token 等）</param>
/// <param name="PrivateKey">WireGuard 客户端私钥（Base64）</param>
/// <param name="PublicKey">WireGuard 服务端公钥（Base64）</param>
///
/// <param name="ExtraParams">
/// **扩展字段字典：用于存放所有协议特性扩展字段**
///
/// 典型示例：  
/// - `"utls.fingerprint": "chrome"`  
/// - `"early_data_header_name": "Sec-WebSocket-Protocol"`  
/// - `"packet_encoding": "xudp"`  
/// - `"grpc.service": "xxx"`  
/// - `"ws.max_early_data": "1024"`  
///
/// **任何不是通用协议字段的内容，都应进入 ExtraParams。**
/// </param>
///
/// <param name="Latency">检测得到的网络延迟（可选，单位 ms）</param>
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
    // 复用空字典，减少对象创建
    private static readonly IReadOnlyDictionary<string, string> EmptyParams =
        new ReadOnlyDictionary<string, string>(
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// 通过静态工厂方法创建 NodeInfo，保证 Host / Port 合法并安全封装 ExtraParams。
    /// </summary>
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
            throw new ArgumentException($"Host 不能为空: {OriginalLink}", nameof(Host));

        if (Port is < 1 or > 65535)
            throw new ArgumentException($"Port 必须在 1-65535 之间: {Port}", nameof(Port));

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

    /// <summary>避免重复检测时使用的 Key（Host + Port）</summary>
    public (string Host, int Port) DedupKey => (Host, Port);

    /// <summary>用于排序延迟（无延迟则为最大值）</summary>
    public TimeSpan SortLatency => Latency ?? TimeSpan.MaxValue;

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
            string masked = Password.Length >= 3 ? Password[..3] + "***" : "***";
            sb.Append($" | PWD: {masked}");
        }

        if (!string.IsNullOrEmpty(PrivateKey))
        {
            string masked = PrivateKey.Length >= 8 ? PrivateKey[..8] + "***" : "***";
            sb.Append($" | PRIV: {masked}");
        }

        if (!string.IsNullOrEmpty(PublicKey))
        {
            string masked = PublicKey.Length >= 8 ? PublicKey[..8] + "***" : "***";
            sb.Append($" | PUB: {masked}");
        }

        if (Latency.HasValue)
            sb.Append($" | LATENCY: {Latency.Value.TotalMilliseconds:F0}ms");

        return sb.ToString();
    }
}
