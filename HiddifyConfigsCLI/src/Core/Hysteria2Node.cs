// HiddifyConfigsCLI/src/Core/Hysteria2Node.cs
using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Core;

/// <summary>
/// Hysteria2 节点配置（完整字段补全版）
/// 参考：https://v2.hysteria.network/docs/developers/Client-Config/
/// </summary>
public sealed class Hysteria2Node : NodeInfoBase
{
    // ──────────────────────────────
    // 认证相关
    // ──────────────────────────────
    /// <summary>
    /// 密码（必填）
    /// </summary>
    // 已存在于基类
    // public string Password { get; set; } = "";

    // ──────────────────────────────
    // TLS 相关
    // ──────────────────────────────
    /// <summary>
    /// SNI 服务器名称（优先于 Host）
    /// </summary>
    // public string? HostParam { get; set; }

    /// <summary>
    /// 跳过证书验证（insecure / skip-cert-verify）
    /// </summary>
    public bool SkipCertVerify { get; set; } = false;

    /// <summary>
    /// ALPN 协议列表（逗号分隔）
    /// </summary>
    public string? Alpn { get; set; }

    /// <summary>
    /// uTLS 指纹（如 chrome, firefox）
    /// </summary>
    public string? Fingerprint { get; set; }

    // ──────────────────────────────
    // 混淌（Obfuscation）
    // ──────────────────────────────
    /// <summary>
    /// 混淌类型（如 salamander）
    /// </summary>
    public string? Obfs { get; set; }

    /// <summary>
    /// 混淌密码
    /// </summary>
    public string? ObfsPassword { get; set; }

    // ──────────────────────────────
    // 带宽控制
    // ──────────────────────────────
    /// <summary>
    /// 上行带宽限制（Mbps）
    /// </summary>
    public int? UpMbps { get; set; }

    /// <summary>
    /// 下行带宽限制（Mbps）
    /// </summary>
    public int? DownMbps { get; set; }

    // ──────────────────────────────
    // 传输控制
    // ──────────────────────────────
    /// <summary>
    /// 是否禁用 UDP（用于纯 TCP 场景）
    /// </summary>
    public bool? DisableUdp { get; set; }    

    /// <summary>
    /// 传输类型（udp / wechat-video 等，默认为 udp）
    /// </summary>
    public string? TransportType { get; set; } = "udp";

    /// <summary
    /// 安全类型（tls / none，默认为 tls）
    /// </summary>
    public string? Security { get; set; } = "tls";

    // ──────────────────────────────
    // 高级选项（保留在 ExtraParams 中）
    // ──────────────────────────────
    /// <summary>
    /// 其他未映射字段（如 congestion, fast-open 等）通过 ExtraParams 传递
    /// </summary>
    // public Dictionary<string, string> ExtraParams { get; set; } = new();

    // ──────────────────────────────
    // 兼容字段（从 NodeInfoBase 继承）
    // ──────────────────────────────
    // OriginalLink, Type, Host, Port, Remark, Transport 已由基类提供
    // Security 固定为 "tls"，由 Parser 设置
}