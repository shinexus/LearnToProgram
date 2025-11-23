using System;
using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Core
{
    /// <summary>
    /// 所有协议节点的抽象基类。
    /// 协议公共字段：原始链接、类型、服务器、端口、备注。
    /// </summary>
    public abstract class NodeInfoBase
    {
        /// <summary>
        /// 节点的原始完整链接字符串（用于保存或导出）
        /// </summary>
        public string OriginalLink { get; set; } = "";

        /// <summary>
        /// 协议类型（vless/trojan/hysteria2/tuic/wireguard/socks5）
        /// </summary>
        public string Type { get; set; } = "";

        ///<summary>
        ///UA
        /// </summary>
        public string UserAgent { get; set; } = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

        /// <summary>
        /// 服务器地址域名或 IP
        /// </summary>
        public string Host { get; set; } = "";

        /// <summary>
        /// 服务器端口
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// TLS SNI 主机名（优先于 Host）
        /// 可为空 → 使用 Host
        /// SNI 必须为域名
        /// </summary>
        public string? HostParam { get; set; }

        /// <summary>
        /// 备注
        /// </summary>
        public string Remark { get; set; } = "";

        /// <summary>
        /// 协议可自带 transport 类型（如 ws、grpc、h2、tcp，具体由派生类决定）
        /// </summary>
        public virtual string Transport { get; set; } = "tcp";

        /// <summary>
        /// 用户ID（如 VLESS UUID、TUIC UUID、SOCKS5 用户名）
        /// </summary>
        public string? UserId { get; set; }

        /// <summary>
        /// 密码（如 Trojan、TUIC、SOCKS5、Hysteria2）
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// WireGuard 私钥
        /// </summary>
        public string? PrivateKey { get; set; }

        // ──────────────────────────────
        // 延迟
        // ──────────────────────────────
        public TimeSpan Latency { get; set; } = TimeSpan.Zero;

        /// <summary>
        /// 用于排序的延迟（无延迟 → 排后）
        /// </summary>
        public TimeSpan SortLatency => Latency == TimeSpan.Zero ? TimeSpan.MaxValue : Latency;

        // ──────────────────────────────
        // ToString
        // ──────────────────────────────
        public override string ToString() =>
            $"{Type}://{Host}:{Port} [{Remark.Trim()}]".TrimEnd();

        /// <summary>
        /// 其他通用保留参数（极少使用，仅作扩展）
        /// </summary>
        public Dictionary<string, string> ExtraParams { get; set; } = new();

        public string? EffectiveSni { get; set; }
    }
}
