using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Core
{
    /// <summary>
    /// VLESS 节点结构（Xray/sing-box 兼容版）
    /// </summary>
    public sealed class VlessNode : NodeInfoBase
    {

        //──────────────────────────────
        // 用户字段
        //──────────────────────────────
        // 使用基类的 UserId
        // public string UserId { get; set; } = "";
        public string Flow { get; set; } = ""; // xtls-rprx-vision 等

        //──────────────────────────────
        // TLS / Reality / uTLS
        //──────────────────────────────
        public string Security { get; set; } = "none"; // tls/reality/none

        // 已存在于基类
        // public string? HostParam { get; set; }          // SNI
        public string? Fingerprint { get; set; }        // utls_fingerprint
        public string? Alpn { get; set; }               // ["h2","http/1.1"]
        public string? PublicKey { get; set; }          // Reality
        public string? ShortId { get; set; }            // Reality
        public string? SpiderX { get; set; }            // Reality path

        //──────────────────────────────
        // WS / gRPC / HTTP2 / TCP
        //──────────────────────────────
        public string? Path { get; set; }
        public string? HostHeader { get; set; }
        public int? MaxEarlyData { get; set; }
        public string? EarlyDataHeaderName { get; set; }
        public string? GrpcServiceName { get; set; }

        //──────────────────────────────
        // QUIC / XHTTP / Packet Encoding
        //──────────────────────────────
        public string? QuicSecurity { get; set; }
        public string? QuicKey { get; set; }

        // 已经在 ExtraParams
        // public string? PacketEncoding { get; set; }     // xudp / none

        //──────────────────────────────
        // Extra 字段容器（未知或未来字段）
        //──────────────────────────────
        // 基类中已存在
        // public Dictionary<string, string> ExtraParams { get; set; } = new();
    }
}
