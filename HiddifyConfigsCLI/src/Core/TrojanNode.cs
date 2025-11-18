using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Core
{
    /// <summary>
    /// Trojan 节点结构（兼容 Xray / Trojan-Go）
    /// </summary>
    public sealed class TrojanNode : NodeInfoBase
    {
        public string Encryption { get; set; } = "none";       // 加密方式（默认为 "none"）

        // 已存在于基类
        // public string? UserId { get; set; }                     // 用户标识（如 UUID 或用户名等）
        // public string Password { get; set; } = "";
        // public string? HostParam { get; set; }


        //──────────────────────────────
        // TLS / uTLS
        //──────────────────────────────
        public string Security { get; set; } = "tls";
        
        public string? Fingerprint { get; set; }
        public string? Alpn { get; set; }

        //──────────────────────────────
        // WS / gRPC
        //──────────────────────────────
        public string? Path { get; set; }
        public string? HostHeader { get; set; }
        public int? MaxEarlyData { get; set; }
        public string? EarlyDataHeaderName { get; set; }
        public string? GrpcServiceName { get; set; }

        public string? PacketEncoding { get; set; }

        // public Dictionary<string, string> ExtraParams { get; set; } = new();
    }
}
