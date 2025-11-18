using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Core
{
    /// <summary>
    /// TUIC 节点配置（支持 tuic5）
    /// </summary>
    public sealed class TuicNode : NodeInfoBase
    {
        // 已存在于基类
        // public string UserId { get; set; } = "";
        // public string Password { get; set; } = "";

        public string? Token { get; set; }

        public string? Alpn { get; set; }

        public string? CongestionControl { get; set; }
        public string? PacketEncoding { get; set; }

        // public Dictionary<string, string> ExtraParams { get; set; } = new();
    }
}
