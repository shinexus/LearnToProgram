using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Core
{
    /// <summary>
    /// WireGuard 节点结构
    /// </summary>
    public sealed class WireguardNode : NodeInfoBase
    {
        // 已存在于基类
        // public string PrivateKey { get; set; } = "";
        public string PublicKey { get; set; } = "";

        public string? LocalAddress { get; set; }
        public string? Dns { get; set; }
        public string? PreSharedKey { get; set; }

        // public Dictionary<string, string> ExtraParams { get; set; } = new();
    }
}
