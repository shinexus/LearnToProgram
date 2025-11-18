using System.Collections.Generic;

namespace HiddifyConfigsCLI.src.Core
{
    /// <summary>
    /// SOCKS5 节点结构
    /// </summary>
    public sealed class Socks5Node : NodeInfoBase
    {
        public string? Username { get; set; }

        // 已存在于基类
        // public string? Password { get; set; }

        public bool UdpEnabled { get; set; } = true;

        // public Dictionary<string, string> ExtraParams { get; set; } = new();
    }
}
