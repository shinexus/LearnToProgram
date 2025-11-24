// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2PortResolver.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static class Hysteria2PortResolver
    {
        public static int Resolve( Hysteria2Node node )
        {
            if (node.MultiPorts != null && node.MultiPorts.Length > 0)
            {
                int index = Random.Shared.Next(node.MultiPorts.Length);
                int port = node.MultiPorts[index];
                LogHelper.Verbose($"[Hysteria2] mport 随机选择端口 → {port} (共 {node.MultiPorts.Length} 个)");
                return port;
            }
            return node.Port;
        }
    }
}