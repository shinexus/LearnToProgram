// HiddifyConfigsCLI.src.Checking/Handshakers/Hysteria2/Hysteria2AlpnBuilder.cs
using System.Net.Security;
using HiddifyConfigsCLI.src.Logging;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Hysteria2
{
    internal static class Hysteria2AlpnBuilder
    {
        public static List<SslApplicationProtocol> Build( string? alpnConfig )
        {
            var list = new List<SslApplicationProtocol>();

            if (string.IsNullOrWhiteSpace(alpnConfig))
            {
                list.Add(SslApplicationProtocol.Http3);
                return list;
            }

            var parts = alpnConfig.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool hasValid = false;

            foreach (var p in parts)
            {
                if (Hysteria2RequestBuilder.TryGetKnownProtocol(p, out var proto))
                {
                    list.Add(proto);
                    hasValid = true;
                }
            }

            if (!hasValid || list.Count == 0)
            {
                LogHelper.Warn("[Hysteria2] ALPN 配置无效，强制使用 h3");
                list.Clear();
            }

            if (!list.Contains(SslApplicationProtocol.Http3))
                list.Insert(0, SslApplicationProtocol.Http3);

            return list;
        }
    }
}