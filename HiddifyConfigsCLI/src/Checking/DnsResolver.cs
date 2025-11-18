// src/Checking/DnsResolver.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Net.Sockets;

namespace HiddifyConfigsCLI.src.Checking;

/// <summary>
/// 【DNS 解析器】批量预解析 + 缓存，优先 IPv4
/// </summary>
internal static class DnsResolver
{
    /// <summary>
    /// 批量预解析 DNS，缓存主机地址（同时支持 IPv4 与 IPv6）
    /// </summary>
    public static async Task<Dictionary<string, IPAddress>> ResolveAsync( List<NodeInfoBase> nodes )
    {
        var hostAddresses = new Dictionary<string, IPAddress>();
        var uniqueHosts = nodes.Select(n => n.Host).Distinct().ToList();

        foreach (var host in uniqueHosts)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                IPAddress? resolved = null;

                // IPv4 优先
                try
                {
                    var ipv4List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cts.Token);
                    if (ipv4List.Length > 0) resolved = ipv4List[0];
                }
                catch { }

                // IPv6 兜底
                if (resolved == null)
                {
                    try
                    {
                        var ipv6List = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetworkV6, cts.Token);
                        if (ipv6List.Length > 0) resolved = ipv6List[0];
                    }
                    catch { }
                }

                if (resolved != null)
                    hostAddresses[host] = resolved;
            }
            catch (OperationCanceledException)
            {
                LogHelper.Error($"[DNS 超时] {host} (5s)");
            }
            catch (Exception ex)
            {
                LogHelper.Error($"DNS 解析失败: {host} | {ex.Message}");
            }
        }
        return hostAddresses;
    }
}