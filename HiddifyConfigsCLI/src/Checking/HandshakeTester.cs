// src/Checking/HandshakeTester.cs


using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System.Net;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking;

/// <summary>
/// 【握手测试分发器】根据协议类型路由到具体实现
/// </summary>
internal static class HandshakeTester
{
    /// <summary>
    /// 尝试协议握手
    /// </summary/// <summary>
    /// 尝试协议握手（异步）
    /// </summary>
    /// <param name="node">节点信息（继承自 NodeInfoBase）</param>
    /// <param name="dnsCache">DNS 缓存（Host → IPAddress）</param>
    /// <param name="timeoutSec">超时时间（秒）</param>
    /// <param name="opts">运行选项</param>
    /// <returns>(success, latency, stream)</returns>
    public static async Task<(bool success, TimeSpan latency, Stream? stream)> TryHandshakeAsync(
        NodeInfoBase node,
        Dictionary<string, IPAddress> dnsCache,
        int timeoutSec,
        RunOptions opts )
    {            

        if (!dnsCache.TryGetValue(node.Host, out var address))
        {
            LogHelper.Error($"[跳过] {node.Type}://{node.Host}:{node.Port} | DNS 解析失败");

            // 失败或无意义（如DNS解析）使用 TimeSpan.Zero 成功使用 sw.Elapsed
            return (false, TimeSpan.Zero, null);
        }

        if (node.Type is not ("vless" or "trojan" or "hysteria2" or "tuic" or "wireguard" or "socks5"))
        {
            LogHelper.Error($"[跳过] {node.Host}:{node.Port} | 不支持的协议: {node.Type}");
            return (false, TimeSpan.Zero, null);
        }

        LogHelper.Debug($"[正在测试协议握手] {node.Type}://{node.Host}:{node.Port}");

        return node.Type switch
        {
            "vless" => node is VlessNode vlessNode
                ? await Handshakers.VlessHandshaker.TestAsync(vlessNode, address, timeoutSec, opts)
                : (false, TimeSpan.Zero, null),

            "trojan" => node is TrojanNode trojanNode
                ? await Handshakers.TrojanHandshaker.TestAsync(trojanNode, address, timeoutSec, opts)
                : (false, TimeSpan.Zero, null),

            "hysteria2" => node is Hysteria2Node hysteria2Node
                ? await Handshakers.Hysteria2Handshaker.TestAsync(hysteria2Node, address, timeoutSec, opts)
                : (false, TimeSpan.Zero, null),

            _ => (false, TimeSpan.Zero, null) // 防御性
        };
    }
}