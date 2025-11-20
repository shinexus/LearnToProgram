// src/Checking/Handshakers/VlessHeaderBuilder.cs
// [重构版_2025-11-20]
// 功能：VLESS Header 构建 + UUID 解析
// 目的：将 VlessHandshaker 内部 header 构建逻辑抽离，保证代码可读性与可维护性

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace HiddifyConfigsCLI.src.Checking.Handshakers;

internal static class VlessHeaderBuilder
{
    /// <summary>
    /// 构建 VLESS Header
    /// </summary>
    /// <param name="node">Vless 节点信息</param>
    /// <param name="address">解析后的 IP 地址</param>
    /// <param name="uuid">UUID，保证有效</param>
    /// <param name="extra">节点额外参数（只读）</param>
    /// <returns>VLESS Header 字节数组</returns>
    public static byte[] BuildVlessHeader(
        VlessNode node,
        IPAddress address,
        Guid uuid,
        IReadOnlyDictionary<string, string> extra )
    {
        // 将 UUID 转换为字节数组（16 字节）
        var uuidBytes = uuid.ToByteArray();

        // ====== 处理地址类型 ======
        byte addrType;
        byte[] addrBytes;

        if (IPAddress.TryParse(node.Host, out var ip))
        {
            // IP 地址
            addrType = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
            addrBytes = ip.GetAddressBytes();
        }
        else
        {
            // 域名
            addrType = 0x03;
            var domainBytes = Encoding.UTF8.GetBytes(node.Host);
            addrBytes = new byte[1 + domainBytes.Length];
            addrBytes[0] = (byte)domainBytes.Length;
            Buffer.BlockCopy(domainBytes, 0, addrBytes, 1, domainBytes.Length);
        }

        // 网络序端口
        var networkPort = IPAddress.HostToNetworkOrder((short)node.Port);
        var portBytes = BitConverter.GetBytes(networkPort);

        // 组装 Header：16 UUID + 1 命令 + 1 地址类型 + 地址字节 + 2 端口字节
        var header = new byte[16 + 1 + 1 + addrBytes.Length + 2];
        Buffer.BlockCopy(uuidBytes, 0, header, 0, 16);
        header[16] = 0x01; // TCP command
        header[17] = addrType;
        Buffer.BlockCopy(addrBytes, 0, header, 18, addrBytes.Length);
        Buffer.BlockCopy(portBytes, 0, header, 18 + addrBytes.Length, 2);

        // ====== 日志输出 ExtraParams 信息（只读） ======
        var flow = extra.GetValueOrDefault("flow") ?? "";
        var isTls = extra.GetValueOrDefault("tls") == "tls" || extra.GetValueOrDefault("tls_enabled") == "true";
        var isReality = extra.GetValueOrDefault("tls") == "reality" || extra.GetValueOrDefault("reality_enabled") == "true";
        LogHelper.Verbose($"[VLESS Header] flow={flow}, tls={isTls}, reality={isReality}");

        return header;
    }

    /// <summary>
    /// 解析 UUID，如果无效则生成新的随机 UUID
    /// </summary>
    /// <param name="s">原始 UUID 字符串</param>
    /// <returns>有效 UUID</returns>
    public static Guid ParseOrRandomUuid( string? s )
    {
        if (Guid.TryParse(s, out var id))
            return id;

        // UUID 无效时生成新的随机 UUID
        return Guid.NewGuid();
    }
}
