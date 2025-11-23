// src/Checking/Handshakers/VlessWsHandler.cs
// [重构版_2025-11-20]
// 功能：VLESS 节点 WebSocket 处理
// 目的：将 VlessHandshaker 中 WS 相关逻辑抽离为独立类，提高可读性与可维护性

using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI.src.Checking.Handshakers.Vless;

internal static class VlessWsHandler
{
    /// <summary>
    /// 处理 WebSocket / HTTP Upgrade 传输类型
    /// </summary>
    /// <param name="node">VLESS 节点信息</param>
    /// <param name="stream">已建立的基础 Stream（可能是 TLS / REALITY Stream）</param>
    /// <param name="effectiveSni">有效 SNI</param>
    /// <param name="port">节点端口</param>
    /// <param name="path">WebSocket 路径</param>
    /// <param name="opts">运行选项</param>
    /// <param name="extra">节点额外参数</param>
    /// <param name="ct">取消令牌</param>
    /// <returns>是否握手+出网成功</returns>
    public static async Task<bool> HandleWebSocketAsync(
        VlessNode node,
        Stream stream,
        string effectiveSni,
        int port,
        string path,
        RunOptions opts,
        IReadOnlyDictionary<string, string> extra,
        CancellationToken ct )
    {
        try
        {
            // 调用统一的 WebSocket 升级检测方法
            bool wsSuccess = await HttpInternetChecker.CheckWebSocketUpgradeAsync(
                node,
                stream,
                effectiveSni,
                port,
                path,
                opts,
                extra,
                ct).ConfigureAwait(false);

            if (wsSuccess)
            {
                node.EffectiveSni = effectiveSni;
                LogHelper.Info($"[VLESS-WS] {node.Host}:{port} | WebSocket 握手+出网成功");
            }
            else
            {
                LogHelper.Warn($"[VLESS-WS] {node.Host}:{port} | WebSocket 升级失败");
            }

            return wsSuccess;
        }
        catch (Exception ex)
        {
            LogHelper.Warn($"[VLESS-WS] {node.Host}:{port} | WebSocket 握手异常: {ex.Message}");
            return false;
        }
    }
}
