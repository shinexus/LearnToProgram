// src/Checking/ConnectivityChecker.cs
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;

namespace HiddifyConfigsCLI.src.Checking;

/// <summary>
/// 【主流程编排器】仅负责入口调用，核心逻辑已全部外移
/// </summary>
internal static class ConnectivityChecker
{
    /// <summary>
    /// 并发检测节点连通性，仅支持 vless、trojan、hysteria2 协议
    /// 优化：连接池复用、动态超时、批量 DNS 解析
    /// 协议握手成功后，自动进行出网测试（除非 --no-check）
    /// </summary>
    public static async Task<List<NodeInfoBase>> CheckAsync( List<NodeInfoBase> nodes, RunOptions opts )
    {
        // 【Grok 提炼】主入口极简，仅做参数校验与委托
        if (nodes.Count == 0) return [];
        if (opts.NoCheck)
        {
            LogHelper.Info("[跳过] 连通性与出网检测 (--no-check)");
            return nodes;
        }

        // 【Grok 新增】创建编排器，执行完整流程
        var orchestrator = new ConnectivityOrchestrator(opts);
        return await orchestrator.RunAsync(nodes);
    }
}