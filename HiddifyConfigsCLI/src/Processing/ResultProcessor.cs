// ResultProcessor.cs
// 负责：去重 + 排序（增强去重键，支持多种排序策略）
// 命名空间：HiddifyConfigsCLI
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HiddifyConfigsCLI;

internal static class ResultProcessor
{
    /// <summary>
    /// 对有效节点进行去重与排序
    /// </summary>
    /// <param name="nodes">待处理的节点列表</param>
    /// <param name="sortBy">排序依据：latency / host / type</param>
    /// <returns>处理后的有序节点列表</returns>
    public static List<NodeInfo> Process( List<NodeInfo> nodes, string sortBy )
    {
        if (nodes.Count == 0)
            return new List<NodeInfo>();

        // 【修改】增强去重键：不再依赖 DedupKey，而是动态构建全面唯一标识
        // 键组成：{Type}://{Host}:{Port}[/uid:{UserId}][/pwd:{PasswordHash}][/priv:{PrivateKeyHash}]
        // 目的：
        //   1. 同一服务器不同用户配置（如多 UUID VLESS）保留独立节点
        //   2. 相同凭证只保留延迟最低的
        //   3. WireGuard 私钥也参与去重（防止重复配置）
        //   4. 密码/私钥使用 GetHashCode() 防止明文泄露
        //   5. 可扩展：未来可加入 ExtraParams 中关键字段（如 "allowInsecure=1"）
        var dedup = nodes
            .GroupBy(n =>
            {
                var key = new StringBuilder();
                key.Append($"{n.Type}://{n.Host}:{n.Port}");

                // 【新增】VLESS/Trojan/Tuic/SOCKS5：UserId（如 UUID）参与去重
                if (!string.IsNullOrEmpty(n.UserId))
                    key.Append($"/uid:{n.UserId}");

                // 【新增】Trojan/Tuic/SOCKS5：Password 参与去重（哈希防泄露）
                if (!string.IsNullOrEmpty(n.Password))
                    key.Append($"/pwd:{n.Password.GetHashCode()}");

                // 【新增】WireGuard：私钥参与去重（哈希）
                if (!string.IsNullOrEmpty(n.PrivateKey))
                    key.Append($"/priv:{n.PrivateKey.GetHashCode()}");

                // 【可扩展点】Hysteria2 auth / VLESS flow / reality pubkey 等
                // 示例：if (n.ExtraParams?.TryGetValue("auth", out var auth) == true)
                //         key.Append($"/auth:{auth.GetHashCode()}");

                return key.ToString();
            })
            .Select(g =>
            {
                // 在同一去重组内，优先选择延迟最低的节点
                // SortLatency 已处理 null → TimeSpan.MaxValue
                var best = g
                    .OrderBy(n => n.SortLatency)     // 延迟升序
                    .ThenBy(n => n.Type)             // 次选协议类型（稳定）
                    .First();
                return best;
            })
            .ToList();

        // 2. 全局排序
        var sorted = sortBy?.Trim().ToLowerInvariant() switch
        {
            "latency" => dedup
                .OrderBy(n => n.SortLatency)     // 无延迟节点（MaxValue）自动后置
                .ThenBy(n => n.Host)
                .ThenBy(n => n.Port)
                .ThenBy(n => n.Type)
                .ToList(),

            "host" => dedup
                .OrderBy(n => n.Host)
                .ThenBy(n => n.Port)
                .ThenBy(n => n.Type)
                .ThenBy(n => n.SortLatency)
                .ToList(),

            "type" => dedup
                .OrderBy(n => n.Type)
                .ThenBy(n => n.Host)
                .ThenBy(n => n.Port)
                .ThenBy(n => n.SortLatency)
                .ToList(),

            _ => dedup // 默认：保持去重顺序（已低延迟优先）
        };

        // 【增强日志】更详细的去重统计
        var removedByDedup = nodes.Count - dedup.Count;
        LogHelper.Info($"去重排序完成：{nodes.Count} → {dedup.Count}（去重，移除 {removedByDedup} 条）→ {sorted.Count}（最终） | 排序: {sortBy ?? "default"}");

        // 【新增】Verbose 模式下输出去重详情
        //if (Program.Options!.Verbose && removedByDedup > 0)
        //{
        //    var sampleDup = nodes
        //        .GroupBy(n => n.DedupKey)
        //        .Where(g => g.Count() > 1)
        //        .FirstOrDefault();

        //    if (sampleDup != null)
        //    {
        //        LogHelper.Verbose($"示例重复组 [{sampleDup.Key}]: 保留延迟 {(sampleDup.Min(n => n.SortLatency).TotalMilliseconds == double.MaxValue ? "N/A" : sampleDup.Min(n => n.SortLatency).TotalMilliseconds + "ms")} 的节点");
        //    }
        //}

        return sorted;
    }
}