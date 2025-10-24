using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HiddifyConfigs
{
    /// <summary>
    /// ResultProcessor：处理检测结果，排序并去重。
    /// 按响应时间（ResponseTimeMs）排序，移除重复的 (Host, Port)。
    /// 兼容 .NET Framework 4.7.2。
    /// </summary>
    public static class ResultProcessor
    {
        /// <summary>
        /// 处理检测结果，按响应时间排序并去重。
        /// 返回排序后的可达链接列表。
        /// 新增：支持 VLESS、Trojan、Hysteria2 协议，包含 Protocol 和 ExtraParams。
        /// 新增：去重基于 (Host, Port)，保留响应时间最短的记录。
        /// </summary>
        /// <param name="results">检测结果列表，包含原始链接、主机、端口、HostParam、Encryption、Security、Protocol、ExtraParams 和响应时间</param>
        /// <param name="logInfo">日志信息，记录去重和排序结果</param>
        /// <param name="logProgress">进度日志</param>
        /// <returns>去重和排序后的可达链接列表</returns>
        public static List<(string Line, string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams, long? ResponseTimeMs)> ProcessResults(
            List<(string Line, string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams, long? ResponseTimeMs)> results,
            StringBuilder logInfo,
            IProgress<string> logProgress )
        {
            // 新增：适配 Trojan 和 Hysteria2 的 HostParam、Encryption、Security、Protocol 和 ExtraParams
            // 新增：去重基于 (Host, Port)，保留响应时间最短的记录
            var distinctResults = results
                .GroupBy(r => (r.Host.Trim('[', ']').ToLowerInvariant(), r.Port))
                .Select(g => g.OrderBy(r => r.ResponseTimeMs ?? long.MaxValue).First())
                .OrderBy(r => r.ResponseTimeMs ?? long.MaxValue)
                .ToList();

            // 新增：统计各协议的去重结果
            var protocolCounts = new Dictionary<string, int>
            {
                { "VLESS", distinctResults.Count(r => r.Protocol == "VLESS") },
                { "Trojan", distinctResults.Count(r => r.Protocol == "Trojan") },
                { "Hysteria2", distinctResults.Count(r => r.Protocol == "Hysteria2") }
            };
            string protocolSummary = string.Join(", ", protocolCounts.Where(kv => kv.Value > 0).Select(kv => $"{kv.Key}: {kv.Value}"));

            // 原有注释：记录去重结果
            // 新增：记录协议分布
            string log = $"[去重] 从 {results.Count} 条减少到 {distinctResults.Count} 条可达链接（{protocolSummary})";
            logInfo.AppendLine(log);
            logProgress?.Report(log);

            // 新增：返回去重和排序后的结果，供 FileSaver 使用
            return distinctResults;
        }
    }
}