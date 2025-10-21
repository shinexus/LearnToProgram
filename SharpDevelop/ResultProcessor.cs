using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HiddifyConfigs
{
    /// <summary>
    /// ResultProcessor 负责对所有检测结果进行统一处理：
    /// 1️⃣ 去重（每个 Host:Port 只保留一个，优先保留响应时间最短的）
    /// 2️⃣ 排序（按响应时间升序）
    /// 3️⃣ 输出日志信息
    /// 
    /// 设计目的：
    /// - 减轻 DoParse 的逻辑复杂度；
    /// - 提高排序性能；
    /// - 确保最终结果唯一、最优、有序。
    /// </summary>
    internal static class ResultProcessor
    {
        public static List<(string Line, string Host, int Port, long? ResponseTimeMs)>
            ProcessResults(IEnumerable<(string Line, string Host, int Port, long? ResponseTimeMs)> allResults,
                           StringBuilder logInfo = null,
                           IProgress<string> logProgress = null)
        {
            if (allResults == null) return new List<(string, string, int, long?)>();

            int totalCount = allResults.Count();

            // === 1️⃣ 去重：按 (Host, Port) 分组，只保留响应最快的一条 ===
            var distinct = allResults
                .GroupBy(r => (r.Host, r.Port))
                .Select(g => g.OrderBy(r => r.ResponseTimeMs ?? int.MaxValue).First())
                .ToList();

            // === 2️⃣ 排序：按响应时间升序排列（若无响应时间则放最后） ===
            var sorted = distinct
                .OrderBy(r => r.ResponseTimeMs ?? int.MaxValue)
                .ToList();

            // === 3️⃣ 日志输出 ===
            string logMsg = $"结果处理完成：输入 {totalCount} 条 → 去重后 {distinct.Count} 条 → 已按耗时升序排序。";
            logInfo?.AppendLine(logMsg);
            logProgress?.Report(logMsg);

            return sorted;
        }
    }
}