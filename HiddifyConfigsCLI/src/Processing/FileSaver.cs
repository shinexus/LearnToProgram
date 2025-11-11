// FileSaver.cs
// 负责：保存主文件 (valid_links.txt) 及自动分段输出 (valid_links_01.txt 等)
// 命名空间：HiddifyConfigsCLI
// 修改说明：
// - 整合 MaxLines 和 MaxParts 参数，实现分段文件数量限制
// - 主文件始终包含所有内容，分段文件丢弃超出 MaxParts 的部分
// - 【新增】支持 --max-parts 0：完全禁用分段文件生成（仅保留主文件）
// - 优化异常处理、日志记录、路径处理
// - [新增功能] 支持 --info 参数：统一替换每个链接的 # 后备注为指定内容（无 # 时追加）
// 作者：Grok (xAI) | 2025-11-08
using HiddifyConfigsCLI.src.Core;
using HiddifyConfigsCLI.src.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HiddifyConfigsCLI;

internal static class FileSaver
{
    /// <summary>
    /// 异步保存节点信息到主文件和分段文件
    /// 主文件始终包含所有内容，分段文件按 MaxLines 和 MaxParts 限制
    /// 【新增】若 MaxParts == 0，则完全跳过分段逻辑，仅生成主文件
    /// [新增] 若 opts.InfoTag 不为空，则替换每个链接最后一个 # 后的内容为 InfoTag
    /// </summary>
    /// <param name="nodes">已排序的最终节点列表</param>
    /// <param name="opts">运行配置（输出路径、最大行数、最大分段数、InfoTag）</param>
    /// <returns>任务对象</returns>
    public static async Task SaveAsync( List<NodeInfo> nodes, RunOptions opts )
    {
        // 【日志】记录传入的输出路径，便于调试
        LogHelper.Info($"传入的输出路径: {opts.Output ?? "<null>"}");

        // 确定输出路径：若为空则使用默认文件名 valid_links.txt
        var output = string.IsNullOrEmpty(opts.Output) ? "valid_links.txt" : opts.Output;

        // 获取目录路径，若为空则使用当前目录
        var dir = string.IsNullOrEmpty(Path.GetDirectoryName(output)) ? "." : Path.GetDirectoryName(output)!;

        // 防御性处理：防止 dir 为 null
        if (string.IsNullOrEmpty(dir))
        {
            LogHelper.Warn("目录路径为空，默认使用当前目录: .");
            dir = ".";
        }

        // 确保输出目录存在
        LogHelper.Info($"准备创建目录: {dir}");
        Directory.CreateDirectory(dir);

        // 主文件完整路径
        var mainPath = Path.GetFullPath(Path.Combine(dir, Path.GetFileName(output)));

        // 【新增】统一处理链接：替换 # 后备注为 opts.InfoTag（若指定）
        // 规则：
        // 1. 有 # → 替换最后一个 # 后的内容为 InfoTag
        // 2. 无 # → 追加 #InfoTag
        // 3. InfoTag 为空 → 保留原链接
        var processedLinks = nodes.Select(n =>
        {
            var link = n.OriginalLink;
            if (!string.IsNullOrEmpty(opts.InfoTag))
            {
                var lastHashIndex = link.LastIndexOf('#');
                if (lastHashIndex >= 0)
                {
                    // 替换最后一个 # 后的内容（使用范围运算符，高效且安全）
                    link = link[..(lastHashIndex + 1)] + opts.InfoTag;
                }
                else
                {
                    // 无 #，追加备注
                    link += "#" + opts.InfoTag;
                }
            }
            return link;
        }).ToList();

        // 【主文件】始终保存完整内容（不受分段限制）
        try
        {
            await File.WriteAllLinesAsync(mainPath, processedLinks, Encoding.UTF8);
            LogHelper.Info($"主文件已保存: {mainPath}（{processedLinks.Count} 行），始终包含全部内容");
        }
        catch (UnauthorizedAccessException ex)
        {
            LogHelper.Error($"无权限保存主文件: {mainPath}", ex);
            throw;
        }
        catch (Exception ex)
        {
            LogHelper.Error($"保存主文件失败: {mainPath}", ex);
            throw;
        }

        // 【分段逻辑】—— 新增：若 MaxParts == 0，则完全跳过分段
        if (opts.MaxParts <= 0)
        {
            LogHelper.Info("--max-parts <= 0：分段输出已禁用，仅保留主文件");
            return; // 直接返回，跳过所有分段逻辑
        }

        // 分段输出核心逻辑（仅在 MaxParts > 0 时执行）
        int totalLines = processedLinks.Count;
        int maxLines = opts.MaxLines > 0 ? opts.MaxLines : 100; // 防止 MaxLines <= 0
        int maxParts = opts.MaxParts;

        // 计算理论分段数
        int totalParts = (int)Math.Ceiling((double)totalLines / maxLines);
        int effectiveParts = Math.Min(totalParts, maxParts); // 限制不超过 MaxParts

        int partIndex = 1;
        int start = 0;

        var baseName = Path.GetFileNameWithoutExtension(output);

        while (start < totalLines && partIndex <= effectiveParts)
        {
            int remainingLines = totalLines - start;
            int linesToTake = Math.Min(maxLines, remainingLines);

            var segment = processedLinks
                .Skip(start)
                .Take(linesToTake)
                .ToList();

            var partFileName = $"{baseName}_{partIndex:D2}.txt";
            var partPath = Path.Combine(dir, partFileName);

            try
            {
                await File.WriteAllLinesAsync(partPath, segment, Encoding.UTF8);
                LogHelper.Info($"分段文件已生成: {partPath}（{segment.Count} 行）");
            }
            catch (Exception ex)
            {
                LogHelper.Error($"保存分段文件失败: {partPath}", ex);
                throw;
            }

            start += linesToTake;
            partIndex++;
        }

        // 【日志】分段完成统计
        int generatedParts = partIndex - 1;
        LogHelper.Info($"所有分段文件保存完成。共生成 {generatedParts} 个分段文件（限制为 {maxParts} 个）");

        // 【警告】超出部分被丢弃
        if (totalParts > maxParts)
        {
            int discardedLines = totalLines - (effectiveParts * maxLines);
            if (discardedLines < 0) discardedLines = totalLines % maxLines;
            LogHelper.Warn($"超出 {maxParts} 个分段的部分已被丢弃（{discardedLines} 行）");
        }
    }
}