using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace HiddifyConfigs
{
    internal static class FileSaver
    {
        /// <summary>
        /// 写入单独文件
        /// </summary>
        public static void SaveToFile(
            string fileName,
            IEnumerable<string> lines,
            StringBuilder logInfo = null,
            IProgress<string> logProgress = null)
        {
            if (lines == null) throw new ArgumentNullException(nameof(lines));
            if (string.IsNullOrWhiteSpace(fileName)) throw new ArgumentException("文件名不能为空。", nameof(fileName));

            try
            {
                File.WriteAllLines(fileName, lines, Encoding.UTF8);
                string msg = $"✅ 已写入 {CountLines(lines)} 条数据到 {fileName}";
                logInfo?.AppendLine(msg);
                logProgress?.Report(msg);
            }
            catch (Exception ex)
            {
                string msg = $"❌ 写入 {fileName} 失败: {ex.Message}";
                logInfo?.AppendLine(msg);
                logProgress?.Report(msg);
            }
        }

        /// <summary>
        /// 根据用户设置，支持按行数分割输出文件。
        /// </summary>
        public static void SaveToFileWithSplit(
            string fileName,
            IEnumerable<string> lines,
            bool enableSplit,
            int linesPerFile,
            int maxFiles,
            StringBuilder logInfo = null,
            IProgress<string> logProgress = null)
        {
            if (lines == null) throw new ArgumentNullException(nameof(lines));
            if (string.IsNullOrWhiteSpace(fileName)) throw new ArgumentException("文件名不能为空。", nameof(fileName));

            // 如果没有启用分割，则直接使用原有方法写入
            if (!enableSplit)
            {
                // SaveToFile(fileName, lines, logInfo, logProgress);
                SaveToFile("non_vmess_raw.txt", lines, logInfo, logProgress);
                return;
            }

            try
            {
                // 将所有数据加载为 List，方便分批操作
                var allLines = lines.ToList();
                int totalLines = allLines.Count;
                if (totalLines == 0)
                {
                    string msg = $"⚠️ 无数据可写入，跳过创建文件 {fileName}";
                    logInfo?.AppendLine(msg);
                    logProgress?.Report(msg);
                    return;
                }

                // === 计算总文件数 ===
                int totalFiles = (int)Math.Ceiling(totalLines / (double)linesPerFile);
                if (totalFiles > maxFiles)
                {
                    totalFiles = maxFiles; // 超过最大文件数时截断
                }

                string baseName = Path.GetFileNameWithoutExtension(fileName);
                string dir = Path.GetDirectoryName(fileName) ?? "";
                string ext = Path.GetExtension(fileName);

                for (int i = 0; i < totalFiles; i++)
                {
                    // 当前文件的起始与结束索引
                    int start = i * linesPerFile;
                    int count = Math.Min(linesPerFile, totalLines - start);

                    // 如果剩余行数为 0，则不创建空文件
                    if (count <= 0)
                        break;

                    // 生成带编号的文件名，例如 xxx_01.txt
                    string newFileName = Path.Combine(dir, $"{baseName}_{(i + 1):D2}{ext}");

                    // 截取当前批次的行
                    var chunk = allLines.Skip(start).Take(count);

                    // 执行写入
                    File.WriteAllLines(newFileName, chunk, Encoding.UTF8);

                    // 输出日志
                    string msg = $"✅ 已写入 {count} 条数据到 {newFileName}";
                    logInfo?.AppendLine(msg);
                    logProgress?.Report(msg);
                }

                // 如果还有剩余未写入的数据，输出警告日志
                if (totalLines > linesPerFile * totalFiles)
                {
                    int skipped = totalLines - linesPerFile * totalFiles;
                    string warn = $"⚠️ 已达到最大文件数 {totalFiles}，剩余 {skipped} 条未写入。";
                    logInfo?.AppendLine(warn);
                    logProgress?.Report(warn);
                }
            }
            catch (Exception ex)
            {
                string msg = $"❌ 文件分割写入失败: {ex.Message}";
                logInfo?.AppendLine(msg);
                logProgress?.Report(msg);
            }
        }

        /// <summary>
        /// 工具方法：统计行数。
        /// </summary>
        private static int CountLines(IEnumerable<string> lines)
        {
            int count = 0;
            foreach (var _ in lines) count++;
            return count;
        }
    }
}
