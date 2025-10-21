using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace HiddifyConfigs
{
    public static class GitHelper
    {
        /// <summary>
        /// 提交指定文件到Git，并推送到远程仓库
        /// </summary>
        public static void CommitAndPushFile(string filePath, string commitMessage = "自动提交vmess_raw.txt")
        {
            try
            {
                RunGitCommand($"add \"{filePath}\"");
                RunGitCommand($"commit -m \"{commitMessage}\"");
                RunGitCommand("push");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Git提交失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// 执行git命令
        /// </summary>
        private static void RunGitCommand(string arguments)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "git",
                Arguments = arguments,
                WorkingDirectory = Application.StartupPath,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (var process = Process.Start(psi))
            {
                process.WaitForExit();
                string error = process.StandardError.ReadToEnd();
                if (process.ExitCode != 0)
                {
                    throw new Exception(error);
                }
            }
        }
    }
}