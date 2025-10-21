using System;
using System.Diagnostics;
using System.Windows.Forms;

namespace HiddifyConfigs
{
    public static class GitHelper
    {
        /// <summary>
        /// �ύָ���ļ���Git�������͵�Զ�ֿ̲�
        /// </summary>
        public static void CommitAndPushFile(string filePath, string commitMessage = "�Զ��ύvmess_raw.txt")
        {
            try
            {
                RunGitCommand($"add \"{filePath}\"");
                RunGitCommand($"commit -m \"{commitMessage}\"");
                RunGitCommand("push");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Git�ύʧ��: {ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// ִ��git����
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