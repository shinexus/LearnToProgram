using System;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace HiddifyConfigs
{
    public static class LogHelper
    {
        private static readonly object _lock = new object();
        private static readonly string logDirectory = Path.Combine(Application.StartupPath, "logs");
        private static readonly string logFile = Path.Combine(logDirectory, "error.log");

        public static void WriteError(string message, Exception ex = null)
        {
            try
            {
                if (!Directory.Exists(logDirectory))
                    Directory.CreateDirectory(logDirectory);

                var sb = new StringBuilder();
                sb.AppendLine("──────────────────────────────────────────────");
                sb.AppendLine($"时间：{DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"消息：{message}");
                if (ex != null)
                {
                    sb.AppendLine($"异常类型：{ex.GetType().FullName}");
                    sb.AppendLine($"异常信息：{ex.Message}");
                    sb.AppendLine($"堆栈：{ex.StackTrace}");
                }

                lock (_lock)
                {
                    File.AppendAllText(logFile, sb.ToString() + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch
            {
                // 如果日志写入也失败，就忽略，不抛异常
            }
        }
    }
}