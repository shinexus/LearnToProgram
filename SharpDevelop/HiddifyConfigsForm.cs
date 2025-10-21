using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HiddifyConfigs
{
    public partial class HiddifyConfigs : Form
    {
        private CancellationTokenSource cts;
        private AppSettings appSettings = new AppSettings(); // 保存所有配置
        private IWebProxy proxy = null;                      // 存储代理设置，null 表示不使用代理

        public HiddifyConfigs()
        {
            InitializeComponent();
        }

        private void HiddifyConfigs_Load(object sender, EventArgs e)
        {
            ParsingCancelButton.Enabled = false; // 初始禁用

            // 预设默认代理 127.0.0.1:12334            
            proxy = new WebProxy("127.0.0.1", 12334); // 默认使用代理
        }

        private void ToolStripSettingsButton_Click(object sender, EventArgs e)
        {            
            using (var settingsForm = new SettingsForm())
            {
                if (settingsForm.ShowDialog(this) == DialogResult.OK)
                {
                    appSettings = settingsForm.Config;
                    proxy = appSettings?.Proxy.Enabled == true
                        ? new WebProxy(appSettings.Proxy.Address, appSettings.Proxy.Port)
                        : null;

                    toolStripStatusLabel1.Text = proxy == null
                        ? "代理设置：无"
                        : $"代理设置：{appSettings.Proxy.Address}:{appSettings.Proxy.Port}";
                }
            }
        }

        private void OpenFileButton_Click(object sender, EventArgs e)
        {
            openFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"; // 设置文件类型过滤器
            openFileDialog.Title = "选择要打开的文件";
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string filePath = openFileDialog.FileName;
                FilePathTextBox.Text = filePath; // 在 textBox 中显示文件路径
            }
        }

        /// <summary>
        /// 从文件读取 URL 列表，下载内容。
        /// </summary>
        private async void ParsingFileButton_Click(object sender, EventArgs e)
        {

            ParsingFileButton.Enabled = false; // 开始时禁用按钮
            ParsingCancelButton.Enabled = true;
            toolStripStatusLabel1.Text = "开始...";
            LogInfoTextBox.Clear();

            string filePath = FilePathTextBox.Text;
            if (!File.Exists(filePath))
            {
                MessageBox.Show("文件不存在，请检查路径是否正确。", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                ParsingFileButton.Enabled = true;

                toolStripStatusLabel1.Text = "文件不存在";
                return;
            }
            var doParse = new DoParse();
            // var vmessList = new List<string>();
            // var nonVmessList = new List<string>(); // 用于存储非 vmess:// 链接

            var validList = new List<string>();    // 用于存储可达的链接
            var sb = new StringBuilder();
            var logInfo = new StringBuilder();      // 用于日志和调试信息

            IProgress<string> logProgress = new Progress<string>(log =>
            {
                if (LogInfoTextBox.InvokeRequired)
                    LogInfoTextBox.Invoke(new Action(() => LogInfoTextBox.AppendText(log + Environment.NewLine)));
                else
                    LogInfoTextBox.AppendText(log + Environment.NewLine);
            });

            // 设置进度条和状态标签的 IProgress
            IProgress<int> progress = new Progress<int>(percent =>
            {
                if (InvokeRequired)
                    Invoke(new Action(() => toolStripProgressBar1.Value = Math.Min(percent, toolStripProgressBar1.Maximum)));
                else
                    toolStripProgressBar1.Value = Math.Min(percent, toolStripProgressBar1.Maximum);
            });

            IProgress<string> status = new Progress<string>(message =>
            {
                if (InvokeRequired)
                    Invoke(new Action(() => toolStripStatusLabel1.Text = message));
                else
                    toolStripStatusLabel1.Text = message;
            });

            try
            {                
                cts = new CancellationTokenSource();
                await doParse.ProcessUrlsAsync(
                    filePath,
                    logInfo,
                    validList,
                    cts.Token,
                    progress,
                    status,
                    proxy,
                    logProgress);

                // 保存非 vmess:// 链接                
                // FileSaver.SaveToFile("non_vmess_raw.txt", validList, logInfo, logProgress);
                FileSaver.SaveToFileWithSplit(
                    "valid_links.txt",
                    validList,
                    appSettings.OutputSplit.EnableSplit,
                    appSettings.OutputSplit.LinesPerFile,
                    appSettings.OutputSplit.MaxFiles,
                    logInfo,
                    logProgress);

                // 保存 vmess:// 链接
                // FileSaver.SaveToFile("vmess_raw.txt", vmessList, logInfo, logProgress);

                // 显示非 vmess:// 链接到 ParseOutputTextBox
                // ParseOutputTextBox.Text = sb.Length > 0 ? sb.ToString() : "没有找到可 ping 通的非 vmess:// 链接。";

                toolStripStatusLabel1.Text = "处理完成";
                status.Report("处理完成");
            }
            catch (OperationCanceledException)
            {
                logInfo.AppendLine("操作已取消。（OperationCanceledException）");
                toolStripStatusLabel1.Text = "操作已取消";
                logProgress.Report("logProgress.Report：操作已取消。");
            }            
            catch (Exception ex)
            {
                logInfo.AppendLine($"处理失败: {ex.Message}");
                toolStripStatusLabel1.Text = "处理失败";
                logProgress.Report($"处理失败: {ex.Message}");
                MessageBox.Show($"处理失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);

            }
            finally
            {
                LogInfoTextBox.Text = logInfo.ToString();
                ParsingFileButton.Enabled = true;       // 结束时恢复按钮可用
                ParsingCancelButton.Enabled = false;
                toolStripProgressBar1.Value = 100;      // 确保结束时进度条满
            }
        }

        private void ParsingCancelButton_Click(object sender, EventArgs e)
        {
            cts?.Cancel();
            LogInfoTextBox.AppendText("\r\n用户请求取消操作...\r\n");
            ParsingCancelButton.Enabled = false;
            toolStripStatusLabel1.Text = "正在取消...";
        }

        private void DoTestToolStripButton_Click(object sender, EventArgs e)
        {
            //var t = new Test();
            //t.DoTest();
        }
    }
}
