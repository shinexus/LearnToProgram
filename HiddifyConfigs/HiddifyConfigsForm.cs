using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace HiddifyConfigs
{
    public partial class HiddifyConfigs : Form
    {
        private CancellationTokenSource cts;
        private IWebProxy proxy = null; // 存储代理设置，null 表示不使用代理

        public HiddifyConfigs()
        {
            InitializeComponent();
        }

        private void HiddifyConfigs_Load(object sender, EventArgs e)
        {
            ParsingCancelButton.Enabled = false; // 初始禁用

            // 预设默认代理 127.0.0.1:12334
            AddressTextBox.Text = "127.0.0.1";
            PortTextBox.Text = "12334";
            proxy = new WebProxy("127.0.0.1", 12334); // 默认使用代理
        }

        private void ToolStripButton_Click(object sender, EventArgs e)
        {
            if (ProxySettingsPanel == null)
            {
                MessageBox.Show("UseProxyPanel 未初始化", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }            
            ProxySettingsPanel.Visible = true; // 显示 Panel
            ProxySettingsPanel.BringToFront(); // 确保 Panel 在最前面
            
            // UseProxyPanel.Controls.Clear(); // 清空旧内容

            // 添加新的控件到 Panel，例如一个 Label
            //var label = new Label();
            // label.Text = "这里是 Panel 显示的内容";
            // label.Location = new Point(10, 10);
            // UseProxyPanel.Controls.Add(label);
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
        /// 从文件读取 URL 列表，下载内容并提取 vmess 协议链接，保存到 vmess_raw.txt 文件。
        /// </summary>
        private async void ParsingFileButton_Click(object sender, EventArgs e)
        {
            ProxySettingsPanel.Visible = false;
            ParsingFileButton.Enabled = false; // 开始时禁用按钮
            ParsingCancelButton.Enabled = true;
            toolStripStatusLabel1.Text = "开始...";

            string filePath = FilePathTextBox.Text;
            if (!File.Exists(filePath))
            {
                MessageBox.Show("文件不存在，请检查路径是否正确。", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                ParsingFileButton.Enabled = true;

                toolStripStatusLabel1.Text = "文件不存在";
                return;
            }
            var doParse = new DoParse();
            var vmessList = new List<string>();
            var nonVmessList = new List<string>(); // 用于存储非 vmess:// 链接
            var sb = new StringBuilder();
            var logInfo = new StringBuilder();  // 用于日志和调试信息

            // 设置进度条和状态标签的 IProgress
            var progress = new Progress<int>(percent =>
            {
                if (InvokeRequired)
                {
                    Invoke(new Action(() => toolStripProgressBar1.Value = Math.Min(percent, toolStripProgressBar1.Maximum)));
                }
                else
                {
                    toolStripProgressBar1.Value = Math.Min(percent, toolStripProgressBar1.Maximum);
                }
            });

            var status = new Progress<string>(message =>
            {
                if (InvokeRequired)
                {
                    Invoke(new Action(() => toolStripStatusLabel1.Text = message));
                }
                else
                {
                    toolStripStatusLabel1.Text = message;
                }
            });

            try
            {
                cts = new CancellationTokenSource();
                await doParse.ProcessUrlsAsync(filePath, sb, logInfo, vmessList, nonVmessList, cts.Token, progress, status, proxy);

                doParse.SaveNonVmessList(nonVmessList, logInfo);
                doParse.SaveVmessList(vmessList, logInfo);

                // 显示非 vmess:// 链接到 ParseOutputTextBox
                ParseOutputTextBox.Text = sb.Length > 0 ? sb.ToString() : "没有找到可 ping 通的非 vmess:// 链接。";

                toolStripStatusLabel1.Text = "处理完成";
            }
            catch (OperationCanceledException)
            {
                logInfo.AppendLine("操作已取消。");
                toolStripStatusLabel1.Text = "操作已取消";
            }
            catch (Exception ex)
            {
                logInfo.AppendLine($"处理失败: {ex.Message}");
                MessageBox.Show($"处理失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                toolStripStatusLabel1.Text = "处理失败";
            }
            finally
            {
                LogInfoTextBox.Text = logInfo.ToString();
                ParsingFileButton.Enabled = true;       // 结束时恢复按钮可用
                ParsingCancelButton.Enabled = false;
                toolStripProgressBar1.Value = 100;      // 确保结束时进度条满
            }            
        }               

        private void ProxySettingsApplyButton_Click(object sender, EventArgs e)
        {
            string address = AddressTextBox.Text.Trim();
            string portText = PortTextBox.Text.Trim();

            // 如果地址和端口同时为空，表示不使用代理
            if (string.IsNullOrEmpty(address) && string.IsNullOrEmpty(portText))
            {
                proxy = null;
                MessageBox.Show("代理设置：不使用代理。", "信息", MessageBoxButtons.OK, MessageBoxIcon.Information);
                ProxySettingsPanel.Visible = false;
                return;
            }

            // 否则，验证并设置代理
            if (string.IsNullOrEmpty(address))
            {
                MessageBox.Show("代理地址不能为空。", "警告", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (!int.TryParse(portText, out int port) || port < 1 || port > 65535)
            {
                MessageBox.Show("端口必须是 1-65535 之间的数字。", "警告", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                proxy = new WebProxy(address, port);
                MessageBox.Show($"代理设置成功: {address}:{port}", "信息", MessageBoxButtons.OK, MessageBoxIcon.Information);
                ProxySettingsPanel.Visible = false; // 可选：关闭面板
            }
            catch (Exception ex)
            {
                MessageBox.Show($"代理设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ProxySettingsCloseButton_Click(object sender, EventArgs e)
        {
            ProxySettingsPanel.Visible = false; // 隐藏 UseProsyPanel
        }

        private void ParsingCancelbutton_Click(object sender, EventArgs e)
        {
            cts?.Cancel();
            LogInfoTextBox.AppendText("\r\n用户请求取消操作...\r\n");
            ParsingCancelButton.Enabled = false;
            toolStripStatusLabel1.Text = "正在取消...";
            ParsingFileButton.Enabled = true;
        }
    }
}
