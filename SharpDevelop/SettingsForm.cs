using System;
using System.Net;
using System.Windows.Forms;

namespace HiddifyConfigs
{
    public partial class SettingsForm : Form
    {
        // 结构化配置对象
        public AppSettings Config { get; private set; } = new AppSettings();

        public SettingsForm()
        {
            InitializeComponent();
            // 预设默认值
            ProxyAddressTextBox.Text = Config.Proxy.Address;
            ProxyPortTextBox.Text = Config.Proxy.Port.ToString();
            FileSplitLinesTextBox.Text = Config.OutputSplit.LinesPerFile.ToString();
            FileSplitCountTextBox.Text = Config.OutputSplit.MaxFiles.ToString();
            FileTruncateCheckBox.Checked = Config.OutputSplit.EnableSplit;
        }

        private void ApplyButton_Click(object sender, EventArgs e)
        {
            // 验证代理设置
            string address = ProxyAddressTextBox.Text.Trim();
            string portText = ProxyPortTextBox.Text.Trim();

            if (string.IsNullOrEmpty(address) && string.IsNullOrEmpty(portText))
            {
                // Config.Proxy = null;

                //创建一个禁用状态的代理对象，而不是设置为 null
                Config.Proxy = new ProxySettings
                {
                    Enabled = false,
                    Address = "",
                    Port = 0
                };
                MessageBox.Show("代理设置：不使用代理。", "信息", 
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
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
                    Config.Proxy = new ProxySettings
                    {
                        Address = address,
                        Port = port
                    };
                    MessageBox.Show($"代理设置成功: {address}:{port}", "信息", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"代理设置失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }

            // 验证 TCP 检测设置
            if (!int.TryParse(TcpConcurrencyTextBox.Text.Trim(), out int maxConcurrency) || maxConcurrency < 1)
            {
                MessageBox.Show("并发数量必须是正整数。", "警告", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (!int.TryParse(TcpTimeoutTextBox.Text.Trim(), out int timeoutMs) || timeoutMs < 1)
            {
                MessageBox.Show("连接超时必须是正整数。", "警告", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            Config.TcpCheck.MaxConcurrency = maxConcurrency;
            Config.TcpCheck.TimeoutMs = timeoutMs;

            // 验证文件分割设置
            if (FileTruncateCheckBox.Checked)
            {
                if (!int.TryParse(FileSplitLinesTextBox.Text.Trim(), out int linesPerFile) || linesPerFile <= 0)
                {
                    MessageBox.Show("分割行数必须是正整数，已恢复默认值 100。", "警告", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    FileSplitLinesTextBox.Text = "100";
                    linesPerFile = 100;
                }

                if (!int.TryParse(FileSplitCountTextBox.Text.Trim(), out int maxFiles) || maxFiles <= 0)
                {
                    MessageBox.Show("分割数量必须是正整数，已恢复默认值 2。", "警告", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    FileSplitCountTextBox.Text = "2";
                    maxFiles = 2;
                }

                Config.OutputSplit.EnableSplit = true;
                Config.OutputSplit.LinesPerFile = linesPerFile;
                Config.OutputSplit.MaxFiles = maxFiles;
            }
            else
            {
                Config.OutputSplit.EnableSplit = false;
            }

            // 如果所有验证通过，保存配置并关闭
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void CloseButton_Click(object sender, EventArgs e)
        {
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }
    }

    // 代理设置
    public class ProxySettings
    {
        public string Address { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 12334;
        
        // public bool Enabled => !string.IsNullOrEmpty(Address) && Port > 0;
        public bool Enabled { get; set; } = true;
    }

    // TCP 检测设置
    public class TcpCheckSettings
    {
        public int MaxConcurrency { get; set; } = 20;
        public int TimeoutMs { get; set; } = 1500;
    }

    // 文件分割设置
    public class OutputSplitSettings
    {
        public bool EnableSplit { get; set; } = true;
        public int LinesPerFile { get; set; } = 100;
        public int MaxFiles { get; set; } = 2;
    }

    // 应用设置
    public class AppSettings
    {
        public ProxySettings Proxy { get; set; } = new ProxySettings();
        public TcpCheckSettings TcpCheck { get; set; } = new TcpCheckSettings();
        public OutputSplitSettings OutputSplit { get; set; } = new OutputSplitSettings();
    }
}
