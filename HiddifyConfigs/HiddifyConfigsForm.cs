using System;
using System.Collections.Generic;
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
        private AppSettings appSettings = new AppSettings(); // 保存所有配置
        private IWebProxy proxy = null;                      // 存储代理设置，null 表示不使用代理

        public HiddifyConfigs()
        {
            InitializeComponent();
        }

        private void HiddifyConfigs_Load( object sender, EventArgs e )
        {
            ParsingCancelButton.Enabled = false; // 初始禁用

            // 原有注释：预设默认代理 127.0.0.1:12334
            // 新增：初始化代理设置，防止二义性错误，使用独立属性设置
            if (appSettings.Proxy == null)
            {
                appSettings.Proxy = new ProxySettings();
            }
            proxy = appSettings.Proxy.Enabled ? new WebProxy
            {
                Address = new Uri($"http://{appSettings.Proxy.Address}:{appSettings.Proxy.Port}"),
                BypassProxyOnLocal = false
            } : null;
            toolStripStatusLabel1.Text = proxy == null ? "代理设置：无" : $"代理设置：{appSettings.Proxy.Address}:{appSettings.Proxy.Port}";
        }

        private void ToolStripSettingsButton_Click( object sender, EventArgs e )
        {
            // 原有注释：打开设置窗口，更新代理配置
            using (var settingsForm = new SettingsForm())
            {
                settingsForm.Config = appSettings; // 传递当前配置
                if (settingsForm.ShowDialog(this) == DialogResult.OK)
                {
                    appSettings = settingsForm.Config ?? new AppSettings(); // 防止 null
                    if (appSettings.Proxy == null) appSettings.Proxy = new ProxySettings();
                    proxy = appSettings.Proxy.Enabled
                        ? new WebProxy
                        {
                            Address = new Uri($"http://{appSettings.Proxy.Address}:{appSettings.Proxy.Port}"),
                            BypassProxyOnLocal = false
                        }
                        : null;

                    toolStripStatusLabel1.Text = proxy == null
                        ? "代理设置：无"
                        : $"代理设置：{appSettings.Proxy.Address}:{appSettings.Proxy.Port}";
                }
            }
        }

        private void OpenFileButton_Click( object sender, EventArgs e )
        {
            // 原有注释：设置文件类型过滤器
            openFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*";
            openFileDialog.Title = "选择要打开的文件";
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                string filePath = openFileDialog.FileName;
                FilePathTextBox.Text = filePath; // 在 textBox 中显示文件路径
            }
        }

        /// <summary>
        /// 从文件读取 URL 列表，下载内容，解析协议，测试连接，去重并保存结果。
        /// </summary>
        private async void ParsingFileButton_Click( object sender, EventArgs e )
        {
            // 禁用按钮并初始化界面
            ParsingFileButton.Enabled = false;
            ParsingCancelButton.Enabled = true;
            toolStripStatusLabel1.Text = "开始...";
            LogInfoTextBox.Clear();
            toolStripProgressBar1.Value = 0;

            string filePath = FilePathTextBox.Text;
            if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            {
                MessageBox.Show("请选择有效的文件路径。", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                ParsingFileButton.Enabled = true;
                toolStripStatusLabel1.Text = "未选择文件或文件不存在";
                return;
            }

            var logInfo = new StringBuilder();

            // 设置日志进度回调
            IProgress<string> logProgress = new Progress<string>(log =>
            {
                if (LogInfoTextBox.InvokeRequired)
                    LogInfoTextBox.Invoke(new Action(() => LogInfoTextBox.AppendText(log + Environment.NewLine)));
                else
                    LogInfoTextBox.AppendText(log + Environment.NewLine);
            });

            // 设置进度条回调
            IProgress<int> progress = new Progress<int>(percent =>
            {
                if (InvokeRequired)
                    Invoke(new Action(() => toolStripProgressBar1.Value = Math.Min(percent, toolStripProgressBar1.Maximum)));
                else
                    toolStripProgressBar1.Value = Math.Min(percent, toolStripProgressBar1.Maximum);
            });

            // 设置状态标签回调
            IProgress<string> status = new Progress<string>(message =>
            {
                if (InvokeRequired)
                    Invoke(new Action(() => toolStripStatusLabel1.Text = message));
                else
                    toolStripStatusLabel1.Text = message;
            });

            // 验证输出配置
            if (appSettings.OutputSplit.LinesPerFile <= 0 || appSettings.OutputSplit.MaxFiles <= 0)
            {
                MessageBox.Show("输出分割设置无效，请检查配置。", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                ParsingFileButton.Enabled = true;
                ParsingCancelButton.Enabled = false;
                return;
            }

            // 验证代理可用性
            if (proxy != null)
            {
                try
                {
                    using (var testClient = new HttpClient(new HttpClientHandler { Proxy = proxy }))
                    {
                        await testClient.GetAsync("http://www.google.com", cts?.Token ?? CancellationToken.None);
                    }
                }
                catch
                {
                    MessageBox.Show("代理配置不可用，请检查设置。", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    ParsingFileButton.Enabled = true;
                    ParsingCancelButton.Enabled = false;
                    return;
                }
            }

            try
            {
                // 新增：初始化 CancellationTokenSource
                cts = new CancellationTokenSource();

                // ✅ 异步调用 DoParse.ProcessUrlsAsync，避免 UI 卡死
                var parsedResults = await DoParse.ProcessUrlsAsync(
                    filePath,
                    logInfo,
                    cts.Token,
                    proxy,
                    logProgress,
                    status)
                    ?? new List<(string Line, string Host, int Port, string HostParam, string Encryption, string Security, string Protocol, Dictionary<string, string> ExtraParams)>();

                progress.Report(20);
                status.Report("解析完成，正在测试连接...");

                // 调用 ConnectivityChecker 异步测试连接
                var connectivityResults = await ConnectivityChecker.CheckHostsBatchAsync(
                    parsedResults.Select(r => (r.Host, r.Port, r.HostParam, r.Encryption, r.Security, r.Protocol, r.ExtraParams)),
                    timeoutMs: appSettings.TcpCheck.TimeoutMs,
                    maxConcurrency: appSettings.TcpCheck.MaxConcurrency,
                    cancellationToken: cts.Token,
                    progress: logProgress)
                    ?? new List<ConnectivityResult>();

                progress.Report(60);
                status.Report("连接测试完成，正在去重...");

                // 转换结果，保持原有逻辑
                // var parsedDict = parsedResults.ToDictionary(p => (p.Host, p.Port));
                var convertedResults = connectivityResults.Select(cr =>
                {
                    var (Line, Host, Port, HostParam, Encryption, Security, Protocol, ExtraParams) = parsedResults
                        .Where(pr => pr.Host == cr.Host && pr.Port == cr.Port)
                        .DefaultIfEmpty((
                            Line: "",
                            Host: cr.Host,
                            Port: cr.Port,
                            HostParam: cr.HostParam,
                            Encryption: cr.Encryption,
                            Security: cr.Security,
                            Protocol: cr.Protocol,
                            ExtraParams: cr.ExtraParams
                        ))
                        .First();

                    return (
                        Line: Line,
                        Host: cr.Host,
                        Port: cr.Port,
                        HostParam: HostParam,
                        Encryption: Encryption,
                        Security: Security,
                        Protocol: Protocol,
                        ExtraParams: cr.ExtraParams,
                        ResponseTimeMs: cr.ResponseTimeMs
                    );
                }).ToList();

                var processedResults = ResultProcessor.ProcessResults(
                    convertedResults,
                    logInfo,
                    logProgress);

                progress.Report(80);
                status.Report("去重完成，正在保存...");

                FileSaver.SaveToFileWithSplit(
                    "valid_links.txt",
                    processedResults,
                    appSettings.OutputSplit.EnableSplit,
                    appSettings.OutputSplit.LinesPerFile,
                    appSettings.OutputSplit.MaxFiles,
                    logInfo,
                    logProgress);

                progress.Report(100);
                toolStripStatusLabel1.Text = "处理完成";
                status.Report("处理完成");
            }
            catch (OperationCanceledException)
            {
                logInfo.AppendLine("操作已取消");
                toolStripStatusLabel1.Text = "操作已取消";
                logProgress.Report("操作已取消。");
            }
            catch (ArgumentNullException ae)
            {
                logInfo.AppendLine($"处理失败: {ae.Message} (Inner: {ae.InnerException?.Message})");
                toolStripStatusLabel1.Text = "AE处理失败";
                logProgress.Report($"处理失败: {ae.Message}");                
                logInfo.AppendLine($"信息: {ae.ParamName}");
                logInfo.AppendLine($"堆栈信息: {ae.StackTrace}");
                // MessageBox.Show($"处理失败: {ae.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (NullReferenceException ne)
            {
                logInfo.AppendLine($"处理失败: {ne.Message} (Inner: {ne.InnerException?.Message})");
                toolStripStatusLabel1.Text = "NE处理失败";
                logProgress.Report($"处理失败: {ne.Message}");
                LogHelper.WriteError($"NE处理失败: {ne.Message}");             
            }
            catch (Exception ex)
            {
                logInfo.AppendLine($"处理失败: {ex.Message} (Inner: {ex.InnerException?.Message})");
                toolStripStatusLabel1.Text = "处理失败";
                logProgress.Report($"处理失败: {ex.Message}");
                // MessageBox.Show($"处理失败: {ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                LogInfoTextBox.Text = logInfo.ToString();
                ParsingFileButton.Enabled = true;
                ParsingCancelButton.Enabled = false;
                toolStripProgressBar1.Value = 100;
            }
        }

        private void ParsingCancelButton_Click( object sender, EventArgs e )
        {
            cts?.Cancel();
            LogInfoTextBox.AppendText("\r\n用户请求取消操作...\r\n");
            ParsingCancelButton.Enabled = false;
            toolStripStatusLabel1.Text = "正在取消...";
        }

        private void DoTestToolStripButton_Click( object sender, EventArgs e )
        {
            // 原有注释：测试功能（未实现）
        }

        private void ClearCacheToolStripButton_Click( object sender, EventArgs e )
        {
            // 原有注释：清除连接缓存（未实现）
        }
    }

    // 代理设置
    public class ProxySettings
    {
        public bool Enabled { get; set; } = true;
        public string Address { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 12334;
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