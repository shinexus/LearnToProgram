namespace HiddifyConfigs
{
    partial class SettingsForm
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        private void InitializeComponent()
        {
            this.ProxySettingsGroupBox = new System.Windows.Forms.GroupBox();
            this.ProxyPortLabel = new System.Windows.Forms.Label();
            this.ProxyPortTextBox = new System.Windows.Forms.TextBox();
            this.ProxyAddressTextBox = new System.Windows.Forms.TextBox();
            this.ProxyAdressLabel = new System.Windows.Forms.Label();
            this.TcpGroupBox = new System.Windows.Forms.GroupBox();
            this.TcpTimeoutTextBox = new System.Windows.Forms.TextBox();
            this.TcpTimeoutLabel = new System.Windows.Forms.Label();
            this.TcpConcurrencyTextBox = new System.Windows.Forms.TextBox();
            this.TcpConcurrencyLabel = new System.Windows.Forms.Label();
            this.FileSplitGroupBox = new System.Windows.Forms.GroupBox();
            this.FileSplitCountTextBox = new System.Windows.Forms.TextBox();
            this.FileSplitCountLabel = new System.Windows.Forms.Label();
            this.FileTruncateCheckBox = new System.Windows.Forms.CheckBox();
            this.FileSplitLinesTextBox = new System.Windows.Forms.TextBox();
            this.FileSplitLinesLabel = new System.Windows.Forms.Label();
            this.ApplyButton = new System.Windows.Forms.Button();
            this.CloseButton = new System.Windows.Forms.Button();

            this.SuspendLayout();

            // ========= 窗体基础 =========
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(420, 310);
            this.MinimumSize = new System.Drawing.Size(400, 300);
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterParent;
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Text = "设置";
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ShowInTaskbar = false;

            // ========= ProxySettingsGroupBox =========
            this.ProxySettingsGroupBox.Controls.Add(this.ProxyPortLabel);
            this.ProxySettingsGroupBox.Controls.Add(this.ProxyPortTextBox);
            this.ProxySettingsGroupBox.Controls.Add(this.ProxyAddressTextBox);
            this.ProxySettingsGroupBox.Controls.Add(this.ProxyAdressLabel);
            this.ProxySettingsGroupBox.Location = new System.Drawing.Point(15, 15);
            this.ProxySettingsGroupBox.Name = "ProxySettingsGroupBox";
            this.ProxySettingsGroupBox.Size = new System.Drawing.Size(190, 85);
            this.ProxySettingsGroupBox.TabStop = false;
            this.ProxySettingsGroupBox.Text = "代理设置";

            this.ProxyAdressLabel.Location = new System.Drawing.Point(10, 25);
            this.ProxyAdressLabel.Size = new System.Drawing.Size(65, 20);
            this.ProxyAdressLabel.Text = "代理地址：";
            this.ProxyAdressLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;

            this.ProxyAddressTextBox.Location = new System.Drawing.Point(80, 25);
            this.ProxyAddressTextBox.Size = new System.Drawing.Size(90, 23);
            this.ProxyAddressTextBox.Text = "127.0.0.1";

            this.ProxyPortLabel.Location = new System.Drawing.Point(10, 52);
            this.ProxyPortLabel.Size = new System.Drawing.Size(65, 20);
            this.ProxyPortLabel.Text = "代理端口：";
            this.ProxyPortLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;

            this.ProxyPortTextBox.Location = new System.Drawing.Point(80, 52);
            this.ProxyPortTextBox.Size = new System.Drawing.Size(50, 23);
            this.ProxyPortTextBox.Text = "12334";

            // ========= TCP 检测 =========
            this.TcpGroupBox.Controls.Add(this.TcpTimeoutTextBox);
            this.TcpGroupBox.Controls.Add(this.TcpTimeoutLabel);
            this.TcpGroupBox.Controls.Add(this.TcpConcurrencyTextBox);
            this.TcpGroupBox.Controls.Add(this.TcpConcurrencyLabel);
            this.TcpGroupBox.Location = new System.Drawing.Point(220, 15);
            this.TcpGroupBox.Size = new System.Drawing.Size(180, 85);
            this.TcpGroupBox.TabStop = false;
            this.TcpGroupBox.Text = "TCP 检测";

            this.TcpConcurrencyLabel.Location = new System.Drawing.Point(10, 25);
            this.TcpConcurrencyLabel.Size = new System.Drawing.Size(70, 20);
            this.TcpConcurrencyLabel.Text = "并发数量：";
            this.TcpConcurrencyLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;

            this.TcpConcurrencyTextBox.Location = new System.Drawing.Point(90, 25);
            this.TcpConcurrencyTextBox.Size = new System.Drawing.Size(50, 23);
            this.TcpConcurrencyTextBox.Text = "20";

            this.TcpTimeoutLabel.Location = new System.Drawing.Point(10, 52);
            this.TcpTimeoutLabel.Size = new System.Drawing.Size(70, 20);
            this.TcpTimeoutLabel.Text = "连接超时：";
            this.TcpTimeoutLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;

            this.TcpTimeoutTextBox.Location = new System.Drawing.Point(90, 52);
            this.TcpTimeoutTextBox.Size = new System.Drawing.Size(50, 23);
            this.TcpTimeoutTextBox.Text = "1500";

            // ========= 文件分割 =========
            this.FileSplitGroupBox.Controls.Add(this.FileSplitCountTextBox);
            this.FileSplitGroupBox.Controls.Add(this.FileSplitCountLabel);
            this.FileSplitGroupBox.Controls.Add(this.FileTruncateCheckBox);
            this.FileSplitGroupBox.Controls.Add(this.FileSplitLinesTextBox);
            this.FileSplitGroupBox.Controls.Add(this.FileSplitLinesLabel);
            this.FileSplitGroupBox.Location = new System.Drawing.Point(15, 110);
            this.FileSplitGroupBox.Size = new System.Drawing.Size(385, 110);
            this.FileSplitGroupBox.TabStop = false;
            this.FileSplitGroupBox.Text = "文件分割";

            this.FileSplitLinesLabel.Location = new System.Drawing.Point(15, 28);
            this.FileSplitLinesLabel.Size = new System.Drawing.Size(65, 20);
            this.FileSplitLinesLabel.Text = "分割行数：";
            this.FileSplitLinesLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;

            this.FileSplitLinesTextBox.Location = new System.Drawing.Point(85, 25);
            this.FileSplitLinesTextBox.Size = new System.Drawing.Size(70, 23);
            this.FileSplitLinesTextBox.Text = "100";

            this.FileSplitCountLabel.Location = new System.Drawing.Point(190, 28);
            this.FileSplitCountLabel.Size = new System.Drawing.Size(65, 20);
            this.FileSplitCountLabel.Text = "分割数量：";
            this.FileSplitCountLabel.TextAlign = System.Drawing.ContentAlignment.MiddleRight;

            this.FileSplitCountTextBox.Location = new System.Drawing.Point(260, 25);
            this.FileSplitCountTextBox.Size = new System.Drawing.Size(60, 23);
            this.FileSplitCountTextBox.Text = "2";

            this.FileTruncateCheckBox.Location = new System.Drawing.Point(15, 65);
            this.FileTruncateCheckBox.Size = new System.Drawing.Size(100, 20);
            this.FileTruncateCheckBox.Text = "是否截断";
            this.FileTruncateCheckBox.Checked = true;

            // ========= 按钮 =========
            this.ApplyButton.Location = new System.Drawing.Point(230, 240);
            this.ApplyButton.Size = new System.Drawing.Size(80, 28);
            this.ApplyButton.Text = "应用";
            this.ApplyButton.UseVisualStyleBackColor = true;
            this.ApplyButton.Click += new System.EventHandler(this.ApplyButton_Click);

            this.CloseButton.Location = new System.Drawing.Point(320, 240);
            this.CloseButton.Size = new System.Drawing.Size(80, 28);
            this.CloseButton.Text = "关闭";
            this.CloseButton.UseVisualStyleBackColor = true;
            this.CloseButton.Click += new System.EventHandler(this.CloseButton_Click);

            // ========= 添加控件 =========
            this.Controls.Add(this.ProxySettingsGroupBox);
            this.Controls.Add(this.TcpGroupBox);
            this.Controls.Add(this.FileSplitGroupBox);
            this.Controls.Add(this.ApplyButton);
            this.Controls.Add(this.CloseButton);

            this.ResumeLayout(false);
        }

        #endregion

        private System.Windows.Forms.GroupBox ProxySettingsGroupBox;
        private System.Windows.Forms.Label ProxyPortLabel;
        private System.Windows.Forms.TextBox ProxyPortTextBox;
        private System.Windows.Forms.TextBox ProxyAddressTextBox;
        private System.Windows.Forms.Label ProxyAdressLabel;
        private System.Windows.Forms.GroupBox TcpGroupBox;
        private System.Windows.Forms.TextBox TcpTimeoutTextBox;
        private System.Windows.Forms.Label TcpTimeoutLabel;
        private System.Windows.Forms.TextBox TcpConcurrencyTextBox;
        private System.Windows.Forms.Label TcpConcurrencyLabel;
        private System.Windows.Forms.GroupBox FileSplitGroupBox;
        private System.Windows.Forms.TextBox FileSplitCountTextBox;
        private System.Windows.Forms.Label FileSplitCountLabel;
        private System.Windows.Forms.CheckBox FileTruncateCheckBox;
        private System.Windows.Forms.TextBox FileSplitLinesTextBox;
        private System.Windows.Forms.Label FileSplitLinesLabel;
        private System.Windows.Forms.Button ApplyButton;
        private System.Windows.Forms.Button CloseButton;
    }
}