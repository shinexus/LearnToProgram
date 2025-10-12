namespace HiddifyConfigs
{
    partial class HiddifyConfigs
    {
        /// <summary>
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        /// <summary>
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(HiddifyConfigs));
            this.toolStrip = new System.Windows.Forms.ToolStrip();
            this.toolStripButton = new System.Windows.Forms.ToolStripButton();
            this.ProxySettingsPanel = new System.Windows.Forms.Panel();
            this.AdressLabel = new System.Windows.Forms.Label();
            this.ProxySettingsCloseButton = new System.Windows.Forms.Button();
            this.ProxySettingsApplyButton = new System.Windows.Forms.Button();
            this.PortTextBox = new System.Windows.Forms.TextBox();
            this.PortLabel = new System.Windows.Forms.Label();
            this.AddressTextBox = new System.Windows.Forms.TextBox();
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.FilePathTextBox = new System.Windows.Forms.TextBox();
            this.OpenFileButton = new System.Windows.Forms.Button();
            this.ParsingFileButton = new System.Windows.Forms.Button();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.ParseOutputTextBox = new System.Windows.Forms.TextBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.LogInfoTextBox = new System.Windows.Forms.TextBox();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripProgressBar1 = new System.Windows.Forms.ToolStripProgressBar();
            this.ParsingCancelButton = new System.Windows.Forms.Button();
            this.toolStrip.SuspendLayout();
            this.ProxySettingsPanel.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // toolStrip
            // 
            this.toolStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripButton});
            resources.ApplyResources(this.toolStrip, "toolStrip");
            this.toolStrip.Name = "toolStrip";
            // 
            // toolStripButton
            // 
            this.toolStripButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            resources.ApplyResources(this.toolStripButton, "toolStripButton");
            this.toolStripButton.Name = "toolStripButton";
            this.toolStripButton.Click += new System.EventHandler(this.ToolStripButton_Click);
            // 
            // ProxySettingsPanel
            // 
            this.ProxySettingsPanel.Controls.Add(this.AdressLabel);
            this.ProxySettingsPanel.Controls.Add(this.ProxySettingsCloseButton);
            this.ProxySettingsPanel.Controls.Add(this.ProxySettingsApplyButton);
            this.ProxySettingsPanel.Controls.Add(this.PortTextBox);
            this.ProxySettingsPanel.Controls.Add(this.PortLabel);
            this.ProxySettingsPanel.Controls.Add(this.AddressTextBox);
            resources.ApplyResources(this.ProxySettingsPanel, "ProxySettingsPanel");
            this.ProxySettingsPanel.Name = "ProxySettingsPanel";
            // 
            // AdressLabel
            // 
            resources.ApplyResources(this.AdressLabel, "AdressLabel");
            this.AdressLabel.Name = "AdressLabel";
            // 
            // ProxySettingsCloseButton
            // 
            resources.ApplyResources(this.ProxySettingsCloseButton, "ProxySettingsCloseButton");
            this.ProxySettingsCloseButton.Name = "ProxySettingsCloseButton";
            this.ProxySettingsCloseButton.UseVisualStyleBackColor = true;
            this.ProxySettingsCloseButton.Click += new System.EventHandler(this.ProxySettingsCloseButton_Click);
            // 
            // ProxySettingsApplyButton
            // 
            resources.ApplyResources(this.ProxySettingsApplyButton, "ProxySettingsApplyButton");
            this.ProxySettingsApplyButton.Name = "ProxySettingsApplyButton";
            this.ProxySettingsApplyButton.UseVisualStyleBackColor = true;
            this.ProxySettingsApplyButton.Click += new System.EventHandler(this.ProxySettingsApplyButton_Click);
            // 
            // PortTextBox
            // 
            resources.ApplyResources(this.PortTextBox, "PortTextBox");
            this.PortTextBox.Name = "PortTextBox";
            // 
            // PortLabel
            // 
            resources.ApplyResources(this.PortLabel, "PortLabel");
            this.PortLabel.Name = "PortLabel";
            // 
            // AddressTextBox
            // 
            resources.ApplyResources(this.AddressTextBox, "AddressTextBox");
            this.AddressTextBox.Name = "AddressTextBox";
            // 
            // openFileDialog
            // 
            this.openFileDialog.FileName = "openFileDialog";
            // 
            // FilePathTextBox
            // 
            resources.ApplyResources(this.FilePathTextBox, "FilePathTextBox");
            this.FilePathTextBox.Name = "FilePathTextBox";
            // 
            // OpenFileButton
            // 
            resources.ApplyResources(this.OpenFileButton, "OpenFileButton");
            this.OpenFileButton.Name = "OpenFileButton";
            this.OpenFileButton.UseVisualStyleBackColor = true;
            this.OpenFileButton.Click += new System.EventHandler(this.OpenFileButton_Click);
            // 
            // ParsingFileButton
            // 
            resources.ApplyResources(this.ParsingFileButton, "ParsingFileButton");
            this.ParsingFileButton.Name = "ParsingFileButton";
            this.ParsingFileButton.UseVisualStyleBackColor = true;
            this.ParsingFileButton.Click += new System.EventHandler(this.ParsingFileButton_Click);
            // 
            // tabControl
            // 
            this.tabControl.Controls.Add(this.tabPage1);
            this.tabControl.Controls.Add(this.tabPage2);
            this.tabControl.Controls.Add(this.tabPage3);
            resources.ApplyResources(this.tabControl, "tabControl");
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.ParseOutputTextBox);
            resources.ApplyResources(this.tabPage1, "tabPage1");
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // ParseOutputTextBox
            // 
            resources.ApplyResources(this.ParseOutputTextBox, "ParseOutputTextBox");
            this.ParseOutputTextBox.Name = "ParseOutputTextBox";
            this.ParseOutputTextBox.ReadOnly = true;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.LogInfoTextBox);
            resources.ApplyResources(this.tabPage2, "tabPage2");
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // LogInfoTextBox
            // 
            resources.ApplyResources(this.LogInfoTextBox, "LogInfoTextBox");
            this.LogInfoTextBox.Name = "LogInfoTextBox";
            this.LogInfoTextBox.ReadOnly = true;
            // 
            // tabPage3
            // 
            resources.ApplyResources(this.tabPage3, "tabPage3");
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.UseVisualStyleBackColor = true;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripStatusLabel1,
            this.toolStripProgressBar1});
            resources.ApplyResources(this.statusStrip1, "statusStrip1");
            this.statusStrip1.Name = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            this.toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            resources.ApplyResources(this.toolStripStatusLabel1, "toolStripStatusLabel1");
            // 
            // toolStripProgressBar1
            // 
            this.toolStripProgressBar1.Name = "toolStripProgressBar1";
            resources.ApplyResources(this.toolStripProgressBar1, "toolStripProgressBar1");
            // 
            // ParsingCancelButton
            // 
            resources.ApplyResources(this.ParsingCancelButton, "ParsingCancelButton");
            this.ParsingCancelButton.Name = "ParsingCancelButton";
            this.ParsingCancelButton.UseVisualStyleBackColor = true;
            this.ParsingCancelButton.Click += new System.EventHandler(this.ParsingCancelbutton_Click);
            // 
            // HiddifyConfigs
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.ParsingCancelButton);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.tabControl);
            this.Controls.Add(this.ParsingFileButton);
            this.Controls.Add(this.OpenFileButton);
            this.Controls.Add(this.FilePathTextBox);
            this.Controls.Add(this.ProxySettingsPanel);
            this.Controls.Add(this.toolStrip);
            this.Name = "HiddifyConfigs";
            this.Load += new System.EventHandler(this.HiddifyConfigs_Load);
            this.toolStrip.ResumeLayout(false);
            this.toolStrip.PerformLayout();
            this.ProxySettingsPanel.ResumeLayout(false);
            this.ProxySettingsPanel.PerformLayout();
            this.tabControl.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.tabPage2.ResumeLayout(false);
            this.tabPage2.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ToolStrip toolStrip;
        private System.Windows.Forms.ToolStripButton toolStripButton;
        private System.Windows.Forms.Panel ProxySettingsPanel;
        private System.Windows.Forms.TextBox PortTextBox;
        private System.Windows.Forms.Label PortLabel;
        private System.Windows.Forms.TextBox AddressTextBox;
        
        private System.Windows.Forms.Button ProxySettingsCloseButton;
        private System.Windows.Forms.Button ProxySettingsApplyButton;
        private System.Windows.Forms.Label AdressLabel;
        private System.Windows.Forms.OpenFileDialog openFileDialog;
        private System.Windows.Forms.TextBox FilePathTextBox;
        private System.Windows.Forms.Button OpenFileButton;
        private System.Windows.Forms.Button ParsingFileButton;
        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.TextBox ParseOutputTextBox;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.TextBox LogInfoTextBox;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private System.Windows.Forms.ToolStripProgressBar toolStripProgressBar1;
        private System.Windows.Forms.Button ParsingCancelButton;
    }
}

