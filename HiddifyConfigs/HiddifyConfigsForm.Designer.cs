namespace HiddifyConfigs
{
    partial class HiddifyConfigs
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();
            base.Dispose(disposing);
        }

        #region Windows 窗体设计器生成的代码

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(HiddifyConfigs));
            this.toolStrip = new System.Windows.Forms.ToolStrip();
            this.ToolStripSettingsButton = new System.Windows.Forms.ToolStripButton();
            this.ClearCacheToolStripButton = new System.Windows.Forms.ToolStripButton();
            this.DoTestToolStripButton = new System.Windows.Forms.ToolStripButton();
            this.flowLayoutPanel1 = new System.Windows.Forms.FlowLayoutPanel();
            this.FilePathTextBox = new System.Windows.Forms.TextBox();
            this.OpenFileButton = new System.Windows.Forms.Button();
            this.ParsingFileButton = new System.Windows.Forms.Button();
            this.ParsingCancelButton = new System.Windows.Forms.Button();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.LogInfoTabPage = new System.Windows.Forms.TabPage();
            this.LogInfoTextBox = new System.Windows.Forms.TextBox();
            this.ParseOutTabPage = new System.Windows.Forms.TabPage();
            this.ParseOutPutTextBox = new System.Windows.Forms.TextBox();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.toolStripProgressBar1 = new System.Windows.Forms.ToolStripProgressBar();
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.toolStrip.SuspendLayout();
            this.flowLayoutPanel1.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.LogInfoTabPage.SuspendLayout();
            this.ParseOutTabPage.SuspendLayout();
            this.statusStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // toolStrip
            // 
            this.toolStrip.GripStyle = System.Windows.Forms.ToolStripGripStyle.Hidden;
            this.toolStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.ToolStripSettingsButton,
            this.ClearCacheToolStripButton,
            this.DoTestToolStripButton});
            resources.ApplyResources(this.toolStrip, "toolStrip");
            this.toolStrip.Name = "toolStrip";
            // 
            // ToolStripSettingsButton
            // 
            this.ToolStripSettingsButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.ToolStripSettingsButton.Name = "ToolStripSettingsButton";
            resources.ApplyResources(this.ToolStripSettingsButton, "ToolStripSettingsButton");
            this.ToolStripSettingsButton.Click += new System.EventHandler(this.ToolStripSettingsButton_Click);
            // 
            // ClearCacheToolStripButton
            // 
            this.ClearCacheToolStripButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.ClearCacheToolStripButton.Name = "ClearCacheToolStripButton";
            resources.ApplyResources(this.ClearCacheToolStripButton, "ClearCacheToolStripButton");
            this.ClearCacheToolStripButton.Click += new System.EventHandler(this.ClearCacheToolStripButton_Click);
            // 
            // DoTestToolStripButton
            // 
            this.DoTestToolStripButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.DoTestToolStripButton.Name = "DoTestToolStripButton";
            resources.ApplyResources(this.DoTestToolStripButton, "DoTestToolStripButton");
            this.DoTestToolStripButton.Click += new System.EventHandler(this.DoTestToolStripButton_Click);
            // 
            // flowLayoutPanel1
            // 
            this.flowLayoutPanel1.Controls.Add(this.FilePathTextBox);
            this.flowLayoutPanel1.Controls.Add(this.OpenFileButton);
            this.flowLayoutPanel1.Controls.Add(this.ParsingFileButton);
            this.flowLayoutPanel1.Controls.Add(this.ParsingCancelButton);
            resources.ApplyResources(this.flowLayoutPanel1, "flowLayoutPanel1");
            this.flowLayoutPanel1.Name = "flowLayoutPanel1";
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
            // ParsingCancelButton
            // 
            resources.ApplyResources(this.ParsingCancelButton, "ParsingCancelButton");
            this.ParsingCancelButton.Name = "ParsingCancelButton";
            this.ParsingCancelButton.UseVisualStyleBackColor = true;
            this.ParsingCancelButton.Click += new System.EventHandler(this.ParsingCancelButton_Click);
            // 
            // tabControl
            // 
            this.tabControl.Controls.Add(this.LogInfoTabPage);
            this.tabControl.Controls.Add(this.ParseOutTabPage);
            this.tabControl.Controls.Add(this.tabPage3);
            resources.ApplyResources(this.tabControl, "tabControl");
            this.tabControl.Name = "tabControl";
            this.tabControl.SelectedIndex = 0;
            // 
            // LogInfoTabPage
            // 
            this.LogInfoTabPage.Controls.Add(this.LogInfoTextBox);
            resources.ApplyResources(this.LogInfoTabPage, "LogInfoTabPage");
            this.LogInfoTabPage.Name = "LogInfoTabPage";
            // 
            // LogInfoTextBox
            // 
            resources.ApplyResources(this.LogInfoTextBox, "LogInfoTextBox");
            this.LogInfoTextBox.Name = "LogInfoTextBox";
            this.LogInfoTextBox.ReadOnly = true;
            // 
            // ParseOutTabPage
            // 
            this.ParseOutTabPage.Controls.Add(this.ParseOutPutTextBox);
            resources.ApplyResources(this.ParseOutTabPage, "ParseOutTabPage");
            this.ParseOutTabPage.Name = "ParseOutTabPage";
            // 
            // ParseOutPutTextBox
            // 
            resources.ApplyResources(this.ParseOutPutTextBox, "ParseOutPutTextBox");
            this.ParseOutPutTextBox.Name = "ParseOutPutTextBox";
            this.ParseOutPutTextBox.ReadOnly = true;
            // 
            // tabPage3
            // 
            resources.ApplyResources(this.tabPage3, "tabPage3");
            this.tabPage3.Name = "tabPage3";
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
            this.toolStripStatusLabel1.Spring = true;
            // 
            // toolStripProgressBar1
            // 
            this.toolStripProgressBar1.Name = "toolStripProgressBar1";
            resources.ApplyResources(this.toolStripProgressBar1, "toolStripProgressBar1");
            // 
            // HiddifyConfigs
            // 
            resources.ApplyResources(this, "$this");
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.tabControl);
            this.Controls.Add(this.flowLayoutPanel1);
            this.Controls.Add(this.toolStrip);
            this.Controls.Add(this.statusStrip1);
            this.Name = "HiddifyConfigs";
            this.ShowIcon = false;
            this.Load += new System.EventHandler(this.HiddifyConfigs_Load);
            this.toolStrip.ResumeLayout(false);
            this.toolStrip.PerformLayout();
            this.flowLayoutPanel1.ResumeLayout(false);
            this.flowLayoutPanel1.PerformLayout();
            this.tabControl.ResumeLayout(false);
            this.LogInfoTabPage.ResumeLayout(false);
            this.LogInfoTabPage.PerformLayout();
            this.ParseOutTabPage.ResumeLayout(false);
            this.ParseOutTabPage.PerformLayout();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ToolStrip toolStrip;
        private System.Windows.Forms.ToolStripButton ToolStripSettingsButton;
        private System.Windows.Forms.ToolStripButton ClearCacheToolStripButton;
        private System.Windows.Forms.ToolStripButton DoTestToolStripButton;
        private System.Windows.Forms.FlowLayoutPanel flowLayoutPanel1;
        private System.Windows.Forms.TextBox FilePathTextBox;
        private System.Windows.Forms.Button OpenFileButton;
        private System.Windows.Forms.Button ParsingFileButton;
        private System.Windows.Forms.Button ParsingCancelButton;
        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage LogInfoTabPage;
        private System.Windows.Forms.TabPage ParseOutTabPage;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.TextBox LogInfoTextBox;
        private System.Windows.Forms.TextBox ParseOutPutTextBox;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private System.Windows.Forms.ToolStripProgressBar toolStripProgressBar1;
        private System.Windows.Forms.OpenFileDialog openFileDialog;
    }
}