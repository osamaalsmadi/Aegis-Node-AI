using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace EndpointSecurity.Setup
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new SetupWizard());
        }
    }

    public class SetupWizard : Form
    {
        private int step = 0;
        private Panel pnlContent;
        private Label lblTitle;
        private Label lblDesc;
        private Button btnNext, btnBack, btnCancel;
        private TextBox txtPath;
        private ProgressBar pbProgress;
        private string installPath = @"C:\Program Files\EndpointSecurityPlatform";
        private bool isUpgrade = false;

        public SetupWizard()
        {
            Text = "Endpoint Security Platform - Setup";
            Size = new Size(550, 400);
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;

            CheckUpgrade();

            pnlContent = new Panel { Dock = DockStyle.Top, Height = 300, BackColor = Color.White };
            lblTitle = new Label { Font = new Font("Segoe UI", 16, FontStyle.Bold), Location = new Point(20, 20), AutoSize = true };
            lblDesc = new Label { Font = new Font("Segoe UI", 10), Location = new Point(20, 60), Size = new Size(500, 200) };
            txtPath = new TextBox { Location = new Point(20, 100), Width = 400, Visible = false };
            pbProgress = new ProgressBar { Location = new Point(20, 100), Width = 480, Height = 25, Visible = false };

            pnlContent.Controls.Add(lblTitle);
            pnlContent.Controls.Add(lblDesc);
            pnlContent.Controls.Add(txtPath);
            pnlContent.Controls.Add(pbProgress);

            Panel pnlBottom = new Panel { Dock = DockStyle.Bottom, Height = 60, BackColor = SystemColors.Control };
            btnBack = new Button { Text = "< Back", Location = new Point(250, 15), Size = new Size(80, 30) };
            btnNext = new Button { Text = "Next >", Location = new Point(340, 15), Size = new Size(80, 30) };
            btnCancel = new Button { Text = "Cancel", Location = new Point(440, 15), Size = new Size(80, 30) };

            btnBack.Click += (s, e) => { step--; UpdateUI(); };
            btnNext.Click += (s, e) => { step++; UpdateUI(); };
            btnCancel.Click += (s, e) => Application.Exit();

            pnlBottom.Controls.Add(btnBack);
            pnlBottom.Controls.Add(btnNext);
            pnlBottom.Controls.Add(btnCancel);

            Controls.Add(pnlContent);
            Controls.Add(pnlBottom);

            UpdateUI();
        }

        private void CheckUpgrade()
        {
            using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EndpointSecurityPlatform"))
            {
                if (key != null)
                {
                    isUpgrade = true;
                    var path = key.GetValue("InstallLocation") as string;
                    if (!string.IsNullOrEmpty(path)) installPath = path;
                }
            }
        }

        private async void UpdateUI()
        {
            btnBack.Enabled = step > 0 && step < 3;
            btnNext.Enabled = step < 3;
            txtPath.Visible = step == 2;
            pbProgress.Visible = step == 3;
            lblDesc.Visible = step != 3;

            if (step == 0)
            {
                lblTitle.Text = isUpgrade ? "Upgrade Endpoint Security Platform" : "Welcome to Setup";
                lblDesc.Text = isUpgrade ? "An existing installation was found.\nClick Next to upgrade and preserve your data." : "This wizard will guide you through the installation.\n\nClick Next to continue.";
            }
            else if (step == 1)
            {
                lblTitle.Text = "License Agreement";
                lblDesc.Text = "By installing this software, you agree to the usage terms.\nThis software is strictly for authorized security operations.\n\nClick Next if you accept the terms.";
            }
            else if (step == 2)
            {
                lblTitle.Text = "Select Installation Folder";
                lblDesc.Text = "Setup will install the platform in the following folder:";
                txtPath.Text = installPath;
                if (isUpgrade) { step++; UpdateUI(); return; }
            }
            else if (step == 3)
            {
                lblTitle.Text = "Installing...";
                btnBack.Enabled = false;
                btnNext.Enabled = false;
                btnCancel.Enabled = false;
                installPath = string.IsNullOrWhiteSpace(txtPath.Text) ? @"C:\Program Files\EndpointSecurityPlatform" : txtPath.Text; if (!Path.IsPathRooted(installPath)) installPath = @"C:\Program Files\EndpointSecurityPlatform";
                await InstallAsync();
            }
            else if (step == 4)
            {
                lblTitle.Text = "Installation Complete";
                lblDesc.Visible = true;
                lblDesc.Text = "The platform has been successfully installed.\nClick Finish to exit and launch the Dashboard.";
                btnNext.Text = "Finish";
                btnNext.Enabled = true;
                btnNext.Click -= (s, e) => { step++; UpdateUI(); };
                btnNext.Click += (s, e) => {
                    Process.Start(new ProcessStartInfo("http://localhost:5235") { UseShellExecute = true });
                    Application.Exit();
                };
            }
        }

        private async Task InstallAsync()
        {
            try
            {
                pbProgress.Style = ProgressBarStyle.Marquee;
                await Task.Run(() =>
                {
                    if (!Directory.Exists(installPath)) Directory.CreateDirectory(installPath);
                    
                    using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("EndpointSecurity.Setup.payload.zip"))
                    {
                        if (stream == null) throw new Exception("Payload not found! Compile error.");
                        using (ZipArchive archive = new ZipArchive(stream))
                        {
                            foreach (ZipArchiveEntry entry in archive.Entries)
                            {
                                string destPath = Path.GetFullPath(Path.Combine(installPath, entry.FullName));
                                if (entry.FullName.EndsWith("/") || entry.FullName.EndsWith("\\"))
                                {
                                    Directory.CreateDirectory(destPath);
                                }
                                else
                                {
                                    Directory.CreateDirectory(Path.GetDirectoryName(destPath));
                                    entry.ExtractToFile(destPath, true);
                                }
                            }
                        }
                    }

                    string installScript = Path.Combine(installPath, "Install.ps1");
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-ExecutionPolicy Bypass -WindowStyle Hidden -File \"{installScript}\" -InstallDir \"{installPath}\"",
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using (Process p = Process.Start(psi)) { p.WaitForExit(); }

                    using (var key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\EndpointSecurityPlatform"))
                    {
                        key.SetValue("DisplayName", "Endpoint Security Platform");
                        key.SetValue("UninstallString", $"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Start-Process powershell '-ExecutionPolicy Bypass -WindowStyle Hidden -File \\\"{Path.Combine(installPath, "Uninstall.ps1")}\\\"' -Verb RunAs\"");
                        key.SetValue("InstallLocation", installPath);
                        key.SetValue("Publisher", "Endpoint Security");
                    }
                });
                step++;
                UpdateUI();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Installation failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }
    }
}

