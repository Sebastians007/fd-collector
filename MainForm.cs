using System;
using System.Diagnostics;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace FieldDeskCollector;

public class MainForm : Form
{
    private readonly Button _runBtn;
    private readonly Button _openReportBtn;
    private readonly Button _openFolderBtn;
    private readonly TextBox _log;
    private string? _lastReportPath;

    public MainForm()
    {
        Text = "FieldDesk Collector";
        Width = 780;
        Height = 580;
        MinimumSize = new Size(620, 460);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.White;
        Font = new Font("Segoe UI", 9F);

        // ----- Header band -----
        var header = new Panel { Dock = DockStyle.Top, Height = 66, BackColor = Color.FromArgb(28, 40, 54) };
        var title = new Label
        {
            Text = "FieldDesk Collector",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 15F, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(16, 11)
        };
        var subtitle = new Label
        {
            Text = "Read-only local posture snapshot. This computer only. Nothing is changed or installed.",
            ForeColor = Color.FromArgb(170, 185, 200),
            AutoSize = true,
            Location = new Point(18, 40)
        };
        header.Controls.Add(title);
        header.Controls.Add(subtitle);

        // ----- Buttons -----
        _runBtn = new Button
        {
            Text = "Run Collection",
            Width = 160,
            Height = 40,
            Location = new Point(16, 82),
            BackColor = Color.FromArgb(0, 120, 170),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI Semibold", 10F)
        };
        _runBtn.FlatAppearance.BorderSize = 0;
        _runBtn.Click += async (s, e) => await RunAsync();

        _openReportBtn = new Button
        {
            Text = "Open Report",
            Width = 130,
            Height = 40,
            Location = new Point(186, 82),
            Enabled = false,
            FlatStyle = FlatStyle.System
        };
        _openReportBtn.Click += (s, e) => OpenPath(_lastReportPath);

        _openFolderBtn = new Button
        {
            Text = "Open Folder",
            Width = 130,
            Height = 40,
            Location = new Point(326, 82),
            Enabled = false,
            FlatStyle = FlatStyle.System
        };
        _openFolderBtn.Click += (s, e) => ShowInFolder(_lastReportPath);

        // ----- Log area -----
        _log = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(16, 134),
            Width = 740,
            Height = 400,
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom,
            BackColor = Color.FromArgb(248, 249, 250),
            ForeColor = Color.FromArgb(30, 34, 40),
            Font = new Font("Consolas", 9F),
            BorderStyle = BorderStyle.FixedSingle
        };

        Controls.Add(_log);
        Controls.Add(_openFolderBtn);
        Controls.Add(_openReportBtn);
        Controls.Add(_runBtn);
        Controls.Add(header);

        Log("Ready.");
        Log("Click Run Collection to read this computer and write a report.");
        Log("The report is a Markdown (.md) text file saved next to this app.");
        Log("");
    }

    private void Log(string msg)
    {
        if (_log.InvokeRequired)
        {
            _log.Invoke((MethodInvoker)(() => Log(msg)));
            return;
        }
        _log.AppendText(msg + Environment.NewLine);
    }

    private async Task RunAsync()
    {
        _runBtn.Enabled = false;
        _openReportBtn.Enabled = false;
        _openFolderBtn.Enabled = false;
        Log("Starting collection...");

        try
        {
            string path = await Task.Run(() => Collector.Run(Log));
            _lastReportPath = path;
            Log("");
            Log("Done. Report written to:");
            Log("  " + path);
            _openReportBtn.Enabled = true;
            _openFolderBtn.Enabled = true;
        }
        catch (Exception ex)
        {
            Log("");
            Log("ERROR: " + ex.Message);
        }
        finally
        {
            _runBtn.Enabled = true;
        }
    }

    private void OpenPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Log("Could not open report: " + ex.Message);
        }
    }

    private void ShowInFolder(string? path)
    {
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Log("Could not open folder: " + ex.Message);
        }
    }
}
