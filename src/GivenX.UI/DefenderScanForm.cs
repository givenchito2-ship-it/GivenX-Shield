using System.Diagnostics;
using GivenX.Shared;

namespace GivenX.UI;

public sealed class DefenderScanForm : Form
{
    readonly int _scanType;
    readonly string _scanName;
    readonly Label _state = new(), _elapsed = new(), _explanation = new();
    readonly TextBox _details = new();
    readonly ProgressBar _progress = new();
    readonly Button _cancel = new(), _close = new();
    readonly System.Windows.Forms.Timer _timer = new() { Interval = 1000 };
    readonly Stopwatch _watch = new();
    CancellationTokenSource? _cancellation;
    bool _running;

    public DefenderScanForm(bool fullScan)
    {
        _scanType = fullScan ? 2 : 1; _scanName = fullScan ? "Defender completo" : "Defender rápido";
        Text = $"GivenX Shield | {_scanName}"; Size = new(760, 500); MinimumSize = new(700, 440); StartPosition = FormStartPosition.CenterParent;
        BackColor = Color.FromArgb(7, 12, 20); ForeColor = Color.White; Font = new("Segoe UI", 10);
        BuildUi();
        Shown += async (_, _) => await StartScanAsync();
        _timer.Tick += (_, _) => _elapsed.Text = $"TIEMPO  {_watch.Elapsed:hh\\:mm\\:ss}";
    }

    void BuildUi()
    {
        var title = new Label { Text = _scanName.ToUpperInvariant(), Font = new("Segoe UI Semibold", 22), ForeColor = Color.FromArgb(255, 116, 22), AutoSize = true, Left = 28, Top = 24 };
        _state.Text = "PREPARANDO"; _state.Font = new("Segoe UI Semibold", 24); _state.ForeColor = Color.FromArgb(73, 200, 255); _state.AutoSize = true; _state.Left = 28; _state.Top = 82;
        _elapsed.Text = "TIEMPO  00:00:00"; _elapsed.ForeColor = Color.FromArgb(160, 182, 210); _elapsed.AutoSize = true; _elapsed.Left = 30; _elapsed.Top = 132;
        _explanation.Text = "GivenX inicia el motor oficial de Microsoft Defender sin abrir PowerShell. La barra indica actividad real; Defender no entrega un porcentaje exacto por este canal.";
        _explanation.ForeColor = Color.FromArgb(173, 192, 216); _explanation.Left = 30; _explanation.Top = 164; _explanation.Width = 680; _explanation.Height = 44;
        _progress.Left = 30; _progress.Top = 218; _progress.Width = 680; _progress.Height = 12; _progress.Style = ProgressBarStyle.Marquee; _progress.MarqueeAnimationSpeed = 28;
        _details.Left = 30; _details.Top = 250; _details.Width = 680; _details.Height = 120; _details.Multiline = true; _details.ReadOnly = true; _details.ScrollBars = ScrollBars.Vertical; _details.BackColor = Color.FromArgb(14, 23, 36); _details.ForeColor = Color.FromArgb(202, 216, 234); _details.BorderStyle = BorderStyle.FixedSingle;
        _cancel.Text = "CANCELAR"; Style(_cancel); _cancel.Left = 30; _cancel.Top = 392; _cancel.Width = 130; _cancel.Click += (_, _) => CancelScan();
        var security = new Button { Text = "SEGURIDAD DE WINDOWS", Left = 170, Top = 392, Width = 210 }; Style(security); security.Click += (_, _) => WindowsSecurityLauncher.Open(this);
        _close.Text = "CERRAR"; Style(_close); _close.Left = 580; _close.Top = 392; _close.Width = 130; _close.Enabled = false; _close.Click += (_, _) => Close();
        Controls.AddRange([title, _state, _elapsed, _explanation, _progress, _details, _cancel, security, _close]);
    }

    static void Style(Button button)
    {
        button.Height = 38; button.FlatStyle = FlatStyle.Flat; button.BackColor = Color.FromArgb(25, 39, 58); button.ForeColor = Color.White; button.FlatAppearance.BorderColor = Color.FromArgb(255, 116, 22);
    }

    async Task StartScanAsync()
    {
        if (_running) return;
        var started = DateTimeOffset.Now; _cancellation = new(); _running = true; _watch.Restart(); _timer.Start();
        _state.Text = "ANALIZANDO"; _state.ForeColor = Color.FromArgb(73, 200, 255); _details.Text = "Microsoft Defender está examinando el equipo. Puedes minimizar GivenX; el radar residente continúa activo.";
        var status = "ERROR"; var details = ""; var findings = 0;
        try
        {
            var result = await DefenderCommand.RunScanAsync(_scanType, _cancellation.Token);
            status = result.Status; details = result.Details; findings = result.Status == "REVISAR" ? 1 : 0; _details.Text = result.Details;
            _state.Text = result.Status; _state.ForeColor = result.Status == "COMPLETADO" ? Color.FromArgb(66, 226, 151) : result.Status == "REVISAR" ? Color.FromArgb(255, 190, 70) : Color.FromArgb(255, 73, 91);
        }
        catch (OperationCanceledException)
        {
            status = "CANCELADO"; details = "El usuario canceló el análisis y GivenX envió la orden de cancelación a Defender."; _details.Text = details; _state.Text = status; _state.ForeColor = Color.FromArgb(255, 190, 70);
        }
        catch (Exception ex)
        {
            status = "ERROR"; details = ex.Message; _details.Text = ex.Message; _state.Text = status; _state.ForeColor = Color.FromArgb(255, 73, 91);
        }
        finally
        {
            _watch.Stop(); _timer.Stop(); _running = false; _progress.Style = ProgressBarStyle.Continuous; _progress.Value = status == "COMPLETADO" ? 100 : 0; _cancel.Enabled = false; _close.Enabled = true;
            ScanHistoryStore.Append(new(Guid.NewGuid().ToString("N"), started, DateTimeOffset.Now, _scanName, "Este equipo", status, 0, findings, details));
        }
    }

    void CancelScan()
    {
        if (!_running || _cancellation is null) return;
        _state.Text = "CANCELANDO"; _details.Text = "Solicitando a Microsoft Defender que detenga el análisis activo…"; _cancel.Enabled = false; _cancellation.Cancel();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (_running)
        {
            if (MessageBox.Show(this, "El análisis sigue activo. ¿Quieres cancelarlo?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) CancelScan();
            e.Cancel = true; return;
        }
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _timer.Dispose(); _cancellation?.Dispose(); }
        base.Dispose(disposing);
    }
}
