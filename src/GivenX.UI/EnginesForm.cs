using System.Diagnostics;
using GivenX.Shared;

namespace GivenX.UI;

public sealed class EnginesForm : Form
{
    readonly FlowLayoutPanel _rows = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new(20) };
    readonly System.Windows.Forms.Timer _timer = new() { Interval = 4000 };
    readonly Color _orange = Color.FromArgb(255, 116, 22);

    public EnginesForm()
    {
        Text = "GivenX Shield | Estado de motores"; Size = new(760, 650); StartPosition = FormStartPosition.CenterParent; BackColor = Color.FromArgb(7, 12, 20); ForeColor = Color.White; Font = new("Segoe UI", 10);
        var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 62, Padding = new(18, 12, 0, 0), BackColor = Color.FromArgb(14, 23, 36) };
        var install = Button("INSTALAR / REPARAR MOTORES", 240); install.Click += (_, _) => InstallEngines(); bar.Controls.Add(install);
        var refresh = Button("ACTUALIZAR", 130); refresh.Click += (_, _) => RefreshRows(); bar.Controls.Add(refresh);
        var test = Button("PRUEBA SEGURA YARA", 170); test.Click += async (_, _) => await SafeYaraTest(); bar.Controls.Add(test);
        Controls.Add(_rows); Controls.Add(bar);
        Load += (_, _) => RefreshRows();
        _timer.Tick += (_, _) => RefreshRows(); _timer.Start();
    }

    Button Button(string text, int width) => new() { Text = text, Width = width, Height = 34, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(25, 39, 58), ForeColor = Color.White, FlatAppearance = { BorderColor = _orange } };

    void InstallEngines()
    {
        var launcher = Path.Combine(AppContext.BaseDirectory, "engine-setup.cmd");
        if (!File.Exists(launcher)) { MessageBox.Show("No se encontró el instalador de motores. Reinstala GivenX Shield 1.6.2-R9.", "GivenX Shield", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
        if (MessageBox.Show("Se abrirá un instalador como administrador. Descargará Sysmon desde Microsoft y YARA desde el repositorio oficial de VirusTotal. ¿Continuar?", "Motores oficiales", MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        try
        {
            Process.Start(new ProcessStartInfo(launcher) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory });
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "No se pudo iniciar", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    void RefreshRows()
    {
        _rows.SuspendLayout(); _rows.Controls.Clear(); var state = StateStore.ReadState();
        foreach (var engine in state.Engines)
        {
            var row = new Panel { Width = 675, Height = 76, BackColor = Color.FromArgb(14, 23, 36), Margin = new(4) };
            row.Controls.Add(new Label { Text = engine.Engine, Font = new("Segoe UI Semibold", 12), ForeColor = Color.White, Left = 18, Top = 13, AutoSize = true });
            row.Controls.Add(new Label { Text = engine.Status, ForeColor = engine.Active ? Color.FromArgb(66, 226, 151) : Color.FromArgb(255, 190, 70), Left = 470, Top = 16, AutoSize = true });
            var explanation = engine.Engine == "Antivirus principal" ? (engine.Active ? "Protección principal registrada en Windows Security Center." : "GivenX no afirmará protección completa sin un antivirus activo.") : engine.Active ? "La capa está disponible para el radar." : "GivenX no contará esta capa como protección activa.";
            row.Controls.Add(new Label { Text = explanation, ForeColor = Color.FromArgb(150, 170, 195), Left = 18, Top = 43, AutoSize = true });
            _rows.Controls.Add(row);
        }
        _rows.ResumeLayout();
    }

    async Task SafeYaraTest()
    {
        var yara = Path.Combine(AppContext.BaseDirectory, "engines", "yara", "yara64.exe"); var rules = Path.Combine(AppContext.BaseDirectory, "rules", "givenx-index.yar");
        if (!File.Exists(yara) || !File.Exists(rules)) { MessageBox.Show("YARA todavía no está instalado. Usa INSTALAR / REPARAR MOTORES.", "Prueba segura", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        var sample = Path.Combine(Path.GetTempPath(), "GivenX-Safe-SelfTest-" + Guid.NewGuid().ToString("N") + ".txt");
        try
        {
            await File.WriteAllTextAsync(sample, "GIVENX_SAFE_SELF_TEST_1_6");
            var start = new ProcessStartInfo(yara) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add("-w"); start.ArgumentList.Add(rules); start.ArgumentList.Add(sample);
            using var process = Process.Start(start); if (process is null) throw new InvalidOperationException("YARA no pudo iniciarse.");
            var output = await process.StandardOutput.ReadToEndAsync(); var error = await process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync();
            if (process.ExitCode == 0 && output.Contains("GivenX_Safe_SelfTest", StringComparison.OrdinalIgnoreCase)) MessageBox.Show("Prueba superada: YARA detectó correctamente el marcador inofensivo.", "GivenX Shield", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else MessageBox.Show($"La prueba no se detectó. Código {process.ExitCode}.\n{error}", "Revisar YARA", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Prueba no completada", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { try { File.Delete(sample); } catch { } }
    }

    protected override void Dispose(bool disposing) { if (disposing) _timer.Dispose(); base.Dispose(disposing); }
}
