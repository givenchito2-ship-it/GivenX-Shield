using System.Diagnostics;
using System.Security.Cryptography;
using GivenX.Shared;

namespace GivenX.UI;

public sealed class UnifiedScanForm : Form
{
    static readonly HashSet<string> InterestingExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".scr", ".msi", ".com", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta", ".lnk", ".jar", ".docm", ".xlsm", ".pptm" };
    readonly ThreatOrchestrator _orchestrator = new();
    readonly ListView _results = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, BackColor = Color.FromArgb(9, 16, 26), ForeColor = Color.White };
    readonly Label _status = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Padding = new(16, 0, 0, 0), ForeColor = Color.FromArgb(73, 200, 255) };
    readonly Label _elapsed = new() { Dock = DockStyle.Right, Width = 150, TextAlign = ContentAlignment.MiddleCenter, ForeColor = Color.FromArgb(160, 182, 210), Text = "00:00:00" };
    readonly ProgressBar _progress = new() { Dock = DockStyle.Bottom, Height = 10 };
    readonly Color _orange = Color.FromArgb(255, 116, 22);
    readonly System.Windows.Forms.Timer _clock = new() { Interval = 1000 };
    readonly Stopwatch _watch = new();
    readonly List<Button> _launchButtons = [];
    Button? _cancelButton;
    CancellationTokenSource? _scanCancellation;
    bool _scanActive;

    public UnifiedScanForm()
    {
        Text = "GivenX Shield | Análisis unificado"; Size = new(1220, 720); MinimumSize = new(1050, 650); StartPosition = FormStartPosition.CenterParent; BackColor = Color.FromArgb(7, 12, 20); ForeColor = Color.White; Font = new("Segoe UI", 10);
        _results.Columns.Add("Archivo", 340); _results.Columns.Add("Motor / veredicto", 220); _results.Columns.Add("Riesgo", 80); _results.Columns.Add("Detalle", 500);
        var tools = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 62, Padding = new(14, 12, 0, 0), BackColor = Color.FromArgb(14, 23, 36), WrapContents = false };
        var file = Button("ANALIZAR ARCHIVO", 140); file.Click += async (_, _) => await SelectFile(); tools.Controls.Add(file); _launchButtons.Add(file);
        var folder = Button("ANALIZAR CARPETA", 145); folder.Click += async (_, _) => await SelectFolder(); tools.Controls.Add(folder); _launchButtons.Add(folder);
        var pc = Button("ANÁLISIS COMPLETO PC", 170); pc.Click += async (_, _) => await ScanComputer(); tools.Controls.Add(pc); _launchButtons.Add(pc);
        _cancelButton = Button("CANCELAR", 90); _cancelButton.Enabled = false; _cancelButton.Click += (_, _) => CancelCurrent(); tools.Controls.Add(_cancelButton);
        var quarantine = Button("AISLAR", 100); quarantine.Click += async (_, _) => await QuarantineSelected(); tools.Controls.Add(quarantine);
        var allow = Button("PERMITIR HASH", 115); allow.Click += async (_, _) => await AllowSelected(); tools.Controls.Add(allow);
        var publisher = Button("CONFIAR EDITOR", 125); publisher.Click += (_, _) => AllowPublisherSelected(); tools.Controls.Add(publisher);
        var location = Button("UBICACIÓN", 105); location.Click += (_, _) => OpenSelectedLocation(); tools.Controls.Add(location);
        var footer = new Panel { Dock = DockStyle.Bottom, Height = 58, BackColor = Color.FromArgb(14, 23, 36) }; footer.Controls.Add(_status); footer.Controls.Add(_elapsed); footer.Controls.Add(_progress);
        Controls.Add(_results); Controls.Add(footer); Controls.Add(tools); footer.BringToFront(); tools.BringToFront();
        _status.Text = "Elige archivo, carpeta o PC completo. GivenX nunca subirá un archivo automáticamente.";
        _clock.Tick += (_, _) => _elapsed.Text = _watch.Elapsed.ToString("hh\\:mm\\:ss");
    }

    Button Button(string text, int width) => new() { Text = text, Width = width, Height = 34, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(25, 39, 58), ForeColor = Color.White, FlatAppearance = { BorderColor = _orange } };

    DateTimeOffset BeginScan(bool determinate = false)
    {
        if (_scanActive) throw new InvalidOperationException("Ya hay un análisis en curso.");
        _scanCancellation?.Dispose(); _scanCancellation = new(); _scanActive = true; _results.Items.Clear();
        foreach (var button in _launchButtons) button.Enabled = false; if (_cancelButton is not null) _cancelButton.Enabled = true;
        _watch.Restart(); _clock.Start(); SetProgress(determinate ? 1 : 0, determinate ? 1 : 0); return DateTimeOffset.Now;
    }

    void FinishScan(string status)
    {
        _watch.Stop(); _clock.Stop(); _scanActive = false; foreach (var button in _launchButtons) button.Enabled = true; if (_cancelButton is not null) _cancelButton.Enabled = false;
        _progress.Style = ProgressBarStyle.Continuous; _progress.Maximum = 100; _progress.Value = status == "COMPLETADO" ? 100 : 0;
    }

    void SetProgress(int value, int maximum)
    {
        if (maximum <= 0) { _progress.Style = ProgressBarStyle.Marquee; _progress.MarqueeAnimationSpeed = 24; return; }
        _progress.Style = ProgressBarStyle.Continuous; _progress.Maximum = Math.Max(1, maximum); _progress.Value = Math.Clamp(value, 0, _progress.Maximum);
    }

    async Task SelectFile()
    {
        using var dialog = new OpenFileDialog { Title = "Selecciona el archivo que quieres analizar", CheckFileExists = true };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        var started = BeginScan(); var finalStatus = "ERROR"; var details = ""; var findings = 0;
        try
        {
            await AntivirusProviderDetector.RefreshAsync(cancellationToken: _scanCancellation!.Token);
            _status.Text = "Analizando con motores locales y consultas por SHA-256. El archivo no se subirá.";
            var results = await _orchestrator.ScanAsync(dialog.FileName, _scanCancellation!.Token, includeCloud: true);
            AddEngineRows(dialog.FileName, results); var combined = ThreatOrchestrator.Combine(results); findings = IsFinding(combined.Verdict) ? 1 : 0;
            finalStatus = findings > 0 ? "REVISAR" : "COMPLETADO"; details = $"{combined.Verdict} · riesgo {combined.Score}/100"; _status.Text = $"Terminado: {details}. Revisa la evidencia de cada motor.";
        }
        catch (OperationCanceledException) { finalStatus = "CANCELADO"; details = "Cancelado por el usuario."; _status.Text = "Análisis cancelado."; }
        catch (Exception ex) { finalStatus = "ERROR"; details = ex.Message; _status.Text = "No se completó: " + ex.Message; }
        finally { FinishScan(finalStatus); ScanHistoryStore.Append(new(Guid.NewGuid().ToString("N"), started, DateTimeOffset.Now, "Archivo unificado", dialog.FileName, finalStatus, 1, findings, details)); }
    }

    async Task SelectFolder()
    {
        using var dialog = new FolderBrowserDialog { Description = "Se revisarán hasta 500 archivos ejecutables, scripts y documentos con macros.", UseDescriptionForTitle = true };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        var started = BeginScan(); var finalStatus = "ERROR"; var details = ""; var checkedFiles = 0; var findings = 0; var cloudChecks = 0;
        try
        {
            var ct = _scanCancellation!.Token; await AntivirusProviderDetector.RefreshAsync(cancellationToken: ct); _status.Text = "Preparando la lista de archivos…"; SetProgress(0, 0); var files = await Task.Run(() => EnumerateInterestingFiles(dialog.SelectedPath, 500, ct).ToList(), ct);
            if (files.Count == 0) { finalStatus = "COMPLETADO"; details = "No se encontraron archivos compatibles."; _status.Text = details; return; }
            SetProgress(0, files.Count);
            for (var index = 0; index < files.Count; index++)
            {
                ct.ThrowIfCancellationRequested(); var path = files[index]; _status.Text = $"Analizando {index + 1}/{files.Count}: {Path.GetFileName(path)}";
                IReadOnlyList<EngineResult> results = await _orchestrator.ScanAsync(path, ct, includeCloud: false); var combined = ThreatOrchestrator.Combine(results);
                if (IsFinding(combined.Verdict)) { results = await _orchestrator.ScanAsync(path, ct, includeCloud: true); combined = ThreatOrchestrator.Combine(results); cloudChecks++; }
                if (IsFinding(combined.Verdict)) findings++; AddSummaryRow(path, combined, results); checkedFiles++; SetProgress(index + 1, files.Count);
            }
            finalStatus = findings > 0 ? "REVISAR" : "COMPLETADO"; details = $"{checkedFiles} archivos; {findings} hallazgos; {cloudChecks} consultas por hash"; _status.Text = $"Carpeta terminada: {details}. No se subió ningún archivo.";
        }
        catch (OperationCanceledException) { finalStatus = "CANCELADO"; details = $"Cancelado tras {checkedFiles} archivos."; _status.Text = "Análisis cancelado."; }
        catch (Exception ex) { finalStatus = "ERROR"; details = ex.Message; _status.Text = "Análisis interrumpido: " + ex.Message; }
        finally { FinishScan(finalStatus); ScanHistoryStore.Append(new(Guid.NewGuid().ToString("N"), started, DateTimeOffset.Now, "Carpeta unificada", dialog.SelectedPath, finalStatus, checkedFiles, findings, details)); }
    }

    async Task ScanComputer()
    {
        var providers = await AntivirusProviderDetector.RefreshAsync(true); var primary = providers.Primary;
        var defenderActive = primary?.IsMicrosoftDefender == true && primary.Enabled && DefenderCommand.IsAvailable;
        var yaraActive = _orchestrator.Health.Any(x => x.Engine == "YARA" && x.Active);
        if (!defenderActive && !yaraActive)
        {
            MessageBox.Show(this, "GivenX no encontró un motor local automatizable: Defender no está activo y YARA no está instalado. Instala YARA desde ESTADO DE MOTORES o inicia el análisis completo desde tu antivirus principal.", "Sin motores locales", MessageBoxButtons.OK, MessageBoxIcon.Warning); return;
        }
        var providerText = primary?.Name ?? "no verificado";
        var antivirusPlan = defenderActive ? "Microsoft Defender examinará el PC completo dentro de GivenX." : $"{providerText} seguirá como antivirus principal, pero su edición de consumo no ofrece a GivenX un canal oficial para iniciar el análisis. Debes iniciar su examen desde el propio antivirus.";
        var yaraPlan = yaraActive ? "YARA revisará hasta 10.000 ejecutables, scripts y documentos con macros en zonas de mayor riesgo. Solo los sospechosos se consultarán por hash; ningún archivo se subirá." : "YARA no está instalado; este análisis utilizará únicamente Microsoft Defender.";
        var message = antivirusPlan + "\n\n" + yaraPlan + " Puede tardar horas.\n\n¿Continuar?";
        if (MessageBox.Show(this, message, "Análisis completo del PC", MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        var started = BeginScan(); var finalStatus = "ERROR"; var details = ""; var checkedFiles = 0; var findings = 0; var cloudChecks = 0; Task<DefenderScanResult>? defenderTask = null;
        try
        {
            var ct = _scanCancellation!.Token;
            if (defenderActive) defenderTask = DefenderCommand.RunScanAsync(2, ct);
            _status.Text = yaraActive ? (defenderActive ? "Defender completo activo · preparando las zonas YARA de mayor riesgo…" : $"{providerText} activo · preparando el análisis YARA…") : "Defender completo activo…";
            var files = yaraActive ? await Task.Run(() => CollectHighRiskFiles(10_000, ct), ct) : new List<string>(); SetProgress(0, Math.Max(1, files.Count));
            for (var index = 0; index < files.Count; index++)
            {
                ct.ThrowIfCancellationRequested(); var path = files[index]; _status.Text = $"{(defenderActive ? "Defender activo" : providerText + " activo")} · YARA {index + 1}/{files.Count}: {Path.GetFileName(path)}";
                IReadOnlyList<EngineResult> results = await _orchestrator.ScanAsync(path, ct, includeCloud: false, includeDefender: false); var combined = ThreatOrchestrator.Combine(results);
                if (IsFinding(combined.Verdict)) { results = await _orchestrator.ScanAsync(path, ct, includeCloud: true, includeDefender: defenderActive); combined = ThreatOrchestrator.Combine(results); cloudChecks++; }
                if (IsFinding(combined.Verdict)) { findings++; AddSummaryRow(path, combined, results); }
                checkedFiles++; SetProgress(index + 1, Math.Max(1, files.Count));
            }
            string antivirusResult; var antivirusFailed = false;
            if (defenderTask is not null)
            {
                _status.Text = yaraActive ? "YARA terminó. Esperando el resultado del análisis completo de Defender…" : "Esperando el resultado del análisis completo de Defender…"; SetProgress(0, 0);
                var defender = await defenderTask; AddDefenderRow(defender); if (defender.Status == "REVISAR") findings++;
                if (defender.Status == "ERROR") antivirusFailed = true;
                antivirusResult = "Defender: " + defender.Status;
            }
            else { AddProviderRow(providerText); antivirusResult = providerText + ": activo, análisis manual pendiente"; }
            finalStatus = antivirusFailed ? "ERROR" : findings > 0 ? "REVISAR" : "COMPLETADO";
            details = $"{antivirusResult}; YARA: {(yaraActive ? checkedFiles.ToString("N0") + " archivos de alto riesgo" : "no instalado")}; correlaciones cloud: {cloudChecks:N0}; hallazgos/acciones: {findings:N0}"; _status.Text = "Análisis de PC terminado · " + details;
        }
        catch (OperationCanceledException)
        {
            finalStatus = "CANCELADO"; details = $"Cancelado tras {checkedFiles:N0} archivos YARA."; _status.Text = "Cancelando YARA y Defender…"; if (defenderTask is not null) try { await defenderTask; } catch { } _status.Text = "Análisis completo cancelado.";
        }
        catch (Exception ex)
        {
            finalStatus = "ERROR"; details = ex.Message; _status.Text = "Análisis interrumpido: " + ex.Message; _scanCancellation?.Cancel(); if (defenderTask is not null) try { await defenderTask; } catch { }
        }
        finally { FinishScan(finalStatus); ScanHistoryStore.Append(new(Guid.NewGuid().ToString("N"), started, DateTimeOffset.Now, "PC completo antivirus + YARA", "Este equipo", finalStatus, checkedFiles, findings, details)); }
    }

    static List<string> CollectHighRiskFiles(int limit, CancellationToken cancellationToken)
    {
        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new[] { Path.Combine(user, "Downloads"), Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Path.GetTempPath() }.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots) foreach (var file in EnumerateInterestingFiles(root, limit - result.Count, cancellationToken)) { cancellationToken.ThrowIfCancellationRequested(); result.Add(file); if (result.Count >= limit) return result.ToList(); }
        return result.ToList();
    }

    static IEnumerable<string> EnumerateInterestingFiles(string root, int limit, CancellationToken cancellationToken = default)
    {
        if (limit <= 0) yield break; var stack = new Stack<string>(); stack.Push(root); var yielded = 0;
        while (stack.Count > 0 && yielded < limit)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = stack.Pop(); string[] directories, files; try { directories = Directory.GetDirectories(current); files = Directory.GetFiles(current); } catch { continue; }
            foreach (var directory in directories) { try { if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) == 0) stack.Push(directory); } catch { } }
            foreach (var file in files) { if (!InterestingExtensions.Contains(Path.GetExtension(file))) continue; long length; try { length = new FileInfo(file).Length; } catch { continue; } if (length > 512L * 1024 * 1024) continue; yield return file; if (++yielded >= limit) yield break; }
        }
    }

    void AddEngineRows(string path, IReadOnlyList<EngineResult> results)
    {
        foreach (var result in results) { var item = new ListViewItem(Path.GetFileName(path)); item.SubItems.Add($"{result.Engine}: {result.Verdict}"); item.SubItems.Add(result.Score.ToString()); item.SubItems.Add(result.Evidence); item.Tag = path; ColorRow(item, result.Verdict); _results.Items.Add(item); }
    }

    void AddSummaryRow(string path, (EngineVerdict Verdict, int Score, string Evidence) combined, IReadOnlyList<EngineResult> results)
    {
        var detail = string.Join(" | ", results.Select(x => $"{x.Engine}: {x.Verdict} ({x.Evidence})")); var item = new ListViewItem(path); item.SubItems.Add(combined.Verdict.ToString()); item.SubItems.Add(combined.Score.ToString()); item.SubItems.Add(detail); item.Tag = path; ColorRow(item, combined.Verdict); _results.Items.Add(item);
    }

    void AddDefenderRow(DefenderScanResult result)
    {
        var verdict = result.Status == "REVISAR" ? EngineVerdict.Suspicious : result.Status == "ERROR" ? EngineVerdict.Error : EngineVerdict.Clean; var item = new ListViewItem("Este equipo"); item.SubItems.Add("Microsoft Defender: " + result.Status); item.SubItems.Add(result.Status == "REVISAR" ? "60" : "0"); item.SubItems.Add(result.Details); ColorRow(item, verdict); _results.Items.Add(item);
    }

    void AddProviderRow(string provider)
    {
        var item = new ListViewItem("Este equipo"); item.SubItems.Add(provider + ": ACTIVO"); item.SubItems.Add("-"); item.SubItems.Add("GivenX confirmó el proveedor registrado. Inicia el análisis completo desde su propia interfaz; GivenX no fuerza una integración no documentada."); item.ForeColor = Color.FromArgb(73, 200, 255); _results.Items.Add(item);
    }

    static bool IsFinding(EngineVerdict verdict) => verdict is EngineVerdict.Suspicious or EngineVerdict.Malicious;
    static void ColorRow(ListViewItem item, EngineVerdict verdict) { item.ForeColor = verdict switch { EngineVerdict.Malicious => Color.FromArgb(255, 73, 91), EngineVerdict.Suspicious => Color.FromArgb(255, 190, 70), EngineVerdict.Clean => Color.FromArgb(66, 226, 151), _ => Color.FromArgb(180, 195, 215) }; }
    string? SelectedPath() => _results.SelectedItems.Count == 0 ? null : _results.SelectedItems[0].Tag as string;

    async Task QuarantineSelected()
    {
        var path = SelectedPath(); if (path is null || !File.Exists(path)) return; if (MessageBox.Show("El archivo se cifrará y se retirará de su ubicación. ¿Continuar?", "Aislar archivo", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try { await QuarantineStore.QuarantineAsync(path, "Aislamiento desde análisis unificado"); _status.Text = "Archivo aislado en cuarentena."; } catch (Exception ex) { MessageBox.Show(ex.Message, "No se pudo aislar", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    async Task AllowSelected()
    {
        var path = SelectedPath(); if (path is null || !File.Exists(path)) return; if (MessageBox.Show("Solo permite el archivo si conoces su origen. ¿Agregar su hash a la lista segura?", "Permitir archivo", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        await using var stream = File.OpenRead(path); var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant(); AllowListStore.Add(hash); _status.Text = "Hash agregado a la lista segura.";
    }

    void AllowPublisherSelected()
    {
        var path = SelectedPath(); if (path is null || !File.Exists(path)) return;
        var publisher = FileSignatureTrust.TrustedPublisher(path);
        if (publisher is null) { MessageBox.Show(this, "El archivo no tiene una firma digital válida. Solo puede permitirse su hash exacto.", "Editor no verificable", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        var message = $"Editor verificado: {publisher}\n\nConfiar en el editor hará que el radar ignore otros archivos firmados válidamente por el mismo editor. Úsalo solamente con empresas que reconozcas. ¿Continuar?";
        if (MessageBox.Show(this, message, "Confiar en editor", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        TrustedPublisherStore.Add(publisher); _status.Text = "Editor agregado a la lista segura: " + publisher;
    }

    void OpenSelectedLocation()
    {
        var path = SelectedPath(); if (path is null || !File.Exists(path)) return; try { var start = new ProcessStartInfo("explorer.exe") { UseShellExecute = true }; start.ArgumentList.Add("/select,"); start.ArgumentList.Add(path); Process.Start(start); } catch { }
    }

    void CancelCurrent() { if (!_scanActive || _scanCancellation is null) return; _status.Text = "Cancelando el análisis…"; if (_cancelButton is not null) _cancelButton.Enabled = false; _scanCancellation.Cancel(); }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (_scanActive) { if (MessageBox.Show(this, "Hay un análisis activo. ¿Quieres cancelarlo?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) CancelCurrent(); e.Cancel = true; return; } base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing) { if (disposing) { _clock.Dispose(); _scanCancellation?.Dispose(); } base.Dispose(disposing); }
}
