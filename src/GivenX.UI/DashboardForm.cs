using GivenX.Shared;

namespace GivenX.UI;

public sealed class DashboardForm : Form
{
    readonly Color Bg = Color.FromArgb(7, 12, 20), PanelBg = Color.FromArgb(14, 23, 36), Orange = Color.FromArgb(255, 116, 22), Cyan = Color.FromArgb(73, 200, 255), Green = Color.FromArgb(66, 226, 151), Red = Color.FromArgb(255, 73, 91);
    readonly Label _status = new(), _risk = new(), _stats = new();
    readonly FlowLayoutPanel _events = new();
    readonly System.Windows.Forms.Timer _timer = new() { Interval = 2000 };
    readonly NotifyIcon _tray = new();
    readonly HashSet<string> _notified = new(StringComparer.OrdinalIgnoreCase);
    readonly DateTimeOffset _notificationSince = DateTimeOffset.Now;
    readonly ToolTip _tips = new();
    readonly bool _startHidden;
    bool _allowExit;

    public DashboardForm(bool startHidden = false)
    {
        _startHidden = startHidden;
        Text = "GivenX Shield Beta Unificada 1.6.2-R9 HF7"; BackColor = Bg; ForeColor = Color.White; Font = new("Segoe UI", 10); MinimumSize = new(1000, 760); Size = new(1180, 820); StartPosition = FormStartPosition.CenterScreen;
        if (_startHidden) { WindowState = FormWindowState.Minimized; ShowInTaskbar = false; Opacity = 0; }
        BuildUi();
        _tray.Text = "GivenX Shield"; _tray.Icon = SystemIcons.Shield; _tray.Visible = true; _tray.DoubleClick += (_, _) => RestoreWindow();
        _tray.BalloonTipClicked += (_, _) => RestoreWindow();
        _tray.ContextMenuStrip = new ContextMenuStrip(); _tray.ContextMenuStrip.Items.Add("Abrir GivenX Shield", null, (_, _) => RestoreWindow()); _tray.ContextMenuStrip.Items.Add("Conexiones y respuesta",null,(_,_)=>new ConnectionsForm().ShowDialog(this)); _tray.ContextMenuStrip.Items.Add("Historial y listas", null, (_, _) => new HistoryAndTrustForm().ShowDialog(this)); _tray.ContextMenuStrip.Items.Add("Salir del panel", null, (_, _) => ExitPanel());
        _timer.Tick += (_, _) => RefreshState(); _timer.Start(); RefreshState();
        Resize += (_, _) => { if (WindowState == FormWindowState.Minimized) { Hide(); _tray.ShowBalloonTip(2000, "GivenX Shield", "El monitor continúa protegiendo en segundo plano.", ToolTipIcon.Info); } };
        Shown += (_, _) => { if (_startHidden) { Hide(); Opacity = 1; ShowInTaskbar = true; } };
    }

    void BuildUi()
    {
        var side = new Panel { Dock = DockStyle.Left, Width = 220, BackColor = PanelBg, Padding = new(22) };
        side.Controls.Add(new Label { Text = "GIVENX\nSHIELD", Font = new("Segoe UI Semibold", 24), ForeColor = Orange, AutoSize = true, Top = 28, Left = 24 });
        side.Controls.Add(new Label { Text = "PROTECCIÓN RESIDENTE", ForeColor = Cyan, AutoSize = true, Top = 112, Left = 24 });
        var unified = Button("ANÁLISIS UNIFICADO", 178); unified.Top = 180; unified.Left = 20; unified.Click += (_, _) => new UnifiedScanForm().ShowDialog(this); side.Controls.Add(unified);
        var quick = Button("ANTIVIRUS RÁPIDO", 178); quick.Top = 230; quick.Left = 20; quick.Click += async (_, _) => await OpenPrimaryScan(false); side.Controls.Add(quick);
        var full = Button("ANTIVIRUS COMPLETO", 178); full.Top = 280; full.Left = 20; full.Click += async (_, _) => await OpenPrimaryScan(true); side.Controls.Add(full);
        var security = Button("SEGURIDAD WINDOWS", 178); security.Top = 330; security.Left = 20; security.Click += (_, _) => WindowsSecurityLauncher.Open(this); side.Controls.Add(security);
        var settings = Button("CLAVES Y MOTORES", 178); settings.Top = 380; settings.Left = 20; settings.Click += (_, _) => new SettingsForm().ShowDialog(this); side.Controls.Add(settings);
        var quarantine = Button("CUARENTENA", 178); quarantine.Top = 430; quarantine.Left = 20; quarantine.Click += (_, _) => new QuarantineForm().ShowDialog(this); side.Controls.Add(quarantine);
        var engines = Button("ESTADO DE MOTORES", 178); engines.Top = 480; engines.Left = 20; engines.Click += (_, _) => new EnginesForm().ShowDialog(this); side.Controls.Add(engines);
        var response = Button("CONEXIONES Y RESPUESTA",178);response.Top=530;response.Left=20;response.Click+=(_,_)=>new ConnectionsForm().ShowDialog(this);side.Controls.Add(response);
        var history = Button("HISTORIAL Y LISTAS", 178); history.Top = 580; history.Left = 20; history.Click += (_, _) => new HistoryAndTrustForm().ShowDialog(this); side.Controls.Add(history);
        Controls.Add(side);

        var header = new Panel { Dock = DockStyle.Top, Height = 84, BackColor = Bg };
        header.Controls.Add(new Label { Text = "CENTRO DE SEGURIDAD", Font = new("Segoe UI Semibold", 22), AutoSize = true, Left = 28, Top = 20 }); Controls.Add(header);
        var body = new Panel { Dock = DockStyle.Fill, Padding = new(28), AutoScroll = true }; Controls.Add(body); body.BringToFront();
        var cards = new TableLayoutPanel { Dock = DockStyle.Top, Height = 170, ColumnCount = 3, RowCount = 1 }; cards.ColumnStyles.Add(new(SizeType.Percent, 38)); cards.ColumnStyles.Add(new(SizeType.Percent, 31)); cards.ColumnStyles.Add(new(SizeType.Percent, 31));
        cards.Controls.Add(Card("ESTADO GENERAL", _status), 0, 0); cards.Controls.Add(Card("MAYOR ALERTA ACTIVA", _risk), 1, 0); cards.Controls.Add(Card("ACTIVIDAD", _stats), 2, 0); body.Controls.Add(cards);
        _stats.Font = new("Segoe UI Semibold", 16);
        var heading = new Label { Text = "EVENTOS RECIENTES", Dock = DockStyle.Top, Height = 54, Padding = new(4, 22, 0, 0), Font = new("Segoe UI Semibold", 13), ForeColor = Cyan }; body.Controls.Add(heading); heading.BringToFront();
        _events.Dock = DockStyle.Fill; _events.FlowDirection = FlowDirection.TopDown; _events.WrapContents = false; _events.AutoScroll = true; _events.Padding = new(0, 8, 0, 0); body.Controls.Add(_events); _events.BringToFront();
    }

    Panel Card(string title, Label value)
    {
        var p = new Panel { Dock = DockStyle.Fill, BackColor = PanelBg, Margin = new(6), Padding = new(20) };
        p.Controls.Add(new Label { Text = title, ForeColor = Color.FromArgb(142, 163, 190), AutoSize = true, Top = 22, Left = 22 });
        value.Font = new("Segoe UI Semibold", 25); value.AutoSize = true; value.Top = 65; value.Left = 22; p.Controls.Add(value); return p;
    }

    Button Button(string text, int width) => new() { Text = text, Width = width, Height = 38, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(25, 39, 58), ForeColor = Color.White, FlatAppearance = { BorderColor = Orange } };

    void RefreshState()
    {
        var state = StateStore.ReadState();
        var online = state.AgentOnline && state.UpdatedAt > DateTimeOffset.Now.AddSeconds(-12);

        // R9 HF2 can clean known-benign legacy events even when the resident agent is still
        // an older installed build. This is especially useful while testing the portable UI.
        var autoResolvedFingerprints = state.RecentEvents
            .Where(BuildArtifactTrustStore.IsAutomaticallyResolvedEvent)
            .Select(x => x.Fingerprint)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (autoResolvedFingerprints.Count > 0) ResolvedEventStore.AddRange(autoResolvedFingerprints);

        var effectiveEvents = state.RecentEvents
            .Where(x => !autoResolvedFingerprints.Contains(x.Fingerprint))
            .OrderByDescending(x => x.Time)
            .ToList();
        var activeEvents = effectiveEvents.Where(x => x.Time > DateTimeOffset.Now.AddHours(-24)).ToList();
        var effectiveRisk = activeEvents.Select(x => x.Score).DefaultIfEmpty(0).Max();
        var effectiveAlerts = activeEvents.Count(x => x.Severity == Severity.Alert);
        var effectiveReviews = activeEvents.Count(x => x.Severity == Severity.Review);
        var effectiveStatus = state.Status;
        if (online)
        {
            if (effectiveAlerts > 0) effectiveStatus = "PELIGRO";
            else if (effectiveReviews > 0) effectiveStatus = "REVISAR";
            else if (state.Status is "PELIGRO" or "REVISAR") effectiveStatus = state.PrimaryAntivirusActive ? "VIGILANDO" : "VERIFICAR";
        }

        _status.Text = online ? effectiveStatus : "SIN MONITOR";
        _status.ForeColor = !online ? Red : effectiveStatus is "VIGILANDO" or "PROTEGIDO" ? Green : effectiveStatus == "PELIGRO" ? Red : Orange;
        _risk.Text = $"{effectiveRisk}/100";
        _risk.ForeColor = effectiveRisk >= 60 ? Red : effectiveRisk >= 30 ? Orange : Green;

        var feedAge = state.IntelligenceUpdatedAt is null ? "sin inteligencia" : $"{state.IntelligenceIndicators:N0} indicadores";
        var provider = state.PrimaryAntivirus.Length > 24 ? state.PrimaryAntivirus[..24] + "…" : state.PrimaryAntivirus;
        var blocks = FirewallResponse.Read().Count;
        var agentVersion = string.IsNullOrWhiteSpace(state.AgentVersion) ? "NO REPORTADA" : state.AgentVersion;
        _stats.Text = $"{state.ProcessesObserved} procesos · {state.CorrelatedIncidents} correlaciones\nAV: {provider}\n{feedAge} · {blocks} bloqueos\nAgente: {agentVersion}";
        _stats.ForeColor = Cyan;

        var riskDriver = activeEvents.OrderByDescending(x => x.Score).ThenByDescending(x => x.Time).FirstOrDefault();
        _tips.SetToolTip(_status, state.CoverageMessage);
        _tips.SetToolTip(_stats, state.CoverageMessage + $"\nVersión del agente residente: {agentVersion}");
        _tips.SetToolTip(_risk, riskDriver is null ? "No hay eventos activos." : $"Puntuación del evento más importante: {riskDriver.Title} ({riskDriver.Score}/100). No representa uso de CPU ni probabilidad de infección.");

        _events.SuspendLayout();
        _events.Controls.Clear();
        var visibleEvents = effectiveEvents.Take(30).ToList();
        if (riskDriver is not null)
        {
            visibleEvents.RemoveAll(x => x.Fingerprint.Equals(riskDriver.Fingerprint, StringComparison.OrdinalIgnoreCase));
            visibleEvents.Insert(0, riskDriver);
            if (visibleEvents.Count > 30) visibleEvents.RemoveRange(30, visibleEvents.Count - 30);
        }
        foreach (var item in visibleEvents)
        {
            var color = item.Severity == Severity.Alert ? Red : item.Severity == Severity.Review ? Orange : item.Severity == Severity.Safe ? Green : Cyan;
            var card = new Panel { Width = Math.Max(700, _events.ClientSize.Width - 30), Height = 86, BackColor = PanelBg, Margin = new(4) };
            var severityText = item.Severity switch { Severity.Alert => "ALERTA", Severity.Review => "REVISAR", Severity.Safe => "SEGURO", _ => "INFO" };
            card.Controls.Add(new Label { Text = severityText, ForeColor = color, Font = new("Segoe UI Semibold", 9), AutoSize = true, Left = 16, Top = 14 });
            card.Controls.Add(new Label { Text = item.Title, ForeColor = Color.White, Font = new("Segoe UI Semibold", 11), AutoSize = true, Left = 110, Top = 12 });
            card.Controls.Add(new Label { Text = item.Evidence.Replace("\n", "  •  "), ForeColor = Color.FromArgb(165, 184, 207), AutoEllipsis = true, Width = card.Width - 220, Height = 38, Left = 110, Top = 40 });
            var details = Button("VER", 74); details.Left = card.Width - 92; details.Top = 24; details.Click += (_, _) => new EventDetailsForm(item).ShowDialog(this); card.Controls.Add(details);
            _events.Controls.Add(card);
        }
        _events.ResumeLayout();
        NotifyNewThreats(effectiveEvents);
    }

    void NotifyNewThreats(IEnumerable<SecurityEvent> events)
    {
        var pending = events.Where(x => x.Time >= _notificationSince && (x.Severity is Severity.Alert or Severity.Review) && !_notified.Contains(x.Fingerprint)).ToList();
        foreach (var item in pending) _notified.Add(item.Fingerprint);
        var newest = pending.OrderByDescending(x => x.Severity == Severity.Alert).ThenByDescending(x => x.Time).FirstOrDefault();
        if (newest is null) return;
        var evidence = newest.Evidence.Replace('\r', ' ').Replace('\n', ' ').Trim(); if (evidence.Length > 180) evidence = evidence[..180] + "…";
        _tray.ShowBalloonTip(8000, newest.Severity == Severity.Alert ? "GivenX Shield · ALERTA" : "GivenX Shield · Revisar", newest.Title + "\n" + evidence, newest.Severity == Severity.Alert ? ToolTipIcon.Error : ToolTipIcon.Warning);
    }

    async Task OpenPrimaryScan(bool full)
    {
        var snapshot = await AntivirusProviderDetector.RefreshAsync(true); var primary = snapshot.Primary;
        if (primary?.IsMicrosoftDefender == true && primary.Enabled) { new DefenderScanForm(full).ShowDialog(this); return; }
        var name = primary?.Name ?? "ningún antivirus activo";
        MessageBox.Show(this, $"Windows registra {name} como proveedor principal. GivenX no forzará Defender ni ejecutará dos antivirus a la vez. Abre el proveedor desde Seguridad de Windows para iniciar su análisis; el análisis YARA de GivenX sigue disponible en ANÁLISIS UNIFICADO.", "Antivirus principal", MessageBoxButtons.OK, MessageBoxIcon.Information);
        WindowsSecurityLauncher.Open(this);
    }

    void ExitPanel()
    {
        if (MessageBox.Show(this, "Se cerrará solamente el panel y sus notificaciones. El radar residente continuará activo. ¿Continuar?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        _allowExit = true; Close();
    }

    void RestoreWindow() { Opacity = 1; ShowInTaskbar = true; Show(); WindowState = FormWindowState.Normal; Activate(); }
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_allowExit && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); _tray.ShowBalloonTip(2500, "GivenX Shield", "Panel oculto. El radar y las notificaciones continúan activos.", ToolTipIcon.Info); return; }
        base.OnFormClosing(e);
    }
    protected override void OnFormClosed(FormClosedEventArgs e) { _tray.Visible = false; _tips.Dispose(); base.OnFormClosed(e); }
}
