using GivenX.Shared;

namespace GivenX.UI;

public sealed class HistoryAndTrustForm : Form
{
    readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    readonly ListView _scans = List();
    readonly ListView _threats = List();
    readonly ListView _allowed = List();
    readonly ListView _publishers = List();
    readonly ListView _resolved = List();
    readonly ListView _dismissed = List();

    public HistoryAndTrustForm()
    {
        Text = "GivenX Shield | Historial y confianza"; Size = new(1040, 680); StartPosition = FormStartPosition.CenterParent; BackColor = Color.FromArgb(7, 12, 20); ForeColor = Color.White; Font = new("Segoe UI", 10);
        BuildUi(); LoadAll();
    }

    void BuildUi()
    {
        _scans.Columns.Add("Fecha", 150); _scans.Columns.Add("Tipo", 155); _scans.Columns.Add("Objetivo", 260); _scans.Columns.Add("Estado", 105); _scans.Columns.Add("Archivos", 75); _scans.Columns.Add("Hallazgos", 80); _scans.Columns.Add("Duración / detalle", 360);
        _threats.Columns.Add("Fecha", 150); _threats.Columns.Add("Nivel", 85); _threats.Columns.Add("Estado", 95); _threats.Columns.Add("Área", 100); _threats.Columns.Add("Hallazgo", 230); _threats.Columns.Add("Evidencia", 360);
        _allowed.Columns.Add("SHA-256 permitido", 700); _allowed.Columns.Add("Efecto", 240);
        _publishers.Columns.Add("Editor con firma válida", 500); _publishers.Columns.Add("Alcance", 440);
        _resolved.Columns.Add("Huella del evento", 180); _resolved.Columns.Add("Evento resuelto", 280); _resolved.Columns.Add("Evidencia original", 480);
        _dismissed.Columns.Add("Huella del evento", 180); _dismissed.Columns.Add("Hallazgo descartado", 280); _dismissed.Columns.Add("Evidencia original", 480);
        _threats.DoubleClick += (_, _) => { if (_threats.SelectedItems.Count > 0 && _threats.SelectedItems[0].Tag is SecurityEvent item) new EventDetailsForm(item).ShowDialog(this); };
        _tabs.TabPages.Add(Page("ANÁLISIS", _scans)); _tabs.TabPages.Add(Page("AMENAZAS", _threats)); _tabs.TabPages.Add(Page("HASH SEGUROS", _allowed)); _tabs.TabPages.Add(Page("EDITORES", _publishers)); _tabs.TabPages.Add(Page("RESUELTOS", _resolved)); _tabs.TabPages.Add(Page("FALSOS POSITIVOS", _dismissed));
        var footer = new Panel { Dock = DockStyle.Bottom, Height = 64, BackColor = Color.FromArgb(14, 23, 36) };
        var refresh = Button("ACTUALIZAR", 140); refresh.Left = 18; refresh.Top = 14; refresh.Click += (_, _) => LoadAll(); footer.Controls.Add(refresh);
        var remove = Button("QUITAR SELECCIONADO", 210); remove.Left = 170; remove.Top = 14; remove.Click += (_, _) => RemoveSelected(); footer.Controls.Add(remove);
        footer.Controls.Add(new Label { Text = "Quitar una excepción o reabrir un evento vuelve a incluirlo en el riesgo activo.", AutoSize = true, ForeColor = Color.FromArgb(160, 182, 210), Left = 400, Top = 24 });
        Controls.Add(_tabs); Controls.Add(footer); footer.BringToFront();
    }

    static ListView List() => new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = false, BackColor = Color.FromArgb(9, 16, 26), ForeColor = Color.White, BorderStyle = BorderStyle.None };
    static TabPage Page(string title, Control content) { var page = new TabPage(title) { BackColor = Color.FromArgb(7, 12, 20), ForeColor = Color.White, Padding = new(12) }; page.Controls.Add(content); return page; }
    static Button Button(string text, int width) => new() { Text = text, Width = width, Height = 36, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(25, 39, 58), ForeColor = Color.White, FlatAppearance = { BorderColor = Color.FromArgb(255, 116, 22) } };

    void LoadAll()
    {
        _scans.BeginUpdate(); _scans.Items.Clear();
        foreach (var row in ScanHistoryStore.Read())
        {
            var duration = row.FinishedAt - row.StartedAt;
            var item = new ListViewItem(row.StartedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")); item.SubItems.Add(row.ScanType); item.SubItems.Add(row.Target); item.SubItems.Add(row.Status); item.SubItems.Add(row.FilesChecked.ToString("N0")); item.SubItems.Add(row.Findings.ToString("N0")); item.SubItems.Add($"{duration:hh\\:mm\\:ss} · {row.Details}");
            item.ForeColor = row.Status == "COMPLETADO" ? Color.FromArgb(66, 226, 151) : row.Status is "REVISAR" or "CANCELADO" ? Color.FromArgb(255, 190, 70) : Color.FromArgb(255, 90, 105); _scans.Items.Add(item);
        }
        _scans.EndUpdate();

        var events = StateStore.ReadEvents();var resolvedEvents=ResolvedEventStore.Read();var dismissedEvents=DismissedEventStore.Read(); _threats.BeginUpdate(); _threats.Items.Clear();
        foreach (var row in events.Where(x => x.Severity is Severity.Alert or Severity.Review))
        {
            var resolved=resolvedEvents.Contains(row.Fingerprint);var dismissed=dismissedEvents.Contains(row.Fingerprint);var item = new ListViewItem(row.Time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")); item.SubItems.Add(row.Severity == Severity.Alert ? "ALERTA" : "REVISAR");item.SubItems.Add(resolved?"RESUELTO":dismissed?"DESCARTADO":"ACTIVO"); item.SubItems.Add(row.Category); item.SubItems.Add(row.Title); item.SubItems.Add(row.Evidence.Replace('\n', ' ')); item.Tag = row;
            item.ForeColor = resolved||dismissed?Color.FromArgb(150,170,195):row.Severity == Severity.Alert ? Color.FromArgb(255, 73, 91) : Color.FromArgb(255, 190, 70); _threats.Items.Add(item);
        }
        _threats.EndUpdate();

        _allowed.BeginUpdate(); _allowed.Items.Clear();
        foreach (var hash in AllowListStore.Read().OrderBy(x => x)) { var item = new ListViewItem(hash); item.SubItems.Add("El radar ignora este contenido exacto"); item.Tag = hash; _allowed.Items.Add(item); }
        _allowed.EndUpdate();

        _publishers.BeginUpdate(); _publishers.Items.Clear();
        foreach (var publisher in TrustedPublisherStore.Read().OrderBy(x => x)) { var item = new ListViewItem(publisher); item.SubItems.Add("Solo archivos cuya firma digital siga siendo válida"); item.Tag = publisher; _publishers.Items.Add(item); }
        _publishers.EndUpdate();

        var eventMap = events.GroupBy(x => x.Fingerprint, StringComparer.OrdinalIgnoreCase).ToDictionary(x => x.Key, x => x.First(), StringComparer.OrdinalIgnoreCase);
        _resolved.BeginUpdate();_resolved.Items.Clear();foreach(var fingerprint in resolvedEvents.OrderBy(x=>x)){eventMap.TryGetValue(fingerprint,out var original);var item=new ListViewItem(fingerprint);item.SubItems.Add(original?.Title??"Evento no disponible");item.SubItems.Add(original is null?"La huella continúa resuelta.":original.Evidence.Replace('\n',' '));item.Tag=fingerprint;_resolved.Items.Add(item);}_resolved.EndUpdate();
        _dismissed.BeginUpdate(); _dismissed.Items.Clear();
        foreach (var fingerprint in DismissedEventStore.Read().OrderBy(x => x))
        {
            eventMap.TryGetValue(fingerprint, out var original); var item = new ListViewItem(fingerprint); item.SubItems.Add(original?.Title ?? "Evento no disponible"); item.SubItems.Add(original is null ? "La huella continúa descartada." : original.Evidence.Replace('\n', ' ')); item.Tag = fingerprint; _dismissed.Items.Add(item);
        }
        _dismissed.EndUpdate();
    }

    void RemoveSelected()
    {
        var selectedTab = _tabs.SelectedTab;
        if (selectedTab is null || selectedTab.Controls.Count == 0) return;
        if (selectedTab.Controls[0] == _allowed && _allowed.SelectedItems.Count > 0 && _allowed.SelectedItems[0].Tag is string hash)
        {
            if (MessageBox.Show(this, "¿Quitar este hash de la lista segura?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) AllowListStore.Remove(hash);
        }
        else if (selectedTab.Controls[0] == _publishers && _publishers.SelectedItems.Count > 0 && _publishers.SelectedItems[0].Tag is string publisher)
        {
            if (MessageBox.Show(this, "¿Dejar de confiar en este editor?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) TrustedPublisherStore.Remove(publisher);
        }
        else if (selectedTab.Controls[0] == _dismissed && _dismissed.SelectedItems.Count > 0 && _dismissed.SelectedItems[0].Tag is string fingerprint)
        {
            if (MessageBox.Show(this, "¿Volver a vigilar este evento?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) DismissedEventStore.Remove(fingerprint);
        }
        else if (selectedTab.Controls[0] == _resolved && _resolved.SelectedItems.Count > 0 && _resolved.SelectedItems[0].Tag is string resolvedFingerprint)
        {
            if (MessageBox.Show(this, "¿Reabrir este evento y volver a incluirlo en el riesgo activo?", "GivenX Shield", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes) ResolvedEventStore.Remove(resolvedFingerprint);
        }
        else
        {
            MessageBox.Show(this, "Selecciona un hash, editor, evento resuelto o falso positivo. El historial no se elimina desde esta pantalla.", "GivenX Shield", MessageBoxButtons.OK, MessageBoxIcon.Information); return;
        }
        LoadAll();
    }
}
