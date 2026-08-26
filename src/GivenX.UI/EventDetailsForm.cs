using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Net;
using GivenX.Shared;

namespace GivenX.UI;

public sealed class EventDetailsForm : Form
{
    readonly SecurityEvent _event;
    readonly string? _filePath;
    readonly int? _processId;
    readonly string? _remoteAddress;
    readonly Color _orange = Color.FromArgb(255, 116, 22);

    public EventDetailsForm(SecurityEvent item)
    {
        _event = item; _filePath = FindRelevantFile(item.Evidence); _processId = FindProcessId(item.Evidence); _remoteAddress=FindRemoteAddress(item.Evidence);
        Text = "GivenX Shield | Detalle del evento"; Size = new(980, 760); StartPosition = FormStartPosition.CenterParent; BackColor = Color.FromArgb(7, 12, 20); ForeColor = Color.White; Font = new("Segoe UI", 10);
        var title = new Label { Text = item.Title, Font = new("Segoe UI Semibold", 19), ForeColor = item.Severity == Severity.Alert ? Color.FromArgb(255, 73, 91) : _orange, Left = 24, Top = 22, AutoSize = true };
        var meta = new Label { Text = $"{item.Time.LocalDateTime:yyyy-MM-dd HH:mm:ss}  ·  {item.Category}  ·  puntuación del evento {item.Score}/100", ForeColor = Color.FromArgb(150, 170, 195), Left = 26, Top = 62, AutoSize = true };
        var recommendation = new Label { Text = "RECOMENDACIÓN: " + item.Recommendation, ForeColor = Color.FromArgb(73, 200, 255), Left = 26, Top = 94, Width = 845, Height = 48 };
        var evidence = new TextBox { Text = item.Evidence, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Left = 26, Top = 150, Width = 905, Height = 350, BackColor = Color.FromArgb(9, 16, 26), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };
        var bar = new FlowLayoutPanel { Left = 22, Top = 515, Width = 915, Height = 130 };
        var location = Button("ABRIR UBICACIÓN", 160); location.Enabled = _filePath is not null; location.Click += (_, _) => OpenLocation(); bar.Controls.Add(location);
        var quarantine = Button("AISLAR ARCHIVO", 150); quarantine.Enabled = _filePath is not null; quarantine.Click += async (_, _) => await Quarantine(); bar.Controls.Add(quarantine);
        var allow = Button("PERMITIR HASH", 140); allow.Enabled = _filePath is not null; allow.Click += async (_, _) => await Allow(); bar.Controls.Add(allow);
        var block = Button("BLOQUEAR RED", 140); block.Enabled = _filePath?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true; block.Click += async (_, _) => await BlockNetwork(); bar.Controls.Add(block);
        var blockIp = Button("BLOQUEAR IP", 130); blockIp.Enabled = _remoteAddress is not null; blockIp.Click += async (_, _) => await BlockRemote(); bar.Controls.Add(blockIp);
        var terminate = Button("FINALIZAR", 120); terminate.Enabled = _filePath?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true && _processId.HasValue; terminate.Click += (_, _) => TerminateProcess(); bar.Controls.Add(terminate);
        var contain = Button("CONTENER", 130); contain.Enabled = _remoteAddress is not null || _filePath is not null; contain.Click += async (_, _) => await Contain(); bar.Controls.Add(contain);
        var resolved = Button("MARCAR RESUELTO", 165); resolved.Click += (_, _) => MarkResolved(); bar.Controls.Add(resolved);
        var dismiss = Button("DESCARTAR EVENTO", 180); dismiss.Click += (_, _) => Dismiss(); bar.Controls.Add(dismiss);
        Controls.Add(title); Controls.Add(meta); Controls.Add(recommendation); Controls.Add(evidence); Controls.Add(bar);
    }

    Button Button(string text, int width) => new() { Text = text, Width = width, Height = 34, FlatStyle = FlatStyle.Flat, BackColor = Color.FromArgb(25, 39, 58), ForeColor = Color.White, FlatAppearance = { BorderColor = _orange } };

    static string? FindRelevantFile(string evidence)
    {
        foreach (var field in new[] { "Biblioteca", "Proceso" })
        {
            var match = Regex.Match(evidence, "(?:^|\\r?\\n)" + Regex.Escape(field) + @":\s*([^\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!match.Success) continue;
            var candidate = match.Groups[1].Value.Trim().Trim('"');
            if (File.Exists(candidate)) return Path.GetFullPath(candidate);
        }
        return FindExistingFile(evidence);
    }

    static string? FindExistingFile(string evidence)
    {
        foreach (var part in evidence.Split(new[] { '\r', '\n', '|', '•' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim().Trim('"')))
            if (File.Exists(part)) return Path.GetFullPath(part);
        foreach (Match match in Regex.Matches(evidence, @"[A-Za-z]:\\[^<\r\n|]+"))
        {
            var candidate = match.Value.Trim().Trim('"'); if (File.Exists(candidate)) return Path.GetFullPath(candidate);
        }
        return null;
    }

    static int? FindProcessId(string evidence)
    {
        var match=Regex.Match(evidence,@"\bPID\s+(\d+)\b",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);return match.Success&&int.TryParse(match.Groups[1].Value,out var pid)?pid:null;
    }

    static string? FindRemoteAddress(string evidence)
    {
        var match=Regex.Match(evidence,@"IP remota:\s*(\[[^\]]+\]|[^:\s]+)",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);if(!match.Success)return null;var value=match.Groups[1].Value.Trim().Trim('[',']');return IPAddress.TryParse(value,out var address)&&FirewallResponse.IsPublicAddress(address)?address.ToString():null;
    }

    void OpenLocation()
    {
        if (_filePath is null) return;
        try { var start = new ProcessStartInfo("explorer.exe") { UseShellExecute = true }; start.ArgumentList.Add("/select,"); start.ArgumentList.Add(_filePath); Process.Start(start); } catch { }
    }

    async Task Quarantine()
    {
        if (_filePath is null || !File.Exists(_filePath)) return;
        if (MessageBox.Show("El archivo se cifrará y se retirará de su ubicación. ¿Continuar?", "Aislar archivo", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try { await QuarantineStore.QuarantineAsync(_filePath, _event.Title); MessageBox.Show("Archivo aislado correctamente.", "GivenX Shield"); Close(); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "No se pudo aislar", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    async Task Allow()
    {
        if (_filePath is null || !File.Exists(_filePath)) return;
        if (MessageBox.Show("Solo permite el archivo si reconoces su origen. ¿Continuar?", "Lista segura", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        await using var stream = File.OpenRead(_filePath); var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant(); AllowListStore.Add(hash); DismissedEventStore.Remove(_event.Fingerprint); ResolvedEventStore.Add(_event.Fingerprint); ResponseActionStore.Append("Permitir hash",_filePath,"COMPLETADO",true,"El evento actual fue marcado como resuelto; futuros cambios de hash volverán a revisarse."); MessageBox.Show("Hash permitido y evento resuelto. Si el archivo cambia, deberá revisarse nuevamente.", "GivenX Shield"); Close();
    }

    async Task BlockNetwork()
    {
        if (_filePath is null || !File.Exists(_filePath)) return;
        if (MessageBox.Show("Se creará una regla reversible de salida en Windows Firewall. ¿Continuar?", "Bloquear red", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try { var row = await FirewallResponse.BlockAsync(_filePath); MessageBox.Show("Red bloqueada para el programa.\n" + row.RuleName, "GivenX Shield"); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "No se pudo bloquear", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    async Task BlockRemote()
    {
        if(_remoteAddress is null)return;if(MessageBox.Show(this,$"Se bloqueará toda conexión saliente hacia {_remoteAddress}. La acción es reversible. ¿Continuar?","Bloquear IP",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        try{var row=await FirewallResponse.BlockRemoteAddressAsync(_remoteAddress);MessageBox.Show(this,"IP bloqueada.\n"+row.RuleName,"GivenX Shield");}
        catch(Exception ex){MessageBox.Show(this,ex.Message,"No se pudo bloquear",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }

    async Task Contain()
    {
        var warning="GivenX intentará bloquear la IP y el ejecutable, finalizar el PID verificado y aislar el archivo cuando estén disponibles y pertenezcan a una carpeta modificable por el usuario. Puede perderse trabajo no guardado.\n\n¿Ejecutar la contención avanzada?";
        if(MessageBox.Show(this,warning,"Contención avanzada",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        var result=await ContainmentService.ContainAsync(new(_filePath,_processId,_remoteAddress,_event.Title));if(result.Completed){DismissedEventStore.Remove(_event.Fingerprint);ResolvedEventStore.Add(_event.Fingerprint);ResponseActionStore.Append("Resolver evento",_event.Title,"COMPLETADO",false,"Contención completada");}var title=result.Completed?"Contención completa":result.AnyAction?"Contención parcial":"Contención no completada";MessageBox.Show(this,result.Summary,title,MessageBoxButtons.OK,result.Completed?MessageBoxIcon.Information:MessageBoxIcon.Warning);if(result.Completed)Close();
    }

    void MarkResolved()
    {
        if(MessageBox.Show(this,"Usa esta opción solamente cuando ya corregiste o verificaste el evento. Se retirará del riesgo activo, pero permanecerá en el historial. ¿Marcarlo como resuelto?","Resolver evento",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)return;DismissedEventStore.Remove(_event.Fingerprint);ResolvedEventStore.Add(_event.Fingerprint);ResponseActionStore.Append("Resolver evento",_event.Title,"COMPLETADO",false,"Marcado manualmente después de revisión");Close();
    }

    void TerminateProcess()
    {
        if(_filePath is null||!_processId.HasValue)return;
        if(MessageBox.Show(this,$"Se finalizará el proceso PID {_processId.Value}. Puede perderse trabajo no guardado. GivenX verificará que el PID siga perteneciendo al mismo archivo. ¿Continuar?","Finalizar proceso",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        try{ProcessResponse.TerminateUserProcess(_processId.Value,_filePath);MessageBox.Show(this,"Proceso finalizado.","GivenX Shield",MessageBoxButtons.OK,MessageBoxIcon.Information);}
        catch(Exception ex){MessageBox.Show(this,ex.Message,"No se finalizó",MessageBoxButtons.OK,MessageBoxIcon.Error);}
    }

    void Dismiss()
    {
        var message = "Descarta este evento solo si comprobaste que es un falso positivo. Se retirará del panel y del cálculo de riesgo, pero no se permitirá ningún archivo ni se desactivarán futuras detecciones. ¿Continuar?";
        if (MessageBox.Show(message, "Descartar falso positivo", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        ResolvedEventStore.Remove(_event.Fingerprint);DismissedEventStore.Add(_event.Fingerprint);
        MessageBox.Show("Evento descartado. El radar recalculará el riesgo en unos segundos.", "GivenX Shield");
        Close();
    }
}
