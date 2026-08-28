using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using GivenX.Shared;

namespace GivenX.Agent;

public sealed class BehaviorMonitor
{
    readonly HashSet<long> _seenRecords = [];
    readonly Queue<long> _recordOrder = [];
    public bool SysmonAvailable { get; private set; }

    public IReadOnlyList<SecurityEvent> Poll(IReadOnlyCollection<string>? maliciousHosts = null)
    {
        var result = new List<SecurityEvent>();
        try
        {
            var start = new ProcessStartInfo("wevtutil.exe")
            {
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            start.ArgumentList.Add("qe"); start.ArgumentList.Add("Microsoft-Windows-Sysmon/Operational");
            start.ArgumentList.Add("/q:*[System[TimeCreated[timediff(@SystemTime) <= 15000]]]");
            start.ArgumentList.Add("/f:xml"); start.ArgumentList.Add("/rd:false"); start.ArgumentList.Add("/c:200");
            using var process = Process.Start(start);
            if (process is null) { SysmonAvailable = false; return result; }
            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(5000)) { try { process.Kill(true); } catch { } SysmonAvailable = false; return result; }
            SysmonAvailable = process.ExitCode == 0;
            if (!SysmonAvailable) return result;
            foreach (Match match in Regex.Matches(output, @"<Event\b[\s\S]*?</Event>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                var idMatch = Regex.Match(match.Value, @"<EventID(?:\s+[^>]*)?>(\d+)</EventID>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (!idMatch.Success || !int.TryParse(idMatch.Groups[1].Value, out var id)) continue;
                var recordMatch = Regex.Match(match.Value, @"<EventRecordID>(\d+)</EventRecordID>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (recordMatch.Success && long.TryParse(recordMatch.Groups[1].Value, out var recordId) && !Remember(recordId)) continue;
                var finding = Evaluate(id, match.Value, maliciousHosts);
                if (finding is not null) result.Add(finding);
            }
        }
        catch { SysmonAvailable = false; }
        return result;
    }

    bool Remember(long id)
    {
        if (!_seenRecords.Add(id)) return false;
        _recordOrder.Enqueue(id);
        while (_recordOrder.Count > 4000) _seenRecords.Remove(_recordOrder.Dequeue());
        return true;
    }

    static SecurityEvent? Evaluate(int id, string xml, IReadOnlyCollection<string>? maliciousHosts)
    {
        var text = System.Net.WebUtility.HtmlDecode(xml);
        var image = First(Data(text, "Image"), Data(text, "SourceImage"));
        var parent = Data(text, "ParentImage"); var command = Data(text, "CommandLine");
        var target = First(Data(text, "TargetImage"), Data(text, "TargetFilename"), Data(text, "TargetObject"));
        var imageLoaded = Data(text, "ImageLoaded");
        var details = Data(text, "Details");
        var destination = Data(text, "DestinationIp"); var query = Data(text, "QueryName").TrimEnd('.');
        string? rule = null; var score = 0; var recommendation = "Revisa el proceso, su firma y su origen antes de actuar.";

        if ((id == 1 && ContainsAny(command, "sekurlsa::logonpasswords", "lsass.dmp", "comsvcs.dll, MiniDump")) || (id == 10 && target.EndsWith("\\lsass.exe", StringComparison.OrdinalIgnoreCase) && SuspiciousUserPath(image)))
        { rule = "GX-CREDENTIAL-ACCESS"; score = 95; recommendation = "Posible acceso a credenciales. Desconecta Internet y ejecuta un análisis sin conexión con tu antivirus principal."; }
        else if (id == 1 && ContainsAny(command, "Set-MpPreference -DisableRealtimeMonitoring", "Add-MpPreference -Exclusion", "sc stop WinDefend", "taskkill /im GivenX", "Unregister-ScheduledTask -TaskName GivenX"))
        { rule = "GX-SECURITY-TAMPERING"; score = 95; recommendation = "Un proceso intentó reducir las defensas. No lo autorices y revisa inmediatamente el equipo."; }
        else if (id == 1 && ContainsAny(command, "vssadmin delete shadows", "wmic shadowcopy delete", "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled no"))
        { rule = "GX-RANSOMWARE-RECOVERY-TAMPERING"; score = 95; recommendation = "Posible preparación de ransomware. Desconecta Internet y no apagues el equipo hasta identificar el proceso."; }
        else if (id == 1 && IsOffice(parent) && IsScriptHost(image))
        { rule = "GX-OFFICE-SCRIPT-CHILD"; score = 88; recommendation = "Un documento inició un intérprete. Cierra el documento y analiza el archivo de origen."; }
        else if (id == 1 && IsBrowser(parent) && IsScriptHost(image) && ContainsAny(command, " -enc ", "http://", "https://", "javascript:"))
        { rule = "GX-BROWSER-SCRIPT-CHAIN"; score = 85; recommendation = "Un navegador lanzó una cadena de script inusual. Revisa la descarga o página que la originó."; }
        else if (id == 1 && ContainsAny(command, "mshta http", "regsvr32 /s /n /u /i:http", "rundll32 javascript:", "certutil -urlcache", "bitsadmin /transfer"))
        { rule = "GX-LOLBIN-DOWNLOAD"; score = 85; recommendation = "Posible descarga y ejecución mediante una herramienta legítima de Windows."; }
        else if (id == 1 && ContainsAny(command, " -enc ", " -encodedcommand ", "FromBase64String", "DownloadString(", "IEX(", "Invoke-Expression"))
        { rule = "GX-POWERSHELL-OBFUSCATED"; score = 75; recommendation = "Confirma quién inició PowerShell y revisa el comando decodificado antes de permitirlo."; }
        else if (id == 1 && ContainsAny(command, "schtasks /create", "New-ScheduledTaskAction", "Register-ScheduledTask") && SuspiciousUserPath(command))
        { rule = "GX-SCHEDULED-PERSISTENCE"; score = 72; recommendation = "Se intentó crear persistencia desde una carpeta de usuario. Revisa la tarea programada."; }
        else if (id == 1 && ContainsAny(command, "sc create", "New-Service", "CreateService") && SuspiciousUserPath(command))
        { rule = "GX-SERVICE-PERSISTENCE"; score = 78; recommendation = "Se intentó registrar un servicio desde una carpeta modificable por el usuario. Revisa el servicio antes de permitirlo."; }
        else if (id is 19 or 20 or 21)
        { rule = "GX-WMI-PERSISTENCE"; score = 88; recommendation = "Sysmon observó persistencia mediante WMI. Revisa consumidor, filtro y comando asociados."; }
        else if (id == 8 && SuspiciousUserPath(image))
        { rule = "GX-REMOTE-THREAD"; score = 90; recommendation = "Posible inyección de código. Desconecta Internet si no reconoces el programa."; }
        else if (id == 6 && ContainsAny(text, ">false<", "Unavailable"))
        { rule = "GX-UNTRUSTED-DRIVER"; score = 90; recommendation = "Se cargó un controlador sin firma verificada. Revisa su editor y origen."; }
        else if (id == 13 && IsRegistryPersistenceTarget(target) && !KnownBenignActivity.IsKnownBenignRegistryPersistence(image, target, details))
        { rule = "GX-REGISTRY-PERSISTENCE"; score = 62; recommendation = "Revisa el valor modificado y el programa que quedaría iniciándose automáticamente."; }
        else if (id == 13 && target.EndsWith("\\MitigationOptions", StringComparison.OrdinalIgnoreCase) && SuspiciousUserPath(image))
        { rule = "GX-EXPLOIT-MITIGATION-TAMPERING"; score = 70; recommendation = "Un programa ejecutado desde una carpeta modificable cambió la protección contra exploits. Comprueba su firma y origen antes de actuar."; }
        else if (id == 11 && target.Contains("\\Start Menu\\Programs\\Startup\\", StringComparison.OrdinalIgnoreCase))
        { rule = "GX-STARTUP-FILE"; score = 68; recommendation = "Se creó un archivo de inicio automático. Comprueba su firma y procedencia."; }
        else if (id == 7 && SuspiciousUserPath(imageLoaded) && !SamePath(image, imageLoaded) && ContainsAny(text, ">false<", "Unavailable") && !KnownBenignActivity.IsExplicitlyTrustedExecutable(imageLoaded))
        { rule = "GX-UNTRUSTED-DLL"; score = 58; recommendation = "Una aplicación cargó una biblioteca no verificada desde una carpeta modificable. Revisa la ruta de la biblioteca; si verificas ese archivo exacto, puedes permitir su hash."; }
        else if (id == 1 && SuspiciousUserPath(image) && ContainsAny(text, "<Data Name=\"Signed\">false", "<Data Name=\"SignatureStatus\">Unavailable"))
        { rule = "GX-UNSIGNED-USERPATH-PROCESS"; score = 48; }
        else if (id == 3 && IsKnownBad(destination, maliciousHosts))
        { rule = "GX-IOC-NETWORK"; score = 100; recommendation = "El proceso contactó infraestructura asociada a malware. Desconecta Internet y aísla el ejecutable."; }
        else if (id == 3 && SuspiciousUserPath(image) &&
                 !KnownBenignActivity.IsOfficialMicrosoftOneDriveComponent(image) &&
                 !KnownBenignActivity.IsOfficialGitHubDesktop(image) &&
                 !KnownBenignActivity.IsOfficialGitHubDesktopBundledGit(image) &&
                 !KnownBenignActivity.IsExplicitlyTrustedExecutable(image))
        { rule = "GX-USERPATH-NETWORK"; score = 42; recommendation = "Un programa ejecutado desde una carpeta modificable inició una conexión externa."; }
        else if (id == 22 && !KnownBenignActivity.IsSharedHostingDomain(query) && IsKnownBad(query, maliciousHosts))
        { rule = "GX-IOC-DNS"; score = 100; recommendation = "El equipo consultó un dominio asociado a malware. Desconecta Internet y revisa el proceso."; }

        if (rule is null) return null;
        var evidence = BuildEvidence(rule, image, parent, command, target, imageLoaded, details, destination, query);
        // A user-path network rule is about the executable itself. Using every destination in
        // the fingerprint floods the dashboard when one process opens many normal connections.
        // IOC rules still retain destination/query because those indicators are security relevant.
        var fingerprintSource = rule.Equals("GX-USERPATH-NETWORK", StringComparison.OrdinalIgnoreCase)
            ? string.Join('|', rule, image)
            : rule.Equals("GX-UNTRUSTED-DLL", StringComparison.OrdinalIgnoreCase)
                ? string.Join('|', rule, image, imageLoaded)
                : string.Join('|', rule, image, parent, command, target, destination, query);
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintSource))).Substring(0, 16);
        return new(DateTimeOffset.Now, score >= 85 ? Severity.Alert : Severity.Review, "Comportamiento", FriendlyTitle(rule), evidence, recommendation, score, fingerprint);
    }

    static string BuildEvidence(string rule, string image, string parent, string command, string target, string imageLoaded, string details, string destination, string query)
    {
        var parts = new List<string> { "Regla: " + rule };
        Add(parts, "Proceso", image); Add(parts, "Padre", parent); Add(parts, "Comando", Compact(command, 700)); Add(parts, "Objetivo", target);
        Add(parts, "Biblioteca", imageLoaded); Add(parts, "Detalles", Compact(details, 500)); Add(parts, "Destino", destination); Add(parts, "DNS", query);
        return string.Join(Environment.NewLine, parts);
    }

    static string FriendlyTitle(string rule) => rule switch
    {
        "GX-CREDENTIAL-ACCESS" => "Posible acceso a credenciales",
        "GX-SECURITY-TAMPERING" => "Intento de reducir la protección",
        "GX-RANSOMWARE-RECOVERY-TAMPERING" => "Comandos asociados a ransomware",
        "GX-OFFICE-SCRIPT-CHILD" => "Documento inició un intérprete",
        "GX-BROWSER-SCRIPT-CHAIN" => "Navegador inició una cadena de script",
        "GX-LOLBIN-DOWNLOAD" => "Descarga mediante herramienta de Windows",
        "GX-POWERSHELL-OBFUSCATED" => "PowerShell ofuscado o codificado",
        "GX-SCHEDULED-PERSISTENCE" => "Posible persistencia programada",
        "GX-SERVICE-PERSISTENCE" => "Posible persistencia mediante servicio",
        "GX-WMI-PERSISTENCE" => "Posible persistencia mediante WMI",
        "GX-REMOTE-THREAD" => "Posible inyección entre procesos",
        "GX-UNTRUSTED-DRIVER" => "Controlador sin firma verificada",
        "GX-REGISTRY-PERSISTENCE" => "Cambio de inicio automático en registro",
        "GX-EXPLOIT-MITIGATION-TAMPERING" => "Programa sensible modificó la protección contra exploits",
        "GX-STARTUP-FILE" => "Archivo añadido al inicio automático",
        "GX-UNTRUSTED-DLL" => "Biblioteca no verificada cargada",
        "GX-UNSIGNED-USERPATH-PROCESS" => "Proceso sin firma desde carpeta modificable",
        "GX-IOC-NETWORK" => "Conexión con infraestructura maliciosa",
        "GX-USERPATH-NETWORK" => "Conexión desde programa de carpeta sensible",
        "GX-IOC-DNS" => "Consulta DNS asociada a malware",
        _ => rule
    };

    static void Add(List<string> parts, string label, string value) { if (!string.IsNullOrWhiteSpace(value)) parts.Add(label + ": " + value); }
    static string Compact(string value, int maximum) => value.Length <= maximum ? value : value[..maximum] + "…";
    static string First(params string[] values) => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? string.Empty;
    static bool IsOffice(string path) => ContainsAny(path, "\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe");
    static bool IsBrowser(string path) => ContainsAny(path, "\\chrome.exe", "\\msedge.exe", "\\firefox.exe", "\\brave.exe", "\\opera.exe");
    static bool IsScriptHost(string path) => ContainsAny(path, "\\powershell.exe", "\\pwsh.exe", "\\cmd.exe", "\\wscript.exe", "\\cscript.exe", "\\mshta.exe", "\\rundll32.exe", "\\regsvr32.exe");
    static string Data(string xml, string name)
    {
        var pattern="<Data\\s+Name\\s*=\\s*['\"]"+Regex.Escape(name)+"['\"][^>]*>([\\s\\S]*?)</Data>";
        var match = Regex.Match(xml, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
    }
    static bool IsRegistryPersistenceTarget(string target)
    {
        if(ContainsAny(target,"\\CurrentVersion\\Run","\\Winlogon\\Shell","\\Policies\\Explorer\\Run"))return true;
        if(target.Contains("\\Image File Execution Options\\",StringComparison.OrdinalIgnoreCase)&&EndsWithAny(target,"\\Debugger","\\GlobalFlag","\\VerifierDlls"))return true;
        return target.Contains("\\SilentProcessExit\\",StringComparison.OrdinalIgnoreCase)&&target.EndsWith("\\MonitorProcess",StringComparison.OrdinalIgnoreCase);
    }
    static bool IsKnownBad(string candidate, IReadOnlyCollection<string>? indicators)
    {
        if (string.IsNullOrWhiteSpace(candidate) || indicators is null) return false;
        candidate = candidate.Trim().TrimEnd('.');
        return indicators.Any(value => !string.IsNullOrWhiteSpace(value) &&
            candidate.Equals(value.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase));
    }
    static bool SamePath(string left, string right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
        try
        {
            return Path.GetFullPath(left).TrimEnd('\\').Equals(Path.GetFullPath(right).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return left.Trim().TrimEnd('\\').Equals(right.Trim().TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }
    }
    static bool SuspiciousUserPath(string path) => ContainsAny(path, "\\AppData\\", "\\Temp\\", "\\Downloads\\", "\\Users\\Public\\");
    static bool EndsWithAny(string source,params string[] values)=>values.Any(x=>source.EndsWith(x,StringComparison.OrdinalIgnoreCase));
    static bool ContainsAny(string source, params string[] values) => values.Any(x => source.Contains(x, StringComparison.OrdinalIgnoreCase));
}
