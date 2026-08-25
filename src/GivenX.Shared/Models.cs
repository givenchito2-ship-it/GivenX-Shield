using System.Text.Json;
using System.Xml.Linq;

namespace GivenX.Shared;

public enum Severity { Info, Safe, Review, Alert }
public enum EngineVerdict { Unavailable, Clean, Unknown, Suspicious, Malicious, Error }
public sealed record EngineResult(string Engine, EngineVerdict Verdict, int Score, string Evidence, DateTimeOffset CheckedAt);
public sealed record EngineHealth(string Engine, bool Active, string Status, DateTimeOffset CheckedAt);

public sealed record ScanHistoryRecord(string Id, DateTimeOffset StartedAt, DateTimeOffset FinishedAt,
    string ScanType, string Target, string Status, int FilesChecked, int Findings, string Details);

public sealed record SecurityEvent(DateTimeOffset Time, Severity Severity, string Category,
    string Title, string Evidence, string Recommendation, int Score, string Fingerprint);

public static class LegacyEventCompatibility
{
    public static SecurityEvent Normalize(SecurityEvent item)
    {
        if(string.IsNullOrWhiteSpace(item.Evidence)||!item.Evidence.TrimStart().StartsWith("<Event",StringComparison.OrdinalIgnoreCase))return item;
        try
        {
            var document=XDocument.Parse(item.Evidence,LoadOptions.None);var values=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            foreach(var node in document.Descendants().Where(x=>x.Name.LocalName.Equals("Data",StringComparison.OrdinalIgnoreCase)))
            {
                var name=node.Attributes().FirstOrDefault(x=>x.Name.LocalName.Equals("Name",StringComparison.OrdinalIgnoreCase))?.Value;
                if(!string.IsNullOrWhiteSpace(name)&&!values.ContainsKey(name))values[name]=node.Value.Trim();
            }
            var eventId=document.Descendants().FirstOrDefault(x=>x.Name.LocalName.Equals("EventID",StringComparison.OrdinalIgnoreCase))?.Value?.Trim()??string.Empty;
            var provider=document.Descendants().FirstOrDefault(x=>x.Name.LocalName.Equals("Provider",StringComparison.OrdinalIgnoreCase))?.Attributes().FirstOrDefault(x=>x.Name.LocalName.Equals("Name",StringComparison.OrdinalIgnoreCase))?.Value??"Sysmon";
            var formatted=Format(provider,eventId,values);if(formatted.Length==0)return item;
            values.TryGetValue("TargetObject",out var target);
            if(IsLegacyMitigationFalsePositive(item,target))return item with
            {
                Severity=Severity.Review,Category="Configuración",Title="Cambio de protección contra exploits (evento heredado)",Evidence=formatted,
                Recommendation="Este valor configura mitigaciones por programa y no demuestra persistencia. Revisa el proceso que realizó el cambio; no aísles archivos basándote solamente en este registro.",Score=Math.Min(item.Score,35)
            };
            return item with { Evidence=formatted };
        }
        catch{return item;}
    }

    static bool IsLegacyMitigationFalsePositive(SecurityEvent item,string? target)
    {
        if(string.IsNullOrWhiteSpace(target)||!target.EndsWith("\\MitigationOptions",StringComparison.OrdinalIgnoreCase))return false;
        return item.Title.Equals("GX-SIGMA-PERSISTENCE-REGISTRY",StringComparison.OrdinalIgnoreCase)||item.Title.Equals("Cambio de inicio automático en registro",StringComparison.OrdinalIgnoreCase);
    }

    static string Format(string provider,string eventId,IReadOnlyDictionary<string,string> values)
    {
        var rows=new List<string>();Add(rows,"Proveedor",provider);Add(rows,"Evento",eventId);Add(rows,"Proceso",Value(values,"Image"));Add(rows,"PID",Value(values,"ProcessId"));Add(rows,"Usuario",Value(values,"User"));Add(rows,"Acción",Value(values,"EventType"));Add(rows,"Objetivo",Value(values,"TargetObject"));Add(rows,"Valor",Value(values,"Details"));Add(rows,"Comando",Value(values,"CommandLine"));Add(rows,"Destino",Value(values,"DestinationIp"));Add(rows,"DNS",Value(values,"QueryName"));return string.Join(Environment.NewLine,rows);
    }
    static string Value(IReadOnlyDictionary<string,string> values,string key)=>values.TryGetValue(key,out var value)?value:string.Empty;
    static void Add(List<string> rows,string label,string value){if(!string.IsNullOrWhiteSpace(value))rows.Add(label+": "+value);}
}

public sealed record AgentState(DateTimeOffset UpdatedAt, bool AgentOnline, int RiskScore,
    string Status, int ProcessesObserved, int Alerts, int Reviews, DateTimeOffset? IntelligenceUpdatedAt,
    int IntelligenceIndicators, List<SecurityEvent> RecentEvents)
{
    public List<EngineHealth> Engines { get; init; } = [];
    public string PrimaryAntivirus { get; init; } = "NO VERIFICADO";
    public bool PrimaryAntivirusActive { get; init; }
    public string CoverageMessage { get; init; } = "Esperando la comprobación de Windows Security Center.";
    public int CorrelatedIncidents { get; init; }
    public static AgentState Empty => new(DateTimeOffset.MinValue, false, 0, "INICIANDO", 0, 0, 0, null, 0, []);
}

public static class AppPaths
{
    public static readonly string Root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GivenXShield");
    public static readonly string State = Path.Combine(Root, "state.json");
    public static readonly string Events = Path.Combine(Root, "events.jsonl");
    public static readonly string AllowList = Path.Combine(Root, "allow-list.json");
    public static readonly string TrustedPublishers = Path.Combine(Root, "trusted-publishers.json");
    public static readonly string DismissedEvents = Path.Combine(Root, "dismissed-events.json");
    public static readonly string ResolvedEvents = Path.Combine(Root, "resolved-events.json");
    public static readonly string ScanHistory = Path.Combine(Root, "scan-history.json");
    public static readonly string TrustedEngines = Path.Combine(AppContext.BaseDirectory, "trusted-engine-hashes.json");
    public static readonly string TrustedBuildArtifacts = Path.Combine(AppContext.BaseDirectory, "trusted-build-artifacts.json");
    public static readonly string Intelligence = Path.Combine(Root, "urlhaus-hosts.txt");
    public static readonly string IntelligenceHashes = Path.Combine(Root, "threatfox-sha256.txt");
    public static readonly string ThreatFoxHosts = Path.Combine(Root, "threatfox-hosts.txt");
    public static readonly string ThreatFoxHostSchema = Path.Combine(Root, "threatfox-hosts.schema");
    public static readonly string ResponseSettings = Path.Combine(Root, "response-settings.json");
    public static readonly string ResponseHistory = Path.Combine(Root, "response-history.json");
    public static void Ensure() => Directory.CreateDirectory(Root);
}

public static class StateStore
{
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    static readonly object EventGate = new();
    public static void WriteState(AgentState state)
    {
        AppPaths.Ensure(); var temp = AppPaths.State + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, Json));
        File.Move(temp, AppPaths.State, true);
    }
    public static AgentState ReadState()
    {
        try { var state=JsonSerializer.Deserialize<AgentState>(File.ReadAllText(AppPaths.State), Json)??AgentState.Empty;return state with{RecentEvents=(state.RecentEvents??[]).Select(LegacyEventCompatibility.Normalize).ToList()}; }
        catch { return AgentState.Empty; }
    }
    public static void Append(SecurityEvent item)
    {
        lock (EventGate)
        {
            AppPaths.Ensure();
            try
            {
                if (File.Exists(AppPaths.Events) && new FileInfo(AppPaths.Events).Length > 25L * 1024 * 1024)
                {
                    var retained = File.ReadLines(AppPaths.Events).Reverse().Take(5000).Reverse().ToArray();
                    var temp = AppPaths.Events + ".tmp"; File.WriteAllLines(temp, retained); File.Move(temp, AppPaths.Events, true);
                }
            }
            catch { }
            File.AppendAllText(AppPaths.Events, JsonSerializer.Serialize(item) + Environment.NewLine);
        }
    }
    public static List<SecurityEvent> ReadEvents(int maximum = 500)
    {
        try
        {
            if (!File.Exists(AppPaths.Events)) return [];
            return File.ReadLines(AppPaths.Events)
                .Reverse()
                .Select(line => { try { return JsonSerializer.Deserialize<SecurityEvent>(line, Json); } catch { return null; } })
                .Where(item => item is not null)
                .Take(Math.Max(1, maximum))
                .Cast<SecurityEvent>()
                .Select(LegacyEventCompatibility.Normalize)
                .ToList();
        }
        catch { return []; }
    }
}
