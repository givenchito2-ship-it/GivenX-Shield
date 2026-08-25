using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Concurrent;
namespace GivenX.Shared;

public interface IFileThreatEngine
{
    string Name { get; }
    Task<EngineResult> ScanAsync(string path, string sha256, CancellationToken cancellationToken);
    EngineHealth Health();
}

public sealed class ThreatOrchestrator
{
    readonly List<IFileThreatEngine> _engines;
    public ThreatOrchestrator() => _engines = [new DefenderEngine(), new YaraEngine(), new VirusTotalEngine(), new YaraifyHashEngine(), new MalwareBazaarHashEngine()];
    public IReadOnlyList<EngineHealth> Health => _engines.Select(x => x.Health()).ToList();
    public async Task<IReadOnlyList<EngineResult>> ScanAsync(string path, CancellationToken cancellationToken = default, bool includeCloud = true, bool includeDefender = true)
    {
        var hash = await HashAsync(path, cancellationToken);
        IEnumerable<IFileThreatEngine> selected = includeCloud ? _engines : _engines.Where(x => x is DefenderEngine or YaraEngine);
        if (!includeDefender) selected = selected.Where(x => x is not DefenderEngine);
        var tasks = selected.Select(x => SafeScan(x, path, hash, cancellationToken));
        return await Task.WhenAll(tasks);
    }
    static async Task<EngineResult> SafeScan(IFileThreatEngine engine, string path, string hash, CancellationToken ct)
    {
        try { return await engine.ScanAsync(path, hash, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new(engine.Name, EngineVerdict.Error, 0, ex.Message, DateTimeOffset.Now); }
    }
    static async Task<string> HashAsync(string path, CancellationToken ct)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 128, true);
        var bytes = await SHA256.HashDataAsync(stream, ct); return Convert.ToHexString(bytes).ToLowerInvariant();
    }
    public static (EngineVerdict Verdict, int Score, string Evidence) Combine(IEnumerable<EngineResult> results)
    {
        var active = results.Where(x => x.Verdict != EngineVerdict.Unavailable && x.Verdict != EngineVerdict.Error).ToList();
        var malicious = active.Count(x => x.Verdict == EngineVerdict.Malicious); var suspicious = active.Count(x => x.Verdict == EngineVerdict.Suspicious);
        var highConfidence = active.Any(x => x.Verdict == EngineVerdict.Malicious && x.Score >= 90);
        var score = Math.Min(100, active.Select(x => x.Score).DefaultIfEmpty(0).Max() + Math.Max(0, malicious - 1) * 15 + Math.Max(0, suspicious - 1) * 5);
        var verdict = highConfidence || malicious >= 2 || (malicious == 1 && suspicious >= 1) ? EngineVerdict.Malicious : malicious == 1 || suspicious >= 1 ? EngineVerdict.Suspicious : active.Count > 0 && active.All(x => x.Verdict == EngineVerdict.Clean) ? EngineVerdict.Clean : EngineVerdict.Unknown;
        var evidence = string.Join(" | ", results.Select(x => $"{x.Engine}: {x.Verdict} ({x.Evidence})")); return (verdict, score, evidence);
    }
}

static class AbuseChCredential
{
    public static string? Load() => SecureSecrets.Load("abusech") ?? SecureSecrets.Load("threatfox");
    public static bool Exists() => !string.IsNullOrWhiteSpace(Load());
}

static class EngineResultCache
{
    static readonly ConcurrentDictionary<string, (DateTimeOffset Time, EngineResult Result)> Values = new(StringComparer.OrdinalIgnoreCase);
    public static bool TryGet(string engine, string hash, out EngineResult result)
    {
        if (Values.TryGetValue(engine + "|" + hash, out var row) && row.Time > DateTimeOffset.Now.AddHours(-12)) { result = row.Result with { Evidence = row.Result.Evidence + " · caché local" }; return true; }
        result = default!; return false;
    }
    public static EngineResult Save(string hash, EngineResult result) { Values[result.Engine + "|" + hash] = (DateTimeOffset.Now, result); return result; }
}

sealed class VirusTotalEngine : IFileThreatEngine
{
    public string Name => "VirusTotal";
    public EngineHealth Health() => new(Name, SecureSecrets.Exists("virustotal"), SecureSecrets.Exists("virustotal") ? "CONFIGURADO" : "REQUIERE CLAVE", DateTimeOffset.Now);
    public async Task<EngineResult> ScanAsync(string path, string sha256, CancellationToken ct)
    {
        var key = SecureSecrets.Load("virustotal"); if (string.IsNullOrWhiteSpace(key)) return Result(EngineVerdict.Unavailable, 0, "requiere clave");
        if (EngineResultCache.TryGet(Name, sha256, out var cached)) return cached;
        using var http = Client(); http.DefaultRequestHeaders.Add("x-apikey", key); using var response = await http.GetAsync($"https://www.virustotal.com/api/v3/files/{sha256}", ct);
        if (response.StatusCode == HttpStatusCode.NotFound) return EngineResultCache.Save(sha256, Result(EngineVerdict.Unknown, 0, "hash desconocido; no se subió el archivo"));
        if (response.StatusCode == HttpStatusCode.TooManyRequests) return Result(EngineVerdict.Unavailable, 0, "límite de API alcanzado");
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) return Result(EngineVerdict.Unavailable, 0, "clave inválida");
        response.EnsureSuccessStatusCode(); using var json = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        var stats = json.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
        var bad = Get(stats,"malicious") + Get(stats,"suspicious"); var harmless = Get(stats,"harmless") + Get(stats,"undetected");
        var verdict = bad >= 3 ? EngineVerdict.Malicious : bad > 0 ? EngineVerdict.Suspicious : EngineVerdict.Clean;
        return EngineResultCache.Save(sha256, Result(verdict, Math.Min(95, bad * 12), $"{bad} detecciones; {harmless} sin detección"));
    }
    static int Get(JsonElement node, string name) => node.TryGetProperty(name, out var value) ? value.GetInt32() : 0;
    EngineResult Result(EngineVerdict v,int s,string e)=>new(Name,v,s,e,DateTimeOffset.Now);
    static HttpClient Client(){var h=new HttpClient{Timeout=TimeSpan.FromSeconds(25)};h.DefaultRequestHeaders.UserAgent.ParseAdd("GivenX-Shield-Beta/1.6.2-R9");return h;}
}

sealed class DefenderEngine : CommandEngine
{
    public override string Name => "Microsoft Defender";
    protected override string? Executable
    {
        get
        {
            var defender = AntivirusProviderDetector.Cached.Providers.FirstOrDefault(x => x.IsMicrosoftDefender);
            return defender?.Enabled == true ? DefenderCommand.FindExecutable() : null;
        }
    }
    public override EngineHealth Health()
    {
        var snapshot = AntivirusProviderDetector.Cached; var defender = snapshot.Providers.FirstOrDefault(x => x.IsMicrosoftDefender);
        if (!snapshot.QuerySucceeded) return new(Name, false, "ESTADO NO VERIFICADO", DateTimeOffset.Now);
        if (defender is null) return new(Name, false, "NO REGISTRADO", DateTimeOffset.Now);
        return new(Name, defender.Enabled && DefenderCommand.IsAvailable, defender.Enabled ? "ACTIVO" : "MODO PASIVO", DateTimeOffset.Now);
    }
    protected override IEnumerable<string> Arguments(string path) => ["-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"];
    protected override EngineResult Interpret(int code,string output)
    {
        if (code == 0) return Result(EngineVerdict.Clean, 0, "examen completado sin acción pendiente");
        if (code == 2 && ContainsExplicitThreat(output))
            return Result(EngineVerdict.Suspicious, 70, $"Defender informó una detección que requiere revisión: {Trim(output)}");
        return Result(EngineVerdict.Error, 0, $"Defender no pudo concluir el examen (código {code}): {Trim(output)}");
    }
    static bool ContainsExplicitThreat(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return false;
        var text = output.ToLowerInvariant();
        if (new[] { "no threats", "no threat", "no malware", "ninguna amenaza", "no se encontraron amenazas" }.Any(token => text.Contains(token))) return false;
        return new[] { "threat information", "threat name", "threat detected", "found threat", "malware detected", "amenaza detectada", "amenazas detectadas", "malware detectado", "se encontró malware", "se encontro malware" }.Any(token => text.Contains(token));
    }
}

sealed class YaraifyHashEngine : IFileThreatEngine
{
    public string Name => "YARAify (hash)";
    public EngineHealth Health() => new(Name, AbuseChCredential.Exists(), AbuseChCredential.Exists() ? "CONFIGURADO" : "REQUIERE AUTH-KEY", DateTimeOffset.Now);
    public async Task<EngineResult> ScanAsync(string path, string sha256, CancellationToken ct)
    {
        var key = AbuseChCredential.Load();
        if (string.IsNullOrWhiteSpace(key)) return Result(EngineVerdict.Unavailable, 0, "requiere Auth-Key de abuse.ch");
        if (EngineResultCache.TryGet(Name, sha256, out var cached)) return cached;
        using var http = Client();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://yaraify-api.abuse.ch/api/v1/");
        request.Headers.Add("Auth-Key", key);
        request.Content = JsonContent.Create(new { query = "lookup_hash", search_term = sha256 });
        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.TooManyRequests) return Result(EngineVerdict.Unavailable, 0, "límite de API alcanzado");
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) return Result(EngineVerdict.Unavailable, 0, "Auth-Key inválida");
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        var status = json.RootElement.TryGetProperty("query_status", out var value) ? value.GetString() : null;
        if (!string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase)) return EngineResultCache.Save(sha256, Result(EngineVerdict.Unknown, 0, status ?? "hash sin información"));
        if (!json.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object)
            return EngineResultCache.Save(sha256, Result(EngineVerdict.Unknown, 0, "hash conocido sin resultados de análisis"));
        var clamMatches = 0; var suspiciousRules = 0;
        if (data.TryGetProperty("clamav_results", out var clam) && clam.ValueKind == JsonValueKind.Array) clamMatches = clam.GetArrayLength();
        if (data.TryGetProperty("static_results", out var rules) && rules.ValueKind == JsonValueKind.Array)
            foreach (var rule in rules.EnumerateArray()) if (rule.TryGetProperty("rule_name", out var name) && LooksMalicious(name.GetString())) suspiciousRules++;
        if (clamMatches == 0 && suspiciousRules == 0) return EngineResultCache.Save(sha256, Result(EngineVerdict.Unknown, 0, "hash conocido; sin coincidencias maliciosas de alta confianza"));
        return EngineResultCache.Save(sha256, Result(EngineVerdict.Suspicious, Math.Min(85, 50 + clamMatches * 5 + suspiciousRules * 5), $"{clamMatches} firmas; {suspiciousRules} reglas maliciosas"));
    }
    static bool LooksMalicious(string? name) => !string.IsNullOrWhiteSpace(name) && new[] { "malware", "trojan", "ransom", "stealer", "keylog", "backdoor", "rat", "miner", "banker", "credential" }.Any(x => name.Contains(x, StringComparison.OrdinalIgnoreCase));
    EngineResult Result(EngineVerdict verdict, int score, string evidence) => new(Name, verdict, score, evidence, DateTimeOffset.Now);
    static HttpClient Client(){var h=new HttpClient{Timeout=TimeSpan.FromSeconds(25)};h.DefaultRequestHeaders.UserAgent.ParseAdd("GivenX-Shield-Beta/1.6.2-R9");return h;}
}

sealed class MalwareBazaarHashEngine : IFileThreatEngine
{
    public string Name => "MalwareBazaar (hash)";
    public EngineHealth Health() => new(Name, AbuseChCredential.Exists(), AbuseChCredential.Exists() ? "CONFIGURADO" : "REQUIERE AUTH-KEY", DateTimeOffset.Now);
    public async Task<EngineResult> ScanAsync(string path, string sha256, CancellationToken ct)
    {
        var key = AbuseChCredential.Load();
        if (string.IsNullOrWhiteSpace(key)) return Result(EngineVerdict.Unavailable, 0, "requiere Auth-Key de abuse.ch");
        if (EngineResultCache.TryGet(Name, sha256, out var cached)) return cached;
        using var http = Client();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://mb-api.abuse.ch/api/v1/");
        request.Headers.Add("Auth-Key", key);
        request.Content = new FormUrlEncodedContent(new Dictionary<string,string> { ["query"] = "get_info", ["hash"] = sha256 });
        using var response = await http.SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.TooManyRequests) return Result(EngineVerdict.Unavailable, 0, "límite de API alcanzado");
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) return Result(EngineVerdict.Unavailable, 0, "Auth-Key inválida");
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(ct));
        var status = json.RootElement.TryGetProperty("query_status", out var value) ? value.GetString() : null;
        if (string.Equals(status, "hash_not_found", StringComparison.OrdinalIgnoreCase)) return EngineResultCache.Save(sha256, Result(EngineVerdict.Unknown, 0, "hash desconocido"));
        if (!string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase)) return EngineResultCache.Save(sha256, Result(EngineVerdict.Unknown, 0, status ?? "sin información"));
        return EngineResultCache.Save(sha256, Result(EngineVerdict.Malicious, 95, "hash catalogado por MalwareBazaar"));
    }
    EngineResult Result(EngineVerdict verdict, int score, string evidence) => new(Name, verdict, score, evidence, DateTimeOffset.Now);
    static HttpClient Client(){var h=new HttpClient{Timeout=TimeSpan.FromSeconds(25)};h.DefaultRequestHeaders.UserAgent.ParseAdd("GivenX-Shield-Beta/1.6.2-R9");return h;}
}

sealed class YaraEngine : CommandEngine
{
    public override string Name => "YARA";
    static string InstalledExecutable => Path.Combine(AppContext.BaseDirectory,"engines","yara","yara64.exe");
    protected override string? Executable => EngineTrustStore.ContainsFile(InstalledExecutable) ? InstalledExecutable : null;
    protected override IEnumerable<string> Arguments(string path) { var rules=Path.Combine(AppContext.BaseDirectory,"rules","givenx-index.yar"); return ["-w", rules, path]; }
    public override EngineHealth Health(){var rules=Path.Combine(AppContext.BaseDirectory,"rules","givenx-index.yar");var installed=File.Exists(InstalledExecutable);var trusted=installed&&EngineTrustStore.ContainsFile(InstalledExecutable);return new(Name,trusted&&File.Exists(rules),!installed?"NO INSTALADO":!trusted?"REQUIERE VERIFICACIÓN":!File.Exists(rules)?"SIN REGLAS":"ACTIVO",DateTimeOffset.Now);}
    protected override EngineResult Interpret(int code,string output)
    {
        if (code != 0) return Result(EngineVerdict.Error, 0, $"código {code}: {Trim(output)}");
        if (string.IsNullOrWhiteSpace(output)) return Result(EngineVerdict.Clean, 0, "sin coincidencias");
        if (output.Contains("GivenX_Safe_SelfTest", StringComparison.OrdinalIgnoreCase) && output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length == 1)
            return Result(EngineVerdict.Clean, 0, "marcador de diagnóstico inofensivo detectado");
        var high = new[] { "Credential_Dumper", "Browser_Stealer", "Browser_Extension_Theft", "Ransomware", "Security_Tampering", "Token_Stealer" }.Any(x => output.Contains(x, StringComparison.OrdinalIgnoreCase));
        return Result(EngineVerdict.Suspicious, high ? 82 : 58, Trim(output));
    }
}

abstract class CommandEngine : IFileThreatEngine
{
    public abstract string Name {get;} protected abstract string? Executable {get;} protected abstract IEnumerable<string> Arguments(string path); protected abstract EngineResult Interpret(int code,string output);
    public virtual EngineHealth Health()=>new(Name,Executable is not null,Executable is null?"NO INSTALADO":"ACTIVO",DateTimeOffset.Now);
    public async Task<EngineResult> ScanAsync(string path,string sha256,CancellationToken ct)
    {
        var exe=Executable;if(exe is null)return Result(EngineVerdict.Unavailable,0,"motor no instalado");
        var start=new ProcessStartInfo(exe){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true};foreach(var arg in Arguments(path))start.ArgumentList.Add(arg);
        using var process=Process.Start(start);if(process is null)return Result(EngineVerdict.Error,0,"no se pudo iniciar");
        var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        try{await process.WaitForExitAsync(ct);}catch(OperationCanceledException){try{process.Kill(true);}catch{}throw;}
        return Interpret(process.ExitCode,(await stdout)+" "+(await stderr));
    }
    protected EngineResult Result(EngineVerdict verdict,int score,string evidence)=>new(Name,verdict,score,evidence,DateTimeOffset.Now);
    protected static string Trim(string text)
    {
        var value = text.Replace('\r',' ').Replace('\n',' ').Trim();
        return value.Length > 300 ? value[..300] : value;
    }
    protected static string? Find(params string[] candidates)
    {
        foreach(var candidate in candidates)if(Path.IsPathRooted(candidate)&&File.Exists(candidate))return candidate;
        foreach(var candidate in candidates.Where(x=>!Path.IsPathRooted(x)))try{var path=Environment.GetEnvironmentVariable("PATH")?.Split(Path.PathSeparator).Select(x=>Path.Combine(x,candidate)).FirstOrDefault(File.Exists);if(path is not null)return path;}catch{}
        return null;
    }
}
