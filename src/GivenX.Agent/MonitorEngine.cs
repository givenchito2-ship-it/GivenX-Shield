using System.Diagnostics;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using GivenX.Shared;

namespace GivenX.Agent;

public sealed class MonitorEngine : IDisposable
{
    readonly HashSet<int> _seen = [];
    readonly HashSet<string> _scannedFiles = new(StringComparer.OrdinalIgnoreCase);
    readonly Queue<string> _scannedOrder = [];
    readonly ConcurrentDictionary<string, SecurityEvent> _events = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<string, byte> _autoHandledAddresses = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<string, byte> _pendingFiles = new(StringComparer.OrdinalIgnoreCase);
    readonly Channel<string> _fileAnalysisQueue = Channel.CreateBounded<string>(new BoundedChannelOptions(2048)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = false,
        SingleWriter = false
    });
    readonly List<FileSystemWatcher> _watchers = [];
    readonly string[] _remoteTools = ["anydesk", "teamviewer", "rustdesk", "screenconnect", "aeroadmin", "supremo", "dwagent", "meshagent"];
    readonly string[] _knownThreatNames = ["xmrig", "minerd", "ethminer", "njrat", "nanocore", "remcos", "asyncrat", "quasar", "darkcomet"];
    readonly ThreatOrchestrator _orchestrator = new();
    readonly BehaviorMonitor _behavior = new();
    readonly IntegrityMonitor _integrity = new();
    readonly CorrelationEngine _correlation = new();
    int _observed;
    readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(45) };
    readonly HashSet<string> _urlhausHosts = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _threatFoxHosts = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _maliciousHashes = new(StringComparer.OrdinalIgnoreCase);
    readonly object _intelligenceGate = new();
    readonly object _renameGate = new();
    readonly object _fileQueueGate = new();
    readonly Queue<DateTimeOffset> _documentRenames = [];
    DateTimeOffset _lastRenameAlert = DateTimeOffset.MinValue;
    DateTimeOffset _lastFileQueueOverflow = DateTimeOffset.MinValue;
    DateTimeOffset _lastAutoResolveSweep = DateTimeOffset.MinValue;
    DateTimeOffset? _intelligenceUpdated;
    DateTimeOffset? _urlhausUpdated, _threatFoxUpdated;
    bool? _previousAntivirusActive;
    string? _previousPrimaryAntivirus;

    public MonitorEngine()
    {
        AppPaths.Ensure();
        var recentEvents = StateStore.ReadEvents(500).Where(x => x.Time > DateTimeOffset.Now.AddHours(-24)).ToList();
        ResolvedEventStore.AddRange(recentEvents.Where(BuildArtifactTrustStore.IsAutomaticallyResolvedEvent).Select(x => x.Fingerprint));
        foreach (var item in recentEvents)
            _events.TryAdd(item.Fingerprint, item);
        Watch(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads");
        Watch(Path.GetTempPath());
        Watch(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        Watch(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        Watch(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
        for (var i = 0; i < 3; i++) _ = FileAnalysisWorkerAsync();
    }

    public async Task RunAsync()
    {
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("GivenX-Shield-Beta/1.6.2-R9 defensive-security");
        LoadIntelligenceCache();
        await AntivirusProviderDetector.RefreshAsync(true);
        Add(Severity.Info, "Sistema", "Monitor residente iniciado", Environment.MachineName, "GivenX Shield vigila actividad nueva.", 0);
        _ = UpdateIntelligenceLoopAsync();
        while (true)
        {
            try
            {
                await AntivirusProviderDetector.RefreshAsync();
                InspectAntivirusState(); InspectProcesses(); InspectKnownBadConnections(); foreach(var finding in _behavior.Poll(DnsIntelligenceHosts()).Concat(_integrity.Poll())) Add(finding.Severity,finding.Category,finding.Title,finding.Evidence,finding.Recommendation,finding.Score); Publish();
            }
            catch { }
            await Task.Delay(TimeSpan.FromSeconds(4));
        }
    }

    void Watch(string path)
    {
        if (!Directory.Exists(path)) return;
        var watcher = new FileSystemWatcher(path)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
            InternalBufferSize = 64 * 1024
        };
        watcher.Created += (_, e) => InspectNewFile(e.FullPath);
        watcher.Renamed += (_, e) => InspectRename(e.OldFullPath, e.FullPath);
        watcher.Error += (_, e) => Add(
            Severity.Review,
            "Archivos",
            "El monitor de archivos perdió eventos",
            $"Ruta vigilada: {path}\nError: {e.GetException()?.Message ?? "desconocido"}",
            "Ejecuta un análisis unificado si hubo mucha actividad de archivos. GivenX seguirá vigilando los eventos nuevos.",
            55);
        watcher.EnableRaisingEvents = true; _watchers.Add(watcher);
    }

    void InspectNewFile(string path)
    {
        string fullPath;
        try { fullPath = Path.GetFullPath(path); }
        catch { return; }
        if (!_pendingFiles.TryAdd(fullPath, 0)) return;
        if (_fileAnalysisQueue.Writer.TryWrite(fullPath)) return;

        _pendingFiles.TryRemove(fullPath, out _);
        lock (_fileQueueGate)
        {
            var now = DateTimeOffset.Now;
            if (_lastFileQueueOverflow >= now.AddMinutes(-2)) return;
            _lastFileQueueOverflow = now;
            Add(Severity.Review, "Archivos", "Cola de análisis de archivos saturada",
                "La actividad de archivos superó temporalmente la capacidad de análisis en tiempo real.",
                "Ejecuta un análisis unificado cuando termine la copia, instalación o compilación que generó la ráfaga.", 55);
        }
    }

    async Task FileAnalysisWorkerAsync()
    {
        await foreach (var path in _fileAnalysisQueue.Reader.ReadAllAsync())
        {
            try { await AnalyzeNewFileAsync(path); }
            finally { _pendingFiles.TryRemove(path, out _); }
        }
    }

    void InspectRename(string oldPath, string newPath)
    {
        InspectNewFile(newPath);
        if (!IsPersonalDocument(oldPath) || Path.GetExtension(oldPath).Equals(Path.GetExtension(newPath), StringComparison.OrdinalIgnoreCase)) return;
        lock (_renameGate)
        {
            var now = DateTimeOffset.Now; _documentRenames.Enqueue(now);
            while (_documentRenames.Count > 0 && _documentRenames.Peek() < now.AddSeconds(-20)) _documentRenames.Dequeue();
            if (_documentRenames.Count >= 25 && _lastRenameAlert < now.AddMinutes(-2))
            {
                _lastRenameAlert = now;
                Add(Severity.Alert, "Archivos", "Cambio masivo de documentos", $"{_documentRenames.Count} documentos cambiaron de extensión en menos de 20 segundos.\nEjemplo: {oldPath} -> {newPath}", "Posible cifrado masivo. Pausa la actividad que lo originó y desconecta Internet si no reconoces el proceso.", 92);
            }
        }
    }

    async Task AnalyzeNewFileAsync(string path)
    {
        try
        {
            await Task.Delay(1200);
            if (LooksLikeCredentialStaging(path) && File.Exists(path))
                Add(Severity.Review, "Credenciales", "Posible copia temporal de datos del navegador", path, "Comprueba qué proceso creó esta copia. Los navegadores legítimos guardan estos archivos dentro de su propio perfil, no en Temp, Descargas o Public.", 78);
            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext is not (".exe" or ".dll" or ".scr" or ".msi" or ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js")) return;
            var engineStaging = IsGivenXEngineStagingPath(path);
            if (engineStaging) await Task.Delay(4000);
            if (!File.Exists(path)) return;
            var identity = $"{path}|{File.GetLastWriteTimeUtc(path).Ticks}|{new System.IO.FileInfo(path).Length}";
            lock (_scannedFiles)
            {
                if (!_scannedFiles.Add(identity)) return;
                _scannedOrder.Enqueue(identity);
                while (_scannedOrder.Count > 20_000) _scannedFiles.Remove(_scannedOrder.Dequeue());
            }
            var hash = TryHash(path);
            if (KnownMaliciousHash(hash)) { Add(Severity.Alert,"Archivo","Hash confirmado por inteligencia de amenazas",$"{path}\nSHA-256: {hash}","No lo abras. Aísla el archivo y ejecuta un análisis completo.",100); return; }
            if (BuildArtifactTrustStore.Contains(hash)) return;
            if (engineStaging && EngineTrustStore.Contains(hash)) return;
            var signatureTrusted = (ext is ".exe" or ".dll" or ".msi") && FileSignatureTrust.IsTrusted(path);
            var publisher = signatureTrusted ? FileSignatureTrust.TrustedPublisher(path) : null;
            if (publisher is not null && TrustedPublisherStore.Contains(publisher)) return;
            var score = ext is ".scr" or ".vbs" or ".js" ? 30 : 15;
            if (path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase)) score += 20;
            if (HasDoubleExtension(path)) score += 35;
            if (signatureTrusted) score = Math.Max(0, score - 15);
            if (AllowListStore.Contains(hash)) return;
            IReadOnlyList<EngineResult> results = await _orchestrator.ScanAsync(path, includeCloud: false); var combined = ThreatOrchestrator.Combine(results);
            if (score >= 35 || combined.Verdict is EngineVerdict.Suspicious or EngineVerdict.Malicious)
            {
                results = await _orchestrator.ScanAsync(path, includeCloud: true); combined = ThreatOrchestrator.Combine(results);
            }
            var finalScore = Math.Max(score, combined.Score);
            if (finalScore < 25 && combined.Verdict is (EngineVerdict.Clean or EngineVerdict.Unknown)) return;
            var severity = combined.Verdict == EngineVerdict.Malicious ? Severity.Alert : finalScore >= 30 || combined.Verdict == EngineVerdict.Suspicious ? Severity.Review : Severity.Info;
            var publisherText = publisher is null ? "sin editor verificado" : "editor: " + publisher;
            Add(severity, "Archivo", combined.Verdict == EngineVerdict.Malicious ? "Amenaza confirmada por reputación o varios motores" : "Archivo nuevo que requiere revisión", $"{path}\nSHA-256: {hash}\nFirma: {publisherText}\n{combined.Evidence}", combined.Verdict == EngineVerdict.Malicious ? "No lo abras. Revisa la evidencia antes de enviarlo a cuarentena." : "Confirma su origen si no lo reconoces.", finalScore);
        }
        catch { }
    }

    void InspectProcesses()
    {
        var processes = Process.GetProcesses();
        var activeIds = processes.Select(x => x.Id).ToHashSet();
        _seen.RemoveWhere(id => !activeIds.Contains(id));
        foreach (var process in processes)
        {
            using (process)
            {
                if (!_seen.Add(process.Id)) continue; _observed++;
                try
                {
                    var name = process.ProcessName.ToLowerInvariant();
                    var path = process.MainModule?.FileName ?? "";
                    var userWritable=IsUserWritableExecution(path);var interestingName=_knownThreatNames.Contains(name)||_remoteTools.Any(x=>name.Contains(x));var hash=userWritable||interestingName?TryHash(path):string.Empty;
                    var publisher=userWritable||interestingName?FileSignatureTrust.TrustedPublisher(path):null;
                    if (KnownMaliciousHash(hash))
                        Add(Severity.Alert, "Proceso", "Proceso confirmado por inteligencia de amenazas", $"{name} | PID {process.Id} | {path}\nSHA-256: {hash}", "Desconecta Internet, aísla el archivo y analiza el equipo con tu antivirus principal.", 100);
                    else if ((!string.IsNullOrWhiteSpace(hash) && (AllowListStore.Contains(hash) || BuildArtifactTrustStore.Contains(hash))) || (publisher is not null && TrustedPublisherStore.Contains(publisher)))
                        continue;
                    else if (_knownThreatNames.Contains(name))
                        Add(Severity.Review, "Proceso", "Nombre relacionado con RAT, bot o minero", $"{name} | PID {process.Id} | {path}\nEl nombre por sí solo no confirma malware.", "Comprueba la firma, el hash y el origen antes de actuar.", 65);
                    else if (_remoteTools.Any(x => name.Contains(x)))
                        Add(Severity.Review, "Acceso remoto", "Herramienta de control remoto activa", $"{name} | PID {process.Id} | {path}", "Si tú no la instalaste o abriste, desconecta Internet y revisa tus cuentas.", 50);
                else if (userWritable && publisher is null)
                        Add(Severity.Review, "Proceso", "Programa iniciado desde carpeta sensible", $"{name} | PID {process.Id} | {path}\nSHA-256: {TryHash(path)}", "Confirma que reconoces el archivo antes de permitirlo.", 40);
                }
                catch { }
            }
        }
    }

    void InspectAntivirusState()
    {
        var snapshot=AntivirusProviderDetector.Cached;if(!snapshot.QuerySucceeded)return;var primary=snapshot.Primary;var active=primary?.Enabled==true;var name=primary?.Name??"Ninguno";
        if(_previousAntivirusActive is null){_previousAntivirusActive=active;_previousPrimaryAntivirus=name;if(!active)Add(Severity.Review,"Protección","No hay antivirus principal activo",$"Windows Security Center informa: {name}","Activa un antivirus confiable antes de descargar o ejecutar archivos.",75);return;}
        if(_previousAntivirusActive==true&&!active)Add(Severity.Alert,"Protección","El antivirus principal dejó de estar activo",$"Proveedor anterior: {_previousPrimaryAntivirus}\nEstado actual: {name}","No ejecutes archivos nuevos. Abre Seguridad de Windows y reactiva tu proveedor.",95);
        else if(!string.Equals(_previousPrimaryAntivirus,name,StringComparison.OrdinalIgnoreCase))Add(Severity.Review,"Protección","Cambió el antivirus principal",$"Anterior: {_previousPrimaryAntivirus}\nActual: {name}","Confirma que instalaste o cambiaste este proveedor voluntariamente.",65);
        _previousAntivirusActive=active;_previousPrimaryAntivirus=name;
    }

    void Add(Severity severity, string category, string title, string evidence, string recommendation, int score)
    {
        var fingerprint = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(category + title + evidence))).Substring(0, 16);
        var item = new SecurityEvent(DateTimeOffset.Now, severity, category, title, evidence, recommendation, score, fingerprint);

        // Trusted/known-benign activity should disappear immediately, not only after an agent restart.
        if (BuildArtifactTrustStore.IsAutomaticallyResolvedEvent(item))
        {
            ResolvedEventStore.Add(item.Fingerprint);
            _events.TryRemove(item.Fingerprint, out _);
            return;
        }

        if (!_events.TryAdd(fingerprint, item)) return;
        StateStore.Append(item);
        var correlated = _correlation.Observe(item);
        if (correlated is not null && _events.TryAdd(correlated.Fingerprint, correlated)) StateStore.Append(correlated);
    }

    void Publish()
    {
        var expiration=DateTimeOffset.Now.AddDays(-7);foreach(var pair in _events.Where(x=>x.Value.Time<expiration))_events.TryRemove(pair.Key,out _);
        if(_events.Count>2000)foreach(var pair in _events.OrderByDescending(x=>x.Value.Time).Skip(2000).ToList())_events.TryRemove(pair.Key,out _);

        if (_lastAutoResolveSweep < DateTimeOffset.Now.AddMinutes(-1))
        {
            _lastAutoResolveSweep = DateTimeOffset.Now;
            var autoResolved = _events.Values
                .Where(BuildArtifactTrustStore.IsAutomaticallyResolvedEvent)
                .Select(x => x.Fingerprint)
                .ToList();
            ResolvedEventStore.AddRange(autoResolved);
        }

        var dismissed = DismissedEventStore.Read();var resolved=ResolvedEventStore.Read();
        var recent = _events.Values.Where(x => !dismissed.Contains(x.Fingerprint)&&!resolved.Contains(x.Fingerprint)).OrderByDescending(x => x.Time).Take(100).ToList();
        var active = recent.Where(x => x.Time > DateTimeOffset.Now.AddHours(-24)).ToList();
        var risk = active.Select(x => x.Score).DefaultIfEmpty(0).Max();
        var alerts = active.Count(x => x.Severity == Severity.Alert); var reviews = active.Count(x => x.Severity == Severity.Review);
        var antivirus = AntivirusProviderDetector.Cached; var primary = antivirus.Primary;
        var antivirusActive = antivirus.QuerySucceeded && primary?.Enabled == true;
        var status = alerts > 0 ? "PELIGRO" : reviews > 0 ? "REVISAR" : !antivirus.QuerySucceeded ? "VERIFICAR" : !antivirusActive ? "COBERTURA PARCIAL" : "VIGILANDO";
        var abuseConfigured=!string.IsNullOrWhiteSpace(LoadAbuseChKey());
        var health=_orchestrator.Health.ToList();
        health.Insert(0,new("Antivirus principal",antivirusActive,!antivirus.QuerySucceeded?"NO VERIFICADO":primary is null?"NO REGISTRADO":$"{primary.Name} · {primary.Status}",DateTimeOffset.Now));
        health.Add(RulePackHealth());
        int hostCount,urlhausCount,threatFoxHostCount,hashCount;lock(_intelligenceGate){hostCount=_urlhausHosts.Concat(_threatFoxHosts).Distinct(StringComparer.OrdinalIgnoreCase).Count();urlhausCount=_urlhausHosts.Count;threatFoxHostCount=_threatFoxHosts.Count;hashCount=_maliciousHashes.Count;}
        var urlhausFresh=_urlhausUpdated.HasValue&&_urlhausUpdated.Value>DateTimeOffset.Now.AddMinutes(-30);var threatFoxFresh=_threatFoxUpdated.HasValue&&_threatFoxUpdated.Value>DateTimeOffset.Now.AddMinutes(-30);
        health.Add(new("Sysmon",_behavior.SysmonAvailable,_behavior.SysmonAvailable?"ACTIVO":"NO INSTALADO",DateTimeOffset.Now));
        health.Add(new("URLhaus",abuseConfigured&&urlhausFresh,!abuseConfigured?"REQUIERE AUTH-KEY":urlhausFresh?$"{urlhausCount:N0} HOSTS":"CACHÉ · ACTUALIZACIÓN PENDIENTE",DateTimeOffset.Now));
        health.Add(new("ThreatFox",abuseConfigured&&threatFoxFresh,!abuseConfigured?"REQUIERE AUTH-KEY":threatFoxFresh?$"{threatFoxHostCount:N0} HOSTS · {hashCount:N0} HASHES":"CACHÉ · ACTUALIZACIÓN PENDIENTE",DateTimeOffset.Now));
        var autoResponse=ResponseConfigurationStore.Read().AutoBlockConfirmedConnections;health.Add(new("Respuesta automática",autoResponse,autoResponse?"BLOQUEO DE IP CONFIRMADA":"MANUAL",DateTimeOffset.Now));
        var coverage = !antivirus.QuerySucceeded ? "Windows Security Center no respondió; el estado del antivirus no está confirmado." : primary is null ? "Windows no registra un antivirus principal activo." : primary.Enabled ? $"{primary.Name} aporta la protección antivirus principal; GivenX añade radar y correlación." : $"{primary.Name} aparece registrado pero no activo.";
        var state = new AgentState(DateTimeOffset.Now, true, risk, status, _observed, alerts, reviews, _intelligenceUpdated, hostCount + hashCount, recent)
        {
            Engines = health, PrimaryAntivirus = primary?.Name ?? "NO DETECTADO", PrimaryAntivirusActive = antivirusActive,
            CoverageMessage = coverage, CorrelatedIncidents = recent.Count(x => x.Category.Equals("Correlación", StringComparison.OrdinalIgnoreCase)),
            AgentVersion = "1.6.2-R9-HF4"
        };
        StateStore.WriteState(state);
    }

    async Task UpdateIntelligenceLoopAsync()
    {
        while (true)
        {
            try
            {
                var key=LoadAbuseChKey();
                if(!string.IsNullOrWhiteSpace(key))
                {
                    await UpdateUrlhausAsync(key);
                    await UpdateThreatFoxAsync(key);
                }
            }
            catch { }
            await Task.Delay(string.IsNullOrWhiteSpace(LoadAbuseChKey()) ? TimeSpan.FromSeconds(10) : TimeSpan.FromMinutes(10));
        }
    }

    async Task UpdateUrlhausAsync(string key)
    {
        var endpoint=$"https://urlhaus-api.abuse.ch/v2/files/exports/{Uri.EscapeDataString(key)}/recent.csv";
        using var response=await _http.GetAsync(endpoint);if(!response.IsSuccessStatusCode)return;
        var text=await response.Content.ReadAsStringAsync();var hosts=ParseHosts(text);if(hosts.Count==0)return;
        string[] snapshot;lock(_intelligenceGate){_urlhausHosts.Clear();foreach(var host in hosts)_urlhausHosts.Add(host);snapshot=_urlhausHosts.OrderBy(x=>x).ToArray();}
        File.WriteAllLines(AppPaths.Intelligence,snapshot);_urlhausUpdated=DateTimeOffset.Now;_intelligenceUpdated=DateTimeOffset.Now;
    }

    async Task UpdateThreatFoxAsync(string key)
    {
        using var request=new HttpRequestMessage(HttpMethod.Post,"https://threatfox-api.abuse.ch/api/v1/");request.Headers.Add("Auth-Key",key);request.Content=JsonContent.Create(new{query="get_iocs",days=1});
        using var response=await _http.SendAsync(request);if(!response.IsSuccessStatusCode)return;using var json=JsonDocument.Parse(await response.Content.ReadAsStreamAsync());
        if(!json.RootElement.TryGetProperty("data",out var data)||data.ValueKind!=JsonValueKind.Array)return;
        var currentHashes=new HashSet<string>(StringComparer.OrdinalIgnoreCase);var currentHosts=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var row in data.EnumerateArray())
        {
            var ioc=row.TryGetProperty("ioc",out var i)?i.GetString():null;var type=row.TryGetProperty("ioc_type",out var t)?t.GetString():null;if(string.IsNullOrWhiteSpace(ioc))continue;
            if(type is "sha256_hash")currentHashes.Add(ioc);
            else if(type is "domain" or "ip:port")
            {
                var host=NormalizeHost(ioc);if(!string.IsNullOrWhiteSpace(host))currentHosts.Add(host);
            }
        }
        string[] hashes,hosts;lock(_intelligenceGate){_maliciousHashes.Clear();foreach(var hash in currentHashes)_maliciousHashes.Add(hash);_threatFoxHosts.Clear();foreach(var host in currentHosts)_threatFoxHosts.Add(host);hashes=_maliciousHashes.OrderBy(x=>x).ToArray();hosts=_threatFoxHosts.OrderBy(x=>x).ToArray();}File.WriteAllLines(AppPaths.IntelligenceHashes,hashes);File.WriteAllLines(AppPaths.ThreatFoxHosts,hosts);File.WriteAllText(AppPaths.ThreatFoxHostSchema,"exact-domain-ip-v2");_threatFoxUpdated=DateTimeOffset.Now;_intelligenceUpdated=DateTimeOffset.Now;
    }

    void LoadIntelligenceCache()
    {
        try { lock(_intelligenceGate)foreach (var line in File.ReadLines(AppPaths.Intelligence)) if (!string.IsNullOrWhiteSpace(line)) _urlhausHosts.Add(line.Trim()); _urlhausUpdated = File.GetLastWriteTimeUtc(AppPaths.Intelligence); _intelligenceUpdated = _urlhausUpdated; }
        catch { }
        try { lock(_intelligenceGate)foreach (var line in File.ReadLines(AppPaths.IntelligenceHashes)) if (!string.IsNullOrWhiteSpace(line)) _maliciousHashes.Add(line.Trim()); _threatFoxUpdated = File.GetLastWriteTimeUtc(AppPaths.IntelligenceHashes); if(_intelligenceUpdated is null||_threatFoxUpdated.Value>_intelligenceUpdated.Value)_intelligenceUpdated=_threatFoxUpdated; }
        catch { }
        try { if(File.ReadAllText(AppPaths.ThreatFoxHostSchema).Trim().Equals("exact-domain-ip-v2",StringComparison.Ordinal)){lock(_intelligenceGate)foreach (var line in File.ReadLines(AppPaths.ThreatFoxHosts)) if (!string.IsNullOrWhiteSpace(line)) _threatFoxHosts.Add(line.Trim());} }
        catch { }
    }

    static HashSet<string> ParseHosts(string text)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Regex.Matches(text,@"https?://[^\s,\""']+",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant))
        {
            var value=match.Value.TrimEnd('.',')',']','}');
            if (Uri.TryCreate(value, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host)) result.Add(uri.Host);
        }
        return result;
    }

    static string? LoadAbuseChKey()=>SecureSecrets.Load("abusech")??SecureSecrets.Load("threatfox");

    static string? NormalizeHost(string value)
    {
        value=value.Trim();
        if(Uri.TryCreate(value,UriKind.Absolute,out var uri)&&!string.IsNullOrWhiteSpace(uri.Host))return uri.Host.TrimEnd('.');
        if(System.Net.IPAddress.TryParse(value.Trim('[',']'),out _))return value.Trim('[',']');
        var host=value;
        if(value.StartsWith('[')&&value.Contains(']'))host=value[1..value.IndexOf(']')];
        else if(value.Count(x=>x==':')==1)host=value[..value.LastIndexOf(':')];
        host=host.Trim().TrimEnd('.');return host.Length==0?null:host;
    }

    void InspectKnownBadConnections()
    {
        var indicators=IntelligenceHosts();if (indicators.Length == 0) return;
        try
        {
            foreach (var connection in ConnectionInspector.Snapshot().Where(x=>x.IsEstablished))
            {
                var remote = connection.Remote.Address.ToString();
                if (indicators.Contains(remote, StringComparer.OrdinalIgnoreCase))
                {
                    Add(Severity.Alert, "Red", "Proceso conectado con infraestructura maliciosa", $"{connection.ProcessName} (PID {connection.ProcessId}) | {connection.ProcessPath}\nIP remota: {connection.Remote}", "GivenX puede bloquear la IP o contener el proceso desde el detalle del evento.", 100);
                    if(ResponseConfigurationStore.Read().AutoBlockConfirmedConnections&&IsFreshConfirmedAddress(remote)&&FirewallResponse.IsPublicAddress(connection.Remote.Address)&&_autoHandledAddresses.TryAdd(remote,0))_ = AutoBlockAddressAsync(remote,connection);
                }
            }
        }
        catch { }
    }

    async Task AutoBlockAddressAsync(string address,LiveConnection connection)
    {
        try
        {
            var row=await FirewallResponse.BlockRemoteAddressAsync(address);
            Add(Severity.Info,"Respuesta","Conexión maliciosa bloqueada automáticamente",$"{connection.ProcessName} (PID {connection.ProcessId})\nIP remota: {address}\nRegla: {row.RuleName}","El bloqueo es reversible desde CONEXIONES Y RESPUESTA.",20);
        }
        catch(Exception ex)
        {
            _autoHandledAddresses.TryRemove(address,out _);
            ResponseActionStore.Append("Bloqueo automático",address,"ERROR",false,ex.Message);
            Add(Severity.Review,"Respuesta","No se pudo bloquear una IP maliciosa",$"IP remota: {address}\nError: {ex.Message}","Abre GivenX con permisos de administrador y revisa el firewall.",70);
        }
    }

    string[] IntelligenceHosts(){lock(_intelligenceGate)return _urlhausHosts.Concat(_threatFoxHosts).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();}
    string[] DnsIntelligenceHosts(){lock(_intelligenceGate)return _threatFoxHosts.Where(x=>!System.Net.IPAddress.TryParse(x,out _)&&!KnownBenignActivity.IsSharedHostingDomain(x)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();}
    bool IsFreshConfirmedAddress(string address)
    {
        lock(_intelligenceGate)
        {
            var threshold=DateTimeOffset.Now.AddMinutes(-30);
            return (_urlhausUpdated.HasValue&&_urlhausUpdated.Value>threshold&&_urlhausHosts.Contains(address))||(_threatFoxUpdated.HasValue&&_threatFoxUpdated.Value>threshold&&_threatFoxHosts.Contains(address));
        }
    }
    bool KnownMaliciousHash(string hash){lock(_intelligenceGate)return _maliciousHashes.Contains(hash);}
    static EngineHealth RulePackHealth()
    {
        try{var path=Path.Combine(AppContext.BaseDirectory,"rules","givenx-index.yar");if(!File.Exists(path))return new("Reglas GivenX",false,"SIN REGLAS",DateTimeOffset.Now);var count=File.ReadLines(path).Count(x=>x.TrimStart().StartsWith("rule ",StringComparison.Ordinal));return new("Reglas GivenX",count>0,$"PAQUETE 1.6.2-R9 · {count} REGLAS",DateTimeOffset.Now);}catch{return new("Reglas GivenX",false,"NO VERIFICADAS",DateTimeOffset.Now);}
    }

    static bool HasDoubleExtension(string path) => Path.GetFileName(path).Split('.').Length > 2;
    static bool LooksLikeCredentialStaging(string path)
    {
        if (!path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) && !path.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase) && !path.Contains("\\Users\\Public\\", StringComparison.OrdinalIgnoreCase)) return false;
        var name=Path.GetFileName(path);return name.Equals("Login Data",StringComparison.OrdinalIgnoreCase)||name.Equals("Cookies",StringComparison.OrdinalIgnoreCase)||name.Equals("Local State",StringComparison.OrdinalIgnoreCase)||name.Equals("Web Data",StringComparison.OrdinalIgnoreCase);
    }
    static bool IsPersonalDocument(string path)
    {
        var ext=Path.GetExtension(path);return new[]{".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pdf",".txt",".jpg",".jpeg",".png",".zip",".7z"}.Contains(ext,StringComparer.OrdinalIgnoreCase);
    }
    static bool IsGivenXEngineStagingPath(string path)
    {
        try
        {
            var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(path);
            if (!full.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) return false;
            var relative = full[temp.Length..];
            var firstSegment = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)[0];
            return firstSegment.StartsWith("GivenX-Engines-", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
    static bool IsUserWritableExecution(string path) => !string.IsNullOrWhiteSpace(path) &&
        (path.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase) || path.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase) || path.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase) || path.Contains("\\Public\\", StringComparison.OrdinalIgnoreCase));
    static string TryHash(string path) { try { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); } catch { return "no disponible"; } }
    public void Dispose() { foreach (var watcher in _watchers) watcher.Dispose(); _fileAnalysisQueue.Writer.TryComplete(); _http.Dispose(); }
}
