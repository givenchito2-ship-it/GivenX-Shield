using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace GivenX.Shared;

public static class KnownBenignActivity
{
    static readonly object SignatureGate = new();
    static readonly Dictionary<string, (DateTime WriteTimeUtc, DateTimeOffset ExpiresAt, bool Official)> SignatureCache = new(StringComparer.OrdinalIgnoreCase);
    static readonly Dictionary<string, (DateTime WriteTimeUtc, DateTimeOffset ExpiresAt, bool Trusted)> ExplicitTrustCache = new(StringComparer.OrdinalIgnoreCase);
    static readonly string[] SharedHostingDnsRoots =
    [
        "github.com",
        "githubusercontent.com",
        "githubassets.com"
    ];
    static readonly HashSet<string> OfficialOneDriveComponents = new(StringComparer.OrdinalIgnoreCase)
    {
        "OneDrive.exe",
        "FileCoAuth.exe",
        "OneDrive.Sync.Service.exe",
        "Microsoft.SharePoint.exe",
        "OneDriveSetup.exe"
    };

    public static bool IsOfficialMicrosoftOneDrive(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var expected = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "OneDrive", "OneDrive.exe"));
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            return actual.Equals(expected, StringComparison.OrdinalIgnoreCase) && IsOfficialMicrosoftOneDriveComponent(actual);
        }
        catch { return false; }
    }

    public static bool IsOfficialMicrosoftOneDriveComponent(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var root = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "OneDrive")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!actual.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
                !OfficialOneDriveComponents.Contains(Path.GetFileName(actual)) ||
                !File.Exists(actual)) return false;

            var writeTime = File.GetLastWriteTimeUtc(actual);
            lock (SignatureGate)
                if (SignatureCache.TryGetValue(actual, out var cached) && cached.WriteTimeUtc == writeTime && cached.ExpiresAt > DateTimeOffset.Now) return cached.Official;

            var publisher = FileSignatureTrust.TrustedPublisher(actual);
            var official = IsTrustedMicrosoftPublisher(publisher);
            lock (SignatureGate)
            {
                SignatureCache[actual] = (writeTime, DateTimeOffset.Now.AddSeconds(official ? 600 : 20), official);
                if (SignatureCache.Count > 32)
                    foreach (var key in SignatureCache.Keys.Take(SignatureCache.Count - 32).ToList()) SignatureCache.Remove(key);
            }
            return official;
        }
        catch { return false; }
    }


    public static bool IsOfficialMicrosoftOneDriveSetup(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var root = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "OneDrive")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!Path.GetFileName(actual).Equals("OneDriveSetup.exe", StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(actual) || !actual.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
            var relative = actual[root.Length..].Replace('/', '\\');
            if (!relative.Equals(@"Update\OneDriveSetup.exe", StringComparison.OrdinalIgnoreCase)) return false;
            return IsTrustedMicrosoftPublisher(FileSignatureTrust.TrustedPublisher(actual));
        }
        catch { return false; }
    }


    public static bool IsOfficialMicrosoftSysmon(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!Path.GetFileName(actual).Equals("Sysmon64.exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(actual)) return false;
            var normalized = actual.Replace('/', '\\');
            if (!normalized.Contains("\\engines\\sysmon\\", StringComparison.OrdinalIgnoreCase)) return false;
            return IsTrustedMicrosoftPublisher(FileSignatureTrust.TrustedPublisher(actual));
        }
        catch { return false; }
    }


    public static bool IsKnownBenignRegistryPersistence(string image, string target, string details)
    {
        // Do not blanket-allow persistence. Only suppress ordinary per-user Run entries from
        // explicitly verified vendor binaries. Critical locations such as Winlogon, Policies,
        // IFEO and SilentProcessExit are never covered by this helper.
        if (!IsOrdinaryUserRunKey(target)) return false;
        if (IsOfficialGoogleChrome(image)) return true;
        if (IsOfficialMicrosoftEdge(image) &&
            target.Contains("\\MicrosoftEdgeAutoLaunch_", StringComparison.OrdinalIgnoreCase) &&
            details.Contains("--win-session-start", StringComparison.OrdinalIgnoreCase)) return true;
        return IsOfficialMicrosoftOneDriveSetup(image) &&
               (target.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) ||
                details.Contains("OneDrive", StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsOfficialGoogleChrome(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!Path.GetFileName(actual).Equals("chrome.exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(actual)) return false;
            if (!IsUnderProgramFiles(actual, Path.Combine("Google", "Chrome", "Application"))) return false;
            var publisher = FileSignatureTrust.TrustedPublisher(actual);
            return IsTrustedGooglePublisher(publisher);
        }
        catch { return false; }
    }

    public static bool IsOfficialMicrosoftEdge(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!Path.GetFileName(actual).Equals("msedge.exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(actual)) return false;
            if (!IsUnderProgramFiles(actual, Path.Combine("Microsoft", "Edge", "Application"))) return false;
            return IsTrustedMicrosoftPublisher(FileSignatureTrust.TrustedPublisher(actual));
        }
        catch { return false; }
    }

    public static bool IsOfficialGitHubDesktop(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!Path.GetFileName(actual).Equals("GitHubDesktop.exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(actual)) return false;
            var root = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "GitHubDesktop")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!actual.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;
            var relative = actual[root.Length..].Replace('/', '\\');
            if (!Regex.IsMatch(relative, @"^app-[^\\]+\\GitHubDesktop\.exe$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) return false;
            return IsTrustedGitHubPublisher(FileSignatureTrust.TrustedPublisher(actual));
        }
        catch { return false; }
    }

    public static bool IsOfficialGitHubDesktopBundledGit(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!Path.GetFileName(actual).Equals("git-remote-https.exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(actual)) return false;

            var root = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "GitHubDesktop")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!actual.StartsWith(root, StringComparison.OrdinalIgnoreCase)) return false;

            var relative = actual[root.Length..].Replace('/', '\\');
            var match = Regex.Match(relative,
                @"^(app-[^\\]+)\\resources\\app\\git\\mingw64\\bin\\git-remote-https\.exe$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!match.Success) return false;

            var desktop = Path.Combine(root, match.Groups[1].Value, "GitHubDesktop.exe");
            if (!IsOfficialGitHubDesktop(desktop)) return false;

            return IsTrustedGitForWindowsPublisher(FileSignatureTrust.TrustedPublisher(actual));
        }
        catch { return false; }
    }


    public static bool IsOfficialChromeRegistryEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Cambio de inicio automático en registro", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-REGISTRY-PERSISTENCE", StringComparison.OrdinalIgnoreCase)) return false;

        var process = EvidenceField(item.Evidence, "Proceso");
        var target = EvidenceField(item.Evidence, "Objetivo");
        var details = EvidenceField(item.Evidence, "Detalles") ?? string.Empty;
        return process is not null && target is not null && IsOfficialGoogleChrome(process) &&
               IsKnownBenignRegistryPersistence(process, target, details);
    }

    public static bool IsOfficialEdgeRegistryEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Cambio de inicio automático en registro", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-REGISTRY-PERSISTENCE", StringComparison.OrdinalIgnoreCase)) return false;
        var process = EvidenceField(item.Evidence, "Proceso");
        var target = EvidenceField(item.Evidence, "Objetivo");
        var details = EvidenceField(item.Evidence, "Detalles") ?? string.Empty;
        return process is not null && target is not null && IsOfficialMicrosoftEdge(process) &&
               IsKnownBenignRegistryPersistence(process, target, details);
    }

    public static bool IsOfficialOneDriveRegistryEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-2) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Cambio de inicio automático en registro", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-REGISTRY-PERSISTENCE", StringComparison.OrdinalIgnoreCase)) return false;

        var process = EvidenceField(item.Evidence, "Proceso");
        var target = EvidenceField(item.Evidence, "Objetivo");
        var details = EvidenceField(item.Evidence, "Detalles") ?? string.Empty;
        if (process is null || target is null || !IsOrdinaryUserRunKey(target)) return false;

        if (IsOfficialMicrosoftOneDriveSetup(process) &&
            (target.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) || details.Contains("OneDrive", StringComparison.OrdinalIgnoreCase))) return true;

        // OneDriveSetup.exe is transient and may already be deleted when the dashboard re-evaluates
        // the event. For cleanup only, accept the exact updater location when the current OneDrive
        // installation is still Microsoft-signed and the Run entry is clearly OneDrive-related.
        if (!IsExpectedOneDriveSetupPath(process) ||
            !(target.Contains("OneDrive", StringComparison.OrdinalIgnoreCase) || details.Contains("OneDrive", StringComparison.OrdinalIgnoreCase))) return false;

        var currentOneDrive = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "OneDrive", "OneDrive.exe");
        return IsOfficialMicrosoftOneDrive(currentOneDrive);
    }


    public static bool IsOfficialGitHubDesktopNetworkEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Conexión desde programa de carpeta sensible", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-USERPATH-NETWORK", StringComparison.OrdinalIgnoreCase)) return false;
        var process = EvidenceField(item.Evidence, "Proceso");
        return process is not null &&
               (IsOfficialGitHubDesktop(process) || IsOfficialGitHubDesktopBundledGit(process));
    }

    public static bool IsTrustedLoadedLibraryEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Biblioteca no verificada cargada", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-UNTRUSTED-DLL", StringComparison.OrdinalIgnoreCase)) return false;
        var library = EvidenceField(item.Evidence, "Biblioteca");
        return library is not null && IsExplicitlyTrustedExecutable(library);
    }

    public static bool IsCleanCompilerTemporaryEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-2) ||
            !item.Category.Equals("Archivo", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.StartsWith("Archivo nuevo", StringComparison.OrdinalIgnoreCase)) return false;

        var path = FirstEvidenceLine(item.Evidence);
        var expectedHash = ExtractHash(item.Evidence);
        if (path is null || expectedHash is null || !IsCompilerAnalyzerPath(path)) return false;
        if (!ContainsCleanResult(item.Evidence, "Microsoft Defender") ||
            !ContainsCleanResult(item.Evidence, "YARA") ||
            !HasAcceptableVirusTotalResult(item.Evidence) ||
            Regex.IsMatch(item.Evidence, @":\s*(?:Malicious|Suspicious)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) return false;

        if (File.Exists(path))
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var actualHash = Convert.ToHexString(SHA256.HashData(stream));
                if (!actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) return false;
                var publisher = FileSignatureTrust.TrustedPublisher(path);
                return IsDotNetPublisher(publisher);
            }
            catch { return false; }
        }

        return Regex.IsMatch(item.Evidence,
            @"Firma:\s*editor:\s*(?:\.NET|Microsoft Corporation|Microsoft Windows)\s*\[[A-Fa-f0-9]{64}\]",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static bool IsOfficialOneDriveNetworkEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Conexión desde programa de carpeta sensible", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-USERPATH-NETWORK", StringComparison.OrdinalIgnoreCase)) return false;
        var process = EvidenceField(item.Evidence, "Proceso");
        return process is not null && IsOfficialMicrosoftOneDriveComponent(process);
    }

    public static bool IsTrustedUserPathNetworkEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Conexión desde programa de carpeta sensible", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-USERPATH-NETWORK", StringComparison.OrdinalIgnoreCase)) return false;
        var process = EvidenceField(item.Evidence, "Proceso");
        return process is not null && IsExplicitlyTrustedExecutable(process);
    }

    public static bool IsInvalidSharedHostingDnsEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Comportamiento", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Consulta DNS asociada a malware", StringComparison.OrdinalIgnoreCase) ||
            !item.Evidence.Contains("Regla: GX-IOC-DNS", StringComparison.OrdinalIgnoreCase)) return false;

        var query = EvidenceField(item.Evidence, "DNS");
        return IsSharedHostingDomain(query);
    }

    public static bool IsVerifiedEngineStagingEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-2) ||
            !item.Category.Equals("Archivo", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.StartsWith("Archivo nuevo", StringComparison.OrdinalIgnoreCase)) return false;

        var path = FirstEvidenceLine(item.Evidence);
        var expectedHash = ExtractHash(item.Evidence);
        if (path is null || expectedHash is null || !IsEngineStagingPath(path) ||
            Regex.IsMatch(item.Evidence, @"(?:Microsoft Defender|YARA):\s*(?:Malicious|Suspicious)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
            !EngineTrustStore.Contains(expectedHash)) return false;

        try
        {
            var installed = Path.Combine(AppContext.BaseDirectory, "engines", "yara", Path.GetFileName(path));
            if (!File.Exists(installed)) return false;
            using var stream = new FileStream(installed, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Convert.ToHexString(SHA256.HashData(stream)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    public static bool IsNowTrustedEngineIntegrityEvent(SecurityEvent item)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7) ||
            !item.Category.Equals("Autoprotección", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.Equals("Motor local no confiable", StringComparison.OrdinalIgnoreCase)) return false;

        var match = Regex.Match(item.Evidence,
            @"^El ejecutable del motor no coincide con la copia verificada:\s*(engines\\(?:(?:yara\\(?:yara64|yarac64)\.exe)|(?:sysmon\\Sysmon64\.exe)))$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success) return false;

        var relative = match.Groups[1].Value;
        foreach (var baseDirectory in EngineBaseDirectories())
        {
            try
            {
                var path = Path.GetFullPath(Path.Combine(baseDirectory, relative));
                var root = Path.GetFullPath(baseDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) continue;
                if (relative.StartsWith("engines\\sysmon\\", StringComparison.OrdinalIgnoreCase))
                {
                    if (IsOfficialMicrosoftSysmon(path)) return true;
                    continue;
                }
                if (HashListedInEngineTrustStore(baseDirectory, path)) return true;
            }
            catch { }
        }
        return false;
    }

    public static bool IsExplicitlyTrustedExecutable(string path)
    {
        try
        {
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!File.Exists(actual)) return false;
            var writeTime = File.GetLastWriteTimeUtc(actual);
            lock (SignatureGate)
                if (ExplicitTrustCache.TryGetValue(actual, out var cached) && cached.WriteTimeUtc == writeTime && cached.ExpiresAt > DateTimeOffset.Now) return cached.Trusted;
            using var stream = new FileStream(actual, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            var trusted = AllowListStore.Contains(hash) || BuildArtifactTrustStore.Contains(hash);
            if (!trusted)
            {
                var publisher = FileSignatureTrust.TrustedPublisher(actual);
                trusted = publisher is not null && TrustedPublisherStore.Contains(publisher);
            }
            lock (SignatureGate)
            {
                ExplicitTrustCache[actual] = (writeTime, DateTimeOffset.Now.AddSeconds(trusted ? 60 : 10), trusted);
                if (ExplicitTrustCache.Count > 128)
                    foreach (var key in ExplicitTrustCache.OrderBy(x => x.Value.ExpiresAt).Take(ExplicitTrustCache.Count - 128).Select(x => x.Key).ToList()) ExplicitTrustCache.Remove(key);
            }
            return trusted;
        }
        catch { return false; }
    }

    public static bool IsSharedHostingDomain(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return false;
        var host = candidate.Trim().TrimEnd('.');
        return SharedHostingDnsRoots.Any(root =>
            host.Equals(root, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith("." + root, StringComparison.OrdinalIgnoreCase));
    }

    static bool IsCompilerAnalyzerPath(string path)
    {
        try
        {
            var root = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Temp", "VBCSCompiler", "AnalyzerAssemblyLoader")) + Path.DirectorySeparatorChar;
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!actual.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
                !actual.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return false;
            var relative = actual[root.Length..].Replace('/', '\\');
            return Regex.IsMatch(relative,
                @"^[A-Fa-f0-9-]{16,}\\[A-Fa-f0-9-]{16,}\\(?:[A-Za-z-]{2,12}\\)?[^\\]+\.dll$",
                RegexOptions.CultureInvariant);
        }
        catch { return false; }
    }

    static bool IsEngineStagingPath(string path)
    {
        try
        {
            var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            if (!actual.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) return false;
            var relative = actual[temp.Length..].Replace('/', '\\');
            return Regex.IsMatch(relative,
                @"^GivenX-Engines-[A-Fa-f0-9]{32}\\YARA\\(?:[^\\]+\\)*[^\\]+\.(?:exe|dll)$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }
        catch { return false; }
    }


    static bool IsOrdinaryUserRunKey(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return false;
        var normalized = target.Replace('/', '\\');
        if (normalized.Contains("\\Policies\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\Winlogon\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\Image File Execution Options\\", StringComparison.OrdinalIgnoreCase) ||
            normalized.Contains("\\SilentProcessExit\\", StringComparison.OrdinalIgnoreCase)) return false;
        return normalized.Contains("\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsExpectedOneDriveSetupPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            var expected = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "OneDrive", "Update", "OneDriveSetup.exe"));
            var actual = Path.GetFullPath(path.Trim().Trim('"'));
            return actual.Equals(expected, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    static bool IsUnderProgramFiles(string actual, string relativeRoot)
    {
        foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
        {
            try
            {
                var basePath = Environment.GetFolderPath(folder);
                if (string.IsNullOrWhiteSpace(basePath)) continue;
                var expected = Path.GetFullPath(Path.Combine(basePath, relativeRoot)).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch { }
        }
        return false;
    }

    static bool IsTrustedGooglePublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var bracket = publisher.LastIndexOf(" [", StringComparison.Ordinal);
        var name = (bracket > 0 ? publisher[..bracket] : publisher).Trim();
        return name.Equals("Google LLC", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Google Inc", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Google Inc.", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsTrustedGitHubPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var bracket = publisher.LastIndexOf(" [", StringComparison.Ordinal);
        var name = (bracket > 0 ? publisher[..bracket] : publisher).Trim();
        return name.Equals("GitHub, Inc.", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("GitHub, Inc", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("GitHub", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsTrustedGitForWindowsPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var bracket = publisher.LastIndexOf(" [", StringComparison.Ordinal);
        var name = (bracket > 0 ? publisher[..bracket] : publisher).Trim();
        return name.Equals("Johannes Schindelin", StringComparison.OrdinalIgnoreCase);
    }

    static bool IsDotNetPublisher(string? publisher) => publisher is not null &&
        (publisher.StartsWith(".NET [", StringComparison.OrdinalIgnoreCase) || IsTrustedMicrosoftPublisher(publisher));

    static bool IsTrustedMicrosoftPublisher(string? publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var bracket = publisher.LastIndexOf(" [", StringComparison.Ordinal);
        var name = (bracket > 0 ? publisher[..bracket] : publisher).Trim();
        return name.Equals("Microsoft", StringComparison.OrdinalIgnoreCase) ||
               name.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase);
    }

    static IEnumerable<string> EngineBaseDirectories()
    {
        var values = new List<string> { AppContext.BaseDirectory };
        try
        {
            var installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "GivenX Shield");
            if (!string.IsNullOrWhiteSpace(installed)) values.Add(installed);
        }
        catch { }
        return values.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    static bool HashListedInEngineTrustStore(string baseDirectory, string path)
    {
        try
        {
            var store = Path.Combine(baseDirectory, "trusted-engine-hashes.json");
            if (!File.Exists(store)) return false;
            var values = JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(store)) ?? [];
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var hash = Convert.ToHexString(SHA256.HashData(stream));
            return values.Contains(hash, StringComparer.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    static bool ContainsCleanResult(string evidence, string engine) => Regex.IsMatch(evidence,
        Regex.Escape(engine) + @":\s*Clean\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    static bool HasAcceptableVirusTotalResult(string evidence) =>
        Regex.IsMatch(evidence, @"VirusTotal:\s*Clean\s*\(0\s+detecciones", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant) ||
        Regex.IsMatch(evidence, @"VirusTotal:\s*Unknown\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    static string? FirstEvidenceLine(string evidence) => evidence
        .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        .FirstOrDefault()?.Trim().Trim('"');

    static string? EvidenceField(string evidence, string field)
    {
        var match = Regex.Match(evidence, "(?:^|\\r?\\n)" + Regex.Escape(field) + @":\s*([^\r\n]+)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value.Trim().Trim('"') : null;
    }

    static string? ExtractHash(string evidence)
    {
        var match = Regex.Match(evidence, @"SHA-256:\s*([A-Fa-f0-9]{64})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value : null;
    }
}
