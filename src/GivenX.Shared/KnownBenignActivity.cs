using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace GivenX.Shared;

public static class KnownBenignActivity
{
    static readonly object SignatureGate = new();
    static readonly Dictionary<string, (DateTime WriteTimeUtc, bool Official)> SignatureCache = new(StringComparer.OrdinalIgnoreCase);
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
        "Microsoft.SharePoint.exe"
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
                if (SignatureCache.TryGetValue(actual, out var cached) && cached.WriteTimeUtc == writeTime) return cached.Official;

            var publisher = FileSignatureTrust.TrustedPublisher(actual);
            var official = publisher is not null &&
                           (publisher.StartsWith("Microsoft Corporation [", StringComparison.OrdinalIgnoreCase) ||
                            publisher.StartsWith("Microsoft Windows [", StringComparison.OrdinalIgnoreCase));
            lock (SignatureGate)
            {
                SignatureCache[actual] = (writeTime, official);
                if (SignatureCache.Count > 32)
                    foreach (var key in SignatureCache.Keys.Take(SignatureCache.Count - 32).ToList()) SignatureCache.Remove(key);
            }
            return official;
        }
        catch { return false; }
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
            @"^El ejecutable del motor no coincide con la copia verificada:\s*(engines\\yara\\(?:yara64|yarac64)\.exe)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!match.Success) return false;
        try
        {
            var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, match.Groups[1].Value));
            var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "engines", "yara")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) return false;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return EngineTrustStore.Contains(Convert.ToHexString(SHA256.HashData(stream)));
        }
        catch { return false; }
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

    static bool IsDotNetPublisher(string? publisher) => publisher is not null &&
        (publisher.StartsWith(".NET [", StringComparison.OrdinalIgnoreCase) ||
         publisher.StartsWith("Microsoft Corporation [", StringComparison.OrdinalIgnoreCase) ||
         publisher.StartsWith("Microsoft Windows [", StringComparison.OrdinalIgnoreCase));

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
