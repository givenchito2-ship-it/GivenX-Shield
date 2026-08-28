using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace GivenX.Shared;

public sealed record TrustedBuildArtifact(string Sha256, string FileName, string RelativePath, long Length);
public sealed record TrustedBuildArtifactManifest(string Version, DateTimeOffset VerifiedAt, string AgentSha256, string UiSha256, List<TrustedBuildArtifact> Artifacts);

public static class BuildArtifactTrustStore
{
    static readonly object Gate = new();
    static DateTime _loadedWriteTimeUtc = DateTime.MinValue;
    static HashSet<string> _hashes = new(StringComparer.OrdinalIgnoreCase);
    static readonly HashSet<string> LegacyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "GivenX.Agent.exe", "GivenX.Agent.dll", "GivenX.UI.exe", "GivenX.UI.dll",
        "GivenX.Shared.dll", "singlefilehost.exe", "apphost.exe"
    };
    static readonly HashSet<string> KnownPackageScripts = new(StringComparer.OrdinalIgnoreCase)
    {
        "INSTALAR-GIVENX.cmd", "RECUPERAR-GIVENX.cmd", "VERIFICAR-COMPILACION.cmd",
        "build-install.ps1", "engine-setup.cmd", "engine-setup.ps1", "rollback.ps1",
        "uninstall.ps1", "verify-build.ps1", "REPARAR-ALERTAS-ACTUALES.cmd",
        "repair-current-alerts.ps1", "CONFIGURAR-FIRMA.cmd", "configure-signing.ps1",
        "prepare-signing-input.ps1", "prepare-signed-release.ps1", "package-signed-release.ps1",
        "install-test-unsigned.ps1"
    };

    public static bool Contains(string sha256)
    {
        if (!IsSha256(sha256)) return false;
        EnsureLoaded();
        lock (Gate) return _hashes.Contains(sha256);
    }

    public static bool IsTrustedBuildEvent(SecurityEvent item)
    {
        if (!item.Category.Equals("Archivo", StringComparison.OrdinalIgnoreCase) ||
            !item.Title.StartsWith("Archivo nuevo", StringComparison.OrdinalIgnoreCase)) return false;

        var hash = ExtractHash(item.Evidence);
        if (hash is null) return false;
        if (Contains(hash)) return true;
        return IsVerifiedLegacyR2Artifact(item, hash);
    }

    public static bool IsAutomaticallyResolvedEvent(SecurityEvent item) =>
        IsTrustedBuildEvent(item) ||
        KnownBenignActivity.IsCleanCompilerTemporaryEvent(item) ||
        KnownBenignActivity.IsOfficialOneDriveNetworkEvent(item) ||
        KnownBenignActivity.IsOfficialChromeRegistryEvent(item) ||
        KnownBenignActivity.IsOfficialEdgeRegistryEvent(item) ||
        KnownBenignActivity.IsOfficialGitHubDesktopNetworkEvent(item) ||
        KnownBenignActivity.IsTrustedLoadedLibraryEvent(item) ||
        KnownBenignActivity.IsTrustedUserPathNetworkEvent(item) ||
        KnownBenignActivity.IsInvalidSharedHostingDnsEvent(item) ||
        KnownBenignActivity.IsVerifiedEngineStagingEvent(item) ||
        KnownBenignActivity.IsNowTrustedEngineIntegrityEvent(item);

    static bool IsVerifiedLegacyR2Artifact(SecurityEvent item, string expectedHash)
    {
        if (item.Time < DateTimeOffset.Now.AddDays(-7)) return false;
        var firstLine = item.Evidence.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(firstLine) || !Path.IsPathRooted(firstLine) || !File.Exists(firstLine)) return false;

        var path = firstLine.Replace('/', '\\');
        if (!path.Contains("\\GivenX_Beta_1_6_2_R2\\GivenX-Shield-Beta\\", StringComparison.OrdinalIgnoreCase)) return false;
        var generated = path.Contains("\\publish-r2\\", StringComparison.OrdinalIgnoreCase) ||
                        Regex.IsMatch(path, @"\\src\\GivenX\.(?:Agent|UI|Shared)\\(?:bin|obj)\\", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (!generated || !LegacyNames.Contains(Path.GetFileName(path))) return false;

        try
        {
            using var stream = new FileStream(firstLine, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var actualHash = Convert.ToHexString(SHA256.HashData(stream));
            return actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    static string? ExtractHash(string evidence)
    {
        var match = Regex.Match(evidence ?? string.Empty, @"SHA-256:\s*([A-Fa-f0-9]{64})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value : null;
    }

    static bool IsSha256(string value) => !string.IsNullOrWhiteSpace(value) && Regex.IsMatch(value, "^[A-Fa-f0-9]{64}$", RegexOptions.CultureInvariant);

    static void EnsureLoaded()
    {
        lock (Gate)
        {
            try
            {
                var writeTime = File.GetLastWriteTimeUtc(AppPaths.TrustedBuildArtifacts);
                if (writeTime == _loadedWriteTimeUtc) return;
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var manifest = JsonSerializer.Deserialize<TrustedBuildArtifactManifest>(File.ReadAllText(AppPaths.TrustedBuildArtifacts), options);
                if (manifest is null || !manifest.Version.Equals("1.6.2-R9", StringComparison.OrdinalIgnoreCase) ||
                    !IsSha256(manifest.AgentSha256) || !IsSha256(manifest.UiSha256) || manifest.Artifacts is null)
                    throw new InvalidDataException("El manifiesto de compilación no es válido.");

                var baseDirectory = AppContext.BaseDirectory;
                if (!FileHashEquals(Path.Combine(baseDirectory, "GivenX.Agent.exe"), manifest.AgentSha256) ||
                    !FileHashEquals(Path.Combine(baseDirectory, "GivenX.UI.exe"), manifest.UiSha256))
                    throw new InvalidDataException("El manifiesto no corresponde a los ejecutables instalados.");

                var values = manifest.Artifacts
                    .Where(x => IsSha256(x.Sha256) && x.Length >= 0 &&
                                !string.IsNullOrWhiteSpace(x.FileName) && !string.IsNullOrWhiteSpace(x.RelativePath) &&
                                !Path.IsPathRooted(x.RelativePath) && !x.RelativePath.Split('\\', '/').Contains("..") &&
                                IsExpectedArtifact(x.RelativePath, x.FileName))
                    .Select(x => x.Sha256);
                _hashes = new HashSet<string>(values, StringComparer.OrdinalIgnoreCase);
                _loadedWriteTimeUtc = writeTime;
            }
            catch
            {
                _hashes = new(StringComparer.OrdinalIgnoreCase);
                _loadedWriteTimeUtc = DateTime.MinValue;
            }
        }
    }

    static bool FileHashEquals(string path, string expectedHash)
    {
        if (!File.Exists(path)) return false;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase);
    }

    static bool IsExpectedArtifact(string relativePath, string fileName)
    {
        var normalized = relativePath.Replace('/', '\\');
        if (!Path.GetFileName(normalized).Equals(fileName, StringComparison.OrdinalIgnoreCase)) return false;
        if (!normalized.Contains('\\')) return KnownPackageScripts.Contains(fileName);
        return Regex.IsMatch(normalized,
            @"^(?:(?:publish-r9|release-r9)\\(?:Agent|UI|Installer)|src\\GivenX\.(?:Agent|UI|Shared)\\(?:bin|obj))\\",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
