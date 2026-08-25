using System.Diagnostics;
using System.Text.Json;

namespace GivenX.Shared;

public sealed record AntivirusProviderInfo(string Name, bool Enabled, bool UpToDate, int ProductState, string? ProductExecutable)
{
    public bool IsMicrosoftDefender => Name.Contains("Defender", StringComparison.OrdinalIgnoreCase);
    public string Status => Enabled ? (UpToDate ? "ACTIVO" : "ACTIVO · FIRMAS ANTIGUAS") : "REGISTRADO · NO ACTIVO";
}

public sealed record AntivirusProviderSnapshot(DateTimeOffset CheckedAt, bool QuerySucceeded, IReadOnlyList<AntivirusProviderInfo> Providers)
{
    public AntivirusProviderInfo? Primary => Providers
        .OrderByDescending(x => x.Enabled)
        .ThenBy(x => x.IsMicrosoftDefender)
        .FirstOrDefault();

    public static AntivirusProviderSnapshot Unknown => new(DateTimeOffset.MinValue, false, []);
}

public static class AntivirusProviderDetector
{
    static readonly SemaphoreSlim Gate = new(1, 1);
    static AntivirusProviderSnapshot _cached = AntivirusProviderSnapshot.Unknown;
    public static AntivirusProviderSnapshot Cached => _cached;

    public static async Task<AntivirusProviderSnapshot> RefreshAsync(bool force = false, CancellationToken cancellationToken = default)
    {
        if (!force && _cached.CheckedAt > DateTimeOffset.Now.AddMinutes(-2)) return _cached;
        await Gate.WaitAsync(cancellationToken);
        try
        {
            if (!force && _cached.CheckedAt > DateTimeOffset.Now.AddMinutes(-2)) return _cached;
            _cached = await QueryWindowsSecurityCenterAsync(cancellationToken);
            return _cached;
        }
        finally { Gate.Release(); }
    }

    static async Task<AntivirusProviderSnapshot> QueryWindowsSecurityCenterAsync(CancellationToken cancellationToken)
    {
        try
        {
            var shell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(shell)) shell = "powershell.exe";
            const string command = "$ErrorActionPreference='Stop'; $items=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntivirusProduct | Select-Object displayName,productState,pathToSignedProductExe); [pscustomobject]@{items=$items} | ConvertTo-Json -Compress -Depth 4";
            var start = new ProcessStartInfo(shell)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.ArgumentList.Add("-NoLogo"); start.ArgumentList.Add("-NoProfile"); start.ArgumentList.Add("-NonInteractive"); start.ArgumentList.Add("-WindowStyle"); start.ArgumentList.Add("Hidden"); start.ArgumentList.Add("-Command"); start.ArgumentList.Add(command);
            using var process = Process.Start(start);
            if (process is null) return new(DateTimeOffset.Now, false, []);
            var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(8));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch { try { process.Kill(true); } catch { } return new(DateTimeOffset.Now, false, []); }
            var output = await stdout; await stderr;
            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output)) return new(DateTimeOffset.Now, false, []);
            using var json = JsonDocument.Parse(output);
            if (!json.RootElement.TryGetProperty("items", out var items)) return new(DateTimeOffset.Now, true, []);
            var providers = new List<AntivirusProviderInfo>();
            if (items.ValueKind == JsonValueKind.Array) foreach (var item in items.EnumerateArray()) Add(item, providers);
            else if (items.ValueKind == JsonValueKind.Object) Add(items, providers);
            return new(DateTimeOffset.Now, true, providers.OrderByDescending(x => x.Enabled).ThenBy(x => x.Name).ToList());
        }
        catch { return new(DateTimeOffset.Now, false, []); }
    }

    static void Add(JsonElement item, List<AntivirusProviderInfo> providers)
    {
        var name = Text(item, "displayName");
        if (string.IsNullOrWhiteSpace(name)) return;
        var state = item.TryGetProperty("productState", out var value) && value.TryGetInt32(out var parsed) ? parsed : 0;
        var stateByte = (state >> 8) & 0xFF;
        var enabled = stateByte is 0x10 or 0x11;
        var upToDate = (state & 0xFF) == 0;
        providers.Add(new(name.Trim(), enabled, upToDate, state, Text(item, "pathToSignedProductExe")));
    }

    static string? Text(JsonElement item, string name) => item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
