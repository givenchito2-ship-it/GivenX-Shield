using System.Diagnostics;

namespace GivenX.Shared;

public sealed record DefenderScanResult(int ExitCode, string Status, string Details);

public static class DefenderCommand
{
    public static string? FindExecutable()
    {
        var classic = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        try
        {
            var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
            if (Directory.Exists(platform))
            {
                var current = Directory.GetDirectories(platform)
                    .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase)
                    .Select(path => Path.Combine(path, "MpCmdRun.exe"))
                    .FirstOrDefault(File.Exists);
                if (current is not null) return current;
            }
        }
        catch { }
        return File.Exists(classic) ? classic : null;
    }

    public static bool IsAvailable => FindExecutable() is not null;

    public static bool IsActive
    {
        get
        {
            var snapshot = AntivirusProviderDetector.Cached;
            return snapshot.QuerySucceeded && snapshot.Providers.Any(x => x.IsMicrosoftDefender && x.Enabled) && IsAvailable;
        }
    }

    public static async Task<DefenderScanResult> RunScanAsync(int scanType, CancellationToken cancellationToken = default)
    {
        if (scanType is not (1 or 2)) throw new ArgumentOutOfRangeException(nameof(scanType));
        var providers = await AntivirusProviderDetector.RefreshAsync(cancellationToken: cancellationToken);
        var defender = providers.Providers.FirstOrDefault(x => x.IsMicrosoftDefender);
        if (defender?.Enabled != true)
        {
            var primary = providers.Primary?.Name ?? "otro antivirus";
            throw new InvalidOperationException($"Microsoft Defender no está activo como motor principal. Windows registra: {primary}. GivenX no forzará dos antivirus en tiempo real.");
        }
        var executable = FindExecutable() ?? throw new FileNotFoundException("Microsoft Defender no está disponible en este equipo.");
        var start = HiddenStart(executable);
        start.ArgumentList.Add("-Scan"); start.ArgumentList.Add("-ScanType"); start.ArgumentList.Add(scanType.ToString());
        using var process = Process.Start(start) ?? throw new InvalidOperationException("No se pudo iniciar Microsoft Defender.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            try { await CancelActiveScanAsync(CancellationToken.None); } catch { }
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8)); }
            catch { try { process.Kill(true); } catch { } }
            throw;
        }
        var output = Compact((await stdout) + Environment.NewLine + (await stderr));
        return process.ExitCode switch
        {
            0 => new(0, "COMPLETADO", string.IsNullOrWhiteSpace(output) ? "Defender finalizó sin acciones pendientes. Revisa el historial de protección para ver cualquier corrección realizada." : output),
            2 => new(2, "REVISAR", string.IsNullOrWhiteSpace(output) ? "Defender requiere una acción o encontró un error de análisis. Abre Seguridad de Windows." : output),
            _ => new(process.ExitCode, "ERROR", string.IsNullOrWhiteSpace(output) ? $"Defender devolvió el código {process.ExitCode}." : output)
        };
    }

    public static async Task<int> CancelActiveScanAsync(CancellationToken cancellationToken = default)
    {
        var executable = FindExecutable() ?? throw new FileNotFoundException("Microsoft Defender no está disponible en este equipo.");
        var start = HiddenStart(executable); start.ArgumentList.Add("-Scan"); start.ArgumentList.Add("-Cancel");
        using var process = Process.Start(start) ?? throw new InvalidOperationException("No se pudo solicitar la cancelación a Defender.");
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(cancellationToken); await Task.WhenAll(stdout, stderr);
        return process.ExitCode;
    }

    static ProcessStartInfo HiddenStart(string executable) => new(executable)
    {
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true,
        WindowStyle = ProcessWindowStyle.Hidden
    };

    static string Compact(string value)
    {
        value = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return value.Length > 2000 ? value[..2000] : value;
    }
}
