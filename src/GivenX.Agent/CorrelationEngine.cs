using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using GivenX.Shared;

namespace GivenX.Agent;

public sealed class CorrelationEngine
{
    sealed record Signal(DateTimeOffset Time, string Fingerprint, string Title, int Score);
    readonly Dictionary<string, List<Signal>> _signals = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _emitted = new(StringComparer.OrdinalIgnoreCase);
    readonly object _gate = new();

    public SecurityEvent? Observe(SecurityEvent item)
    {
        lock (_gate) return ObserveLocked(item);
    }

    SecurityEvent? ObserveLocked(SecurityEvent item)
    {
        if (item.Score < 35 || item.Category.Equals("Correlación", StringComparison.OrdinalIgnoreCase)) return null;
        var entity = Entity(item.Evidence); if (entity is null) return null;
        var now = DateTimeOffset.Now;
        if (_signals.Count > 500)
            foreach (var key in _signals.Where(x => x.Value.All(y => y.Time < now.AddMinutes(-15))).Select(x => x.Key).ToList()) _signals.Remove(key);
        if (!_signals.TryGetValue(entity, out var entries)) _signals[entity] = entries = [];
        entries.RemoveAll(x => x.Time < now.AddMinutes(-15));
        if (entries.All(x => !x.Fingerprint.Equals(item.Fingerprint, StringComparison.OrdinalIgnoreCase))) entries.Add(new(item.Time, item.Fingerprint, item.Title, item.Score));
        var distinct = entries.GroupBy(x => x.Title, StringComparer.OrdinalIgnoreCase).Select(x => x.OrderByDescending(y => y.Score).First()).ToList();
        if (distinct.Count < 2 || (distinct.Count < 3 && distinct.Sum(x => x.Score) < 165)) return null;
        var signature = entity + "|" + string.Join('|', distinct.Select(x => x.Title).OrderBy(x => x));
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signature))).Substring(0, 16);
        if (!_emitted.Add(fingerprint)) return null;
        var score = Math.Min(100, distinct.Max(x => x.Score) + Math.Min(20, (distinct.Count - 1) * 8));
        var evidence = $"Entidad: {entity}{Environment.NewLine}Señales relacionadas en 15 minutos:{Environment.NewLine}- " + string.Join(Environment.NewLine + "- ", distinct.Select(x => $"{x.Title} ({x.Score}/100)"));
        return new(now, score >= 85 ? Severity.Alert : Severity.Review, "Correlación", "Cadena de actividad sospechosa", evidence, "Revisa el proceso y su archivo. Si no lo reconoces, desconecta Internet y utiliza la cuarentena confirmada.", score, fingerprint);
    }

    static string? Entity(string evidence)
    {
        var match = Regex.Match(evidence, "[A-Za-z]:\\\\[^\\r\\n|<>\\\"]+?\\.(?:exe|dll|scr|com|ps1|bat|cmd|vbs|js|hta)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (match.Success) return match.Value.Trim().Trim('"');
        var pid = Regex.Match(evidence, @"\bPID\s+(\d+)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return pid.Success ? "PID " + pid.Groups[1].Value : null;
    }
}
