using System.Security.Cryptography;
using System.Text.Json;
using System.Diagnostics;
using System.Xml.Linq;
using GivenX.Shared;
namespace GivenX.Agent;
public sealed class IntegrityMonitor
{
    DateTimeOffset _last=DateTimeOffset.MinValue;
    public IEnumerable<SecurityEvent> Poll()
    {
        if(DateTimeOffset.Now-_last<TimeSpan.FromMinutes(1))return[];
        _last=DateTimeOffset.Now;
        var manifest=Path.Combine(AppContext.BaseDirectory,"install-manifest.json");
        if(!File.Exists(manifest))return[Finding(Severity.Alert,"Falta el manifiesto de integridad","No existe install-manifest.json.",95)];
        try
        {
            var rows=JsonSerializer.Deserialize<List<Row>>(File.ReadAllText(manifest))??[];
            var findings=new List<SecurityEvent>();
            foreach(var row in rows)
            {
                var path=Path.Combine(AppContext.BaseDirectory,row.Path);
                Track(findings,File.Exists(path)&&Hash(path).Equals(row.Hash,StringComparison.OrdinalIgnoreCase),
                    Finding(Severity.Alert,"Archivo de GivenX modificado",$"Integridad alterada: {row.Path}",95));
            }

            var engines=Path.Combine(AppContext.BaseDirectory,"engines");
            if(Directory.Exists(engines))foreach(var path in Directory.EnumerateFiles(engines,"*",SearchOption.AllDirectories).Where(x=>new[]{".exe",".dll"}.Contains(Path.GetExtension(x),StringComparer.OrdinalIgnoreCase)))
            {
                var finding=Finding(Severity.Alert,"Motor local no confiable",$"El ejecutable del motor no coincide con la copia verificada: {Path.GetRelativePath(AppContext.BaseDirectory,path)}",95);
                var trustedByHash = EngineTrustStore.Contains(Hash(path));
                var trustedOfficialSysmon = KnownBenignActivity.IsOfficialMicrosoftSysmon(path);
                Track(findings,trustedByHash || trustedOfficialSysmon,finding);
            }

            if(IsInstalled())
            {
                Track(findings,TaskHealthy("GivenX Shield Agent",Path.Combine(AppContext.BaseDirectory,"GivenX.Agent.exe")),
                    Finding(Severity.Alert,"Recuperación del radar desactivada","La tarea GivenX Shield Agent falta, está deshabilitada o apunta a otro ejecutable.",95));
                Track(findings,TaskHealthy("GivenX Shield UI",Path.Combine(AppContext.BaseDirectory,"GivenX.UI.exe")),
                    Finding(Severity.Review,"Inicio del panel desactivado","La tarea GivenX Shield UI falta, está deshabilitada o apunta a otro ejecutable.",65));
            }
            return findings;
        }
        catch(Exception ex){return[Finding(Severity.Review,"No se pudo verificar la integridad",ex.Message,70)];}
    }
    static void Track(List<SecurityEvent> findings,bool healthy,SecurityEvent finding)
    {
        if (healthy)
        {
            ResolvedEventStore.Add(finding.Fingerprint);
            return;
        }

        // A previously healthy integrity check may become unsafe later.
        // Do not let the old automatic resolution hide a new regression.
        ResolvedEventStore.Remove(finding.Fingerprint);
        findings.Add(finding);
    }
    static string Hash(string path){using var stream=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(stream));}
    static bool IsInstalled(){try{var programFiles=Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;return Path.GetFullPath(AppContext.BaseDirectory).StartsWith(programFiles,StringComparison.OrdinalIgnoreCase);}catch{return false;}}
    static bool TaskHealthy(string name,string expectedExecutable)
    {
        try
        {
            var start=new ProcessStartInfo("schtasks.exe")
            {
                UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,
                RedirectStandardOutput=true,RedirectStandardError=true
            };
            start.ArgumentList.Add("/Query");start.ArgumentList.Add("/TN");start.ArgumentList.Add(name);start.ArgumentList.Add("/XML");
            using var process=Process.Start(start);if(process is null)return false;
            var output=process.StandardOutput.ReadToEnd();
            _=process.StandardError.ReadToEnd();
            if(!process.WaitForExit(4000)){try{process.Kill(true);}catch{}return false;}
            if(process.ExitCode!=0||string.IsNullOrWhiteSpace(output))return false;

            var document=XDocument.Parse(output,LoadOptions.None);
            var enabled=document.Descendants().FirstOrDefault(x=>x.Name.LocalName.Equals("Enabled",StringComparison.OrdinalIgnoreCase))?.Value?.Trim();
            if(enabled is not null&&enabled.Equals("false",StringComparison.OrdinalIgnoreCase))return false;

            var expected=NormalizeExecutable(expectedExecutable);
            return document.Descendants()
                .Where(x=>x.Name.LocalName.Equals("Command",StringComparison.OrdinalIgnoreCase))
                .Select(x=>NormalizeExecutable(x.Value))
                .Any(command=>command.Equals(expected,StringComparison.OrdinalIgnoreCase));
        }
        catch{return false;}
    }
    static string NormalizeExecutable(string value)
    {
        var clean=(value??string.Empty).Trim().Trim('\"');
        try{return Path.GetFullPath(Environment.ExpandEnvironmentVariables(clean)).TrimEnd(Path.DirectorySeparatorChar);}catch{return clean;}
    }
    static SecurityEvent Finding(Severity severity,string title,string evidence,int score){var fp=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("Autoprotección"+title+evidence))).Substring(0,16);return new(DateTimeOffset.Now,severity,"Autoprotección",title,evidence,"Reinstala desde una copia confiable y analiza el PC.",score,fp);}
    sealed record Row(string Path,string Hash);
}
