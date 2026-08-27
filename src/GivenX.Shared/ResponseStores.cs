using System.Security.Cryptography;
using System.Text.Json;

namespace GivenX.Shared;

public sealed record QuarantineRecord(string Id, string OriginalPath, string Sha256, DateTimeOffset QuarantinedAt, string Reason, string EncryptedFile, long OriginalSize = 0, string Format = "GXQ1");
public sealed record ResponseActionRecord(string Id, DateTimeOffset Time, string Action, string Target, string Outcome, bool Reversible, string Details);
public sealed record ResponseConfiguration(bool AutoBlockConfirmedConnections = false);

public static class ResponseConfigurationStore
{
    static readonly object Gate = new();
    public static ResponseConfiguration Read(){lock(Gate)try{return JsonSerializer.Deserialize<ResponseConfiguration>(File.ReadAllText(AppPaths.ResponseSettings))??new();}catch{return new();}}
    public static void Write(ResponseConfiguration value){lock(Gate){AppPaths.Ensure();var temp=AppPaths.ResponseSettings+".tmp";File.WriteAllText(temp,JsonSerializer.Serialize(value,new JsonSerializerOptions{WriteIndented=true}));File.Move(temp,AppPaths.ResponseSettings,true);}}
}

public static class ResponseActionStore
{
    static readonly object Gate = new();
    public static List<ResponseActionRecord> Read(int maximum=500){lock(Gate)try{return (JsonSerializer.Deserialize<List<ResponseActionRecord>>(File.ReadAllText(AppPaths.ResponseHistory))??[]).OrderByDescending(x=>x.Time).Take(Math.Max(1,maximum)).ToList();}catch{return[];}}
    public static void Append(string action,string target,string outcome,bool reversible,string details)
    {
        try{lock(Gate)
        {
            List<ResponseActionRecord> rows;try{rows=JsonSerializer.Deserialize<List<ResponseActionRecord>>(File.ReadAllText(AppPaths.ResponseHistory))??[];}catch{rows=[];}
            rows.Add(new(Guid.NewGuid().ToString("N"),DateTimeOffset.Now,action,target,outcome,reversible,details));rows=rows.OrderByDescending(x=>x.Time).Take(1000).ToList();
            AppPaths.Ensure();var temp=AppPaths.ResponseHistory+".tmp";File.WriteAllText(temp,JsonSerializer.Serialize(rows,new JsonSerializerOptions{WriteIndented=true}));File.Move(temp,AppPaths.ResponseHistory,true);
        }}catch{}
    }
}

public static class ThreatIndicatorStore
{
    public static HashSet<string> ReadHosts()
    {
        var values=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(var path in new[]{AppPaths.Intelligence,AppPaths.ThreatFoxHosts})try{foreach(var line in File.ReadLines(path))if(!string.IsNullOrWhiteSpace(line))values.Add(line.Trim().TrimEnd('.'));}catch{}
        return values;
    }
}

public static class AllowListStore
{
    static readonly object Gate = new();
    public static HashSet<string> Read()
    {
        lock (Gate) try { return JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(AppPaths.AllowList)) ?? new(StringComparer.OrdinalIgnoreCase); }
        catch { return new(StringComparer.OrdinalIgnoreCase); }
    }
    public static void Add(string sha256) { lock (Gate) { var values=Read(); values.Add(sha256.ToLowerInvariant()); Write(values); } }
    public static void Remove(string sha256) { lock (Gate) { var values=Read(); values.Remove(sha256.ToLowerInvariant()); Write(values); } }
    public static bool Contains(string sha256) => Read().Contains(sha256.ToLowerInvariant());
    static void Write(HashSet<string> values) { AppPaths.Ensure(); var temp=AppPaths.AllowList+".tmp"; File.WriteAllText(temp,JsonSerializer.Serialize(values,new JsonSerializerOptions{WriteIndented=true}));File.Move(temp,AppPaths.AllowList,true); }
}

public static class TrustedPublisherStore
{
    static readonly object Gate = new();
    public static HashSet<string> Read()
    {
        lock (Gate) try
        {
            var values = JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(AppPaths.TrustedPublishers)) ?? [];
            return new(values.Where(x => !string.IsNullOrWhiteSpace(x)), StringComparer.OrdinalIgnoreCase);
        }
        catch { return new(StringComparer.OrdinalIgnoreCase); }
    }
    public static bool Contains(string publisher) => !string.IsNullOrWhiteSpace(publisher) && Read().Contains(publisher.Trim());
    public static void Add(string publisher) { if (string.IsNullOrWhiteSpace(publisher)) return; lock (Gate) { var values = Read(); values.Add(publisher.Trim()); Write(values); } }
    public static void Remove(string publisher) { if (string.IsNullOrWhiteSpace(publisher)) return; lock (Gate) { var values = Read(); values.Remove(publisher.Trim()); Write(values); } }
    static void Write(HashSet<string> values)
    {
        AppPaths.Ensure(); var temp = AppPaths.TrustedPublishers + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(values.OrderBy(x => x), new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, AppPaths.TrustedPublishers, true);
    }
}

public static class DismissedEventStore
{
    static readonly object Gate = new();
    public static HashSet<string> Read()
    {
        lock (Gate) try
        {
            var values = JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(AppPaths.DismissedEvents)) ?? [];
            return new(values.Where(x => !string.IsNullOrWhiteSpace(x)), StringComparer.OrdinalIgnoreCase);
        }
        catch { return new(StringComparer.OrdinalIgnoreCase); }
    }
    public static void Add(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint)) return;
        lock (Gate)
        {
            var values = Read(); values.Add(fingerprint);
            AppPaths.Ensure(); var temp = AppPaths.DismissedEvents + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(values.OrderBy(x => x), new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temp, AppPaths.DismissedEvents, true);
        }
    }
    public static void Remove(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint)) return;
        lock (Gate)
        {
            var values = Read(); values.Remove(fingerprint);
            AppPaths.Ensure(); var temp = AppPaths.DismissedEvents + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(values.OrderBy(x => x), new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temp, AppPaths.DismissedEvents, true);
        }
    }
}

public static class ResolvedEventStore
{
    static readonly object Gate=new();
    public static HashSet<string> Read(){lock(Gate)try{var values=JsonSerializer.Deserialize<HashSet<string>>(File.ReadAllText(AppPaths.ResolvedEvents))??[];return new(values.Where(x=>!string.IsNullOrWhiteSpace(x)),StringComparer.OrdinalIgnoreCase);}catch{return new(StringComparer.OrdinalIgnoreCase);}}
    public static void Add(string fingerprint){if(string.IsNullOrWhiteSpace(fingerprint))return;lock(Gate){var values=Read();if(values.Add(fingerprint))Write(values);}}
    public static void AddRange(IEnumerable<string> fingerprints){lock(Gate){var values=Read();var changed=false;foreach(var fingerprint in fingerprints.Where(x=>!string.IsNullOrWhiteSpace(x)))changed|=values.Add(fingerprint);if(changed)Write(values);}}
    public static void Remove(string fingerprint){if(string.IsNullOrWhiteSpace(fingerprint))return;lock(Gate){var values=Read();if(values.Remove(fingerprint))Write(values);}}
    static void Write(HashSet<string> values){AppPaths.Ensure();var temp=AppPaths.ResolvedEvents+".tmp";File.WriteAllText(temp,JsonSerializer.Serialize(values.OrderBy(x=>x),new JsonSerializerOptions{WriteIndented=true}));File.Move(temp,AppPaths.ResolvedEvents,true);}
}

public static class ScanHistoryStore
{
    static readonly object Gate = new();
    static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static List<ScanHistoryRecord> Read(int maximum = 500)
    {
        lock (Gate)
        {
            try
            {
                var rows = JsonSerializer.Deserialize<List<ScanHistoryRecord>>(File.ReadAllText(AppPaths.ScanHistory), Json) ?? [];
                return rows.OrderByDescending(x => x.StartedAt).Take(Math.Max(1, maximum)).ToList();
            }
            catch { return []; }
        }
    }

    public static void Append(ScanHistoryRecord record)
    {
        lock (Gate)
        {
            List<ScanHistoryRecord> rows;
            try { rows = JsonSerializer.Deserialize<List<ScanHistoryRecord>>(File.ReadAllText(AppPaths.ScanHistory), Json) ?? []; }
            catch { rows = []; }
            rows.Add(record);
            rows = rows.OrderByDescending(x => x.StartedAt).Take(1000).ToList();
            AppPaths.Ensure(); var temp = AppPaths.ScanHistory + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(rows, Json));
            File.Move(temp, AppPaths.ScanHistory, true);
        }
    }
}

public static class EngineTrustStore
{
    public static bool Contains(string sha256)
    {
        if (!IsSha256(sha256)) return false;
        try
        {
            using var document=JsonDocument.Parse(File.ReadAllText(AppPaths.TrustedEngines));
            var values=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            CollectHashes(document.RootElement,values);
            return values.Contains(sha256.Trim());
        }
        catch { return false; }
    }

    public static bool ContainsFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return false;
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Contains(Convert.ToHexString(SHA256.HashData(stream)));
        }
        catch { return false; }
    }

    static void CollectHashes(JsonElement element,HashSet<string> values)
    {
        switch(element.ValueKind)
        {
            case JsonValueKind.String:
                var value=element.GetString();if(IsSha256(value))values.Add(value!.Trim());break;
            case JsonValueKind.Array:
                foreach(var item in element.EnumerateArray())CollectHashes(item,values);break;
            case JsonValueKind.Object:
                foreach(var property in element.EnumerateObject())CollectHashes(property.Value,values);break;
        }
    }
    static bool IsSha256(string? value)
    {
        if(string.IsNullOrWhiteSpace(value)||value.Trim().Length!=64)return false;
        foreach(var c in value.Trim())if(!Uri.IsHexDigit(c))return false;
        return true;
    }
}

public static class QuarantineStore
{
    static readonly string Folder = Path.Combine(AppPaths.Root,"Quarantine");
    static readonly string Index = Path.Combine(Folder,"index.json");
    static readonly object Gate = new();

    public static async Task<QuarantineRecord> QuarantineAsync(string path,string reason,CancellationToken ct=default)
    {
        if(!File.Exists(path))throw new FileNotFoundException("El archivo ya no existe.",path);
        var info=new FileInfo(path);if(info.Length>512L*1024*1024)throw new InvalidOperationException("La cuarentena Beta admite archivos de hasta 512 MB para evitar agotar la memoria.");
        Directory.CreateDirectory(Folder); var id=Guid.NewGuid().ToString("N"); var encrypted=Path.Combine(Folder,id+".gxq"); var tempEncrypted=encrypted+".tmp"; var key=MasterKey();var indexed=false;
        try
        {
            var clear=await File.ReadAllBytesAsync(path,ct); var nonce=RandomNumberGenerator.GetBytes(12);var tag=new byte[16];var cipher=new byte[clear.Length];
            var sha=Convert.ToHexString(SHA256.HashData(clear)).ToLowerInvariant();
            try{using var aes=new AesGcm(key,16);aes.Encrypt(nonce,clear,cipher,tag);await using var output=new FileStream(tempEncrypted,FileMode.CreateNew,FileAccess.Write,FileShare.None,128*1024,FileOptions.Asynchronous|FileOptions.WriteThrough);await output.WriteAsync(nonce,ct);await output.WriteAsync(tag,ct);await output.WriteAsync(cipher,ct);await output.FlushAsync(ct);}
            finally{CryptographicOperations.ZeroMemory(clear);CryptographicOperations.ZeroMemory(cipher);}
            File.Move(tempEncrypted,encrypted);var record=new QuarantineRecord(id,path,sha,DateTimeOffset.Now,reason,encrypted,info.Length,"GXQ1");
            lock(Gate){var all=ReadInternal();all.Add(record);WriteInternal(all);indexed=true;}
            File.Delete(path);ResponseActionStore.Append("Aislar archivo",path,"COMPLETADO",true,$"Cuarentena {record.Id} · {reason}");return record;
        }
        catch{if(indexed)lock(Gate){var all=ReadInternal();all.RemoveAll(x=>x.Id==id);WriteInternal(all);}try{File.Delete(tempEncrypted);}catch{}try{File.Delete(encrypted);}catch{}throw;}
        finally{CryptographicOperations.ZeroMemory(key);}
    }

    public static async Task<string> RestoreAsync(string id,CancellationToken ct=default)
    {
        QuarantineRecord record;lock(Gate){record=ReadInternal().Single(x=>x.Id==id);}if(!File.Exists(record.EncryptedFile))throw new FileNotFoundException("Falta el contenido cifrado.");
        var encryptedFull=Path.GetFullPath(record.EncryptedFile);var folderFull=Path.GetFullPath(Folder).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;if(!encryptedFull.StartsWith(folderFull,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("La ruta de cuarentena no es válida.");
        var target=RestoreTarget(record.OriginalPath);Directory.CreateDirectory(Path.GetDirectoryName(target)!);var data=await File.ReadAllBytesAsync(record.EncryptedFile,ct);
        if(data.Length<28)throw new InvalidDataException("Contenido de cuarentena inválido.");var nonce=data[..12];var tag=data[12..28];var cipher=data[28..];var clear=new byte[cipher.Length];var key=MasterKey();
        var tempTarget=target+".givenx-restoring";
        try{using var aes=new AesGcm(key,16);aes.Decrypt(nonce,cipher,tag,clear);var restoredHash=Convert.ToHexString(SHA256.HashData(clear)).ToLowerInvariant();if(!restoredHash.Equals(record.Sha256,StringComparison.OrdinalIgnoreCase))throw new CryptographicException("La verificación SHA-256 de la restauración falló.");await File.WriteAllBytesAsync(tempTarget,clear,ct);File.Move(tempTarget,target);}
        catch{try{File.Delete(tempTarget);}catch{}throw;}
        finally{CryptographicOperations.ZeroMemory(clear);CryptographicOperations.ZeroMemory(cipher);CryptographicOperations.ZeroMemory(key);}
        lock(Gate){var all=ReadInternal();all.RemoveAll(x=>x.Id==id);WriteInternal(all);}File.Delete(record.EncryptedFile);ResponseActionStore.Append("Restaurar archivo",target,"COMPLETADO",false,$"Cuarentena {id}");return target;
    }

    public static List<QuarantineRecord> Read(){lock(Gate)return ReadInternal();}
    static string RestoreTarget(string original){if(!File.Exists(original))return original;for(var i=1;i<1000;i++){var candidate=original+(i==1?".restored":$".restored-{i}");if(!File.Exists(candidate)&&!File.Exists(candidate+".givenx-restoring"))return candidate;}throw new IOException("No se encontró un nombre libre para restaurar el archivo.");}
    static byte[] MasterKey(){var stored=SecureSecrets.Load("quarantine-master");if(stored is not null)return Convert.FromBase64String(stored);var key=RandomNumberGenerator.GetBytes(32);SecureSecrets.Save("quarantine-master",Convert.ToBase64String(key));return key;}
    static List<QuarantineRecord> ReadInternal(){try{return JsonSerializer.Deserialize<List<QuarantineRecord>>(File.ReadAllText(Index))??[];}catch{return[];}}
    static void WriteInternal(List<QuarantineRecord> rows){Directory.CreateDirectory(Folder);var temp=Index+".tmp";File.WriteAllText(temp,JsonSerializer.Serialize(rows,new JsonSerializerOptions{WriteIndented=true}));File.Move(temp,Index,true);}
}
