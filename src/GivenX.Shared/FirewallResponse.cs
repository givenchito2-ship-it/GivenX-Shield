using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net;
using System.Net.Sockets;

namespace GivenX.Shared;

public sealed record NetworkBlock(string RuleName,string ProgramPath,DateTimeOffset CreatedAt,string Kind="Programa",string Target="");
public static class FirewallResponse
{
    static readonly string Index=Path.Combine(AppPaths.Root,"network-blocks.json");static readonly object Gate=new();
    public static async Task<NetworkBlock> BlockAsync(string program,CancellationToken ct=default)
    {
        if(!File.Exists(program))throw new FileNotFoundException("No se encontró el ejecutable.",program);program=Path.GetFullPath(program);var existing=Read().FirstOrDefault(x=>(x.Kind??"Programa").Equals("Programa",StringComparison.OrdinalIgnoreCase)&&(x.ProgramPath??string.Empty).Equals(program,StringComparison.OrdinalIgnoreCase));if(existing is not null)return existing;var suffix=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(program))).Substring(0,12);var rule="GivenX Shield Program "+suffix;
        var code=await Netsh(["advfirewall","firewall","add","rule",$"name={rule}","dir=out","action=block",$"program={program}","enable=yes"],ct);if(code!=0)throw new InvalidOperationException("Windows Firewall rechazó el bloqueo.");
        var row=new NetworkBlock(rule,program,DateTimeOffset.Now,"Programa",program);lock(Gate){var all=ReadInternal();all.RemoveAll(x=>x.RuleName==rule);all.Add(row);Write(all);}ResponseActionStore.Append("Bloquear programa",program,"COMPLETADO",true,rule);return row;
    }
    public static async Task<NetworkBlock> BlockRemoteAddressAsync(string address,CancellationToken ct=default)
    {
        if(!IPAddress.TryParse(address,out var ip)||!IsPublicAddress(ip))throw new InvalidOperationException("GivenX solo permite bloquear direcciones IP públicas válidas desde esta función.");
        address=ip.ToString();var existing=Read().FirstOrDefault(x=>(x.Kind??string.Empty).Equals("IP",StringComparison.OrdinalIgnoreCase)&&(x.Target??string.Empty).Equals(address,StringComparison.OrdinalIgnoreCase));if(existing is not null)return existing;
        var suffix=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(address))).Substring(0,12);var rule="GivenX Shield Remote "+suffix;
        var code=await Netsh(["advfirewall","firewall","add","rule",$"name={rule}","dir=out","action=block",$"remoteip={address}","enable=yes"],ct);if(code!=0)throw new InvalidOperationException("Windows Firewall rechazó el bloqueo de la dirección remota.");
        var row=new NetworkBlock(rule,string.Empty,DateTimeOffset.Now,"IP",address);lock(Gate){var all=ReadInternal();all.RemoveAll(x=>x.RuleName==rule);all.Add(row);Write(all);}ResponseActionStore.Append("Bloquear IP",address,"COMPLETADO",true,rule);return row;
    }
    public static async Task UnblockAsync(string rule,CancellationToken ct=default)
    {
        var current=Read().FirstOrDefault(x=>(x.RuleName??string.Empty).Equals(rule,StringComparison.OrdinalIgnoreCase));var code=await Netsh(["advfirewall","firewall","delete","rule",$"name={rule}"],ct);if(code!=0)throw new InvalidOperationException("No se pudo retirar la regla.");lock(Gate){var all=ReadInternal();all.RemoveAll(x=>x.RuleName==rule);Write(all);}var target=current is null?rule:string.IsNullOrWhiteSpace(current.Target)?current.ProgramPath??rule:current.Target;ResponseActionStore.Append("Retirar bloqueo",target,"COMPLETADO",false,rule);
    }
    public static List<NetworkBlock> Read(){lock(Gate)return ReadInternal();}
    static async Task<int> Netsh(IEnumerable<string> args,CancellationToken ct){var start=new ProcessStartInfo("netsh.exe"){UseShellExecute=false,CreateNoWindow=true};foreach(var arg in args)start.ArgumentList.Add(arg);using var process=Process.Start(start)??throw new InvalidOperationException("No se pudo abrir netsh.");await process.WaitForExitAsync(ct);return process.ExitCode;}
    static List<NetworkBlock> ReadInternal(){try{return JsonSerializer.Deserialize<List<NetworkBlock>>(File.ReadAllText(Index))??[];}catch{return[];}}
    static void Write(List<NetworkBlock> rows){AppPaths.Ensure();var temp=Index+".tmp";File.WriteAllText(temp,JsonSerializer.Serialize(rows,new JsonSerializerOptions{WriteIndented=true}));File.Move(temp,Index,true);}
    public static bool IsPublicAddress(IPAddress address)
    {
        if(address.IsIPv4MappedToIPv6)return IsPublicAddress(address.MapToIPv4());
        if(IPAddress.IsLoopback(address)||address.Equals(IPAddress.Any)||address.Equals(IPAddress.IPv6Any)||address.Equals(IPAddress.Broadcast)||address.Equals(IPAddress.None))return false;
        var bytes=address.GetAddressBytes();
        if(address.AddressFamily==AddressFamily.InterNetwork)
        {
            if(bytes[0] is 0 or 10 or 127||bytes[0]>=224)return false;
            if(bytes[0]==100&&bytes[1]>=64&&bytes[1]<=127)return false;
            if(bytes[0]==169&&bytes[1]==254)return false;
            if(bytes[0]==172&&bytes[1]>=16&&bytes[1]<=31)return false;
            if(bytes[0]==192&&bytes[1]==168)return false;
            return true;
        }
        if(address.AddressFamily==AddressFamily.InterNetworkV6)
        {
            if(address.IsIPv6LinkLocal||address.IsIPv6Multicast||address.IsIPv6SiteLocal)return false;
            if((bytes[0]&0xFE)==0xFC)return false;
            return true;
        }
        return false;
    }
}
