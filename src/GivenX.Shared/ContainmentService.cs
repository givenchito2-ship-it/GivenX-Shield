using System.Net;

namespace GivenX.Shared;

public sealed record ContainmentRequest(string? FilePath,int? ProcessId,string? RemoteAddress,string Reason);
public sealed record ContainmentStep(string Action,string Outcome,string Details);
public sealed record ContainmentResult(IReadOnlyList<ContainmentStep> Steps)
{
    public bool AnyAction => Steps.Any(x=>x.Outcome=="COMPLETADO");
    public bool Completed => AnyAction&&Steps.All(x=>x.Outcome=="COMPLETADO");
    public string Summary => string.Join(Environment.NewLine,Steps.Select(x=>$"{x.Action}: {x.Outcome} · {x.Details}"));
}

public static class ContainmentService
{
    public static async Task<ContainmentResult> ContainAsync(ContainmentRequest request,CancellationToken cancellationToken=default)
    {
        var steps=new List<ContainmentStep>();var path=string.IsNullOrWhiteSpace(request.FilePath)?null:Path.GetFullPath(request.FilePath);
        if(!string.IsNullOrWhiteSpace(request.RemoteAddress)&&IPAddress.TryParse(request.RemoteAddress,out var remote)&&FirewallResponse.IsPublicAddress(remote))
        {
            try{var row=await FirewallResponse.BlockRemoteAddressAsync(remote.ToString(),cancellationToken);steps.Add(new("Bloquear IP","COMPLETADO",row.RuleName));}
            catch(Exception ex){steps.Add(new("Bloquear IP","ERROR",ex.Message));ResponseActionStore.Append("Contención: bloquear IP",remote.ToString(),"ERROR",false,ex.Message);}
        }
        if(path is not null&&File.Exists(path)&&ProcessResponse.IsUserWritable(path))
        {
            if(path.EndsWith(".exe",StringComparison.OrdinalIgnoreCase))
            {
                try{var row=await FirewallResponse.BlockAsync(path,cancellationToken);steps.Add(new("Bloquear programa","COMPLETADO",row.RuleName));}
                catch(Exception ex){steps.Add(new("Bloquear programa","ERROR",ex.Message));ResponseActionStore.Append("Contención: bloquear programa",path,"ERROR",false,ex.Message);}
            }
            if(request.ProcessId.HasValue)
            {
                try{ProcessResponse.TerminateUserProcess(request.ProcessId.Value,path);steps.Add(new("Finalizar proceso","COMPLETADO",$"PID {request.ProcessId.Value}"));}
                catch(Exception ex){steps.Add(new("Finalizar proceso","ERROR",ex.Message));ResponseActionStore.Append("Contención: finalizar proceso",$"PID {request.ProcessId.Value}","ERROR",false,ex.Message);}
            }
            if(File.Exists(path))
            {
                try{var row=await QuarantineStore.QuarantineAsync(path,"Contención avanzada: "+request.Reason,cancellationToken);steps.Add(new("Aislar archivo","COMPLETADO",row.Id));}
                catch(Exception ex){steps.Add(new("Aislar archivo","ERROR",ex.Message));ResponseActionStore.Append("Contención: aislar archivo",path,"ERROR",false,ex.Message);}
            }
        }
        else if(path is not null)steps.Add(new("Archivo","OMITIDO","La contención automática de archivos se limita a carpetas modificables por el usuario."));
        if(steps.Count==0)steps.Add(new("Contención","OMITIDO","El evento no contiene una IP pública ni un archivo apto para respuesta segura."));
        return new(steps);
    }
}
