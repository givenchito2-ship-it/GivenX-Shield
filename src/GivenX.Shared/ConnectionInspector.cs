using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace GivenX.Shared;

public sealed record LiveConnection(int ProcessId,string ProcessName,string ProcessPath,IPEndPoint Local,IPEndPoint Remote,uint State)
{
    public bool IsEstablished => State == 5;
}

public static class ConnectionInspector
{
    const int AF_INET=2,AF_INET6=23,TCP_TABLE_OWNER_PID_ALL=5;
    [StructLayout(LayoutKind.Sequential)]struct Row4{public uint State,LocalAddress,LocalPort,RemoteAddress,RemotePort,ProcessId;}
    [StructLayout(LayoutKind.Sequential)]struct Row6
    {
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=16)]public byte[]? LocalAddress;
        public uint LocalScopeId,LocalPort;
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=16)]public byte[]? RemoteAddress;
        public uint RemoteScopeId,RemotePort,State,ProcessId;
    }
    sealed record Raw(int ProcessId,IPEndPoint Local,IPEndPoint Remote,uint State);
    [DllImport("iphlpapi.dll",SetLastError=true)]static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool order,int family,int tableClass,uint reserved);

    public static IReadOnlyList<LiveConnection> Snapshot()
    {
        var raw=new List<Raw>();try{raw.AddRange(Read4());}catch{}try{raw.AddRange(Read6());}catch{}
        var identities=new Dictionary<int,(string Name,string Path)>();var result=new List<LiveConnection>(raw.Count);
        foreach(var row in raw)
        {
            if(!identities.TryGetValue(row.ProcessId,out var identity))
            {
                identity=("Proceso no disponible",string.Empty);
                try{using var process=Process.GetProcessById(row.ProcessId);identity=(process.ProcessName,process.MainModule?.FileName??string.Empty);}catch{}
                identities[row.ProcessId]=identity;
            }
            result.Add(new(row.ProcessId,identity.Name,identity.Path,row.Local,row.Remote,row.State));
        }
        return result.OrderByDescending(x=>x.IsEstablished).ThenBy(x=>x.ProcessName,StringComparer.OrdinalIgnoreCase).ThenBy(x=>x.Remote.Address.ToString(),StringComparer.OrdinalIgnoreCase).ToList();
    }

    static IReadOnlyList<Raw> Read4()
    {
        var size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,true,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);if(size<=0)return[];var buffer=Marshal.AllocHGlobal(size);
        try
        {
            if(GetExtendedTcpTable(buffer,ref size,true,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)!=0)return[];var count=Marshal.ReadInt32(buffer);var pointer=IntPtr.Add(buffer,4);var rowSize=Marshal.SizeOf<Row4>();var rows=new List<Raw>(count);
            for(var i=0;i<count;i++){var row=Marshal.PtrToStructure<Row4>(IntPtr.Add(pointer,i*rowSize));rows.Add(new((int)row.ProcessId,new(new IPAddress(row.LocalAddress),Port(row.LocalPort)),new(new IPAddress(row.RemoteAddress),Port(row.RemotePort)),row.State));}return rows;
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }

    static IReadOnlyList<Raw> Read6()
    {
        var size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,true,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0);if(size<=0)return[];var buffer=Marshal.AllocHGlobal(size);
        try
        {
            if(GetExtendedTcpTable(buffer,ref size,true,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0)!=0)return[];var count=Marshal.ReadInt32(buffer);var pointer=IntPtr.Add(buffer,4);var rowSize=Marshal.SizeOf<Row6>();var rows=new List<Raw>(count);
            for(var i=0;i<count;i++){var row=Marshal.PtrToStructure<Row6>(IntPtr.Add(pointer,i*rowSize));rows.Add(new((int)row.ProcessId,new(Address6(row.LocalAddress,row.LocalScopeId),Port(row.LocalPort)),new(Address6(row.RemoteAddress,row.RemoteScopeId),Port(row.RemotePort)),row.State));}return rows;
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }

    static int Port(uint value)=>(ushort)IPAddress.NetworkToHostOrder((short)value);
    static IPAddress Address6(byte[]? bytes,uint scope){var address=new IPAddress(bytes??new byte[16],scope);return address.IsIPv4MappedToIPv6?address.MapToIPv4():address;}
}
