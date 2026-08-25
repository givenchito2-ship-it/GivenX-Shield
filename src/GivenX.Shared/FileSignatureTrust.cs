using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace GivenX.Shared;

public static class FileSignatureTrust
{
    static readonly Guid Action = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct FileInfo { public uint Size; public string? FilePath; public IntPtr FileHandle; public IntPtr KnownSubject; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct TrustData
    {
        public uint Size; public IntPtr PolicyCallbackData; public IntPtr SIPClientData; public uint UIChoice;
        public uint RevocationChecks; public uint UnionChoice; public IntPtr FileInfoPtr; public uint StateAction;
        public IntPtr StateData; public string? URLReference; public uint ProviderFlags; public uint UIContext;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, IntPtr data);

    public static bool IsTrusted(string path)
    {
        if (!File.Exists(path)) return false;
        var file = new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), FilePath = path };
        var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>()); var dataPtr = IntPtr.Zero;
        try
        {
            Marshal.StructureToPtr(file, filePtr, false);
            var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), UIChoice = 2, RevocationChecks = 0, UnionChoice = 1, FileInfoPtr = filePtr, StateAction = 0, ProviderFlags = 0x00000040 };
            dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<TrustData>()); Marshal.StructureToPtr(data, dataPtr, false);
            return WinVerifyTrust(new IntPtr(-1), Action, dataPtr) == 0;
        }
        catch { return false; }
        finally
        {
            if (dataPtr != IntPtr.Zero) { Marshal.DestroyStructure<TrustData>(dataPtr); Marshal.FreeHGlobal(dataPtr); }
            Marshal.DestroyStructure<FileInfo>(filePtr); Marshal.FreeHGlobal(filePtr);
        }
    }

    public static string? TrustedPublisher(string path)
    {
        if (!IsTrusted(path)) return null;
        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            var name = certificate.GetNameInfo(X509NameType.SimpleName, false);
            if (string.IsNullOrWhiteSpace(name)) name = certificate.Subject;
            var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            return $"{name.Trim()} [{fingerprint}]";
        }
        catch { return null; }
    }
}
