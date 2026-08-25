using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace GivenX.Shared;

public static class SecureSecrets
{
    static readonly byte[] Entropy = SHA256.HashData(Encoding.UTF8.GetBytes("GivenX Shield|API secrets|v1"));
    static string PathFor(string name) => Path.Combine(AppPaths.Root, $"secret-{name}.bin");

    public static void Save(string name, string value)
    {
        AppPaths.Ensure();
        if (string.IsNullOrWhiteSpace(value)) { Delete(name); return; }
        var plain = Encoding.UTF8.GetBytes(value.Trim());
        try { File.WriteAllBytes(PathFor(name), Protect(plain)); }
        finally { CryptographicOperations.ZeroMemory(plain); }
    }

    public static string? Load(string name)
    {
        try
        {
            var clear = Unprotect(File.ReadAllBytes(PathFor(name)));
            try { return Encoding.UTF8.GetString(clear); }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        catch { return null; }
    }

    public static bool Exists(string name) => File.Exists(PathFor(name));
    public static void Delete(string name) { try { File.Delete(PathFor(name)); } catch { } }

    static byte[] Protect(byte[] input) => Transform(input, true);
    static byte[] Unprotect(byte[] input) => Transform(input, false);

    static byte[] Transform(byte[] input, bool protect)
    {
        var inBlob = ToBlob(input); var entropyBlob = ToBlob(Entropy); DATA_BLOB output = default;
        try
        {
            var ok = protect
                ? CryptProtectData(ref inBlob, "GivenX Shield", ref entropyBlob, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref inBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new InvalidOperationException("Windows no pudo proteger la credencial.");
            var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, output.Size); return result;
        }
        finally { FreeBlob(ref inBlob); FreeBlob(ref entropyBlob); if (output.Data != IntPtr.Zero) LocalFree(output.Data); }
    }

    static DATA_BLOB ToBlob(byte[] bytes) { var blob = new DATA_BLOB { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) }; Marshal.Copy(bytes, 0, blob.Data, bytes.Length); return blob; }
    static void FreeBlob(ref DATA_BLOB blob) { if (blob.Data != IntPtr.Zero) { Marshal.FreeHGlobal(blob.Data); blob.Data = IntPtr.Zero; } }
    [StructLayout(LayoutKind.Sequential)] struct DATA_BLOB { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptProtectData(ref DATA_BLOB input, string description, ref DATA_BLOB entropy, IntPtr reserved, IntPtr prompt, int flags, out DATA_BLOB output);
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptUnprotectData(ref DATA_BLOB input, IntPtr description, ref DATA_BLOB entropy, IntPtr reserved, IntPtr prompt, int flags, out DATA_BLOB output);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
}
