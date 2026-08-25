using System.Diagnostics;

namespace GivenX.UI;

internal static class WindowsSecurityLauncher
{
    public static void Open(IWin32Window? owner = null)
    {
        try
        {
            Process.Start(new ProcessStartInfo("ms-settings:windowsdefender") { UseShellExecute = true });
        }
        catch
        {
            try { Process.Start(new ProcessStartInfo("windowsdefender:") { UseShellExecute = true }); }
            catch (Exception ex) { MessageBox.Show(owner, "Windows no pudo abrir Seguridad de Windows.\n\n" + ex.Message, "GivenX Shield", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }
    }
}
