using System.Diagnostics;

namespace GivenX.Shared;

public static class ProcessResponse
{
    public static void TerminateUserProcess(int processId, string expectedPath)
    {
        if (processId <= 4 || processId == Environment.ProcessId) throw new InvalidOperationException("GivenX no finalizará un proceso crítico o su propio proceso.");
        using var process = Process.GetProcessById(processId); var actualPath = process.MainModule?.FileName ?? string.Empty;
        if (string.IsNullOrWhiteSpace(actualPath) || !Path.GetFullPath(actualPath).Equals(Path.GetFullPath(expectedPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("El PID ya no corresponde al archivo mostrado. No se realizó ninguna acción.");
        if (!IsUserWritable(actualPath)) throw new InvalidOperationException("La Beta solo permite finalizar desde GivenX procesos ubicados en carpetas modificables por el usuario. Usa el Administrador de tareas para otros casos.");
        process.Kill(true); process.WaitForExit(5000);ResponseActionStore.Append("Finalizar proceso",actualPath,"COMPLETADO",false,$"PID {processId}");
    }

    public static bool IsUserWritable(string path)
    {
        if(string.IsNullOrWhiteSpace(path))return false;
        try
        {
            var full=Path.GetFullPath(path);var profile=Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar;
            if(full.StartsWith(profile,StringComparison.OrdinalIgnoreCase))return true;
            var publicProfile=Environment.GetEnvironmentVariable("PUBLIC");
            return !string.IsNullOrWhiteSpace(publicProfile)&&full.StartsWith(Path.GetFullPath(publicProfile).TrimEnd(Path.DirectorySeparatorChar)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase);
        }
        catch{return false;}
    }
}
