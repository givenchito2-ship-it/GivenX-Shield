namespace GivenX.UI;
internal static class Program
{
    [STAThread] static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Any(x => x.Equals("--givenx-preflight", StringComparison.OrdinalIgnoreCase))) return;
        Application.Run(new DashboardForm(args.Any(x => x.Equals("--background", StringComparison.OrdinalIgnoreCase))));
    }
}
