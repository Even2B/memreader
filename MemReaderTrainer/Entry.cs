using System.Text;

namespace MemReader;

internal static class Entry
{
    [STAThread]
    private static void Main()
    {
        // A GUI crash otherwise vanishes with the window; leave a breadcrumb next to the exe.
        AppDomain.CurrentDomain.UnhandledException += (_, e) => LogCrash(e.ExceptionObject as Exception);
        Application.ThreadException += (_, e) => LogCrash(e.Exception);

        ApplicationConfiguration.Initialize();

        try
        {
            Application.Run(new TrainerForm());
        }
        catch (Exception ex)
        {
            LogCrash(ex);
            throw;
        }
    }

    private static void LogCrash(Exception? ex)
    {
        if (ex is null) return;
        try
        {
            string path = Path.Combine(AppContext.BaseDirectory, "crash.log");
            File.AppendAllText(path, $"[{DateTime.Now:s}] {ex}\n\n", Encoding.UTF8);
        }
        catch { /* nothing useful left to do */ }
    }
}
