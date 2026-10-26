using System.Runtime.InteropServices;

namespace AISkanner.App;

internal static class Program
{
    // Programmappa + System32 + brukermapper, men IKKE arbeidsmappa.
    private const uint LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetDefaultDllDirectories(uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetDllDirectory(string? sti);

    [STAThread]
    private static void Main(string[] args)
    {
        // Sikkerhet: systembiblioteker (winsqlite3, iphlpapi, wintrust, dnsapi) lastes bare fra System32 og
        // programmappa, aldri fra arbeidsmappa. Hindrer DLL-kapring der en falsk DLL i mappa programmet startes
        // fra blir kjørt. (WebView2Loader.dll ligger lovlig i programmappa, så den søkes fortsatt.)
        try { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS); } catch { }
        try { SetDllDirectory(""); } catch { }   // ta arbeidsmappa helt ut av søket (eldre Windows uten kallet over)

        // Sikkerhet: en ondsinnet YARA-regel (ai-modeller.yar ved siden av programmet) kan ikke henge
        // programmet med et regex som aldri blir ferdig. Alle regex får en øvre tidsgrense.
        try { AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", TimeSpan.FromSeconds(2)); } catch { }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new Hovedvindu(args));
    }
}
