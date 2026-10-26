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
        // Programmet skal aldri forsvinne uten å si hvorfor. Feil vises i en melding som kan kopieres (Ctrl+C).
        AppDomain.CurrentDomain.UnhandledException += (_, e) => VisFeil(e.ExceptionObject as Exception);
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => VisFeil(e.Exception);

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
        try { Kjor(args); }
        catch (Exception e) { VisFeil(e); }
    }

    // Egen metode: hvis en DLL mangler, feiler den her (når vinduet lages), etter at feilmeldingen er klar.
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void Kjor(string[] args) => Application.Run(new Hovedvindu(args));

    private static void VisFeil(Exception? e)
    {
        try
        {
            var tekst = "AI-skanner kunne ikke starte eller stoppet med en feil.\r\n\r\n" +
                        "Trykk Ctrl+C for å kopiere denne meldingen og send den til IT eller utvikleren.\r\n\r\n" +
                        $"Versjon: {typeof(Program).Assembly.GetName().Version}\r\nMappe: {AppDomain.CurrentDomain.BaseDirectory}\r\n\r\n{e}";
            MessageBox.Show(tekst, "AI-skanner: feil", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        catch { }
    }
}
