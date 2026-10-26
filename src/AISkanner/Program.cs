using System.Reflection;
using System.Runtime.CompilerServices;
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

    /// <summary>
    /// Bibliotekene (DLL-ene) ligger i undermappa «bibliotek», så AISkanner.exe er den eneste programfila i hovedmappa
    /// og det ikke trengs en AISkanner.exe.config. Windows finner dem ikke der selv, så vi viser vei.
    /// Bare filer i vår egen bibliotek-mappe lastes, og bare når .NET ber om dem.
    /// </summary>
    internal static readonly string Bibliotek = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "bibliotek");

    private static Assembly? FinnBibliotek(object? _, ResolveEventArgs e)
    {
        try
        {
            var navn = new AssemblyName(e.Name).Name;
            if (string.IsNullOrEmpty(navn) || navn!.IndexOfAny(new[] { '\\', '/', ':' }) >= 0) return null;
            var sti = Path.Combine(Bibliotek, navn + ".dll");
            // Samme bibliotek uansett hvilken versjon som spørres etter (erstatter bindingRedirect i .config)
            return File.Exists(sti) ? Assembly.LoadFrom(sti) : null;
        }
        catch { return null; }
    }

    [STAThread]
    private static void Main(string[] args)
    {
        // Må skje før noe fra bibliotekene brukes. Resten ligger i Start, så den ikke kompileres før dette er gjort.
        AppDomain.CurrentDomain.AssemblyResolve += FinnBibliotek;
        Start(args);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void Start(string[] args)
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
