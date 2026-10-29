using System.Reflection;
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

    /// <summary>Tid fra programmet startet til skjermen var klar. Vises i bunnlinjen, så oppstarten kan måles.</summary>
    internal static readonly System.Diagnostics.Stopwatch Klokke = System.Diagnostics.Stopwatch.StartNew();
    internal static long? OppstartMs;
    internal static long FraStart()
    {
        try { using var p = System.Diagnostics.Process.GetCurrentProcess(); return Math.Max(Klokke.ElapsedMilliseconds, (long)(DateTime.Now - p.StartTime).TotalMilliseconds); }
        catch { return Klokke.ElapsedMilliseconds; }
    }

    /// <summary>
    /// Ingen AISkanner.exe.config i mappa (med skjulte filendelser ser den ut som en ekstra AISkanner.exe). Den
    /// trengtes bare for å si at en annen versjon av et bibliotek ved siden av programmet er greit. Det gjør vi her:
    /// spør .NET etter en versjon som ikke ligger der, lastes den som ligger ved siden av programmet. Lastes med
    /// Assembly.Load (vanlig lasting fra programmappa), ikke LoadFrom, som .NET nekter for filer fra en nedlastet zip.
    /// </summary>
    static Program() => AppDomain.CurrentDomain.AssemblyResolve += AnnenVersjon;

    internal static readonly List<string> Omdirigert = new();
    [ThreadStatic] private static bool _iGang;

    private static Assembly? AnnenVersjon(object? _, ResolveEventArgs e)
    {
        if (_iGang) { lock (Omdirigert) Omdirigert.Add($"(inni) {e.Name}"); return null; }
        try
        {
            _iGang = true;
            var spurt = new AssemblyName(e.Name);
            if (string.IsNullOrEmpty(spurt.Name) || spurt.Name!.IndexOfAny(new[] { '\\', '/', ':' }) >= 0) return null;
            var sti = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, spurt.Name + ".dll");
            if (!File.Exists(sti)) return null;
            var finnes = AssemblyName.GetAssemblyName(sti);
            // Bare samme bibliotek fra samme utgiver (samme navn og nøkkel), og bare når versjonen er en annen
            var (a, b) = (spurt.GetPublicKeyToken(), finnes.GetPublicKeyToken());
            if (a != null && a.Length > 0 && (b == null || !a.SequenceEqual(b))) return null;
            if (spurt.Version != null && spurt.Version == finnes.Version) return null;
            // Bare navnet som tekst: et AssemblyName fra fila har også CodeBase, og da kan .NET laste som LoadFrom
            var lastet = Assembly.Load(finnes.FullName);
            lock (Omdirigert) Omdirigert.Add($"{spurt.Name} {spurt.Version} -> {finnes.Version}");
            return lastet;
        }
        catch (Exception x) { lock (Omdirigert) Omdirigert.Add($"{e.Name}: {x.GetType().Name}: {x.Message}"); return null; }
        finally { _iGang = false; }
    }

    [STAThread]
    private static void Main(string[] args)
    {
        // Byggeløypa: laster bibliotekene og kjører kontrollen uten vindu, i mappa slik brukeren får den
        if (args.Contains("--lastetest")) { Environment.Exit(Lastetest()); return; }

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

        // Søket gjelder brukeren som er logget inn, også når IT godkjente admin med sin egen konto
        Bruker.Velg();

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        if (args.Contains("--kontroll")) { try { VisKontroll(args.Contains("--en")); } catch (Exception e) { VisFeil(e); } return; }
        try { Kjor(args); }
        catch (Exception e) { VisFeil(e); }
    }

    // Egen metode: hvis en DLL mangler, feiler den her (når vinduet lages), etter at feilmeldingen er klar.
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void Kjor(string[] args) => Application.Run(new Hovedvindu(args));

    // «AISkanner.exe --kontroll»: lager kjente spor i en midlertidig mappe, sjekker at hver alarm slår ut,
    // sletter mappa og viser resultatet (Ctrl+C kopierer). Ingenting lagres.
    private static void VisKontroll(bool engelsk)
    {
        var tekst = Skanner.Kontroll(Regelsett.Last());
        if (engelsk) tekst = string.Join("\r\n", tekst.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).Select(l => Engelsk.Til(l)));
        var feil = tekst.Contains("FEIL");
        MessageBox.Show(tekst + "\r\n" + (engelsk ? "Press Ctrl+C to copy." : "Trykk Ctrl+C for å kopiere."),
            engelsk ? "AI Scanner: alarm check" : "AI-skanner: kontroll av alarmene", MessageBoxButtons.OK,
            feil ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static int Lastetest()
    {
        try
        {
            var tekst = Skanner.Kontroll(Regelsett.Last());
            var feil = tekst.Contains("FEIL");
            Console.WriteLine(tekst.Split('\n').LastOrDefault(l => l.Trim().Length > 0)?.Trim());
            if (feil) Console.WriteLine(string.Join("\n", tekst.Split('\n').Where(l => l.Contains("FEIL"))));

            // SQLite fra Windows (winsqlite3.dll i System32), slik nettleserhistorikken leses
            var tom = Path.GetTempFileName();
            try
            {
                long svar = 0;
                using (var db = new WinSqlite(tom)) db.Les("SELECT 41 + ?", 1, r => svar = r.Tall(0));
                Console.WriteLine($"SQLite: {(svar == 42 ? "OK" : "FEIL")}");
                feil |= svar != 42;
            }
            finally { try { File.Delete(tom); } catch { } }

            // Et helt søk i .NET Framework 4.8 (det brukeren kjører), uten NVD og med kort lytting: ingen sjekk skal krasje
            var sok = new Skanner(Regelsett.Last()) { LytteSekunder = 2 };
            var funn = Task.Run(() => sok.KjorAsync(false)).GetAwaiter().GetResult();
            var stoppet = (Tilgangslogg.Aktiv?.Oppforinger ?? (IReadOnlyCollection<Tilgang>)Array.Empty<Tilgang>())
                .Where(t => t.Hva == "Sjekk" && t.Utfall == Utfall.Feil).Select(t => $"{t.Mal}: {t.Detalj}").ToList();
            Console.WriteLine($"Søk: {sok.Tider.Sum(t => t.Value.TotalSeconds):0.0} s i sum, {(stoppet.Count == 0 ? "ingen sjekk stoppet" : "stoppet: " + string.Join(" | ", stoppet))}");
            Console.WriteLine("Rapport: " + (Rapport.Tekst(funn, sok).Length > 0 ? "OK" : "FEIL") + ", CSV: " + (Rapport.Csv(funn).Length > 0 ? "OK" : "FEIL"));
            feil |= stoppet.Count > 0;

            // WebView2: begge DLL-ene og WebView2Loader.dll (runtimes\win-x64\native) lastes
            using (var vindu = new Microsoft.Web.WebView2.WinForms.WebView2()) { }
            try { Console.WriteLine("WebView2: " + Microsoft.Web.WebView2.Core.CoreWebView2Environment.GetAvailableBrowserVersionString()); }
            catch (Microsoft.Web.WebView2.Core.WebView2RuntimeNotFoundException) { Console.WriteLine("WebView2: lasteren virker, Edge WebView2 Runtime er ikke installert"); }

            Console.WriteLine(feil ? "LASTETEST FEIL" : "LASTETEST OK");
            return feil ? 1 : 0;
        }
        catch (Exception e) { Console.WriteLine("LASTETEST FEIL\n" + e); return 2; }
        finally { lock (Omdirigert) foreach (var o in Omdirigert) Console.WriteLine("Annen versjon: " + o); }
    }

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
