using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Finner lokal AI, skygge-AI og nettleser-AI.
/// Sikkerhet: leser bare, endrer ingenting, trenger ikke admin, starter ingen andre programmer.
/// Ingenting sendes ut med mindre brukeren slår på sårbarhetssjekk (da sendes bare produktord til NVD).
/// </summary>
public sealed partial class Skanner
{
    private readonly Regelsett _regler;
    private readonly Dictionary<string, Funn> _funn = new(StringComparer.OrdinalIgnoreCase);
    private IProgress<string>? _status;

    /// <summary>
    /// Sikkerhetssperre: de eneste filene skanneren åpner og leser innholdet i.
    /// Passord, informasjonskapsler, historikk og lommebøker i nettleseren blir aldri åpnet.
    /// </summary>
    public static readonly ISet<string> LovligeFiler =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "manifest.json", "messages.json", "extensions.json", "Preferences", "History", "places.sqlite" };

    private readonly bool _historikk;

    /// <summary>Hvor lang tid hver sjekk tok i siste søk.</summary>
    public Dictionary<string, TimeSpan> Tider { get; } = new();

    /// <param name="historikk">Søk etter AI-nettsteder i nettleserhistorikken (bare i minnet, lagres aldri).</param>
    public Skanner(Regelsett regler, bool historikk = true)
    {
        _regler = regler;
        _historikk = historikk;
    }

    /// <summary>Når søket startet, for rapporten.</summary>
    public DateTime? Startet { get; private set; }
    public DateTime? Ferdig { get; private set; }

    /// <summary>Alt søket prøvde å lese, og hvordan det gikk (utviklermodus og revisjonslogg).</summary>
    public Tilgangslogg Logg { get; private set; } = new();

    /// <summary>Reglene søket bruker (for revisjonsloggen).</summary>
    public Regelsett Regelsett => _regler;
    public bool MedHistorikk => _historikk;

    /// <summary>Hendelser fra Defender under søket som gjelder dette programmet.</summary>
    public Antivirus.Resultat? Forsvar { get; private set; }

    public async Task<List<Funn>> KjorAsync(bool eksternSjekk, IProgress<string>? status = null, CancellationToken ct = default, IProgress<int>? steg = null)
    {
        _funn.Clear();
        _status = status;
        Startet = DateTime.Now;
        Logg = new Tilgangslogg();
        Tilgangslogg.Aktiv = Logg;
        var stegliste = new (string Tekst, Action Gjor)[]
        {
            ("Ser etter AI som kjører nå...", () => { Prosesser(); MotorerIProsesser(); }),
            ("Sjekker installerte programmer...", Installert),
            ("Sjekker hva som starter av seg selv...", Oppstart),
            ("Ser etter AI-verktøy og AI-nøkler...", () => { Spor(); Nokler(); }),
            ("Spør lokale programmer om de er AI...", () => { Porter(); LokaleServere(); }),
            ("Sjekker utvidelser i nettleserne...", Nettlesere),
            ("Ser etter AI-nettsteder du har brukt...", Nettsteder),
            ("Sjekker innebygd AI i Chrome og Edge...", InnebygdAi),
            ("Leter gjennom filene etter AI-modeller og AI-kode...", Gjennomgang),
            ("Sjekker registeret...", Register),
            ("Leter etter AI som leverandører har lagt inn...", LeverandorAi),
            ("Ser etter ukjente AI-spor...", UkjenteSporSjekk),
        };
        // Alle sjekkene kjører samtidig. Fremdriften er antall ferdige sjekker.
        Tider.Clear();
        _mappeFunn.Clear();
        while (_prosjektOppsett.TryTake(out _)) { }
        lock (Blindsoner) Blindsoner.Clear();
        var klokke = Stopwatch.StartNew();
        // Med administrator: slå på Windows' egne datatellere mens søket pågår, så vi kan måle ekte datamengde
        Tilgangslogg.Sjekk.Value = "Ser hvor AI sender data";
        using var maling = TestNett == null ? Datamaling.Start() : null;
        int ferdig = 0;
        steg?.Report(0);
        await Task.WhenAll(stegliste.Select(x => Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var tid = Stopwatch.StartNew();
            Tilgangslogg.Sjekk.Value = x.Tekst.TrimEnd('.');
            try { x.Gjor(); }
            catch (Exception e)
            {
                Debug.WriteLine($"{x.Tekst} feilet: {e.Message}");
                Tilgangslogg.Logg("Sjekk", x.Tekst.TrimEnd('.'), Utfall.Feil, $"Sjekken stoppet: {Tilgangslogg.Beskriv(e)}");
            }
            lock (Tider) Tider[x.Tekst.TrimEnd('.')] = tid.Elapsed;
            steg?.Report(Interlocked.Increment(ref ferdig));
            _status?.Report(x.Tekst);
        }, ct)));
        // Til slutt: hvor AI-programmene sender data akkurat nå
        try
        {
            if (maling != null && maling.Sekunder < 5) await Task.Delay(TimeSpan.FromSeconds(5 - maling.Sekunder), ct);
            var tid = Stopwatch.StartNew();
            Tilgangslogg.Sjekk.Value = "Ser hvor AI sender data";
            Trafikk(TestNett?.Invoke() ?? NettBilde.Hent(maling));
            Tider["Ser hvor AI sender data"] = tid.Elapsed;
        }
        catch (Exception e) when (e is not OperationCanceledException) { Debug.WriteLine($"Trafikk feilet: {e.Message}"); }
        Risikoregler.Bruk(_funn.Values, _regler);
        // Stoppet antivirus noe av det vi leste? Defender skriver det i sin egen logg.
        Tilgangslogg.Sjekk.Value = "Antivirus";
        Forsvar = Antivirus.Hendelser(Startet.Value);
        Tilgangslogg.Sjekk.Value = null;
        Tider["Totalt"] = klokke.Elapsed;
        Ferdig = DateTime.Now;
        if (eksternSjekk) await Nvd.SjekkAsync(_funn.Values, _status, ct);
        _status?.Report("Ferdig.");
        return _funn.Values.OrderBy(f => f.Risiko).ThenBy(f => f.Navn, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    // ---------- hjelpere ----------

    internal static string Utvid(string sti)
    {
        var s = Environment.ExpandEnvironmentVariables(sti);
        return Plattform.ErWindows ? s : s.Replace('\\', '/');   // bare for testing utenfor Windows
    }

    private static bool Treffer(string tekst, string ord) =>
        Regex.IsMatch(tekst, "(?<![a-z0-9])" + Regex.Escape(ord.ToLowerInvariant()) + "(?![a-z0-9])", RegexOptions.IgnoreCase);

    private Produkt? FinnRegel(string? tekst, bool utvidelse = false)
    {
        if (string.IsNullOrWhiteSpace(tekst)) return null;
        IEnumerable<Produkt> kandidater = utvidelse
            ? _regler.Produkter.Where(p => p.Kategori == "Nettleser-AI" && !p.KunUtvidelse)
                .Concat(_regler.Produkter.Where(p => p.KunUtvidelse))
            : _regler.Produkter.Where(p => !p.KunUtvidelse);
        return kandidater.FirstOrDefault(p => p.Treff.Any(o => Treffer(tekst, o)));
    }

    private Funn LeggTil(string navn, string kategori, Risiko risiko, string hvorfor, string? hvor, string? detalj,
                         Produkt? regel = null, string? enkelt = null, string? rad = null)
    {
        Funn? f;
        lock (_funn)
        {
            if (!_funn.TryGetValue(navn, out f))
                _funn[navn] = f = new Funn { Navn = navn, Kategori = kategori, Risiko = risiko, Hvorfor = hvorfor, Regel = regel, Enkelt = enkelt, Rad = rad };
            f.Risiko = RisikoTekst.Hoyeste(f.Risiko, risiko);
        }
        if (hvor != null) f.LeggTilHvor(hvor);
        if (detalj != null) f.Detalj(detalj);
        return f;
    }

    private Funn FraRegel(Produkt p, string hvor, string detalj) =>
        LeggTil(p.Navn, p.Kategori, RisikoTekst.Fra(p.Risiko), p.HvorforEnkelt ?? p.Hvorfor, hvor, detalj, p, p.Enkelt, p.Rad);

    internal static IEnumerable<string> Mapper(string sti) =>
        Tilgangslogg.Prov("Mappe", sti, () => Directory.EnumerateDirectories(sti).ToList(), new List<string>());

    private static IEnumerable<string> Filer(string sti) =>
        Tilgangslogg.Prov("Mappe", sti, () => Directory.EnumerateFiles(sti).ToList(), new List<string>());

    internal static JsonDocument? LesJson(string sti, ISet<string>? lovlige = null)
    {
        if (!(lovlige ?? LovligeFiler).Contains(Path.GetFileName(sti))) return null;
        try
        {
            var info = new FileInfo(sti);
            if (!info.Exists) { Tilgangslogg.Logg("Fil", sti, Utfall.IkkeFunnet); return null; }
            if (info.Length > 20 * 1024 * 1024) { Tilgangslogg.Logg("Fil", sti, Utfall.HoppetOver, "større enn 20 MB"); return null; }
            var doc = JsonDocument.Parse(File.ReadAllText(sti), new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest);
            return doc;
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return null; }
    }

    private static string Kutt(string s, int maks) => s.Length <= maks ? s : s.Substring(0, maks - 1).TrimEnd() + "…";

    private static string? Str(JsonElement e, string navn) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(navn, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static IEnumerable<JsonElement> Liste(JsonElement e, string navn) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(navn, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray() : Enumerable.Empty<JsonElement>();

    // ---------- 1. Prosesser ----------
    private void Prosesser()
    {
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                var sti = ProsessSti.Hent(p);
                var r = FinnRegel($"{p.ProcessName} {sti}");
                if (r == null) continue;
                var f = FraRegel(r, "Kjører nå", $"Program som kjører: {sti ?? p.ProcessName} (PID {p.Id})");
                f.Bruk = "Kjører nå.";
                HuskMappe(sti, f);
            }
        }
    }

    // ---------- 2. Installerte programmer ----------
    private void Installert()
    {
        if (!Plattform.ErWindows) return;
        var steder = new (RegistryKey Rot, string Sti)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        };
        foreach (var (rot, sti) in steder)
        {
            using var k = Tilgangslogg.Nokkel(rot, sti);
            if (k == null) continue;
            foreach (var under in k.GetSubKeyNames())
            {
                using var app = k.OpenSubKey(under);
                var navn = app?.GetValue("DisplayName") as string;
                var r = FinnRegel(navn);
                if (r != null) FraRegel(r, "Installert program", $"Program: {navn}");
            }
        }
        // Microsoft Store-apper for innlogget bruker
        using var pakker = Tilgangslogg.Nokkel(Registry.CurrentUser, @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages");
        foreach (var pakke in pakker?.GetSubKeyNames() ?? Array.Empty<string>())
        {
            var r = FinnRegel(pakke.Replace('_', ' '));
            if (r != null) FraRegel(r, "Installert app (Microsoft Store)", $"App: {pakke.Split('_')[0]}");
        }
    }

    // ---------- 3. Tjenester, oppstart og planlagte oppgaver ----------
    private void Oppstart()
    {
        if (Plattform.ErWindows)
        {
            using (var tjenester = Tilgangslogg.Nokkel(Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Services"))
            {
                foreach (var navn in tjenester?.GetSubKeyNames() ?? Array.Empty<string>())
                {
                    using var t = tjenester!.OpenSubKey(navn);
                    if (t == null) continue;
                    var visning = t.GetValue("DisplayName") as string;
                    var bilde = t.GetValue("ImagePath") as string;
                    var r = FinnRegel($"{navn} {visning} {bilde}");
                    if (r == null) continue;
                    var f = FraRegel(r, "Windows-tjeneste", $"Tjeneste: {visning ?? navn}");
                    if (t.GetValue("Start") is int start && start == 2) f.Merknad("Starter automatisk som tjeneste.");
                }
            }

            var run = new (RegistryKey Rot, string Sti)[]
            {
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            };
            foreach (var (rot, sti) in run)
            {
                using var k = Tilgangslogg.Nokkel(rot, sti);
                foreach (var verdi in k?.GetValueNames() ?? Array.Empty<string>())
                {
                    var r = FinnRegel($"{verdi} {k!.GetValue(verdi)}");
                    if (r != null) FraRegel(r, "Starter med Windows", $"Oppstart: {verdi}").Merknad("Starter automatisk når PC-en slås på.");
                }
            }

            // Planlagte oppgaver: bare navnene fra registeret (oppgavefilene krever ofte admin)
            using var tre = Tilgangslogg.Nokkel(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree");
            if (tre != null) Oppgaver(tre, "");
        }

        foreach (var mappe in new[] { @"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup", @"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp" })
        {
            foreach (var fil in Filer(Utvid(mappe)))
            {
                var r = FinnRegel(Path.GetFileName(fil));
                if (r != null) FraRegel(r, "Starter med Windows", $"Oppstartsmappe: {Path.GetFileName(fil)}").Merknad("Starter automatisk når PC-en slås på.");
            }
        }
    }

    private void Oppgaver(RegistryKey k, string sti)
    {
        foreach (var navn in k.GetSubKeyNames())
        {
            using var under = k.OpenSubKey(navn);
            if (under == null) continue;
            var full = sti + "\\" + navn;
            var r = FinnRegel(full.Replace('\\', ' '));
            if (r != null) FraRegel(r, "Planlagt oppgave", $"Oppgave: {full}").Merknad("Har en planlagt oppgave i Windows.");
            if (sti.Count(c => c == '\\') < 4) Oppgaver(under, full);
        }
    }

    // ---------- 4. Kjente mapper, kommandoer, npm og kodeeditorer ----------
    private void Spor()
    {
        var path = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(new[] { Path.PathSeparator }, StringSplitOptions.RemoveEmptyEntries);
        var endelser = Plattform.ErWindows ? new[] { ".exe", ".cmd", ".bat", ".ps1" } : new[] { "" };
        foreach (var r in _regler.Produkter)
        {
            foreach (var m in r.Mapper)
            {
                var sti = Utvid(m);
                if (Directory.Exists(sti)) FraRegel(r, "Mappe på disk", $"Mappe: {sti}");
            }
            foreach (var kommando in r.Kommandoer)
            {
                var treff = path.SelectMany(d => endelser.Select(e => Path.Combine(d, kommando + e))).FirstOrDefault(File.Exists);
                if (treff != null) FraRegel(r, "Kommando i terminal", $"Kommando: {treff}");
            }
        }

        // Globale npm-pakker (der Claude Code, Codex og Gemini CLI vanligvis installeres)
        foreach (var d in Mapper(Utvid(@"%APPDATA%\npm\node_modules")))
        {
            var navn = Path.GetFileName(d);
            var pakker = navn.StartsWith("@") ? Mapper(d).Select(u => $"{navn}/{Path.GetFileName(u)}") : new[] { navn };
            foreach (var n in pakker)
            {
                var r = FinnRegel(n);
                if (r != null) FraRegel(r, "npm-pakke", $"npm-pakke: {Path.Combine(Utvid(@"%APPDATA%\npm\node_modules"), n)}");
            }
        }

        foreach (var m in new[] { @"%USERPROFILE%\.vscode\extensions", @"%USERPROFILE%\.vscode-insiders\extensions", @"%USERPROFILE%\.cursor\extensions", @"%USERPROFILE%\.windsurf\extensions" })
        {
            foreach (var d in Mapper(Utvid(m)))
            {
                var id = Regex.Replace(Path.GetFileName(d), @"-\d+(\.\d+)*.*$", "");
                var r = FinnRegel(id);
                if (r != null) FraRegel(r, "Utvidelse i kodeeditor", $"Editor-utvidelse: {d}");
            }
        }
    }

    // ---------- 5. Åpne porter ----------
    private void Porter()
    {
        var lyttere = TcpTabell.Hent();
        foreach (var r in _regler.Produkter.Where(p => p.Porter.Count > 0))
        {
            foreach (var l in lyttere.Where(l => r.Porter.Contains(l.Port)))
            {
                string prosess;
                try { using var p = Process.GetProcessById(l.Pid); prosess = p.ProcessName; } catch { continue; }
                // Generiske porter (8080, 5001 osv.) teller bare hvis prosessen ligner på verktøyet
                if (FinnRegel(prosess)?.Navn != r.Navn) continue;
                bool apen = l.Adresse.Equals(IPAddress.Any) || l.Adresse.Equals(IPAddress.IPv6Any);
                var f = FraRegel(r, "Lytter på nettverksport", $"Nettverksport {l.Port} på {l.Adresse} ({prosess})");
                if (apen)
                {
                    f.Risiko = Risiko.Rod;
                    f.Advarsel("Er åpen mot nettverket. Andre på samme nett kan bruke den uten passord.");
                    f.Detalj($"Port {l.Port} er åpen mot nettverket ({l.Adresse}).");
                }
                else f.Merknad($"Port {l.Port} lytter bare lokalt (OK).");
            }
        }
    }

    // ---------- 7. Nettleserutvidelser ----------
    internal static readonly (string Navn, string Sti)[] Chromium =
    {
        ("Chrome", @"%LOCALAPPDATA%\Google\Chrome\User Data"),
        ("Edge", @"%LOCALAPPDATA%\Microsoft\Edge\User Data"),
        ("Brave", @"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi", @"%LOCALAPPDATA%\Vivaldi\User Data"),
        ("Opera", @"%APPDATA%\Opera Software"),
    };

    private void Nettlesere()
    {
        foreach (var (nettleser, rotSti) in Chromium)
        {
            foreach (var profil in Mapper(Utvid(rotSti)))
            {
                var utv = Path.Combine(profil, "Extensions");
                if (!Directory.Exists(utv)) continue;
                foreach (var idMappe in Mapper(utv))
                {
                    var ver = Mapper(idMappe).OrderByDescending(x => x, StringComparer.Ordinal).FirstOrDefault();
                    if (ver == null) continue;
                    using var doc = LesJson(Path.Combine(ver, "manifest.json"));
                    if (doc == null) continue;
                    var m = doc.RootElement;
                    var lokale = Str(m, "default_locale") ?? "en";
                    var navn = Oversett(ver, lokale, Str(m, "name"));
                    var besk = Oversett(ver, lokale, Str(m, "description"));
                    var tilg = Liste(m, "permissions").Concat(Liste(m, "host_permissions"))
                        .Concat(Liste(m, "content_scripts").SelectMany(cs => Liste(cs, "matches")))
                        .Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!);
                    VurderUtvidelse($"{nettleser} ({Path.GetFileName(profil)})", navn, besk, tilg, idMappe);
                }
            }
        }

        foreach (var profil in Mapper(Utvid(@"%APPDATA%\Mozilla\Firefox\Profiles")))
        {
            using var doc = LesJson(Path.Combine(profil, "extensions.json"));
            if (doc == null) continue;
            foreach (var a in Liste(doc.RootElement, "addons"))
            {
                if (Str(a, "type") != "extension" || Str(a, "location") != "app-profile") continue;
                a.TryGetProperty("defaultLocale", out var dl);
                var tilg = a.TryGetProperty("userPermissions", out var up) ? Liste(up, "origins").Select(e => e.GetString() ?? "") : Enumerable.Empty<string>();
                VurderUtvidelse($"Firefox ({Path.GetFileName(profil)})", Str(dl, "name"), Str(dl, "description"), tilg,
                    Path.Combine(profil, "extensions", (Str(a, "id") ?? "") + ".xpi"));
            }
        }
    }

    /// <summary>Slår opp __MSG_navn__ i utvidelsens språkfil.</summary>
    private static string? Oversett(string mappe, string lokale, string? tekst)
    {
        if (tekst == null) return null;
        var m = Regex.Match(tekst, "^__MSG_(.+)__$");
        if (!m.Success) return tekst;
        // lokale kommer fra utvidelsens egen manifest.json og er ikke til å stole på. Tillat bare vanlige språkkoder,
        // så den ikke kan peke ut av mappa (f.eks. "..\\..\\") med Path.Combine.
        if (string.IsNullOrEmpty(lokale) || !Regex.IsMatch(lokale, @"^[A-Za-z0-9_-]{1,35}$")) return tekst;
        using var doc = LesJson(Path.Combine(mappe, "_locales", lokale, "messages.json"));
        if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object) return tekst;
        foreach (var p in doc.RootElement.EnumerateObject())
            if (string.Equals(p.Name, m.Groups[1].Value, StringComparison.OrdinalIgnoreCase))
                return Str(p.Value, "message") ?? tekst;
        return tekst;
    }

    private void VurderUtvidelse(string hvor, string? navn, string? beskrivelse, IEnumerable<string> tilganger, string mappe)
    {
        if (string.IsNullOrWhiteSpace(navn)) return;
        bool alleSider = tilganger.Any(t => t == "<all_urls>" || Regex.IsMatch(t, @"^(\*|https?)://\*/\*$"));
        var nettleser = hvor.Split(' ')[0];
        var visning = $"{Kutt(navn, 40)} ({nettleser}-utvidelse)";
        Funn f;
        var r = FinnRegel(navn, utvidelse: true);
        if (r != null)
            f = LeggTil(visning, r.Kategori, RisikoTekst.Fra(r.Risiko), r.HvorforEnkelt ?? r.Hvorfor, $"Utvidelse i {hvor}", $"{hvor}: {mappe}", r, r.Enkelt, r.Rad);
        else
        {
            var tekst = $" {navn} {beskrivelse} ".ToLowerInvariant();
            if (!_regler.UkjentUtvidelseOrd.Any(tekst.Contains)) return;
            f = LeggTil(visning, "Nettleser-AI", Risiko.Rod,
                "Ukjent AI-utvidelse. Vi vet ikke hvem som lager den eller hvor dataene havner.",
                $"Utvidelse i {hvor}", $"{hvor}: {mappe}", rad: "Fjern den hvis du ikke vet hva den gjør.");
        }
        if (alleSider)
        {
            f.Risiko = Risiko.Rod;
            f.Advarsel("Kan se alt på alle nettsider du besøker, også nettbanken.");
        }
    }

    // ---------- 8. Innebygd AI i nettleseren ----------
    private static long MappeStorrelse(string sti)
    {
        try
        {
            return Plattform.Filer(sti).Sum(f => f.Length);
        }
        catch { return 0; }
    }

    private static (int Verdi, string Hvor)? LesPolicy(string nokkel, string verdi)
    {
        if (!Plattform.ErWindows) return null;
        foreach (var (rot, navn) in new[] { (Registry.LocalMachine, "HKLM"), (Registry.CurrentUser, "HKCU") })
        {
            using var k = Tilgangslogg.Nokkel(rot, nokkel);
            if (k?.GetValue(verdi) is int v) return (v, navn);
        }
        return null;
    }
}
