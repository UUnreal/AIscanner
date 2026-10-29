using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Finner alle nettlesere på PC-en, ikke bare de kjente: hver Chromium-nettleser har en «User Data»-mappe med «Local State»,
/// og hver Firefox-variant har en profiles.ini. Leser bare mappenavn, profiles.ini (stier til profiler) og, i Firefox,
/// AI-innstillingene i prefs.js (browser.ml.*). Aldri passord, informasjonskapsler eller skjemadata.
/// Gir også AI-assistentene som er bygget inn i Brave (Leo) og Opera (Aria), og AI i Firefox (sidefelt og lokale modeller).
/// </summary>
public sealed partial class Skanner
{
    // Navn på Chromium-nettlesere ut fra mappa (resten får mappenavnet). Bare navnet; ingenting om AI antas.
    private static readonly (string Ord, string Navn)[] ChromiumNavn =
    {
        (@"Perplexity\Comet", "Comet"), (@"Yandex\YandexBrowser", "Yandex"), (@"Arc", "Arc"), (@"Chromium", "Chromium"),
        (@"Thorium", "Thorium"), (@"CentBrowser", "Cent"), (@"Epic Privacy Browser", "Epic"), (@"Island", "Island"),
        (@"Google\Chrome Beta", "Chrome Beta"), (@"Google\Chrome Dev", "Chrome Dev"), (@"Google\Chrome SxS", "Chrome Canary"),
        (@"Microsoft\Edge Beta", "Edge Beta"), (@"Microsoft\Edge Dev", "Edge Dev"), (@"Microsoft\Edge SxS", "Edge Canary"),
        (@"BraveSoftware\Brave-Browser-Beta", "Brave Beta"), (@"BraveSoftware\Brave-Browser-Nightly", "Brave Nightly"),
    };

    private List<(string Navn, string Sti)>? _chromium;

    /// <summary>Alle Chromium-nettlesere: de kjente, og alle andre «User Data»-mapper med «Local State» to nivåer ned i
    /// AppData. Stien er mappa der hver undermappe er en profil (som i <see cref="Chromium"/>).</summary>
    private readonly object _nettleserLas = new();

    internal List<(string Navn, string Sti)> ChromiumRotter()
    {
        lock (_nettleserLas) return _chromium ??= FinnChromium();
    }

    private List<(string Navn, string Sti)> FinnChromium()
    {
        var liste = Chromium.Select(c => (c.Navn, Sti: Utvid(c.Sti))).ToList();
        var kjente = new HashSet<string>(liste.Select(x => x.Sti), StringComparer.OrdinalIgnoreCase);
        foreach (var basis in new[] { Utvid("%LOCALAPPDATA%"), Utvid("%APPDATA%") })
        {
            if (!Directory.Exists(basis)) continue;
            foreach (var d1 in Mapper(basis))
            {
                Sjekk(d1);
                if (Path.GetFileName(d1) is "Packages" or "Temp" or "Microsoft" or "Programs") { if (Path.GetFileName(d1) == "Microsoft") foreach (var d in new[] { "Edge Beta", "Edge Dev", "Edge SxS" }) Sjekk(Path.Combine(d1, d)); continue; }
                foreach (var d2 in Mapper(d1)) Sjekk(d2);
            }
            void Sjekk(string mappe)
            {
                var ud = Path.Combine(mappe, "User Data");
                if (kjente.Contains(ud) || !File.Exists(Path.Combine(ud, "Local State"))) return;
                var rel = mappe.Substring(basis.Length).Trim('\\', '/');
                var navn = ChromiumNavn.FirstOrDefault(x => rel.Equals(x.Ord, StringComparison.OrdinalIgnoreCase)).Navn ?? Path.GetFileName(mappe);
                kjente.Add(ud);
                liste.Add((navn, ud));
                Tilgangslogg.Logg("Mappe", ud, Utfall.Lest, $"nettleser funnet: {navn} (Chromium, «Local State»)");
            }
        }
        return liste;
    }

    private List<(string Navn, string Profil)>? _firefox;

    /// <summary>Alle Firefox-profiler: Firefox, Microsoft Store-utgaven og varianter (LibreWolf, Waterfox, Zen, Floorp …),
    /// fra profiles.ini og Profiles-mappa. Thunderbird er e-post, ikke nettleser, og tas ikke med.</summary>
    internal List<(string Navn, string Profil)> FirefoxProfiler()
    {
        lock (_nettleserLas) return _firefox ??= FinnFirefox();
    }

    private List<(string Navn, string Profil)> FinnFirefox()
    {
        var liste = new List<(string, string)>();
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Legg(string navn, string profil)
        {
            if (Directory.Exists(profil) && sett.Add(Path.GetFullPath(profil))) liste.Add((navn, profil));
        }
        void Ini(string navn, string mappe)
        {
            var ini = Path.Combine(mappe, "profiles.ini");
            if (!File.Exists(ini)) return;
            string[] linjer;
            try { linjer = File.ReadAllLines(ini); Tilgangslogg.Logg("Fil", ini, Utfall.Lest, "bare stiene til profilene"); }
            catch (Exception e) { Tilgangslogg.Feil("Fil", ini, e); return; }
            bool relativ = true;
            foreach (var l in linjer)
            {
                if (l.StartsWith("[")) relativ = true;
                else if (l.StartsWith("IsRelative=", StringComparison.OrdinalIgnoreCase)) relativ = l.EndsWith("1");
                else if (l.StartsWith("Path=", StringComparison.OrdinalIgnoreCase))
                {
                    var p = l.Substring(5).Trim().Replace('/', Path.DirectorySeparatorChar);
                    // Profilstien kommer fra en fil brukeren eier: godta bare stier inne i nettleserens egen mappe eller absolutte stier som finnes
                    var full = relativ ? Path.GetFullPath(Path.Combine(mappe, p)) : p;
                    if (relativ && !full.StartsWith(Path.GetFullPath(mappe), StringComparison.OrdinalIgnoreCase)) continue;
                    Legg(navn, full);
                }
            }
        }
        var appdata = Utvid("%APPDATA%");
        var ff = Path.Combine(appdata, "Mozilla", "Firefox");
        Ini("Firefox", ff);
        foreach (var p in Mapper(Path.Combine(ff, "Profiles"))) Legg("Firefox", p);
        if (Directory.Exists(appdata))
            foreach (var d in Mapper(appdata))
            {
                var n = Path.GetFileName(d);
                if (n is "Mozilla" or "Thunderbird" or "Microsoft") continue;
                if (File.Exists(Path.Combine(d, "profiles.ini")))
                {
                    var navn = n.Equals("zen", StringComparison.OrdinalIgnoreCase) ? "Zen" : n;
                    Ini(navn, d);
                    foreach (var p in Mapper(Path.Combine(d, "Profiles"))) Legg(navn, p);
                }
            }
        // Firefox fra Microsoft Store
        var pakker = Utvid(@"%LOCALAPPDATA%\Packages");
        if (Directory.Exists(pakker))
            foreach (var d in Mapper(pakker).Where(x => Path.GetFileName(x).StartsWith("Mozilla.Firefox", StringComparison.OrdinalIgnoreCase)))
            {
                var m = Path.Combine(d, "LocalCache", "Roaming", "Mozilla", "Firefox");
                Ini("Firefox (Microsoft Store)", m);
                foreach (var p in Mapper(Path.Combine(m, "Profiles"))) Legg("Firefox (Microsoft Store)", p);
            }
        return liste;
    }

    private static readonly Regex FirefoxAiPref = new(@"^user_pref\(""(browser\.ml\.(?:enable|chat\.enabled|chat\.provider))"",\s*(.+?)\);\s*$", RegexOptions.Multiline);

    /// <summary>
    /// AI som er bygget inn i nettleserne utover Chrome og Edge:
    /// Brave (Leo), Opera (Aria), og Firefox (AI-chatbot i sidefeltet og lokale AI-modeller).
    /// </summary>
    private void AndreNettleseresAi()
    {
        // Brave: Leo følger med Brave. IT kan slå den av med policyen BraveAIChatEnabled.
        foreach (var (navn, sti) in ChromiumRotter().Where(x => x.Navn.StartsWith("Brave", StringComparison.Ordinal)))
        {
            var profiler = Mapper(sti).Where(p => Regex.IsMatch(Path.GetFileName(p), @"^(Default|Profile \d+)$")).ToList();
            if (profiler.Count == 0) continue;
            var policy = LesPolicy(@"SOFTWARE\Policies\BraveSoftware\Brave", "BraveAIChatEnabled");
            bool av = policy?.Verdi == 0;
            var f = LeggTil($"Leo (AI-assistent i {navn})", LeverandorKategori + " (nettleser)", av ? Risiko.Gronn : Risiko.Gul,
                $"{navn} har AI-assistenten Leo innebygd. Den bruker AI-modeller i skyen hos Brave, eller en modell brukeren har koblet til selv.",
                navn, $"Mappe: {sti}", enkelt: $"AI bygd inn i {navn}");
            if (av) f.Merknad($"IT har slått av Leo (BraveAIChatEnabled = 0, {policy!.Value.Hvor}).");
            else if (policy == null) f.Merknad("Ingen regel fra IT (policyen BraveAIChatEnabled er ikke satt).");
        }

        // Opera: Aria følger med Opera (også Opera GX og Opera Air)
        var opera = Utvid(@"%APPDATA%\Opera Software");
        foreach (var d in Mapper(opera))
        {
            var n = Path.GetFileName(d);
            if (!Regex.IsMatch(n, @"^Opera( GX| Air)? Stable$") || !File.Exists(Path.Combine(d, "Preferences"))) continue;
            var navn = n.Replace(" Stable", "");
            LeggTil($"Aria (AI-assistent i {navn})", LeverandorKategori + " (nettleser)", Risiko.Gul,
                $"{navn} har AI-assistenten Aria innebygd. Spørsmål og innhold fra sider sendes til AI-tjenesten hos Opera.",
                navn, $"Mappe: {d}", enkelt: $"AI bygd inn i {navn}");
        }

        // Firefox og varianter
        foreach (var (navn, profil) in FirefoxProfiler())
        {
            var prefs = Path.Combine(profil, "prefs.js");
            if (File.Exists(prefs))
            {
                string tekst;
                try { tekst = File.ReadAllText(prefs); Tilgangslogg.Logg("Fil", prefs, Utfall.Lest, "bare AI-innstillingene (browser.ml.*)"); }
                catch (Exception e) { Tilgangslogg.Feil("Fil", prefs, e); tekst = ""; }
                var verdier = FirefoxAiPref.Matches(tekst).Cast<Match>().ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value.Trim().Trim('"'));
                bool chatAv = verdier.TryGetValue("browser.ml.chat.enabled", out var ce) && ce == "false"
                              || verdier.TryGetValue("browser.ml.enable", out var me) && me == "false";
                if (!chatAv && verdier.TryGetValue("browser.ml.chat.provider", out var lev) && Uri.TryCreate(lev, UriKind.Absolute, out var uri) && uri.Scheme is "https" or "http")
                {
                    var tjeneste = FinnNettsted(uri.Host)?.Navn;
                    var f = LeggTil($"AI-chatbot i sidefeltet i {navn}", "Skygge-AI (nettleserflagg)", Risiko.Rod,
                        $"{navn} er satt opp med en AI-chatbot i sidefeltet ({tjeneste ?? uri.Host}). Tekst brukeren markerer på sider kan sendes dit.",
                        navn, $"Innstilling: browser.ml.chat.provider = {uri.Host} · {profil}", enkelt: "AI-chatbot i nettleseren");
                    f.Merknad("Lest fra prefs.js (bare browser.ml.*).");
                }
            }
            // Lokale AI-modeller som Firefox har lastet ned (oversettelse, alt-tekst, gruppering av faner)
            var lagring = Path.Combine(profil, "storage");
            if (!Directory.Exists(lagring)) continue;
            var modeller = Plattform.Filer(lagring, "*", 8).Where(x => x.Length > 5 * 1024 * 1024)
                .Where(x => x.Extension is ".onnx" or ".gguf" or ".tflite" || ModellFormat.Gjenkjenn(x.FullName) != null || ModellFormat.ErOnnxUtenEndelse(x.FullName)).Take(50).ToList();
            if (modeller.Count == 0) continue;
            var lm = LeggTil($"Lokale AI-modeller i {navn}", LeverandorKategori + " (nettleser)", Risiko.Gul,
                $"{navn} har lastet ned AI-modeller som kjører på PC-en.", navn, null, enkelt: $"AI bygd inn i {navn}");
            foreach (var m in modeller.OrderByDescending(x => x.Length).Take(10)) lm.Detalj($"Fil: {m.FullName} · {Rapport.Storrelse(m.Length)}");
            lm.Tidspunkt(modeller.Min(x => x.CreationTime), modeller.Max(x => x.LastWriteTime));
        }
    }
}
