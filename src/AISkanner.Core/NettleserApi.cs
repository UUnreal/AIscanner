using System.Text.Json;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Status for AI-API-ene som Chrome og Edge gir nettsider og utvidelser (Prompt API, Summarizer, Writer, Rewriter,
/// Proofreader, Classifier) og LiteRT-LM-motoren som kjører modellen. Bygger på policyer fra IT, nettleserversjonen
/// (mappenavnet), hvilke modeller som ligger på disk, og eventuelt flaggene brukeren har slått på.
/// </summary>
public sealed partial class Skanner
{
    /// <summary>
    /// Les flaggene i chrome://flags fra filen "Local State". Av som standard, fordi filen også inneholder
    /// nettleserens krypterte hovednøkkel. Når den er på, leses bare lista browser.enabled_labs_experiments;
    /// alt annet i filen hoppes over uten å bli tolket, og innholdet slettes fra minnet med en gang.
    /// </summary>
    public bool LesNettleserflagg { get; set; }

    private sealed record AiApi(string Navn, string Hva, int? NettsiderFra, int? UtvidelserFra, Regex Flagg, bool Blokkerbar);

    // Versjoner fra developer.chrome.com/docs/ai/built-in-apis (sjekket 26.10.2026).
    // Flaggnavnene matches på innhold, fordi de eksakte navnene endrer seg mellom versjoner.
    private static readonly AiApi[] ChromeApi =
    {
        new("Prompt API", "nettsider og utvidelser snakker fritt med språkmodellen", 148, 138, new(@"prompt-api", RegexOptions.IgnoreCase), true),
        new("Summarizer API", "oppsummerer tekst", 138, 138, new(@"summari[sz]", RegexOptions.IgnoreCase), true),
        new("Writer API", "skriver ny tekst", null, null, new(@"(?<!re)writer-api", RegexOptions.IgnoreCase), true),
        new("Rewriter API", "skriver om tekst", null, null, new(@"rewriter-api", RegexOptions.IgnoreCase), true),
        new("Proofreader API", "retter skrivefeil", null, null, new(@"proofread", RegexOptions.IgnoreCase), false),
    };

    private static readonly Regex AiFlagg = new(@"prompt-api|summari[sz]|writer-api|proofread|classif|litert|on-device|ondevice|gemini|optimization-guide|language-model|llm|genai|ai-api|phi", RegexOptions.IgnoreCase);

    private sealed class ApiStatus
    {
        public readonly List<string> Linjer = new();
        public readonly List<string> Manuelt = new();
        public readonly List<string> Merk = new();
    }

    private ApiStatus NettleserApiStatus(string nettleser, string rot, bool harSprak, bool harKlassifiserer, bool modellBlokkert)
    {
        var st = new ApiStatus();
        bool edge = nettleser.StartsWith("Edge");
        var (versjon, appMappe) = Nettleserversjon(rot);
        var policyNokkel = edge ? @"SOFTWARE\Policies\Microsoft\Edge" : @"SOFTWARE\Policies\Google\Chrome";
        var apiPolicy = LesPolicy(policyNokkel, "BuiltInAIAPIsEnabled");
        bool apiBlokkert = apiPolicy?.Verdi == 0;

        List<string>? flagg = LesNettleserflagg ? Flaggliste(Path.Combine(rot, "Local State")) : null;
        var aiFlagg = flagg?.Where(x => AiFlagg.IsMatch(x)).ToList() ?? new List<string>();
        static string FlaggStatus(string x) => x.EndsWith("@1") ? "slått på" : x.EndsWith("@0") ? "standard" : $"endret (valg {x.Substring(x.LastIndexOf('@') + 1)})";

        if (versjon == null && !modellBlokkert && !apiBlokkert && aiFlagg.Count == 0)
            st.Linjer.Add($"AI-API: {string.Join(", ", ChromeApi.Select(a => a.Navn.Replace(" API", "")))} · ukjent (fant ikke versjonen av {nettleser})");
        else foreach (var api in ChromeApi)
        {
            string status;
            var f = aiFlagg.FirstOrDefault(x => api.Flagg.IsMatch(x));
            if (modellBlokkert) status = "blokkert av IT (GenAILocalFoundationalModelSettings)";
            else if (apiBlokkert && api.Blokkerbar) status = "blokkert av IT (BuiltInAIAPIsEnabled)";
            else if (f != null) status = $"{FlaggStatus(f)} manuelt i {(edge ? "edge" : "chrome")}://flags";
            else
            {
                int? fra = edge ? null : api.NettsiderFra, utv = edge ? null : api.UtvidelserFra;
                string modell = harSprak ? "" : ", modellen lastes ned første gang noen bruker den";
                if (versjon == null) status = "ukjent (fant ikke nettleserversjonen)";
                else if (fra != null && versjon >= fra) status = $"på for nettsider og utvidelser{modell}";
                else if (utv != null && versjon >= utv) status = $"på for utvidelser{modell}";
                else status = flagg != null ? "av (krever flagg)" : $"av, med mindre det er slått på i {(edge ? "edge" : "chrome")}://flags (ikke sjekket)";
            }
            if (apiBlokkert && !api.Blokkerbar && !modellBlokkert) status += " · BuiltInAIAPIsEnabled dekker trolig ikke denne (ikke bekreftet)";
            st.Linjer.Add($"AI-API: {api.Navn} · {status}");
        }

        // Classifier: liten modell som vurderer innhold (svindel, farlige sider). Kjører uten at brukeren ser det.
        var klass = aiFlagg.FirstOrDefault(x => Regex.IsMatch(x, "classif", RegexOptions.IgnoreCase));
        st.Linjer.Add($"AI-API: Classifier · {(modellBlokkert ? "blokkert av IT" : klass != null ? $"{FlaggStatus(klass)} manuelt" : harKlassifiserer ? "modellen ligger på PC-en og kjører i bakgrunnen" : "ingen modell på PC-en")}");

        // LiteRT-LM: motoren som kjører språkmodellen. Rulles ut av Google som et forsøk (OnDeviceModelLitertLmBackend).
        var lite = aiFlagg.FirstOrDefault(x => x.Inneholder("litert"));
        string? liteFil = null;
        foreach (var mappe in new[] { appMappe, Path.Combine(rot, "OptGuideOnDeviceModel") })
        {
            if (mappe == null || !Directory.Exists(mappe)) continue;
            liteFil = Plattform.Filer(mappe, "*", 3).Take(3000).FirstOrDefault(x => x.Name.Inneholder("litert"))?.FullName;
            if (liteFil != null) break;
        }
        st.Linjer.Add($"AI-API: LiteRT-LM-motor · {(lite != null ? $"{FlaggStatus(lite)} manuelt" : liteFil != null ? $"ligger på PC-en ({liteFil})" : flagg != null ? "ikke slått på, og ikke funnet på disk" : "ikke funnet på disk (kan være slått på av Google som forsøk, ikke sjekket)")}");

        foreach (var x in aiFlagg.Where(x => !x.EndsWith("@0"))) st.Manuelt.Add($"Flagg: {x} · {FlaggStatus(x)}");
        if (versjon != null) st.Merk.Add($"{nettleser} versjon {versjon}.");
        if (apiPolicy != null) st.Merk.Add($"IT-regel BuiltInAIAPIsEnabled = {apiPolicy.Value.Verdi} ({(apiBlokkert ? "AI-API-er blokkert for nettsider" : "tillatt")}).");
        else if (!modellBlokkert) st.Merk.Add($"Ingen IT-regel for AI-API-ene. Nettsider kan bruke dem. Kan stenges med policyen BuiltInAIAPIsEnabled = 0.");
        if (flagg == null) st.Merk.Add("Flagg i nettleseren er ikke lest (filen Local State åpnes ikke).");
        return st;
    }

    /// <summary>Høyeste versjon i nettleserens Application-mappe (mappenavnet, ingen filer åpnes).</summary>
    private static (int? Hoved, string? Mappe) Nettleserversjon(string brukerdata)
    {
        var program = Path.GetDirectoryName(brukerdata.TrimEnd('\\', '/'));   // ...\Google\Chrome
        if (program == null) return (null, null);
        var lokal = Utvid("%LOCALAPPDATA%");
        var rel = program.StartsWith(lokal, StringComparison.OrdinalIgnoreCase) ? program.Substring(lokal.Length).TrimStart('\\', '/') : null;
        var kandidater = new List<string> { Path.Combine(program, "Application") };
        if (rel != null)
            foreach (var pf in new[] { "%ProgramFiles%", "%ProgramW6432%", "%ProgramFiles(x86)%" })
                kandidater.Add(Path.Combine(Utvid(pf), rel, "Application"));
        foreach (var k in kandidater.Where(k => !k.Contains('%') && Directory.Exists(k)))
        {
            var beste = Mapper(k).Select(d => Path.GetFileName(d)).Where(n => Regex.IsMatch(n, @"^\d+\.\d+\.\d+\.\d+$"))
                                 .OrderByDescending(n => new Version(n)).FirstOrDefault();
            if (beste != null) return (int.Parse(beste.Split('.')[0]), Path.Combine(k, beste));
        }
        return (null, null);
    }

    /// <summary>
    /// Bare lista browser.enabled_labs_experiments fra Local State. Leser med en strømleser som hopper over alle andre verdier
    /// uten å tolke dem (også den krypterte nøkkelen), og nuller ut bytene etterpå.
    /// </summary>
    internal static List<string>? Flaggliste(string localState)
    {
        byte[]? bytes = null;
        try
        {
            using (var s = Admintilgang.AapneLes(localState))
            {
                Tilgangslogg.Logg("Fil", localState, Utfall.Lest, "bare lista over eksperimentflagg (LesNettleserflagg på)");
                if (s.Length > 32 * 1024 * 1024) return null;
                bytes = new byte[s.Length];
                s.LesAlt(bytes);
            }
            var liste = new List<string>();
            var r = new Utf8JsonReader(bytes, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            if (!r.Read() || r.TokenType != JsonTokenType.StartObject) return null;
            while (r.Read() && r.TokenType == JsonTokenType.PropertyName)
            {
                bool nettleser = r.ValueTextEquals("browser");
                r.Read();
                if (!nettleser || r.TokenType != JsonTokenType.StartObject) { r.Skip(); continue; }
                while (r.Read() && r.TokenType == JsonTokenType.PropertyName)
                {
                    bool lab = r.ValueTextEquals("enabled_labs_experiments");
                    r.Read();
                    if (!lab || r.TokenType != JsonTokenType.StartArray) { r.Skip(); continue; }
                    while (r.Read() && r.TokenType == JsonTokenType.String) liste.Add(r.GetString()!);
                    return liste;
                }
                return liste;
            }
            return liste;
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", localState, e); return null; }
        finally { if (bytes != null) Array.Clear(bytes, 0, bytes.Length); }
    }
}
