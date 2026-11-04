using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Statiske spor etter angrep på AI-agenter, fra ATR (Agent Threat Rules), SigmaHQ og MITRE ATLAS:
/// AI-verktøy med kjente sikkerhetshull (versjon), AI-trafikk som er sendt til en annen vert (*_BASE_URL),
/// instruksjonsfiler for AI-agenter i Nedlastinger og filer fra Shai-Hulud/TanStack i node_modules.
/// Samme regler som resten: bare lesing, bare metadata. Verdien av en AI-adresse vises bare som vertsnavn.
/// Alle funn er «Ukjent AI-spor» og røde.
/// </summary>
public sealed partial class Skanner
{
    private readonly ConcurrentBag<(string Sti, string Hva)> _saarbareTreff = new();
    private readonly ConcurrentBag<(string Sti, string Kilde)> _skadefiler = new();

    private void TomAngrep()
    {
        while (_saarbareTreff.TryTake(out _)) { }
        while (_skadefiler.TryTake(out _)) { }
    }

    // ---------- Versjoner ----------

    /// <summary>
    /// Sammenligner to versjoner tall for tall (1.0.87, 2025.7.1). En versjon med tillegg (2.13.0rc3, 1.0.0-beta)
    /// regnes som lavere enn samme versjon uten. Gir negativt tall når a er lavere.
    /// </summary>
    internal static int SammenlignVersjon(string a, string b)
    {
        static (List<long> Tall, bool Tillegg) Del(string v)
        {
            v = v.Trim().TrimStart('v', 'V');
            var m = Regex.Match(v, @"^(\d+(?:\.\d+)*)(.*)$");
            if (!m.Success) return (new List<long>(), true);
            var tall = m.Groups[1].Value.Split('.').Select(x => long.TryParse(x, out var n) ? n : 0).ToList();
            var resten = m.Groups[2].Value;
            return (tall, resten.Length > 0 && !resten.StartsWith("+"));
        }
        var (x, xt) = Del(a);
        var (y, yt) = Del(b);
        for (int i = 0; i < Math.Max(x.Count, y.Count); i++)
        {
            long p = i < x.Count ? x[i] : 0, q = i < y.Count ? y[i] : 0;
            if (p != q) return p < q ? -1 : 1;
        }
        return xt == yt ? 0 : xt ? -1 : 1;
    }

    /// <summary>Hullet når pakken i denne versjonen er sårbar, ellers null.</summary>
    internal string? Saarbar(string navn, string versjon, string type)
    {
        foreach (var s in _regler.SaarbareVersjoner)
        {
            if (!s.Type.Equals(type, StringComparison.OrdinalIgnoreCase)) continue;
            bool sammeNavn = type == "pypi"
                ? Normaliser(s.Navn) == Normaliser(navn)
                : s.Navn.Equals(navn, StringComparison.OrdinalIgnoreCase);
            if (sammeNavn && Regex.IsMatch(versjon, @"^\d") && SammenlignVersjon(versjon, s.Retta) < 0)
                return $"{s.Navn} {versjon} · retta i {s.Retta} · {s.Hull}{(s.Kilde != null ? " · " + s.Kilde : "")}";
        }
        return null;
        static string Normaliser(string n) => Regex.Replace(n.ToLowerInvariant(), "[-_.]+", "-");
    }

    /// <summary>package.json i en pakkemappe: navn og versjon mot lista over sårbare AI-verktøy.</summary>
    private void SjekkNpmPakke(string pakkemappe)
    {
        if (_regler.SaarbareVersjoner.Count == 0) return;
        var navn = Path.GetFileName(pakkemappe);
        var forelder = Path.GetFileName(Path.GetDirectoryName(pakkemappe) ?? "");
        var fullt = forelder.StartsWith("@") ? $"{forelder}/{navn}" : navn;
        if (!_regler.SaarbareVersjoner.Any(s => s.Type == "npm" && s.Navn.Equals(fullt, StringComparison.OrdinalIgnoreCase))) return;
        var pakke = Path.Combine(pakkemappe, "package.json");
        using var doc = LesJson(pakke, Sporfiler);
        if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object) return;
        if (Str(doc.RootElement, "version") is { } ver && Saarbar(fullt, ver, "npm") is { } hva) _saarbareTreff.Add((pakke, hva));
    }

    /// <summary>Kalles av filgjennomgangen for hver node_modules: sårbare AI-verktøy og kjente filer fra Shai-Hulud og TanStack.</summary>
    private void SjekkNodeModules(string nodeModules)
    {
        foreach (var d in Mapper(nodeModules).SelectMany(d => Path.GetFileName(d).StartsWith("@") ? Mapper(d) : new[] { d }).Take(5000))
        {
            SjekkNpmPakke(d);
            foreach (var (fil, kilde) in Skadefilnavn)
            {
                var sti = Path.Combine(d, fil);
                if (File.Exists(sti)) _skadefiler.Add((sti, kilde));
            }
        }
    }

    /// <summary>Filer som Shai-Hulud 2.0 og TanStack-angrepet la i npm-pakker (SigmaHQ). Bare om fila finnes sjekkes.</summary>
    private static readonly (string Fil, string Kilde)[] Skadefilnavn =
    {
        ("bun_environment.js", "Shai-Hulud 2.0 (SigmaHQ proc_creation_win_mal_shai_hulud_malicious_node_bun_execution) · ATLAS AML.T0010"),
        ("setup_bun.js", "Shai-Hulud 2.0 (SigmaHQ, Wiz/Socket nov. 2025) · ATLAS AML.T0010"),
        ("tanstack_runner.js", "Mini Shai-Hulud/TanStack (SigmaHQ file_event_win_malware_tanstack_supply_chain) · ATLAS AML.T0010"),
    };

    private void SaarbareAiVerktoy()
    {
        if (_regler.SaarbareVersjoner.Count == 0) return;
        // Globale npm-pakker og npx-cachen (MCP-servere startet med npx)
        var globalt = Utvid(@"%APPDATA%\npm\node_modules");
        if (Directory.Exists(globalt)) SjekkNodeModules(globalt);
        var npx = Utvid(@"%LOCALAPPDATA%\npm-cache\_npx");
        foreach (var cache in Mapper(npx).Take(500))
        {
            var nm = Path.Combine(cache, "node_modules");
            if (Directory.Exists(nm)) SjekkNodeModules(nm);
        }
        // uv tool (MCP-servere i Python startet med uvx eller uv tool)
        foreach (var verktoy in Mapper(Utvid(@"%APPDATA%\uv\tools")).Take(200))
            foreach (var sp in new[] { Path.Combine(verktoy, "Lib", "site-packages"), Path.Combine(verktoy, "lib") })
                if (Directory.Exists(sp)) SjekkPip(sp);
    }

    // ---------- AI-trafikk sendt til en annen vert ----------

    /// <summary>Miljøvariabler som sender AI-verktøyenes trafikk til en annen adresse.</summary>
    internal static readonly Regex AdresseVariabel = new(
        @"^(ANTHROPIC|OPENAI|AZURE_OPENAI|GEMINI|GOOGLE_GEMINI|GOOGLE_GENAI|MISTRAL|GROQ|DEEPSEEK|XAI|OPENROUTER|COHERE|CLAUDE_CODE|CODEX)_(BASE_URL|API_BASE|API_BASE_URL|API_URL|ENDPOINT|API_HOST)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Vertsnavnet i en adresse, eller null.</summary>
    internal static string? Vert(string verdi)
    {
        var v = verdi.Trim().Trim('"', '\'');
        if (!v.Contains("://")) v = "https://" + v;
        return Uri.TryCreate(v, UriKind.Absolute, out var u) && u.Host.Length > 0 ? u.Host.ToLowerInvariant() : null;
    }

    /// <summary>Om verten er en kjent AI-tjeneste (regler.json) eller denne PC-en.</summary>
    internal bool KjentAiVert(string vert)
    {
        if (vert is "localhost" or "127.0.0.1" or "::1" or "[::1]") return true;
        return _regler.AiTjenester.Concat(_regler.AiNettsteder).SelectMany(t => t.Domener)
            .Any(d => vert.Equals(d, StringComparison.OrdinalIgnoreCase) || vert.EndsWith("." + d.TrimStart('.'), StringComparison.OrdinalIgnoreCase));
    }

    private void OmdirigertAi()
    {
        var treff = new List<(string Linje, DateTime? Tid)>();
        void Vurder(string navn, string verdi, string kilde, DateTime? tid)
        {
            if (!AdresseVariabel.IsMatch(navn) || Vert(verdi) is not { } vert || KjentAiVert(vert)) return;
            var linje = $"{kilde} · {navn.ToUpperInvariant()} peker til {vert}";
            if (!treff.Any(t => t.Linje == linje)) treff.Add((linje, tid));
        }
        // Miljøvariabler for brukeren og maskinen (registeret) og for denne prosessen
        if (Plattform.ErWindows)
        {
            foreach (var (rot, nokkel, hvem) in new[] { (Registry.CurrentUser, "Environment", "HKCU"), (Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "HKLM") })
                try
                {
                    using var k = rot.OpenSubKey(nokkel);
                    Tilgangslogg.Logg("Register", $@"{hvem}\{nokkel}", k != null ? Utfall.Lest : Utfall.IkkeFunnet, "bare navn som sender AI-trafikk til en annen adresse, og vertsnavnet");
                    if (k == null) continue;
                    foreach (var v in k.GetValueNames())
                        if (AdresseVariabel.IsMatch(v) && k.GetValue(v) is string s) Vurder(v, s, $@"Register: {hvem}\{nokkel}", null);
                }
                catch (Exception e) { Tilgangslogg.Feil("Register", $@"{hvem}\{nokkel}", e); }
        }
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
            if (e.Key is string n && AdresseVariabel.IsMatch(n) && e.Value is string s) Vurder(n, s, "Miljøvariabel i økten", null);
        // Claude Code: env-blokken i settings.json (brukeren og prosjektene)
        var claude = new[] { Utvid(@"%USERPROFILE%\.claude\settings.json"), Utvid(@"%USERPROFILE%\.claude\settings.local.json") }
            .Concat(_prosjektOppsett.Where(p => Path.GetFileName(p).StartsWith("settings", StringComparison.OrdinalIgnoreCase)
                                             && Path.GetFileName(Path.GetDirectoryName(p) ?? "").Equals(".claude", StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var sti in claude)
        {
            if (!File.Exists(sti)) continue;
            using var doc = LesJson(sti, Sporfiler);
            if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("env", out var env) || env.ValueKind != JsonValueKind.Object) continue;
            foreach (var p in env.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.String) Vurder(p.Name, p.Value.GetString()!, $"Fil: {sti}", Endret(sti));
        }
        // Codex: base_url i config.toml
        var codex = Utvid(@"%USERPROFILE%\.codex\config.toml");
        if (File.Exists(codex))
            LesLinjer(codex, 1, l =>
            {
                var m = Regex.Match(l, @"^\s*(openai_)?base_url\s*=\s*[""']([^""']+)[""']", RegexOptions.IgnoreCase);
                if (m.Success && Vert(m.Groups[2].Value) is { } vert && !KjentAiVert(vert))
                {
                    var linje = $"Fil: {codex} · base_url peker til {vert}";
                    if (!treff.Any(t => t.Linje == linje)) treff.Add((linje, Endret(codex)));
                }
            });
        if (treff.Count == 0) return;
        var f = Spor("AI-trafikk sendes til en annen vert",
            "En innstilling sender det AI-verktøyet skriver og får svar på, til en annen adresse enn AI-tjenesten. Den som eier verten, kan lese og endre alt. Bare vertsnavnet vises.", null);
        f.Advarsel("AI-adressen er byttet til en vert som ikke er en kjent AI-tjeneste.");
        foreach (var (linje, tid) in treff.Take(20)) { f.Detalj(linje + (tid != null ? " · endret " + Nar(tid.Value, "endringstid på fil") : "")); if (tid != null) f.Tidspunkt(tid, tid); }
        f.Detalj("Regel: ATLAS AML.T0081 (Modify AI Agent Configuration) · ATR-2026-00200 · MALFEX (Aviatrix, okt. 2026)");
    }

    // ---------- Instruksjonsfiler i Nedlastinger ----------

    private void InstruksjonerINedlastinger()
    {
        var ned = Utvid(@"%USERPROFILE%\Downloads");
        if (!Directory.Exists(ned)) { Tilgangslogg.Logg("Mappe", ned, Utfall.IkkeFunnet); return; }
        var funnet = new List<string>();
        foreach (var fil in Plattform.Filer(ned, "*", 2))
            if (Instruksjonsnavn.Contains(fil.Name) || (fil.Name.Equals("SKILL.md", StringComparison.OrdinalIgnoreCase))) funnet.Add(fil.FullName);
        Tilgangslogg.Logg("Mappe", ned, Utfall.Lest, "bare navnene på instruksjonsfiler for AI-agenter (to nivåer)");
        if (funnet.Count == 0) return;
        var f = Spor("Instruksjonsfil for AI-agenter i Nedlastinger",
            "En fil som AI-agenter leser som ordre (AGENTS.md, CLAUDE.md, SKILL.md osv.) ligger i Nedlastinger. Åpnes en agent der, følger den ordrene i fila. Teksten vises ikke.", null);
        f.Advarsel("Instruksjonsfil for AI-agenter i en nedlastingsmappe.");
        foreach (var sti in funnet.Take(20))
        {
            var t = Endret(sti);
            f.Tidspunkt(t, t);
            f.Detalj($"Fil: {sti}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
        }
        f.Detalj("Regel: ATLAS AML.T0080 (AI Agent Context Poisoning) · ATR-2026-00120 · MALFEX (Aviatrix, okt. 2026)");
    }

    // ---------- npx skills add (SigmaHQ) ----------

    internal static bool ErSkillsAdd(string linje) =>
        linje.IndexOf("npx-cli.js", StringComparison.OrdinalIgnoreCase) >= 0 && Regex.IsMatch(linje, @"\sskills(@\S+)?\s+add\s", RegexOptions.IgnoreCase);

    /// <summary>Ferdigheter for AI-agenter installert med «npx skills add». Hvilken ferdighet vises ikke (resten av kommandoen).</summary>
    internal void SkillsLagtTil(DateTime tid, string kilde, string? konto)
    {
        var f = LeggTil("Ferdigheter installert for AI-agenter (npx skills add)", "Skygge-AI (agent)", Risiko.Gul,
            "Noen har lagt til ferdigheter for AI-agenter med «npx skills add». En ferdighet er kode og ordre agenten stoler på.", "Kjørt før", null, enkelt: "Ferdighet for AI-agent");
        f.Tidspunkt(tid, tid);
        f.Detalj($"Hendelse: {kilde} · npx skills add · {Nar(tid, kilde)}{(konto != null ? " · konto " + konto : "")} · Regel: SigmaHQ proc_creation_win_node_new_agent_skills_installed · ATLAS AML.T0104");
    }

    // ---------- Gemini i Chrome (glic) ----------

    /// <summary>Om Gemini i Chrome er slått på i en profil: av/på-verdier under «glic» som heter noe med enabled. Ingen andre verdier leses ut.</summary>
    private void GlicPa(string preferences, string hvor)
    {
        using var doc = LesJson(preferences);
        if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("glic", out var g) || g.ValueKind != JsonValueKind.Object) return;
        var pa = g.EnumerateObject().Where(p => p.Value.ValueKind == JsonValueKind.True && p.Name.IndexOf("enabled", StringComparison.OrdinalIgnoreCase) >= 0).Select(p => p.Name).ToList();
        if (pa.Count == 0) return;
        var f = LeggTil("Gemini i Chrome", "Nettleser-AI", Risiko.Gul,
            "Googles AI-assistent i Chrome er slått på. Den kan lese sidene du har åpne og sende dem til Google.", hvor, null, enkelt: "AI-assistent i nettleseren");
        f.Merk(Tilstand.SattOpp);
        f.Detalj($"Fil: {preferences} · glic: {string.Join(", ", pa.Select(n => n + " = true"))} · nøkkelnavnene er ikke offisielle (github.com/RealFelixWang/glic-switch)");
    }

    // ---------- Windows sin egen MCP-plattform (On-device Agent Registry) ----------

    /// <summary>
    /// MCP-servere registrert i Windows (ODR) og samtykket brukeren har gitt. Stiene er kartlagt på Insider-bygg (Origin HQ, mars 2026)
    /// og er ikke bekreftet på 26H2: finnes de ikke, står det i datagrunnlaget, og ingenting vises som funn.
    /// </summary>
    private void WindowsMcp()
    {
        if (!Plattform.ErWindows) return;
        var odr = Utvid(@"%WINDIR%\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\odr.exe");
        Tilgangslogg.Logg("Fil", odr, File.Exists(odr) ? Utfall.Lest : Utfall.IkkeFunnet, "finnes Windows sitt MCP-register (odr.exe)? Kartlagt på Insider-bygg, ikke bekreftet på 26H2");
        var linjer = new List<string>();
        const string samtykke = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\MCPConsent";
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(samtykke);
            Tilgangslogg.Logg("Register", @"HKCU\" + samtykke, k != null ? Utfall.Lest : Utfall.IkkeFunnet, "bare navn og samtykke (0 = tillat alltid)");
            if (k != null)
                foreach (var navn in k.GetValueNames().Concat(k.GetSubKeyNames()).Distinct().Take(50))
                {
                    var v = k.GetValue(navn) ?? k.OpenSubKey(navn)?.GetValue("Value");
                    linjer.Add($@"Register: HKCU\{samtykke} · {navn}{(v is int i && i == 0 ? " · tillat alltid" : v != null ? $" · verdi {v}" : "")}");
                }
        }
        catch (Exception e) { Tilgangslogg.Feil("Register", @"HKCU\" + samtykke, e); }
        // MSIX-pakker som melder seg som MCP-server i Windows
        var apps = Utvid(@"%ProgramFiles%\WindowsApps");
        foreach (var d in Mapper(apps).Take(2000))
        {
            var m = Path.Combine(d, "AppxManifest.xml");
            try
            {
                if (!File.Exists(m) || new FileInfo(m).Length > 2 * 1024 * 1024) continue;
                if (File.ReadAllText(m).IndexOf("com.microsoft.windows.ai.mcpServer", StringComparison.OrdinalIgnoreCase) >= 0) linjer.Add($"Fil: {m} · pakken melder seg som MCP-server i Windows");
            }
            catch { }
        }
        if (linjer.Count == 0) return;
        var f = Spor("MCP-servere: Windows (ODR)", "Windows sitt eget MCP-register har servere eller samtykke som gir AI-agenter i Windows verktøy på PC-en.", null);
        if (linjer.Any(l => l.EndsWith("tillat alltid"))) f.Advarsel("En AI-agent i Windows har fått «tillat alltid» til et MCP-verktøy.");
        foreach (var l in linjer) f.Detalj(l);
        f.Detalj("Regel: ATLAS AML.T0053 · kartlagt på Insider-bygg (originhq.com/research/msft-odr-mcp), ikke bekreftet på 26H2");
    }

    // ---------- Etter filgjennomgangen ----------

    /// <summary>Sanntidsvakten for AI-agenter (eies av vinduet, lever mens det er åpent). Røde hendelser blir funn.</summary>
    public Vakt? Vakt { get; set; }

    private void VaktTilFunn()
    {
        if (Vakt is not { } v) return;
        foreach (var g in v.Hendelser().Where(h => h.Rod).GroupBy(h => h.Agent))
        {
            var f = Spor($"AI-agent gjør noe kjent fra angrep: {(g.Key == "" ? "ukjent program" : g.Key)}",
                $"Vakt så dette live (siden {v.Startet:HH:mm:ss}): AI-agenten eller et program den startet gjorde noe som er kjent fra angrep på og med AI-agenter. Bare navn på programmer, filer og adresser er lest, aldri innholdet.", null);
            f.Advarsel("Sett live: AI-agent gjorde noe kjent fra angrep.");
            foreach (var h in g.Take(30))
            {
                f.Tidspunkt(h.Tid, h.Tid);
                f.Detalj($"{h.Tid:HH:mm:ss} · {h.Regel} · Program: {h.Program} (PID {h.Pid}){(h.Hva != null ? " · " + h.Hva : "")} · Regel: {Rammeverk.MedOwasp(h.Regel, h.Kilde)} · Kilde: {(v.Etw ? "Windows' hendelser i sanntid" : "prosesslista")}");
            }
        }
    }

    private void AngrepEtterGjennomgang()
    {
        Vakt?.Folg(_prosjektOppsett.Select(p => Path.GetDirectoryName(Path.GetDirectoryName(p))).OfType<string>());
        try { SaarbareAiVerktoy(); } catch (Exception e) { Tilgangslogg.Logg("Sjekk", "Sårbare AI-verktøy", Utfall.Feil, Tilgangslogg.Beskriv(e)); }
        var saar = _saarbareTreff.Distinct().ToList();
        if (saar.Count > 0)
        {
            var f = Spor("AI-verktøy med kjent sikkerhetshull",
                "Et AI-verktøy (MCP-server eller agent) er installert i en versjon med et kjent sikkerhetshull. Hullet er ikke i seg selv et tegn på angrep, men kan brukes til å ta over PC-en.", null);
            f.Advarsel("AI-verktøy i en versjon med kjent sikkerhetshull.");
            foreach (var (sti, hva) in saar.Take(30))
            {
                var t = Endret(sti);
                f.Tidspunkt(t, t);
                f.Detalj($"Fil: {sti} · {hva}{(t != null ? " · installert " + Nar(t.Value, "endringstid på fil") : "")}");
            }
        }
        var skade = _skadefiler.Distinct().ToList();
        if (skade.Count > 0)
        {
            var f = Spor("Filer kjent fra AI-misbruk", "En fil med samme navn som en kjent fil fra AI-misbruk ligger på PC-en.", null);
            f.Advarsel("Fil med samme navn og sted som en kjent fil fra AI-misbruk.");
            foreach (var (sti, kilde) in skade.Take(30))
            {
                var t = Endret(sti);
                f.Tidspunkt(t, t);
                f.Detalj($"Fil: {sti} · {kilde}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
            }
        }
    }
}
