using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Flere ukjente AI-spor (tillegg N1–N13): hooks og oppgaver som starter av seg selv, prosjekt-MCP som starter uten å spørre,
/// symlinker inn i agentoppsett, skjulte tegn i instruksjonsfiler, ferdigheter som laster ned og kjører kode, fjernkode fra
/// Hugging Face, agenter med farlige flagg i autostart, ukjente lokale klienter mot modellserveren, utvidelser som kan lese
/// AI-samtaler, uttak via WebFetch, kjente filer og domener fra AI-misbruk og forgiftede verktøy i npx-cachen.
///
/// Samme regler som resten: bare lesing og bare metadata (navn, antall, sti, tid). Aldri tekst fra instruksjonsfiler,
/// ferdigheter, hooks (bare første ord i kommandoen) eller .env. Kommandolinjene til programmer som kjører leses aldri.
/// Alle funn er «Ukjent AI-spor» og røde.
/// </summary>
public sealed partial class Skanner
{
    // ---------- Funnet av filgjennomgangen, behandlet etterpå ----------
    private readonly ConcurrentBag<string> _instruksjonsfiler = new();
    private readonly ConcurrentBag<string> _geminiEnv = new();
    private readonly ConcurrentBag<string> _envFiler = new();
    private readonly ConcurrentBag<(string Sti, string Type)> _vektorDb = new();
    private readonly ConcurrentBag<string> _oppgavefiler = new();
    private readonly ConcurrentBag<string> _kjorbareIOppsett = new();
    private readonly ConcurrentBag<string> _prosjektSkills = new();
    private readonly ConcurrentBag<(string Lenke, string? Mal)> _lenker = new();
    private readonly ConcurrentBag<(string Sti, string Pakke)> _pipTreff = new();
    private readonly ConcurrentBag<string> _pakketModell = new();

    private static readonly HashSet<string> Instruksjonsnavn = new(StringComparer.OrdinalIgnoreCase)
        { "CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md" };
    private static readonly HashSet<string> KjorbareEndelser = new(StringComparer.OrdinalIgnoreCase)
        { ".js", ".mjs", ".cjs", ".ps1", ".py", ".bat", ".cmd", ".vbs", ".sh" };
    private static readonly string[] Agentoppsett =
        { ".claude", ".cursor", ".codex", ".gemini", ".vscode", ".mcp.json", "mcp.json", "settings.json", "config.toml" };

    private void TomMisbruk()
    {
        foreach (var b in new[] { _instruksjonsfiler, _geminiEnv, _envFiler, _oppgavefiler, _kjorbareIOppsett, _prosjektSkills, _pakketModell })
            while (b.TryTake(out _)) { }
        while (_lenker.TryTake(out _)) { }
        while (_pipTreff.TryTake(out _)) { }
    }

    private string[]? _brukerOppsett;

    private bool ErBrukerOppsett(string sti)
    {
        var hjem = Utvid("%USERPROFILE%").TrimEnd('\\', '/');
        _brukerOppsett ??= new[] { ".claude", ".codex", ".gemini", ".cursor", ".openclaw", ".clawdbot" }.Select(d => Path.Combine(hjem, d)).ToArray();
        foreach (var d in _brukerOppsett)
            if (sti.StartsWith(d, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// Vektordatabaser: der AI-verktøy (RAG, «chat med dokumentene dine») legger tekstbiter fra dokumenter som tall.
    /// Kjennes på filnavn og plassering. Innholdet leses aldri.
    /// </summary>
    internal static string? VektorDb(FileInfo fil)
    {
        var n = fil.Name;
        var forelder = fil.Directory?.Name ?? "";
        if (n.Equals("chroma.sqlite3", StringComparison.OrdinalIgnoreCase)) return "Chroma";
        if (fil.Extension.Equals(".faiss", StringComparison.OrdinalIgnoreCase)) return "FAISS";
        if (fil.Extension.Equals(".lance", StringComparison.OrdinalIgnoreCase) && fil.DirectoryName?.IndexOf(".lance", StringComparison.OrdinalIgnoreCase) >= 0) return "LanceDB";
        if (n.Equals("collection.json", StringComparison.OrdinalIgnoreCase) && fil.Directory?.Parent?.Name == "collections") return "Qdrant";
        if (n.Equals("docstore.json", StringComparison.OrdinalIgnoreCase) && fil.Directory?.GetFiles("vector_store.json").Length > 0) return "LlamaIndex";
        if (n.Equals("index.pkl", StringComparison.OrdinalIgnoreCase) && fil.Directory?.GetFiles("index.faiss").Length > 0) return null;   // telles på index.faiss
        if (n.EndsWith(".usearch", StringComparison.OrdinalIgnoreCase)) return "USearch";
        if (forelder.Equals("lancedb", StringComparison.OrdinalIgnoreCase) || forelder.Equals("chroma_db", StringComparison.OrdinalIgnoreCase) || forelder.Equals("vectorstore", StringComparison.OrdinalIgnoreCase))
            return forelder.Equals("lancedb", StringComparison.OrdinalIgnoreCase) ? "LanceDB" : forelder.Equals("chroma_db", StringComparison.OrdinalIgnoreCase) ? "Chroma" : null;
        return null;
    }

    private void Vektordatabaser(List<(string Sti, string Type)> liste)
    {
        if (liste.Count == 0) return;
        // Én database er én mappe; LanceDB har mange filer per tabell
        var databaser = liste.GroupBy(x => (Mappe: x.Type == "LanceDB" ? LanceRot(x.Sti) : Path.GetDirectoryName(x.Sti)!, x.Type)).Take(200).ToList();
        var f = LeggTil("Vektordatabaser for AI", "Skygge-AI (utvikling)", Risiko.Gul,
            "Lagrer biter av dokumenter som AI-en kan søke i («chat med dokumentene»). Teksten fra dokumentene kan ligge der.",
            "Filer på disken", null, enkelt: "AI-database med dokumentbiter");
        foreach (var d in databaser)
        {
            long storrelse = 0; DateTime? endret = null;
            foreach (var (sti, _) in d) try { var fi = new FileInfo(sti); storrelse += fi.Length; if (endret == null || fi.LastWriteTime > endret) endret = fi.LastWriteTime; } catch { }
            f.Detalj($"{d.Key.Type}: {d.Key.Mappe} · {Rapport.Storrelse(storrelse)}{(endret != null ? " · endret " + Nar(endret.Value, "endringstid på fil") : "")}");
        }
        f.Bruk = $"{string.Join(", ", databaser.Select(d => d.Key.Type).Distinct())}.";
        f.Merk(Tilstand.Finnes);
        f.Sterkt();
    }

    private static string LanceRot(string sti)
    {
        var i = sti.IndexOf(".lance", StringComparison.OrdinalIgnoreCase);
        return i > 0 ? Path.GetDirectoryName(sti.Substring(0, i + 6)) ?? sti : Path.GetDirectoryName(sti)!;
    }

    /// <summary>Kalles fra filgjennomgangen for hver fil. Bare navn og plassering sjekkes her; innholdet leses etterpå.</summary>
    private void SjekkAgentfil(FileInfo fil)
    {
        var navn = fil.Name;
        var forelder = fil.Directory?.Name ?? "";
        var ext = fil.Extension.ToLowerInvariant();
        // Raskt ut for vanlige filer: bare navn, mapper og endelser vi bryr oss om
        // .env og .env.local osv.: bare navnene på AI-nøkler leses etterpå, aldri verdiene
        if (navn.Equals(".env", StringComparison.OrdinalIgnoreCase) || (navn.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) && !navn.EndsWith(".example", StringComparison.OrdinalIgnoreCase) && !navn.EndsWith(".sample", StringComparison.OrdinalIgnoreCase) && !navn.EndsWith(".template", StringComparison.OrdinalIgnoreCase)))
            _envFiler.Add(fil.FullName);
        if (VektorDb(fil) is { } vdb) _vektorDb.Add((fil.FullName, vdb));
        if (!Instruksjonsnavn.Contains(navn) && ext is not (".mdc" or ".env" or ".json" or ".md" or ".pt" or ".pth" or ".bin" or ".ckpt") && forelder is not (".claude" or ".vscode")) return;
        var besteforelder = fil.Directory?.Parent?.Name ?? "";
        if (ErBrukerOppsett(fil.FullName)) return;   // sjekkes direkte av sporsjekken
        if (Instruksjonsnavn.Contains(navn) || (navn.EndsWith(".mdc", StringComparison.OrdinalIgnoreCase) && forelder == "rules" && besteforelder == ".cursor"))
        {
            if (!navn.Equals("copilot-instructions.md", StringComparison.OrdinalIgnoreCase) || forelder == ".github") _instruksjonsfiler.Add(fil.FullName);
        }
        else if (forelder == ".gemini" && navn == ".env") _geminiEnv.Add(fil.FullName);
        else if (forelder == ".vscode" && navn.Equals("tasks.json", StringComparison.OrdinalIgnoreCase)) _oppgavefiler.Add(fil.FullName);
        else if (forelder is ".claude" or ".vscode" && KjorbareEndelser.Contains(fil.Extension)) _kjorbareIOppsett.Add(fil.FullName);
        else if (navn.Equals("SKILL.md", StringComparison.OrdinalIgnoreCase) && besteforelder == "skills" && fil.Directory?.Parent?.Parent?.Name == ".claude")
            _prosjektSkills.Add(fil.DirectoryName!);
        // nullifAI: modellfil som egentlig er et 7z-arkiv (unngår skanning av pickle-innholdet)
        else if (ext is ".pt" or ".pth" or ".bin" or ".ckpt" && ErSjuZip(fil)) _pakketModell.Add(fil.FullName);
    }

    private static bool ErSjuZip(FileInfo fil)
    {
        try
        {
            if (fil.Length < 1024) return false;
            using var fs = Admintilgang.AapneLes(fil.FullName);
            var b = new byte[6];
            return fs.Read(b, 0, 6) == 6 && b[0] == 0x37 && b[1] == 0x7A && b[2] == 0xBC && b[3] == 0xAF && b[4] == 0x27 && b[5] == 0x1C;
        }
        catch { return false; }
    }

    /// <summary>Kalles fra filgjennomgangen for symlinker og junctions. Målet leses, lenken følges aldri.</summary>
    private void SjekkLenke(FileSystemInfo e)
    {
        var mal = Reparse.Mal(e.FullName);
        bool treff = Agentoppsett.Any(a => e.Name.Equals(a, StringComparison.OrdinalIgnoreCase))
            || (mal != null && Agentoppsett.Any(a => mal.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0));
        if (treff) _lenker.Add((e.FullName, mal));
    }

    /// <summary>Python-pakker i site-packages: navn-versjon.dist-info mot lista over dårlige versjoner.</summary>
    private void SjekkPip(string sitePackages)
    {
        if (_regler.DaarligeVersjoner.Count == 0 && _regler.SaarbareVersjoner.Count == 0) return;
        foreach (var d in Mapper(sitePackages))
        {
            var m = Regex.Match(Path.GetFileName(d), @"^(.+?)-(\d[^-]*)\.dist-info$", RegexOptions.IgnoreCase);
            if (m.Success && DaarligVersjon($"{m.Groups[1].Value.Replace('_', '-')}@{m.Groups[2].Value}") is { } dv) _pipTreff.Add((d, dv));
            if (m.Success && Saarbar(m.Groups[1].Value, m.Groups[2].Value, "pypi") is { } sv) _saarbareTreff.Add((d, sv));
        }
    }

    // ---------- Etter filgjennomgangen ----------

    private void MisbrukEtterGjennomgang()
    {
        foreach (var sti in _instruksjonsfiler.Distinct(StringComparer.OrdinalIgnoreCase).Take(500)) SkjulteTegnIFil(sti, "instruksjonsfil");
        // Etter gjennomgangen, så prosjektenes oppsett og node_modules er med
        OmdirigertAi();
        AngrepEtterGjennomgang();
        foreach (var sti in _geminiEnv.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var t = Endret(sti);
            var f = Spor($"Agent-oppsett med .env i prosjekt: {SporProsjekt(Path.GetDirectoryName(sti)!)}",
                "Gemini CLI leser .gemini\\.env i prosjektmappa. Den kan endre hvor agenten sender data eller hvilke nøkler den bruker. Verdiene i fila vises aldri.", null);
            f.Tidspunkt(t, t);
            f.Detalj($"Fil: {sti}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")} · verdiene vises aldri");
        }
        EnvNokler(_envFiler.Distinct(StringComparer.OrdinalIgnoreCase).Take(2000));
        Vektordatabaser(_vektorDb.ToList());
        foreach (var sti in _oppgavefiler.Distinct(StringComparer.OrdinalIgnoreCase).Take(200)) OppgaverVedApning(sti);
        foreach (var g in _kjorbareIOppsett.Distinct(StringComparer.OrdinalIgnoreCase).GroupBy(x => Path.GetDirectoryName(x)!).Take(100))
            KjorbareIAgentmappe(g.Key, g.ToList());
        foreach (var dir in _prosjektSkills.Distinct(StringComparer.OrdinalIgnoreCase).Take(200)) SjekkSkill(dir, "Claude Code (prosjekt)");
        var lenker = _lenker.ToList();
        if (lenker.Count > 0)
        {
            var f = Spor("Snarveier inn i AI-agentens oppsett",
                "En symbolsk lenke eller junction i en prosjektmappe peker på oppsettet til en AI-agent. Slik kan et prosjekt endre agentens innstillinger. Lenken er ikke fulgt.", null);
            foreach (var (lenke, mal) in lenker.Take(20))
            {
                var t = Endret(lenke);
                f.Tidspunkt(t, t);
                f.Detalj($"Fil: {lenke} · peker til {mal ?? "ukjent mål"}{(t != null ? " · " + Nar(t.Value, "endringstid på lenke") : "")}");
            }
        }
        var pip = _pipTreff.ToList();
        if (pip.Count > 0)
        {
            var f = Spor("Python-pakker på lista over kjente dårlige versjoner", "En Python-pakke i en versjon som står på lista over kjente dårlige versjoner i regler.json.", null);
            f.Advarsel("En versjon fra lista over kjente dårlige versjoner er installert.");
            foreach (var (sti, d) in pip.Take(20))
            {
                var t = Endret(sti);
                f.Tidspunkt(t, t);
                f.Detalj($"Fil: {sti} · {d}{(t != null ? " · installert " + Nar(t.Value, "endringstid på mappe") : "")}");
            }
        }
        var pakket = _pakketModell.ToList();
        if (pakket.Count > 0)
        {
            var f = Spor("Modellfil som egentlig er et 7z-arkiv",
                "En fil med modellendelse (.pt, .pth, .bin, .ckpt) er pakket som 7z. Slik har skadelige modeller sluppet forbi skanning (nullifAI).", null);
            foreach (var sti in pakket.Take(20))
            {
                var t = Endret(sti);
                f.Tidspunkt(t, t);
                f.Detalj($"Fil: {sti}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
            }
        }
    }

    // ---------- Sporsjekken (kjører sammen med de andre sjekkene) ----------

    private void MisbrukBruker()
    {
        var hjem = Utvid("%USERPROFILE%");
        // Instruksjonsfiler for alle prosjekter
        foreach (var sti in new[] { @"%USERPROFILE%\.claude\CLAUDE.md", @"%USERPROFILE%\.codex\AGENTS.md", @"%USERPROFILE%\.gemini\GEMINI.md" })
            SkjulteTegnIFil(Utvid(sti), "instruksjonsfil for alle prosjekter");
        foreach (var fil in Plattform.Filer(Utvid(@"%USERPROFILE%\.cursor\rules"), "*.mdc", 1).Take(100)) SkjulteTegnIFil(fil.FullName, "instruksjonsfil for alle prosjekter");
        // Kjørbare filer rett i .claude
        var claude = Utvid(@"%USERPROFILE%\.claude");
        var kjorbare = Filer(claude).Where(x => KjorbareEndelser.Contains(Path.GetExtension(x))).ToList();
        if (kjorbare.Count > 0) KjorbareIAgentmappe(claude, kjorbare);
        // Ferdigheter og tillegg
        foreach (var (mappe, program) in new[]
        {
            (@"%USERPROFILE%\.claude\skills", "Claude Code"), (@"%USERPROFILE%\.claude\plugins", "Claude Code (tillegg)"),
            (@"%USERPROFILE%\.codex\skills", "Codex"), (@"%USERPROFILE%\.openclaw", "OpenClaw"), (@"%USERPROFILE%\.clawdbot", "Clawdbot"),
            (@"%USERPROFILE%\.agents\skills", "AI-agenter (felles mappe for npx skills)"), (@"%USERPROFILE%\.gemini\skills", "Gemini CLI"),
            (@"%USERPROFILE%\.gemini\antigravity-cli\skills", "Google Antigravity"), (@"%USERPROFILE%\.warp\skills", "Warp"), (@"%USERPROFILE%\.hermes\skills", "Hermes Agent"),
        })
        {
            var rot = Utvid(mappe);
            if (!Directory.Exists(rot)) { Tilgangslogg.Logg("Mappe", rot, Utfall.IkkeFunnet); continue; }
            foreach (var d in Mapper(rot).Take(300)) SjekkSkill(d, program);
        }
        // Agenter og kommandoer for Claude Code er filer rett i mappa; utvidelser for Gemini CLI er én mappe hver
        foreach (var (mappe, program) in new[] { (@"%USERPROFILE%\.claude\agents", "Claude Code (agenter)"), (@"%USERPROFILE%\.claude\commands", "Claude Code (kommandoer)") })
        {
            var rot = Utvid(mappe);
            if (Directory.Exists(rot)) SjekkSkill(rot, program); else Tilgangslogg.Logg("Mappe", rot, Utfall.IkkeFunnet);
        }
        var gemini = Utvid(@"%USERPROFILE%\.gemini\extensions");
        if (Directory.Exists(gemini)) foreach (var d in Mapper(gemini).Take(300)) SjekkSkill(d, "Gemini CLI (utvidelse)");
        HfOgOllama();
        AutostartMedFlagg();
        NpxForgiftning();
        KjenteFiler();
        InstruksjonerINedlastinger();
        WindowsMcp();
    }

    // ---------- N4: skjulte tegn ----------

    /// <summary>Tegn som ikke vises, men som AI-modellen leser: tag-tegn, null-bredde, retningsstyring, BOM inne i teksten.</summary>
    internal static int TellSkjulte(string tekst)
    {
        int n = 0;
        for (int i = 0; i < tekst.Length; i++)
        {
            var c = tekst[i];
            if (c == '\uDB40' && i + 1 < tekst.Length && tekst[i + 1] >= '\uDC00' && tekst[i + 1] <= '\uDC7F') { n++; i++; }   // U+E0000–E007F
            else if ((c >= '​' && c <= '‏') || (c >= '⁠' && c <= '⁤') || (c >= '‪' && c <= '‮') || (c == '﻿' && i > 0)) n++;
        }
        return n;
    }

    private void SkjulteTegnIFil(string sti, string hva)
    {
        string tekst;
        try
        {
            var info = new FileInfo(sti);
            if (!info.Exists) { Tilgangslogg.Logg("Fil", sti, Utfall.IkkeFunnet); return; }
            if (info.Length > 1024 * 1024) { Tilgangslogg.Logg("Fil", sti, Utfall.HoppetOver, "større enn 1 MB"); return; }
            tekst = File.ReadAllText(sti, Encoding.UTF8);
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest, "bare antall skjulte tegn og navnene på mønstre fra kjente angrep; teksten lagres ikke");
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return; }
        int n = TellSkjulte(tekst);
        // Mønstre fra kjente angrep på AI-agenter (ATR). Skjulte tegn har sitt eget funn; lange base64-blokker er vanlige i notater.
        var monstre = SkillTreff(tekst).Where(x => x.Navn is not ("skjulte tegn" or "lang base64-blokk")).ToList();
        tekst = "";
        var t = Endret(sti);
        if (monstre.Count > 0)
        {
            var m = Spor($"Instruksjonsfil med mønster fra kjente angrep: {Path.GetFileName(sti)}",
                $"En {hva} for AI-agenter inneholder mønstre fra kjente angrep på AI-agenter (ATR). Agenten leser fila som ordre. Teksten vises ikke, bare navnet på mønsteret.", null);
            m.Advarsel($"Instruksjonsfil for AI-agenter som {monstre[0].Navn}.");
            m.Tidspunkt(t, t);
            m.Detalj($"Fil: {sti} · {string.Join(", ", monstre.Select(x => x.Navn).Distinct())}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
            m.Detalj($"Regel: {string.Join(" · ", monstre.SelectMany(x => x.Kilde.Split(new[] { " · " }, StringSplitOptions.None)).Distinct())}");
        }
        if (n == 0) return;
        var f = Spor($"Skjulte tegn i {Path.GetFileName(sti)}",
            $"En {hva} for AI-agenter har tegn som ikke vises på skjermen, men som AI-en leser. Slik kan noen gi agenten skjulte ordrer.", null);
        f.Advarsel($"{n} skjulte tegn i en instruksjonsfil for AI-agenter.");
        f.Tidspunkt(t, t);
        f.Detalj($"Fil: {sti} · {n} skjulte tegn{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
    }

    // ---------- N1: hooks, oppgaver og kjørbare filer ----------

    /// <summary>Første ord i en kommando, uten sti: "node", "powershell", "setup.mjs". Resten vises aldri.</summary>
    internal static string ForsteOrd(string? kommando)
    {
        if (string.IsNullOrWhiteSpace(kommando)) return "";
        var k = kommando!.TrimStart();
        var ord = k.StartsWith("\"") ? k.Substring(1).Split('"')[0] : k.Split(' ', '\t')[0];
        var navn = Path.GetFileName(ord.Replace('/', '\\').Split('\\').Last());
        return NokkelMonster.IsMatch(navn) || navn.Length > 60 ? "[skjult]" : navn;
    }

    private void Hooks(JsonElement rot, string sti, string program)
    {
        if (!rot.TryGetProperty("hooks", out var h) || h.ValueKind != JsonValueKind.Object) return;
        var linjer = new List<string>();
        foreach (var hendelse in h.EnumerateObject())
        {
            if (hendelse.Value.ValueKind != JsonValueKind.Array) continue;
            foreach (var regel in hendelse.Value.EnumerateArray())
            {
                if (regel.ValueKind != JsonValueKind.Object || !regel.TryGetProperty("hooks", out var liste) || liste.ValueKind != JsonValueKind.Array) continue;
                foreach (var hk in liste.EnumerateArray())
                    if (hk.ValueKind == JsonValueKind.Object && hk.TryGetProperty("command", out var c) && c.ValueKind == JsonValueKind.String)
                        linjer.Add($"{hendelse.Name}: {ForsteOrd(c.GetString())}");
            }
        }
        if (linjer.Count == 0) return;
        var t = Endret(sti);
        var f = Spor($"Hooks i {program}: {(ErBrukerOppsett(sti) ? "alle prosjekter" : SporProsjekt(sti))}",
            "Kommandoer som AI-agenten kjører av seg selv ved bestemte hendelser (oppstart, før verktøy). Bare første ord i kommandoen vises.", null);
        if (!ErBrukerOppsett(sti)) f.Advarsel("Hooks i en prosjektmappe: kjører for alle som åpner prosjektet med agenten.");
        f.Tidspunkt(t, t);
        foreach (var l in linjer.Distinct().Take(20)) f.Detalj($"Fil: {sti} · {l}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
    }

    private void OppgaverVedApning(string sti)
    {
        using var doc = LesJson(sti, Sporfiler);
        if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("tasks", out var tasks) || tasks.ValueKind != JsonValueKind.Array) return;
        var linjer = new List<string>();
        foreach (var task in tasks.EnumerateArray())
        {
            if (task.ValueKind != JsonValueKind.Object || !task.TryGetProperty("runOptions", out var ro) || ro.ValueKind != JsonValueKind.Object) continue;
            if (!ro.TryGetProperty("runOn", out var on) || on.ValueKind != JsonValueKind.String || on.GetString() != "folderOpen") continue;
            var cmd = task.TryGetProperty("command", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
            linjer.Add($"kjøres når mappa åpnes: {ForsteOrd(cmd)}");
        }
        if (linjer.Count == 0) return;
        var t = Endret(sti);
        var f = Spor($"Oppgave som starter når prosjektet åpnes: {SporProsjekt(sti)}",
            "VS Code eller Cursor kjører en kommando av seg selv når prosjektmappa åpnes. Bare første ord i kommandoen vises.", null);
        f.Advarsel("Kommando som kjører av seg selv når prosjektet åpnes.");
        f.Tidspunkt(t, t);
        foreach (var l in linjer.Distinct().Take(10)) f.Detalj($"Fil: {sti} · {l}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
    }

    private void KjorbareIAgentmappe(string mappe, List<string> filer)
    {
        var f = Spor($"Skript i agentmappe: {(ErBrukerOppsett(mappe) ? Path.GetFileName(mappe) : SporProsjekt(Path.Combine(mappe, "x")))}",
            "Kjørbare skript ligger rett i oppsettmappa til en AI-agent eller kodeeditor (.claude, .vscode). Der hører de vanligvis ikke hjemme.", null);
        foreach (var fil in filer.Take(20))
        {
            var t = Endret(fil);
            f.Tidspunkt(t, t);
            f.Detalj($"Fil: {fil}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
        }
    }

    // ---------- N2 og N11: innstillinger i Claude Code ----------

    private static readonly string[] Uttaksverter = { "webhook.site", "pipedream.net", "requestbin", "ngrok", "pastebin.com", "glot.io" };

    /// <summary>Kalles fra ClaudeInnstillinger: hooks, MCP som starter selv, WebFetch uten grense.</summary>
    private void ClaudeMisbruk(JsonElement rot, string sti)
    {
        Hooks(rot, sti, "Claude Code");
        var funn = new List<string>();
        if (rot.TryGetProperty("enableAllProjectMcpServers", out var ea) && ea.ValueKind == JsonValueKind.True)
            funn.Add("enableAllProjectMcpServers = true (MCP-servere i prosjekter starter uten å spørre)");
        if (rot.TryGetProperty("enabledMcpjsonServers", out var em) && em.ValueKind == JsonValueKind.Array && em.GetArrayLength() > 0)
            funn.Add($"enabledMcpjsonServers: {em.GetArrayLength()} MCP-servere fra prosjektet er godkjent på forhånd");
        if (rot.TryGetProperty("permissions", out var p) && p.ValueKind == JsonValueKind.Object && p.TryGetProperty("allow", out var al) && al.ValueKind == JsonValueKind.Array)
            foreach (var a in al.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!))
            {
                if (a is "WebFetch" or "WebFetch(*)") funn.Add("tillater WebFetch til alle adresser uten å spørre");
                else if (a.StartsWith("WebFetch(", StringComparison.Ordinal) && Uttaksverter.FirstOrDefault(v => a.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0) is { } v)
                    funn.Add($"tillater WebFetch til {v} uten å spørre (kjent tjeneste for å ta ut data)");
            }
        if (funn.Count > 0) GodkjennAlt(sti, "Claude Code", funn, !ErBrukerOppsett(sti));
    }

    // ---------- N6: ferdigheter og tillegg ----------

    private const RegexOptions Ri = RegexOptions.IgnoreCase | RegexOptions.Compiled;

    /// <summary>
    /// Mønstre i ferdigheter, tillegg og instruksjonsfiler for AI-agenter. Kilde per mønster: ATR (Agent Threat Rules, MIT) og
    /// MITRE ATLAS. Bare navnet på mønsteret vises, aldri teksten som slo til.
    /// </summary>
    private static readonly (string Navn, Regex Monster, string Kilde)[] Skillmonstre =
    {
        ("laster ned og kjører kode", new Regex(@"(curl|wget)[^|\r\n]{0,200}\|\s*(sh|bash)\b|(irm|iwr|invoke-webrequest|invoke-restmethod)[^|\r\n]{0,200}\|\s*iex\b|-encodedcommand\b", Ri),
            "ATR-2026-00121 · ATLAS AML.T0110.001"),
        ("lang base64-blokk", new Regex(@"[A-Za-z0-9+/]{200,}={0,2}", RegexOptions.Compiled), "ATR-2026-00220 · ATLAS AML.T0123"),
        ("ber om passordbeskyttet zip", new Regex(@"(password|passord)[^\r\n]{0,60}\.(zip|7z|rar)|\.(zip|7z|rar)[^\r\n]{0,60}(password|passord)", Ri), "ATR-2026-02405 · ATLAS AML.T0115.002"),
        ("sender til uttakstjeneste", new Regex(@"glot\.io|webhook\.site|pipedream\.net|requestbin|interact\.sh|oast\.(fun|pro|live|site)|burpcollaborator", Ri), "ATR-2026-00135 · ATLAS AML.T0086"),
        ("skjult beskjed i HTML-kommentar", new Regex(@"<!--[^>]{0,400}?((ignore|override|bypass|disable|forget)\s+(all\s+|the\s+)?(previous|prior|safety|security)\s+(instruction|rule|restriction)s?|do\s+not\s+(mention|tell|inform|reveal|show|disclose)\s+(this|the\s+user|anyone)|exfiltrat|\bcurl\s|\bwget\s)", Ri),
            "ATR-2026-00128 · ATLAS AML.T0080"),
        ("ber agenten sende data til en adresse", new Regex(@"(send|post|upload|submit|forward|transmit)\s+(the|all|your|any|every)?\s*((env|environment)\s+variables?|api\s+keys?|report|data|keys?|credentials?|tokens?|secrets?|passwords?|config|env|variables?)\s+(to|at|via)\s+https?://", Ri),
            "ATR-2026-00135 · ATLAS AML.T0086"),
        ("ber agenten skjule noe for brukeren", new Regex(@"(do\s+not|don't|never)\s+(tell|inform|notify|alert|mention\s+(this\s+)?to)\s+the\s+user|without\s+(the\s+user\s+(knowing|noticing)|telling\s+the\s+user)", Ri),
            "ATR-2026-00105 · ATR-2026-00425 · ATLAS AML.T0080"),
        ("skriver seg inn i agentens oppsett", new Regex(@"(write|append|inject|insert)\s+(an?\s+)?(hidden\s+|new\s+|extra\s+|additional\s+)?(entry|line|block|hook|section)\s+(to|into)\s+[^\r\n]{0,40}(SKILL\.md|claude_desktop_config\.json|\.cursor[/\\]mcp\.json|\.claude[/\\]settings)|(inject|tamper\s+with|overwrite)\s+[^\r\n]{0,30}(the\s+user'?s|your\s+own)\s+[^\r\n]{0,20}(SKILL\.md|claude_desktop_config\.json|mcp\.json|settings\.json)", Ri),
            "ATR-2026-00429 · ATR-2026-00200 · ATLAS AML.T0081"),
        ("kryptomining", new Regex(@"\b(xmrig|xmr-stak|cpuminer|nbminer|phoenixminer|lolminer|teamredminer|nanominer|srbminer)\b|stratum\+(tcp|tcps|ssl)://", Ri), "ATR-2026-02845 · ATLAS AML.T0034"),
        ("erklærer angrep som formål", new Regex(@"(?m)^\s*(category|type|purpose|class)\s*:\s*[""']?(attack|jailbreak|exploit|offensive)[""']?\s*$", Ri), "ATR-2026-02818 · ATLAS AML.T0104"),
    };

    // Sammensatte mønstre: begge delene må finnes i samme fil
    private static readonly Regex Hemmelighetssti = new(@"\.ssh[/\\]id_|\.aws[/\\]credentials|\.git-credentials|Login\s?Data|\.docker[/\\]config\.json|\.kube[/\\]config|\.azure[/\\]|\.codex[/\\]auth\.json|\.claude[/\\]\.credentials|oauth_creds\.json|wallet\.dat|\bkeystore[/\\]", Ri);
    private static readonly Regex Nettsending = new(@"requests\.(post|put)\s*\(|\bfetch\s*\(|axios\.(post|put)|Invoke-(WebRequest|RestMethod)|\bcurl\s[^\r\n]{0,120}(\s-d\s|--data|\s-F\s|\s-T\s|--upload-file)|urllib\.request|https?\.request\s*\(|WebClient\b", Ri);
    private static readonly Regex SokketTilkobling = new(@"socket\.socket\s*\([^)]{0,40}AF_INET[\s\S]{0,160}?\.connect\s*\(|\bnet\.(connect|createConnection)\s*\(|new\s+net\.Socket\s*\(|System\.Net\.Sockets\.TcpClient", Ri);
    private static readonly Regex SkallPaRor = new(@"\bdup2\s*\([^)]{0,40}fileno|\bpty\.spawn\s*\(|\.pipe\s*\(\s*[\w.$]{1,24}\.stdin\s*\)|subprocess\.(call|run|Popen)\s*\(\s*\[\s*[""'](/bin/)?(sh|bash|cmd(\.exe)?|powershell(\.exe)?)[""']|GetStream\(\)[\s\S]{0,200}(cmd\.exe|powershell)", Ri);
    // Nedlasting fra en offentlig IP-adresse uten navn
    private static readonly Regex RaIpUrl = new(@"https?://(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(:\d+)?/", RegexOptions.Compiled);

    /// <summary>Navnene på mønstrene som slår til i en tekst, med kilde. Teksten tas aldri med ut.</summary>
    internal static List<(string Navn, string Kilde)> SkillTreff(string tekst)
    {
        var t = new List<(string, string)>();
        foreach (var (navn, m, kilde) in Skillmonstre)
            if (m.IsMatch(tekst)) t.Add((navn, kilde));
        if (Hemmelighetssti.IsMatch(tekst) && Nettsending.IsMatch(tekst)) t.Add(("leser hemmeligheter og sender på nettet", "ATR-2026-02261 · ATLAS AML.T0098"));
        if (SokketTilkobling.IsMatch(tekst) && SkallPaRor.IsMatch(tekst)) t.Add(("kobler et skall til nettet", "ATR-2026-02600 · ATLAS AML.T0072"));
        foreach (Match x in RaIpUrl.Matches(tekst))
        {
            int a = int.Parse(x.Groups[1].Value), b = int.Parse(x.Groups[2].Value);
            bool privat = a is 0 or 10 or 127 or > 223 || (a == 169 && b == 254) || (a == 172 && b is >= 16 and <= 31) || (a == 192 && b == 168) || (a == 100 && b is >= 64 and <= 127);
            if (!privat) { t.Add(("henter fra en IP-adresse uten navn", "ATR-2026-00225 · ATR-2026-00220 · ATLAS AML.T0072")); break; }
        }
        if (TellSkjulte(tekst) > 0) t.Add(("skjulte tegn", "ATR-2026-00129 · ATLAS AML.T0068"));
        return t;
    }

    private static readonly HashSet<string> Skillendelser = new(StringComparer.OrdinalIgnoreCase) { ".md", ".ps1", ".sh", ".py", ".js", ".mjs", ".bat", ".cmd", ".txt", ".json" };

    private void SjekkSkill(string mappe, string program)
    {
        var treff = new SortedSet<string>();
        var kilder = new SortedSet<string>();
        DateTime? sist = null;
        foreach (var fil in Plattform.Filer(mappe, "*", 4).Where(x => Skillendelser.Contains(x.Extension)).Take(100))
        {
            if (fil.Length > 1024 * 1024) { Tilgangslogg.Tell("Fil", Utfall.HoppetOver, sted: fil.FullName, detalj: "større enn 1 MB"); continue; }
            string tekst;
            try
            {
                using var fs = Admintilgang.AapneLes(fil.FullName);
                using var r = new StreamReader(fs);
                tekst = r.ReadToEnd();
                Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName);
            }
            catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); continue; }
            var tr = SkillTreff(tekst);
            tekst = "";
            foreach (var (navn, kilde) in tr) { treff.Add(navn); kilder.Add(kilde); }
            if (tr.Count > 0 && (sist == null || fil.LastWriteTime > sist)) sist = fil.LastWriteTime;
        }
        if (treff.Count == 0) return;
        var f = Spor($"Ferdighet for AI-agent: {Path.GetFileName(mappe)}",
            $"En ferdighet eller et tillegg for {program} inneholder mønstre fra kjente angrep på AI-agenter (ATR): å laste ned og kjøre kode, sende data ut, skjule handlinger eller endre agentens oppsett. Teksten vises ikke, bare navnet på mønsteret.", null);
        f.Advarsel($"Ferdighet for AI-agent som {treff.First()}.");
        f.Tidspunkt(sist, sist);
        f.Detalj($"Fil: {mappe} · {string.Join(", ", treff)}{(sist != null ? " · endret " + Nar(sist.Value, "endringstid på fil") : "")}");
        f.Detalj($"Regel: {string.Join(" · ", kilder.SelectMany(k => k.Split(new[] { " · " }, StringSplitOptions.None)).Distinct())}");
    }

    // ---------- N7: fjernkode fra Hugging Face og ukjente Ollama-registre ----------

    private static readonly Regex Nettkode = new(@"^\s*(import|from)\s+(socket|requests|urllib|subprocess|httpx|paramiko)\b|\bexec\s*\(|\beval\s*\(|os\.system\s*\(", RegexOptions.Multiline | RegexOptions.Compiled);

    private void HfOgOllama()
    {
        var hf = Environment.GetEnvironmentVariable("HF_HOME") is { Length: > 0 } h ? h : Utvid(@"%USERPROFILE%\.cache\huggingface");
        var moduler = Path.Combine(hf, "modules", "transformers_modules");
        var kjort = Mapper(moduler).Take(50).ToList();
        if (kjort.Count > 0)
        {
            var f = Spor("Fjernkode fra Hugging Face har kjørt",
                "Python-kode som fulgte med en modell fra Hugging Face er lastet ned og kjørt på PC-en (trust_remote_code). Vi vet ikke hva koden gjorde.", null);
            foreach (var d in kjort.Take(20))
            {
                DateTime? t = null;
                try { t = Directory.GetCreationTime(d); } catch { }
                f.Tidspunkt(t, t);
                f.Detalj($"Fil: {d}{(t != null ? " · lastet ned " + Nar(t.Value, "opprettelsestid på mappe") : "")}");
            }
        }
        // .py i modellmappene som kan koble seg til nettet eller kjøre kommandoer
        var py = new List<(string Sti, DateTime T)>();
        foreach (var snap in Mapper(Path.Combine(hf, "hub")).Where(d => Path.GetFileName(d).StartsWith("models--")).Take(200))
            foreach (var fil in Plattform.Filer(Path.Combine(snap, "snapshots"), "*.py", 3).Take(50))
            {
                if (fil.Length > 1024 * 1024) continue;
                bool farlig;
                try { farlig = Nettkode.IsMatch(File.ReadAllText(fil.FullName)); Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName); }
                catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); continue; }
                if (farlig) py.Add((fil.FullName, fil.LastWriteTime));
            }
        if (py.Count > 0)
        {
            var f = Spor("Modellkode som kan bruke nettet eller kjøre kommandoer",
                "Python-filer som fulgte med en modell fra Hugging Face importerer nettverks- eller kommandobiblioteker. De kjører hvis modellen lastes med trust_remote_code.", null);
            foreach (var (sti, t) in py.Take(20)) { f.Tidspunkt(t, t); f.Detalj($"Fil: {sti} · endret {Nar(t, "endringstid på fil")}"); }
        }
        // Ollama: modeller hentet fra andre registre enn de vanlige
        var manifester = Utvid(@"%USERPROFILE%\.ollama\models\manifests");
        var ukjente = Mapper(manifester).Where(d => Path.GetFileName(d) is var v && !v.Equals("registry.ollama.ai", StringComparison.OrdinalIgnoreCase)
            && !v.Equals("hf.co", StringComparison.OrdinalIgnoreCase) && !v.Equals("huggingface.co", StringComparison.OrdinalIgnoreCase)).ToList();
        if (ukjente.Count > 0)
        {
            var f = Spor("Ollama-modeller fra ukjent register",
                "Ollama har hentet modeller fra et annet sted enn Ollama sitt eget register eller Hugging Face.", null);
            foreach (var d in ukjente.Take(20))
            {
                DateTime? t = null;
                try { t = Directory.GetCreationTime(d); } catch { }
                f.Tidspunkt(t, t);
                f.Detalj($"Fil: {d} · register {Path.GetFileName(d)}{(t != null ? " · " + Nar(t.Value, "opprettelsestid på mappe") : "")}");
            }
        }
    }

    // ---------- N8: agenter som starter av seg selv med farlige flagg ----------

    private static readonly (string Agent, Regex Monster)[] FarligeFlagg =
    {
        ("Claude Code", new Regex(@"\bclaude(\.exe|\.cmd|\.ps1)?\b[^\r\n]{0,200}?(--dangerously-skip-permissions|--permission-mode\s+bypassPermissions|(?<=\s)(-p|--print)\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("Codex", new Regex(@"\bcodex(\.exe|\.cmd|\.ps1)?\b[^\r\n]{0,200}?((?<=\s)exec\b|--full-auto|--dangerously-bypass-approvals-and-sandbox|--yolo)", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("Gemini CLI", new Regex(@"\bgemini(\.cmd|\.ps1)?\b[^\r\n]{0,200}?(--yolo|--approval-mode[\s=]+yolo|(?<=\s)-y\b)", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("GitHub Copilot CLI", new Regex(@"\bcopilot(\.cmd|\.ps1)?\b[^\r\n]{0,200}?(--allow-all-tools)", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("Aider", new Regex(@"\baider(\.exe)?\b[^\r\n]{0,200}?(--yes-always)", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
    };

    /// <summary>Agent og flagg i en tekst, aldri resten av kommandoen.</summary>
    internal static List<(string Agent, string Flagg)> FlaggITekst(string tekst)
    {
        var svar = new List<(string, string)>();
        foreach (var (agent, m) in FarligeFlagg)
            foreach (Match x in m.Matches(tekst))
                svar.Add((agent, x.Groups[2].Value.Trim()));
        return svar.Distinct().ToList();
    }

    private void AutostartMedFlagg()
    {
        var linjer = new List<(string Tekst, DateTime? T)>();
        void Sjekk(string tekst, string kilde, DateTime? t)
        {
            foreach (var (agent, flagg) in FlaggITekst(tekst)) linjer.Add(($"{kilde} · {agent} {flagg}", t));
        }
        if (Plattform.ErWindows)
        {
            foreach (var n in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\RunOnce" })
            {
                using var k = Tilgangslogg.Nokkel(Bruker.Hkcu, n);
                if (k == null) continue;
                foreach (var v in k.GetValueNames())
                    if (k.GetValue(v) is string s) Sjekk(s, $"Register: HKCU\\{n} · {v}", null);
            }
        }
        var filer = new List<string>();
        filer.AddRange(Plattform.Filer(Utvid(@"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "*", 0)
            .Where(x => x.Extension.ToLowerInvariant() is ".bat" or ".cmd" or ".ps1" or ".vbs").Select(x => x.FullName));
        var dok = Bruker.Dokumenter();
        if (!string.IsNullOrEmpty(dok))
            foreach (var m in new[] { "WindowsPowerShell", "PowerShell" })
                filer.AddRange(Plattform.Filer(Path.Combine(dok, m), "*profile.ps1", 0).Select(x => x.FullName));
        filer.Add(Utvid(@"%USERPROFILE%\.bashrc"));
        foreach (var fil in filer.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var t = Endret(fil);
            LesLinjer(fil, 1, l => Sjekk(l, $"Fil: {fil}", t));
        }
        if (linjer.Count == 0) return;
        var f = Spor("AI-agent startes med farlige flagg",
            "En AI-agent startes av seg selv (oppstart, profil eller register) med flagg som slår av spørsmålene før den kjører kommandoer. Bare agent og flagg vises.", null);
        f.Advarsel("AI-agent som starter av seg selv uten å spørre før den gjør noe.");
        foreach (var (tekst, t) in linjer.Distinct().Take(20))
        {
            f.Tidspunkt(t, t);
            f.Detalj(tekst + (t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : ""));
        }
    }

    // ---------- N13: forgiftede verktøy i npx-cachen ----------

    private void NpxForgiftning()
    {
        // npx-cachen, globale npm-pakker og uv-verktøy: MCP-servere som er lastet ned og kjøres av agenten
        var rotter = Mapper(Utvid(@"%LOCALAPPDATA%\npm-cache\_npx")).Select(c => Path.Combine(c, "node_modules"))
            .Append(Utvid(@"%APPDATA%\npm\node_modules"))
            .Concat(Mapper(Utvid(@"%APPDATA%\uv\tools")).Select(t => Path.Combine(t, "Lib", "site-packages")))
            .Where(Directory.Exists).ToList();
        var klokke = System.Diagnostics.Stopwatch.StartNew();
        int lest = 0;
        var treff = new Dictionary<string, (int Skjulte, int Viktig, SortedSet<string> Monstre, DateTime T)>(StringComparer.OrdinalIgnoreCase);
        foreach (var nm in rotter)
        {
            foreach (var pakke in Mapper(nm).SelectMany(d => Path.GetFileName(d).StartsWith("@") ? Mapper(d) : new[] { d }))
            {
                // Bare MCP-pakker: navnet nevner mcp eller modelcontextprotocol
                if (pakke.IndexOf("mcp", StringComparison.OrdinalIgnoreCase) < 0 && pakke.IndexOf("modelcontextprotocol", StringComparison.OrdinalIgnoreCase) < 0) continue;
                foreach (var fil in Plattform.Filer(pakke, "*", 4).Where(x => x.Extension is ".js" or ".mjs" or ".cjs" or ".ts" or ".py"))
                {
                    // Fullt søk: alt. Hurtigsøk: 200 filer eller 20 sekunder.
                    if (!Fullt && (lest >= 200 || klokke.Elapsed > TimeSpan.FromSeconds(20))) { Tilgangslogg.EnGang("npx-200", "Mappe", nm, Utfall.Tidsgrense, "200 filer eller 20 sekunder brukt på MCP-pakker"); goto ferdig; }
                    if (fil.Length > 1024 * 1024) continue;
                    string tekst;
                    try { tekst = File.ReadAllText(fil.FullName); lest++; Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName); }
                    catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); continue; }
                    int s = TellSkjulte(tekst), v = Regex.Matches(tekst, "<IMPORTANT>", RegexOptions.IgnoreCase).Count;
                    // Mønstre fra ATR i verktøybeskrivelser og kode. Base64 og IP-adresser er vanlige i ferdigbygd kode.
                    var m = SkillTreff(tekst).Select(x => x.Navn).Where(n => n is not ("lang base64-blokk" or "skjulte tegn" or "henter fra en IP-adresse uten navn")).ToList();
                    tekst = "";
                    if (s + v + m.Count == 0) continue;
                    treff.TryGetValue(pakke, out var x);
                    var ms = x.Monstre ?? new SortedSet<string>();
                    ms.UnionWith(m);
                    treff[pakke] = (x.Skjulte + s, x.Viktig + v, ms, fil.LastWriteTime > x.T ? fil.LastWriteTime : x.T);
                }
            }
        }
        ferdig:
        if (treff.Count == 0) return;
        var f = Spor("MCP-verktøy med skjulte beskjeder til AI-en",
            "Et MCP-verktøy som agenten har lastet ned, har skjulte tegn, <IMPORTANT>-blokker eller mønstre fra kjente angrep i koden. Slik kan et verktøy gi AI-agenten ordrer brukeren ikke ser.", null);
        foreach (var (pakke, x) in treff.Take(20))
        {
            f.Tidspunkt(x.T, x.T);
            f.Detalj($"Fil: {pakke} · {x.Skjulte} skjulte tegn · {x.Viktig} <IMPORTANT>-blokker{(x.Monstre.Count > 0 ? " · " + string.Join(", ", x.Monstre) : "")} · endret {Nar(x.T, "endringstid på fil")}");
        }
        f.Detalj("Regel: ATR-2026-00161 · ATR-2026-00100–00106 · ATLAS AML.T0110");
    }

    // ---------- N12: kjente filer ----------

    private void KjenteFiler()
    {
        var funnet = new List<(string Sti, string Kilde)>();
        foreach (var k in _regler.IocFiler)
        {
            var sti = Utvid(k.Sti);
            if (sti.Contains('%')) continue;
            bool finnes;
            try { finnes = File.Exists(sti); } catch { finnes = false; }
            Tilgangslogg.Logg("Fil", sti, finnes ? Utfall.Lest : Utfall.IkkeFunnet, "finnes fila? (innholdet åpnes ikke)");
            if (finnes) funnet.Add((sti, k.Kilde ?? ""));
        }
        if (funnet.Count == 0) return;
        var f = Spor("Filer kjent fra AI-misbruk",
            "Filer med samme navn og sted som filer kjent fra angrep der AI-verktøy ble brukt eller misbrukt. Samme navn betyr ikke at det er samme fil. Innholdet er ikke åpnet.", null);
        f.Advarsel("Fil med samme navn og sted som en kjent fil fra AI-misbruk.");
        foreach (var (sti, kilde) in funnet)
        {
            var t = Endret(sti);
            f.Tidspunkt(t, t);
            f.Detalj($"Fil: {sti}{(kilde.Length > 0 ? " · " + kilde : "")}{(t != null ? " · endret " + Nar(t.Value, "endringstid på fil") : "")}");
        }
    }

    // ---------- N10: utvidelser ----------

    private static readonly string[] AiChatsider =
        { "chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "chat.deepseek.com", "copilot.microsoft.com", "perplexity.ai" };

    /// <summary>Kalles for hver nettleserutvidelse: kjent dårlig ID, eller en utvidelse som ikke er AI, men kan lese AI-samtaler.</summary>
    private void UtvidelseMisbruk(string hvor, string navn, IEnumerable<string> tilganger, string mappe, bool erAi)
    {
        var id = Path.GetFileName(mappe.TrimEnd('\\', '/'));
        var kjent = _regler.DaarligeUtvidelser.FirstOrDefault(d => d.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        var sider = tilganger.SelectMany(t => AiChatsider.Where(s => t.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0)).Distinct().ToList();
        if (kjent == null && (erAi || sider.Count == 0)) return;
        var f = Spor($"Utvidelse som kan lese AI-samtaler: {Kutt(navn, 40)}",
            kjent != null ? "Utvidelsen står på lista over kjente utvidelser som har tatt ut AI-samtaler." : "En utvidelse som ikke er et AI-verktøy, har tilgang til sidene der du bruker AI. Den kan lese det du skriver og svarene.", null);
        if (kjent != null) f.Advarsel($"Kjent utvidelse fra lista over dårlige utvidelser ({kjent.Kilde ?? id}).");
        f.Detalj($"{hvor}: {mappe}{(sider.Count > 0 ? " · tilgang til " + string.Join(", ", sider) : "")}");
    }
}

/// <summary>Leser målet til en symlink eller junction uten å følge den (FSCTL_GET_REPARSE_POINT).</summary>
internal static class Reparse
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string navn, uint tilgang, uint deling, IntPtr sikkerhet, uint opprett, uint flagg, IntPtr mal);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr h, uint kode, IntPtr inn, int innLengde, byte[] ut, int utLengde, out int lest, IntPtr overlapped);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

    private const uint FSCTL_GET_REPARSE_POINT = 0x000900A8, OPEN_EXISTING = 3, FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000, FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C, IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;

    public static string? Mal(string sti)
    {
        if (!Plattform.ErWindows)
        {
#if NET6_0_OR_GREATER
            try { return new FileInfo(sti).LinkTarget; } catch { return null; }
#else
            return null;
#endif
        }
        var h = CreateFile(sti, 0, 7, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == new IntPtr(-1)) { Tilgangslogg.Logg("Fil", sti, Utfall.Feil, "lenkemålet kunne ikke leses"); return null; }
        try
        {
            var b = new byte[16 * 1024];
            if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, b, b.Length, out _, IntPtr.Zero)) return null;
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest, "bare lenkemålet; lenken følges ikke");
            uint tag = BitConverter.ToUInt32(b, 0);
            int start = tag == IO_REPARSE_TAG_SYMLINK ? 20 : tag == IO_REPARSE_TAG_MOUNT_POINT ? 16 : -1;
            if (start < 0) return null;
            int printOff = BitConverter.ToUInt16(b, 12), printLen = BitConverter.ToUInt16(b, 14);
            int subOff = BitConverter.ToUInt16(b, 8), subLen = BitConverter.ToUInt16(b, 10);
            var navn = printLen > 0 ? Encoding.Unicode.GetString(b, start + printOff, printLen) : Encoding.Unicode.GetString(b, start + subOff, subLen);
            return navn.StartsWith(@"\??\") ? navn.Substring(4) : navn;
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }
}
