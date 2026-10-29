using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Ukjente AI-spor: oppsett og logger etter AI-agenter og AI-tjenester der vi ikke vet hvem som satte dem opp eller hvorfor.
/// MCP-servere, «godkjenn alt»-innstillinger, lokale AI-servere brukt fra andre maskiner, agentøkter uten menneske,
/// skript som snakker med AI-API-er med nøkkel og kjente dårlige pakkeversjoner.
///
/// Bare lesing og bare metadata ut: tid, antall, kategori og filsti. Aldri innhold fra økter, kommandoer, nøkler eller
/// miljøvariabler. Ingenting lagres. Endringstid på filer kan forfalskes, så kilden til hvert tidspunkt står ved siden av.
/// Alle sporene er «Ukjent» og røde (samme regel som ukjent AI). Programmet sier aldri at PC-en er angrepet,
/// og rapporten sier «fant spor» eller «fant ingen spor».
/// </summary>
public sealed partial class Skanner
{
    public const string SporKategori = "Ukjent AI-spor";

    /// <summary>Steder søket ikke kan se inn i, for rapporten (f.eks. WSL).</summary>
    public List<string> Blindsoner { get; } = new();

    /// <summary>Les agentøkter (bare antall, tider og treff per kategori). Av med --uten-agentlogger.</summary>
    public bool MedAgentlogger { get; set; } = true;

    /// <summary>
    /// De eneste filnavnene sporsjekken åpner for å lese innholdet (i tillegg til LovligeFiler).
    /// Agentøkter (*.jsonl, chatSessions\*.json), serverlogger og skript sjekkes med egne regler under.
    /// </summary>
    public static readonly ISet<string> Sporfiler = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "claude_desktop_config.json", ".claude.json", ".mcp.json", "mcp.json", "config.toml",
        "settings.json", "settings.local.json", "package.json", "tasks.json",
        "mcp_config.json", "cline_mcp_settings.json", "mcp_settings.json",
    };

    // Prosjektfiler funnet av filgjennomgangen (.mcp.json, .vscode\mcp.json, .claude\settings*.json osv.)
    private readonly ConcurrentBag<string> _prosjektOppsett = new();

    private static readonly string[] AiApiVerter =
    {
        "generativelanguage.googleapis.com", "api.openai.com", "api.anthropic.com", "api-inference.huggingface.co",
        "router.huggingface.co", "api.deepseek.com", "api.mistral.ai", "api.groq.com", "openrouter.ai", ":11434",
    };

    private static readonly Regex NokkelMonster = new(@"AIza[0-9A-Za-z_\-]{30,}|sk-(?:ant-|proj-)?[0-9A-Za-z_\-]{20,}|hf_[0-9A-Za-z]{30,}", RegexOptions.Compiled);

    /// <summary>MCP-verter som er kjente tjenester. Andre fjern-URL-er blir røde.</summary>
    private static readonly string[] KjenteMcpVerter =
    {
        "githubcopilot.com", "github.com", "mcp.atlassian.com", "mcp.notion.com", "mcp.linear.app", "mcp.stripe.com",
        "mcp.sentry.dev", "cloudflare.com", "huggingface.co", "mcp.asana.com", "mcp.paypal.com", "mcp.zapier.com",
        "mcp.supabase.com", "mcp.vercel.com", "microsoft.com", "anthropic.com", "openai.com", "localhost", "127.0.0.1",
    };

    private static string Nar(DateTime t, string kilde) => $"{t.ToString("d. MMM yyyy 'kl.' HH:mm", NbKultur)} ({kilde})";
    private static DateTime? Endret(string sti) { try { return File.GetLastWriteTime(sti); } catch { return null; } }

    private void UkjenteSporSjekk()
    {
        lock (Blindsoner)
            Blindsoner.AddRange(new[]
            {
                "Ordrer skjult i nettsider eller dokumenter som en AI-agent leste (prompt injection), når agenten ikke fører logg.",
                "Lesing av nøkkelfiler uten revisjon i Windows.",
                "MCP-servere på nettet som endrer seg etter at de ble godkjent.",
                "AI-nettlesere som handler på egen hånd i agentmodus.",
            });
        foreach (var (navn, steg) in new (string, Action)[]
        {
            ("MCP", McpBruker), ("Godkjenn alt", GodkjennAltBruker), ("Serverlogger", Serverlogger),
            ("Agentøkter", Agentokter), ("Misbruk", MisbrukBruker), ("Skript", SkriptMedAi), ("Pakker", DaarligePakker),
        })
        {
            try { steg(); }
            catch (Exception e) { Tilgangslogg.Logg("Sjekk", $"{SporKategori}: {navn}", Utfall.Feil, $"Sjekken stoppet: {Tilgangslogg.Beskriv(e)}"); }
        }
    }

    // Alle spor er ukjente og røde (Risikoregler setter «Ukjent AI-spor» til rødt, som annen ukjent AI)
    private Funn Spor(string navn, string hvorfor, string? detalj) =>
        LeggTil(navn, SporKategori, Risiko.Rod, hvorfor, SporKategori, detalj, enkelt: navn);

    // ---------- P1: MCP-oppsett ----------

    internal sealed record McpServer(string Navn, string? Kommando, string? Argument, string? Url);

    private void McpBruker()
    {
        LesMcpFil(Utvid(@"%APPDATA%\Claude\claude_desktop_config.json"), "Claude Desktop", prosjekt: false);
        LesMcpFil(Utvid(@"%USERPROFILE%\.claude.json"), "Claude Code", prosjekt: false);
        LesMcpFil(Utvid(@"%USERPROFILE%\.cursor\mcp.json"), "Cursor", prosjekt: false);
        LesMcpFil(Utvid(@"%APPDATA%\Code\User\mcp.json"), "VS Code", prosjekt: false);
        LesMcpFil(Utvid(@"%USERPROFILE%\.gemini\settings.json"), "Gemini CLI", prosjekt: false);
        LesMcpFil(Utvid(@"%APPDATA%\Code - Insiders\User\mcp.json"), "VS Code Insiders", prosjekt: false);
        LesMcpFil(Utvid(@"%USERPROFILE%\.codeium\windsurf\mcp_config.json"), "Windsurf", prosjekt: false);
        LesMcpFil(Utvid(@"%USERPROFILE%\.lmstudio\mcp.json"), "LM Studio", prosjekt: false);
        LesMcpFil(Utvid(@"%USERPROFILE%\.mcp.json"), "Visual Studio", prosjekt: false);
        LesMcpFil(Utvid(@"%APPDATA%\Zed\settings.json"), "Zed", prosjekt: false);
        LesMcpFil(Utvid(@"%USERPROFILE%\.continue\config.json"), "Continue", prosjekt: false, tillatt: ContinueFil);
        // Utvidelser i VS Code og Cursor med egne MCP-lister (Cline, Roo Code)
        foreach (var editor in new[] { "Code", "Code - Insiders", "Cursor", "Windsurf" })
        {
            LesMcpFil(Utvid($@"%APPDATA%\{editor}\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json"), $"Cline ({editor})", prosjekt: false);
            LesMcpFil(Utvid($@"%APPDATA%\{editor}\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json"), $"Roo Code ({editor})", prosjekt: false);
        }
        // Claude Desktop fra Microsoft Store: oppsettet ligger i appens egen mappe
        foreach (var pakke in Mapper(Utvid(@"%LOCALAPPDATA%\Packages")).Where(d => Path.GetFileName(d).IndexOf("Claude", StringComparison.OrdinalIgnoreCase) >= 0))
            LesMcpFil(Path.Combine(pakke, "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"), "Claude Desktop (Microsoft Store)", prosjekt: false);
        var codex = Utvid(@"%USERPROFILE%\.codex\config.toml");
        if (LesToml(codex) is { } toml) VurderMcp(codex, "Codex", McpFraToml(toml), prosjekt: false);
    }

    // Continue kaller oppsettet bare config.json, så det navnet åpnes bare i .continue-mappa
    private static readonly ISet<string> ContinueFil = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "config.json" };

    private void LesMcpFil(string sti, string program, bool prosjekt, ISet<string>? tillatt = null)
    {
        using var doc = LesJson(sti, tillatt ?? Sporfiler);
        if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object) return;
        var r = doc.RootElement;
        var servere = new List<McpServer>();
        // Claude, Cursor, Gemini, .mcp.json: "mcpServers"; VS Code: "servers"; Zed: "context_servers"
        foreach (var nokkel in new[] { "mcpServers", "servers", "context_servers" })
            if (r.TryGetProperty(nokkel, out var s)) servere.AddRange(McpFraJson(s));
        // Continue (eldre oppsett): "experimental": { "modelContextProtocolServers": [ { "transport": {...} } ] }
        if (r.TryGetProperty("experimental", out var eks) && eks.ValueKind == JsonValueKind.Object
            && eks.TryGetProperty("modelContextProtocolServers", out var cs)) servere.AddRange(McpFraJson(cs));
        // .claude.json: også per prosjekt ("projects": { "C:\\sti": { "mcpServers": {...} } })
        if (r.TryGetProperty("projects", out var pr) && pr.ValueKind == JsonValueKind.Object)
            foreach (var p in pr.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty("mcpServers", out var ps))
                    servere.AddRange(McpFraJson(ps));
        VurderMcp(sti, program, servere, prosjekt);
    }

    private static IEnumerable<McpServer> McpFraJson(JsonElement s)
    {
        // Objekt med navn som nøkler, eller liste med "name" (Continue)
        IEnumerable<(string Navn, JsonElement Verdi)> servere = s.ValueKind switch
        {
            JsonValueKind.Object => s.EnumerateObject().Select(p => (p.Name, p.Value)),
            JsonValueKind.Array => s.EnumerateArray().Select((v, i) => (v.ValueKind == JsonValueKind.Object && v.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString()! : $"server {i + 1}", v)),
            _ => Enumerable.Empty<(string, JsonElement)>(),
        };
        foreach (var (navn, rå) in servere)
        {
            if (rå.ValueKind != JsonValueKind.Object) continue;
            // Continue legger kommandoen i "transport", Zed kan ha "command": { "path", "args" }
            var v = rå.TryGetProperty("transport", out var t) && t.ValueKind == JsonValueKind.Object ? t : rå;
            if (v.TryGetProperty("command", out var c) && c.ValueKind == JsonValueKind.Object) v = c;
            string? Tekst(string n) => v.TryGetProperty(n, out var x) && x.ValueKind == JsonValueKind.String ? x.GetString() : null;
            // Bare kommando og argumenter. "env" (der nøklene ligger) leses aldri.
            var args = v.TryGetProperty("args", out var a) && a.ValueKind == JsonValueKind.Array
                ? string.Join(" ", a.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()).Take(12))
                : null;
            yield return new McpServer(navn, Tekst("command") ?? Tekst("path"), args, Tekst("url") ?? Tekst("serverUrl") ?? Tekst("httpUrl"));
        }
    }

    /// <summary>Codex: [mcp_servers.navn] med command, args og url. Enkel linjeleser, bare de tre nøklene.</summary>
    internal static List<McpServer> McpFraToml(string[] linjer)
    {
        var liste = new List<McpServer>();
        string? navn = null, cmd = null, args = null, url = null;
        void Lagre() { if (navn != null) liste.Add(new McpServer(navn, cmd, args, url)); navn = cmd = args = url = null; }
        foreach (var rå in linjer)
        {
            var l = rå.Trim();
            if (l.StartsWith("["))
            {
                Lagre();
                var m = Regex.Match(l, @"^\[mcp_servers\.""?([^\]""]+)""?\]$");
                if (m.Success) navn = m.Groups[1].Value;
                continue;
            }
            if (navn == null) continue;
            var kv = Regex.Match(l, @"^(command|args|url)\s*=\s*(.+)$");
            if (!kv.Success) continue;
            var verdi = string.Join(" ", Regex.Matches(kv.Groups[2].Value, @"""([^""]*)""").Cast<Match>().Select(x => x.Groups[1].Value).Take(12));
            if (kv.Groups[1].Value == "command") cmd = verdi; else if (kv.Groups[1].Value == "args") args = verdi; else url = verdi;
        }
        Lagre();
        return liste;
    }

    private string[]? LesToml(string sti)
    {
        if (!Sporfiler.Contains(Path.GetFileName(sti))) return null;
        try
        {
            var info = new FileInfo(sti);
            if (!info.Exists) { Tilgangslogg.Logg("Fil", sti, Utfall.IkkeFunnet); return null; }
            if (info.Length > 1024 * 1024) { Tilgangslogg.Logg("Fil", sti, Utfall.HoppetOver, "større enn 1 MB"); return null; }
            var l = File.ReadAllLines(sti);
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest);
            return l;
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return null; }
    }

    private static readonly Regex InnebygdKode = new(@"\b(node|bun)(\.exe)?\s+(-e|--eval|-p|--print)\b|\bpython[0-9.]*(\.exe)?\s+-c\b|\bdeno(\.exe)?\s+eval\b|\b(powershell|pwsh)(\.exe)?\b.{0,40}\s-c(ommand)?\b.{0,300}(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex FarligKommando = new(@"-enc(odedcommand)?\b|\biex\b|invoke-expression|downloadstring|(curl|wget|irm|iwr|invoke-webrequest|invoke-restmethod)\b[^|]{0,300}\|\s*(sh|bash|iex|pwsh|powershell)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly CultureInfo NbKultur = new("nb-NO");

    private static string SporProsjekt(string sti)
    {
        var mappe = Path.GetDirectoryName(sti)?.TrimEnd('\\', '/') ?? "";
        var navn = Path.GetFileName(mappe);
        if (navn.StartsWith(".")) mappe = Path.GetDirectoryName(mappe) ?? mappe;
        return Path.GetFileName(mappe);
    }

    /// <summary>Hva en MCP-server gir agenten tilgang til, kjent igjen på navn, pakke og adresse. Bare kategorier, ikke innhold.</summary>
    private static readonly (Regex Monster, string Tilgang)[] McpTilganger =
    {
        (new(@"filesystem|\bfiles?\b|\bfs\b|everything", RegexOptions.IgnoreCase), "filer"),
        (new(@"shell|terminal|command|commander|\bexec|powershell|\bcmd\b|bash|ssh", RegexOptions.IgnoreCase), "kjører kommandoer"),
        (new(@"puppeteer|playwright|browser|chrome|selenium", RegexOptions.IgnoreCase), "styrer en nettleser"),
        (new(@"fetch|\bhttp|\bweb\b|search|tavily|\bexa\b|firecrawl|scrap", RegexOptions.IgnoreCase), "henter fra nettet"),
        (new(@"github|gitlab|bitbucket|\bgit\b", RegexOptions.IgnoreCase), "kode og Git"),
        (new(@"postgres|mysql|sqlite|mongo|redis|supabase|database|\bsql|snowflake|bigquery", RegexOptions.IgnoreCase), "databaser"),
        (new(@"gmail|outlook|slack|teams|discord|\bmail|e-?post|telegram|whatsapp", RegexOptions.IgnoreCase), "e-post og chat"),
        (new(@"\baws\b|azure|\bgcp\b|cloudflare|vercel|kubernetes|kubectl|docker|terraform", RegexOptions.IgnoreCase), "sky og drift"),
        (new(@"notion|confluence|jira|linear|asana|gdrive|google-?drive|sharepoint|onedrive|atlassian", RegexOptions.IgnoreCase), "dokumenter og saker"),
        (new(@"stripe|paypal|payment|betaling", RegexOptions.IgnoreCase), "betaling"),
        (new(@"memory|knowledge", RegexOptions.IgnoreCase), "minne for agenten"),
    };

    internal static List<string> McpTilgang(McpServer s)
    {
        var tekst = $"{s.Navn} {Path.GetFileName(s.Kommando ?? "")} {FørsteArgument(s.Argument)} {s.Url}";
        return McpTilganger.Where(t => t.Monster.IsMatch(tekst)).Select(t => t.Tilgang).Distinct().ToList();
    }

    private void VurderMcp(string sti, string program, List<McpServer> servere, bool prosjekt)
    {
        // MCP-servere IT har godkjent (navn eller vert på godkjentlista) er ikke ukjente
        servere = servere.Where(s => !_regler.GodkjentAi.Any(g => g.Equals(s.Navn, StringComparison.OrdinalIgnoreCase)
            || (s.Url != null && Uri.TryCreate(s.Url, UriKind.Absolute, out var u) && (u.Host.Equals(g, StringComparison.OrdinalIgnoreCase) || u.Host.EndsWith("." + g, StringComparison.OrdinalIgnoreCase))))).ToList();
        if (servere.Count == 0) return;
        var endret = Endret(sti);
        var navn = prosjekt ? $"MCP-servere i prosjekt: {SporProsjekt(sti)}" : $"MCP-servere: {program}";
        var f = Spor(navn, "AI-agenten har fått verktøy (MCP-servere) som kan lese filer, kjøre kommandoer eller koble seg til tjenester.", null);
        f.Tidspunkt(endret, endret);
        if (prosjekt) f.Advarsel("MCP-oppsett i en prosjektmappe: kan følge med kode fra andre og starte når prosjektet åpnes.");
        var kart = new Dictionary<string, int>();
        foreach (var s in servere.GroupBy(x => x.Navn).Select(g => g.First()))
        {
            var grunner = new List<string>();
            var hele = $"{s.Kommando} {s.Argument}";
            if (s.Kommando != null && Regex.IsMatch(s.Kommando, @"\\(Temp|Downloads|Nedlastinger)\\|\\ProgramData\\|/tmp/", RegexOptions.IgnoreCase)) grunner.Add("starter et program fra Temp, Nedlastinger eller ProgramData");
            if (FarligKommando.IsMatch(hele)) grunner.Add("starter PowerShell eller laster ned og kjører kode");
            if (InnebygdKode.IsMatch(hele)) grunner.Add("kjører kode skrevet rett i oppsettet (node -e, python -c)");
            string? vert = null;
            if (s.Url != null && Uri.TryCreate(s.Url, UriKind.Absolute, out var u))
            {
                vert = u.Host;
                if (!KjenteMcpVerter.Any(k => vert.Equals(k, StringComparison.OrdinalIgnoreCase) || vert.EndsWith("." + k, StringComparison.OrdinalIgnoreCase)))
                    grunner.Add($"kobler til en ukjent tjeneste ({vert})");
            }
            if (DaarligVersjon(hele) is { } d) grunner.Add($"pakkeversjon på lista over kjente dårlige versjoner: {d}");
            if (prosjekt) grunner.Add("ligger i en prosjektmappe");
            if (grunner.Count > 0) f.Advarsel($"MCP-server «{s.Navn}» {grunner[0]}.");
            var hva = s.Url != null ? $"fjern: {vert ?? s.Url}" : Kutt($"{Path.GetFileName(s.Kommando ?? "")} {FørsteArgument(s.Argument)}".Trim(), 90);
            var tilgang = McpTilgang(s);
            foreach (var t in tilgang) kart[t] = kart.TryGetValue(t, out var n) ? n + 1 : 1;
            f.Detalj($"Fil: {sti} · MCP-server «{s.Navn}» · {hva}{(tilgang.Count > 0 ? $" · tilgang: {string.Join(", ", tilgang)}" : "")}{(endret != null ? " · endret " + Nar(endret.Value, "endringstid på fil") : "")}");
        }
        if (kart.Count > 0) f.ErstattDetalj($"Tilgangskart for {program}:", $"Tilgangskart for {program}: {string.Join(", ", kart.OrderByDescending(x => x.Value).Select(x => $"{x.Key} ({x.Value})"))}");
        f.Bruk = $"{servere.Count} MCP-server{(servere.Count == 1 ? "" : "e")} i {program}.";
        f.Merk(Tilstand.SattOpp);
    }

    // Pakkenavnet (første argument som ikke er et flagg), aldri resten: kan inneholde stier eller tokens
    internal static string FørsteArgument(string? args)
    {
        if (string.IsNullOrEmpty(args)) return "";
        // Etter -enc, -c, -Command, -e og --eval kommer kode, ikke et pakkenavn: vises aldri
        var deler = args!.Split(' ').Where(x => x.Length > 0).ToArray();
        for (int i = 0; i < deler.Length; i++)
        {
            if (deler[i].StartsWith("-")) continue;
            if (i > 0 && Regex.IsMatch(deler[i - 1], @"^-(enc(odedcommand)?|e|c|command|-eval)$", RegexOptions.IgnoreCase)) return "[kode skjult]";
            var ord = deler[i];
            return NokkelMonster.IsMatch(ord) || ord.Length > 80 ? "[skjult]" : ord;
        }
        return "";
    }

    // ---------- P1: «Godkjenn alt» ----------

    private void GodkjennAltBruker()
    {
        foreach (var sti in new[] { Utvid(@"%USERPROFILE%\.claude\settings.json"), Utvid(@"%USERPROFILE%\.claude\settings.local.json") })
            ClaudeInnstillinger(sti, prosjekt: false);
        foreach (var (sti, program) in new[] { (Utvid(@"%APPDATA%\Code\User\settings.json"), "VS Code"), (Utvid(@"%APPDATA%\Cursor\User\settings.json"), "Cursor") })
            EditorInnstillinger(sti, program, prosjekt: false);
        var codex = Utvid(@"%USERPROFILE%\.codex\config.toml");
        if (LesToml(codex) is { } toml)
        {
            var funn = new List<string>();
            foreach (var l in toml.Select(x => x.Trim()))
            {
                if (Regex.IsMatch(l, @"^approval_policy\s*=\s*""never""")) funn.Add("approval_policy = never (spør aldri før kommandoer)");
                if (Regex.IsMatch(l, @"^sandbox_mode\s*=\s*""danger-full-access""")) funn.Add("sandbox_mode = danger-full-access (ingen sandkasse)");
            }
            GodkjennAlt(codex, "Codex", funn, prosjekt: false);
        }
    }

    private void ClaudeInnstillinger(string sti, bool prosjekt)
    {
        using var doc = LesJson(sti, Sporfiler);
        if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object) return;
        var funn = new List<string>();
        if (doc.RootElement.TryGetProperty("permissions", out var p) && p.ValueKind == JsonValueKind.Object)
        {
            if (p.TryGetProperty("defaultMode", out var dm) && dm.ValueKind == JsonValueKind.String && dm.GetString() == "bypassPermissions")
                funn.Add("defaultMode = bypassPermissions (spør aldri)");
            if (p.TryGetProperty("allow", out var al) && al.ValueKind == JsonValueKind.Array)
                foreach (var a in al.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!))
                    if (a is "Bash" or "Bash(*)" or "Bash(*:*)" or "*" or "PowerShell" or "PowerShell(*)") funn.Add($"tillater {a} uten å spørre");
        }
        GodkjennAlt(sti, "Claude Code", funn, prosjekt);
        ClaudeMisbruk(doc.RootElement, sti);
    }

    private void EditorInnstillinger(string sti, string program, bool prosjekt)
    {
        using var doc = LesJson(sti, Sporfiler);
        if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object) return;
        var funn = new List<string>();
        foreach (var n in new[] { "chat.tools.autoApprove", "chat.tools.global.autoApprove" })
            if (doc.RootElement.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True) funn.Add($"{n} = true (CVE-2025-53773)");
        GodkjennAlt(sti, program, funn, prosjekt);
    }

    private void GodkjennAlt(string sti, string program, List<string> funn, bool prosjekt)
    {
        if (funn.Count == 0) return;
        var endret = Endret(sti);
        var f = Spor($"Godkjenn alt: {program}",
            "AI-agenten kan kjøre kommandoer og endre filer uten å spørre.", null);
        f.Tidspunkt(endret, endret);
        if (prosjekt) f.Advarsel("«Godkjenn alt» er slått på i en prosjektmappe: gjelder alle som åpner prosjektet.");
        foreach (var x in funn.Distinct())
            f.Detalj($"Fil: {sti} · {x}{(endret != null ? " · endret " + Nar(endret.Value, "endringstid på fil") : "")}");
    }

    /// <summary>Kalles fra filgjennomgangen: er dette et AI-oppsett i en prosjektmappe?</summary>
    private void SjekkProsjektOppsett(FileInfo fil)
    {
        var navn = fil.Name;
        var forelder = fil.Directory?.Name ?? "";
        bool aktuell = navn.Equals(".mcp.json", StringComparison.OrdinalIgnoreCase)
            || (forelder is ".vscode" or ".cursor" && (navn.Equals("mcp.json", StringComparison.OrdinalIgnoreCase) || navn.Equals("settings.json", StringComparison.OrdinalIgnoreCase)))
            || (forelder == ".claude" && navn.StartsWith("settings", StringComparison.OrdinalIgnoreCase) && navn.EndsWith(".json", StringComparison.OrdinalIgnoreCase));
        if (!aktuell) return;
        // Brukerens egne filer (%USERPROFILE%\.claude, \.cursor) sjekkes av sporsjekken selv
        var hjem = Utvid("%USERPROFILE%").TrimEnd('\\', '/');
        var mappe = forelder.StartsWith(".") ? fil.Directory?.Parent?.FullName : fil.DirectoryName;
        if (mappe == null || mappe.TrimEnd('\\', '/').Equals(hjem, StringComparison.OrdinalIgnoreCase)) return;
        _prosjektOppsett.Add(fil.FullName);
    }

    /// <summary>Prosjektfilene filgjennomgangen fant. Kjøres etter gjennomgangen.</summary>
    private void ProsjektOppsett()
    {
        var forrige = Tilgangslogg.Sjekk.Value;
        Tilgangslogg.Sjekk.Value = "Ser etter ukjente AI-spor";
        try
        {
            foreach (var sti in _prosjektOppsett.Distinct(StringComparer.OrdinalIgnoreCase).Take(200))
            {
                var navn = Path.GetFileName(sti);
                var forelder = Path.GetFileName(Path.GetDirectoryName(sti) ?? "");
                if (navn.Equals(".mcp.json", StringComparison.OrdinalIgnoreCase) || navn.Equals("mcp.json", StringComparison.OrdinalIgnoreCase))
                    LesMcpFil(sti, forelder == ".cursor" ? "Cursor" : forelder == ".vscode" ? "VS Code" : "Claude Code", prosjekt: true);
                else if (forelder == ".claude") ClaudeInnstillinger(sti, prosjekt: true);
                else EditorInnstillinger(sti, forelder == ".cursor" ? "Cursor" : "VS Code", prosjekt: true);
            }
            MisbrukEtterGjennomgang();
        }
        finally { Tilgangslogg.Sjekk.Value = forrige; }
    }

    // ---------- P1: lokale AI-servere brukt fra andre maskiner ----------

    // [GIN] 2025/10/26 - 09:12:33 | 200 |  1.2345ms |   192.168.1.20 | POST     "/api/generate"
    internal static readonly Regex GinLinje = new(@"\[GIN\]\s+(\d{4}/\d{2}/\d{2}\s+-\s+\d{2}:\d{2}:\d{2})\s*\|\s*(\d{3})\s*\|[^|]*\|\s*([0-9A-Fa-f:.]+)\s*\|\s*([A-Z]+)\s+""([^""?]+)", RegexOptions.Compiled);
    private static readonly Regex Ipv4 = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);

    private void Serverlogger()
    {
        // Ollama: server.log, server-1.log ...
        var ollama = Utvid(@"%LOCALAPPDATA%\Ollama");
        var klienter = new Dictionary<string, (int Antall, DateTime? Forst, DateTime? Sist, bool Farlig)>();
        foreach (var fil in Filer(ollama).Where(x => Regex.IsMatch(Path.GetFileName(x), @"^server(-\d+)?\.log$", RegexOptions.IgnoreCase)).Take(10))
            LesLinjer(fil, 50, l =>
            {
                var m = GinLinje.Match(l);
                if (!m.Success || !IPAddress.TryParse(m.Groups[3].Value, out var ip) || IPAddress.IsLoopback(ip)) return;
                var ende = m.Groups[5].Value;
                bool farlig = ende.StartsWith("/api/generate") || ende.StartsWith("/api/chat") || ende.StartsWith("/v1/") || ende.StartsWith("/api/pull") || ende.StartsWith("/api/create");
                DateTime? t = DateTime.TryParseExact(m.Groups[1].Value.Replace("  ", " "), "yyyy/MM/dd - HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var tt) ? tt.ToLocalTime() : null;
                var k = ip.ToString();
                klienter.TryGetValue(k, out var x);
                klienter[k] = (x.Antall + 1, x.Forst == null || t < x.Forst ? t ?? x.Forst : x.Forst, x.Sist == null || t > x.Sist ? t ?? x.Sist : x.Sist, x.Farlig || farlig);
            });
        if (klienter.Count > 0)
        {
            var farlig = klienter.Any(k => k.Value.Farlig);
            var f = Spor("Ollama brukt fra andre maskiner",
                "Den lokale AI-serveren har svart på forespørsler fra andre adresser enn denne PC-en.", null);
            if (farlig) f.Advarsel("Andre maskiner har kjørt AI-modellen eller lastet ned modeller via Ollama.");
            foreach (var (ip, x) in klienter.OrderByDescending(k => k.Value.Antall).Take(20))
            {
                f.Tidspunkt(x.Forst, x.Sist);
                var land = IPAddress.TryParse(ip, out var a) ? IpLand.Navn(IpLand.Finn(a)) : null;
                f.Detalj($"Fil: {Path.Combine(ollama, "server.log")} · klient {ip}{(land != null ? $" ({land})" : "")} · {x.Antall} forespørsler · første {(x.Forst is { } fo ? Nar(fo, "tid i logglinje") : "ukjent")} · sist {(x.Sist is { } si ? Nar(si, "tid i logglinje") : "ukjent")}");
            }
            f.Bruk = $"{klienter.Count} andre adresse{(klienter.Count == 1 ? "" : "r")} i Ollama-loggen.";
            f.Merk(Tilstand.BruktFor);
        }

        // LM Studio: formatet er ikke bekreftet. Teller IPv4-adresser som ikke er denne PC-en.
        var lm = Utvid(@"%USERPROFILE%\.lmstudio\server-logs");
        var andre = new Dictionary<string, int>();
        DateTime? sistEndret = null;
        foreach (var fil in Plattform.Filer(lm, "*", 3).OrderByDescending(x => x.LastWriteTime).Take(10))
        {
            if (sistEndret == null || fil.LastWriteTime > sistEndret) sistEndret = fil.LastWriteTime;
            LesLinjer(fil.FullName, 50, l =>
            {
                foreach (Match m in Ipv4.Matches(l))
                    if (IPAddress.TryParse(m.Value, out var ip) && !IPAddress.IsLoopback(ip) && m.Value != "0.0.0.0")
                        andre[m.Value] = andre.TryGetValue(m.Value, out var n) ? n + 1 : 1;
            });
        }
        if (andre.Count > 0)
        {
            var f = Spor("LM Studio-server: andre adresser i loggen", "Serverloggen til LM Studio nevner andre adresser enn denne PC-en.", null);
            f.Tidspunkt(sistEndret, sistEndret);
            foreach (var (ip, n) in andre.OrderByDescending(x => x.Value).Take(20))
                f.Detalj($"Fil: {lm} · adresse {ip} · {n} linjer · sist endret {(sistEndret is { } s ? Nar(s, "endringstid på fil") : "ukjent")}");
        }
    }

    /// <summary>Leser en fil linje for linje (uten å holde den i minnet), med størrelsesgrense i MB.</summary>
    private static void LesLinjer(string sti, int maksMB, Action<string> linje, Func<bool>? stopp = null)
    {
        try
        {
            var info = new FileInfo(sti);
            if (!info.Exists) { Tilgangslogg.Logg("Fil", sti, Utfall.IkkeFunnet); return; }
            if (info.Length > maksMB * 1024L * 1024) { Tilgangslogg.Logg("Fil", sti, Utfall.HoppetOver, $"større enn {maksMB} MB"); return; }
            using var fs = Admintilgang.AapneLes(sti);
            using var r = new StreamReader(fs, Encoding.UTF8);
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest, "bare tider, antall og adresser; innhold lagres ikke");
            string? l;
            while ((l = r.ReadLine()) != null)
            {
                linje(l);
                if (stopp?.Invoke() == true) { Tilgangslogg.Logg("Fil", sti, Utfall.Tidsgrense, "tidsgrensen for agentøkter er nådd"); break; }
            }
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); }
    }

    // ---------- P2: agentøkter, bare metadata ----------

    private static readonly (string Navn, Regex Monster)[] Oktkategorier =
    {
        ("leste nøkler", new Regex(@"[\\/]\.ssh[\\/]|[\\/]\.aws[\\/]|\.env\b|\.npmrc|id_rsa|id_ed25519|wallet|auth\.json|credentials\.json", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("hentet tokens", new Regex(@"gh auth token|npm whoami|gh auth status|az account get-access-token|gcloud auth print-access-token", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("lastet ned og kjørte", new Regex(@"(curl|wget)[^|""]{0,200}\|\s*(sh|bash)\b|(irm|iwr|invoke-webrequest|invoke-restmethod)[^|""]{0,200}\|\s*iex\b|-encodedcommand\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("slettet mye", new Regex(@"rm\s+-rf\s+(~|/|\$home|c:)|remove-item[^""]{0,120}-recurse[^""]{0,120}(\$home|c:\\\\|~)", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        ("opprettet GitHub-repo", new Regex(@"gh repo create|api\.github\.com/user/repos", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
    };

    private static readonly Regex Tidsfelt = new(@"""timestamp""\s*:\s*""(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)""", RegexOptions.Compiled);
    private static readonly Regex Menneske = new(@"""(type|role)""\s*:\s*""user""", RegexOptions.Compiled);
    private static readonly Regex Verktoysvar = new(@"tool_result|function_call_output|""toolUseResult""", RegexOptions.Compiled);

    private sealed class Okt
    {
        public DateTime? Forst, Sist;
        public int Menneske;
        public readonly int[] Treff = new int[Oktkategorier.Length];
    }

    private void Agentokter()
    {
        if (!MedAgentlogger) { Tilgangslogg.Logg("Fil", "agentøkter", Utfall.HoppetOver, "slått av av IT (--uten-agentlogger)"); return; }
        var klokke = Stopwatch.StartNew();
        bool Stopp() => klokke.Elapsed > TimeSpan.FromSeconds(Fullt ? 600 : 20);
        var kilder = new (string Program, string Mappe, string Monster, int Dybde)[]
        {
            ("Claude Code", Utvid(@"%USERPROFILE%\.claude\projects"), "*.jsonl", 2),
            ("Codex", Utvid(@"%USERPROFILE%\.codex\sessions"), "rollout-*.jsonl", 4),
            ("Gemini CLI", Utvid(@"%USERPROFILE%\.gemini\tmp"), "*.json", 3),
            ("GitHub Copilot", Utvid(@"%APPDATA%\Code\User\workspaceStorage"), "*.json", 3),
        };
        var hodelose = new List<(string Program, DateTime Start)>();
        foreach (var (program, mappe, monster, dybde) in kilder)
        {
            var okter = new List<Okt>();
            var filer = Plattform.Filer(mappe, monster, dybde).Where(x => program != "GitHub Copilot" || x.Directory?.Name == "chatSessions");
            foreach (var fil in filer.OrderByDescending(x => x.LastWriteTime).Take(500))
            {
                if (Stopp()) { Tilgangslogg.EnGang("agent-20", "Fil", fil.FullName, Utfall.Tidsgrense, Fullt ? "10 minutter brukt på agentøkter; resten ble ikke lest" : "20 sekunder brukt på agentøkter; resten ble ikke lest"); break; }
                var o = new Okt();
                LesLinjer(fil.FullName, 50, l =>
                {
                    // Bare tider, antall og om en kategori traff. Teksten i linja beholdes aldri.
                    foreach (Match t in Tidsfelt.Matches(l))
                        if (DateTime.TryParse(t.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var tid))
                        {
                            var lokal = tid.ToLocalTime();
                            if (o.Forst == null || lokal < o.Forst) o.Forst = lokal;
                            if (o.Sist == null || lokal > o.Sist) o.Sist = lokal;
                        }
                    if (Menneske.IsMatch(l) && !Verktoysvar.IsMatch(l)) o.Menneske++;   // én per linje: "type" og "role" står ofte begge
                    for (int i = 0; i < Oktkategorier.Length; i++)
                        if (Oktkategorier[i].Monster.IsMatch(l)) o.Treff[i]++;
                }, Stopp);
                o.Forst ??= fil.LastWriteTime;
                o.Sist ??= fil.LastWriteTime;
                okter.Add(o);
            }
            if (okter.Count == 0) continue;
            hodelose.AddRange(okter.Where(o => o.Menneske <= 1 && o.Forst != null).Select(o => (program, o.Forst!.Value)));
            var utenMenneske = okter.Count(o => o.Menneske <= 1);
            var medTreff = okter.Where(o => o.Treff.Any(t => t > 0)).ToList();
            // Rødt: en økt uten menneske som leste nøkler, hentet tokens, lastet ned og kjørte eller slettet mye
            bool rod = okter.Any(o => o.Menneske <= 1 && o.Treff.Take(4).Any(t => t > 0));
            // Bare økter med treff er spor. Korte økter med én melding er vanlig bruk og vises allerede som AI-app.
            if (medTreff.Count == 0) continue;
            var f = Spor($"Agentøkter: {program}",
                "Loggene til AI-agenten viser økter uten menneske, eller at agenten har vært borti nøkler, tokens, nedlasting og kjøring av kode eller sletting. Bare tider og antall er lest, ikke hva som ble skrevet.", null);
            if (rod) f.Advarsel("En agentøkt uten menneske har lest nøkler, hentet tokens, lastet ned og kjørt kode eller slettet mye.");
            f.Tidspunkt(okter.Min(o => o.Forst), okter.Max(o => o.Sist));
            f.Bruk = $"{okter.Count} økter, {utenMenneske} uten menneske etter første melding.";
            f.Merk(Tilstand.BruktFor);
            for (int i = 0; i < Oktkategorier.Length; i++)
            {
                var med = okter.Where(o => o.Treff[i] > 0).ToList();
                if (med.Count == 0) continue;
                f.Detalj($"{Oktkategorier[i].Navn}: {med.Count} økter, {med.Sum(o => o.Treff[i])} treff · sist {Nar(med.Max(o => o.Sist!.Value), "tid i logglinje")}");
            }
            f.Detalj($"Fil: {mappe} · økter: {okter.Count} · uten menneske: {utenMenneske} · første {Nar(okter.Min(o => o.Forst!.Value), "tid i logglinje")} · sist {Nar(okter.Max(o => o.Sist!.Value), "tid i logglinje")}");
        }
        // Flere agenter startet uten menneske innen samme minutt: mønster fra misbruk der én agent starter andre
        var klynger = hodelose.GroupBy(x => new DateTime(x.Start.Year, x.Start.Month, x.Start.Day, x.Start.Hour, x.Start.Minute, 0))
            .Where(g => g.Count() >= 3 && g.Select(x => x.Program).Distinct().Count() >= 2).OrderByDescending(g => g.Key).ToList();
        if (klynger.Count > 0)
        {
            var f = Spor("Flere AI-agenter startet samtidig uten menneske",
                "Økter i flere ulike AI-agenter startet innen samme minutt, uten at et menneske skrev noe etter første melding. Det er et kjent mønster når én agent starter andre.", null);
            f.Advarsel("Flere AI-agenter startet uten menneske innen samme minutt.");
            foreach (var g in klynger.Take(10))
            {
                f.Tidspunkt(g.Key, g.Key);
                f.Detalj($"{Nar(g.Key, "tid i logglinje")} · {g.Count()} økter · {string.Join(", ", g.Select(x => x.Program).Distinct())}");
            }
        }
    }

    // ---------- P2: skript som snakker med AI-API-er med nøkkel ----------

    private void SkriptMedAi()
    {
        var mapper = new List<(string Sti, int Dybde)>
        {
            (Utvid(@"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), 0),
            (Utvid(@"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"), 0),
            (Utvid(@"%TEMP%"), 0),
            (Utvid(@"%ProgramData%"), 1),
        };
        var endelser = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".vbs", ".js", ".ps1", ".py", ".bat", ".cmd" };
        foreach (var (mappe, dybde) in mapper)
        {
            if (mappe.Contains('%')) continue;
            foreach (var fil in Plattform.Filer(mappe, "*", dybde).Where(x => endelser.Contains(x.Extension)).Take(2000))
            {
                long lengde;
                try { lengde = fil.Length; } catch { continue; }
                if (lengde > 1024 * 1024) { Tilgangslogg.Tell("Fil", Utfall.HoppetOver, sted: fil.FullName, detalj: "større enn 1 MB"); continue; }
                string tekst;
                try
                {
                    using var fs = Admintilgang.AapneLes(fil.FullName);
                    using var r = new StreamReader(fs);
                    tekst = r.ReadToEnd();
                    Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName);
                }
                catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); continue; }
                var vert = AiApiVerter.FirstOrDefault(v => tekst.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0);
                bool nokkel = NokkelMonster.IsMatch(tekst);
                tekst = "";
                if (vert == null || !nokkel) continue;
                var f = Spor("Skript som bruker AI med nøkkel", "Et skript i en oppstarts- eller midlertidig mappe snakker med en AI-tjeneste og har en API-nøkkel i seg.", null);
                f.Advarsel("Skript med AI-nøkkel i oppstart, Temp eller ProgramData. Ukjent hvem som la det der.");
                f.Tidspunkt(fil.CreationTime, fil.LastWriteTime);
                f.Detalj($"Fil: {fil.FullName} · snakker med {vert.TrimStart(':')} · har nøkkel (vises ikke) · opprettet {Nar(fil.CreationTime, "opprettelsestid på fil")} · endret {Nar(fil.LastWriteTime, "endringstid på fil")}");
            }
        }
    }

    // ---------- P3: kjente dårlige pakkeversjoner ----------

    private string? DaarligVersjon(string tekst)
    {
        foreach (var d in _regler.DaarligeVersjoner)
            foreach (var v in d.Versjoner)
            {
                // navn@versjon (package.json, lockfil) eller npm-tarball i logg: /nx/-/nx-21.5.0.tgz
                var kort = d.Navn.Substring(d.Navn.LastIndexOf('/') + 1);
                // "*": alle versjoner (navnetyveri som claud-code)
                if (v == "*")
                {
                    if (Regex.IsMatch(tekst, $@"(?<![\w\-/.@]){Regex.Escape(d.Navn)}@\d|/{Regex.Escape(d.Navn)}/-/", RegexOptions.IgnoreCase)) return d.Navn;
                    continue;
                }
                if (Regex.IsMatch(tekst, $@"(?<![\w\-/.@]){Regex.Escape(d.Navn)}@{Regex.Escape(v)}(?![\w.\-])|/{Regex.Escape(d.Navn)}/-/{Regex.Escape(kort)}-{Regex.Escape(v)}\.tgz", RegexOptions.IgnoreCase))
                    return $"{d.Navn} {v}";
            }
        return null;
    }

    private void DaarligePakker()
    {
        if (_regler.DaarligeVersjoner.Count == 0) return;
        var treff = new List<string>();
        DateTime? sist = null;
        // Globale npm-pakker
        var npm = Utvid(@"%APPDATA%\npm\node_modules");
        foreach (var dir in Mapper(npm).SelectMany(d => Path.GetFileName(d).StartsWith("@") ? Mapper(d) : new[] { d }).Take(500))
        {
            var pakke = Path.Combine(dir, "package.json");
            if (!File.Exists(pakke)) continue;
            using var doc = LesJson(pakke, Sporfiler);
            if (doc == null || doc.RootElement.ValueKind != JsonValueKind.Object) continue;
            string? S(string n) => doc.RootElement.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            if (S("name") is { } navn && S("version") is { } ver && DaarligVersjon($"{navn}@{ver}") is { } d)
            {
                var t = Endret(pakke);
                if (t > sist || sist == null) sist = t;
                treff.Add($"Fil: {pakke} · {d} · installert {(t != null ? Nar(t.Value, "endringstid på fil") : "ukjent")}");
            }
        }
        // npm-logger: de 10 siste, tid fra filnavnet (2025-08-27T10_11_12_123Z-debug-0.log)
        var logger = Utvid(@"%LOCALAPPDATA%\npm-cache\_logs");
        foreach (var fil in Filer(logger).Where(x => x.EndsWith(".log", StringComparison.OrdinalIgnoreCase)).OrderByDescending(x => x, StringComparer.Ordinal).Take(10))
        {
            string? d = null;
            LesLinjer(fil, 20, l => d ??= DaarligVersjon(l));
            if (d == null) continue;
            var m = Regex.Match(Path.GetFileName(fil), @"^(\d{4}-\d{2}-\d{2})T(\d{2})_(\d{2})_(\d{2})");
            DateTime? t = m.Success && DateTime.TryParse($"{m.Groups[1].Value}T{m.Groups[2].Value}:{m.Groups[3].Value}:{m.Groups[4].Value}Z", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var tt) ? tt.ToLocalTime() : Endret(fil);
            if (t > sist || sist == null) sist = t;
            treff.Add($"Fil: {fil} · npm installerte {d} · {(t != null ? Nar(t.Value, m.Success ? "tid i filnavn" : "endringstid på fil") : "ukjent tid")}");
        }
        // VS Code-utvidelser: mappenavn utgiver.navn-versjon
        foreach (var dir in Mapper(Utvid(@"%USERPROFILE%\.vscode\extensions")).Concat(Mapper(Utvid(@"%USERPROFILE%\.cursor\extensions"))))
        {
            var m = Regex.Match(Path.GetFileName(dir), @"^(.+)-(\d+\.\d+\.\d+)(-[a-z0-9-]+)?$", RegexOptions.IgnoreCase);
            if (m.Success && DaarligVersjon($"{m.Groups[1].Value}@{m.Groups[2].Value}") is { } d)
            {
                var t = Endret(dir);
                treff.Add($"Fil: {dir} · utvidelse {d}{(t != null ? " · " + Nar(t.Value, "endringstid på mappe") : "")}");
            }
        }
        if (treff.Count == 0) return;
        var f = Spor("Pakker på lista over kjente dårlige versjoner", "En pakke eller utvidelse i en versjon som står på lista over kjente dårlige versjoner i regler.json.", null);
        f.Advarsel("En versjon fra lista over kjente dårlige versjoner er eller har vært installert.");
        f.Tidspunkt(sist, sist);
        foreach (var t in treff) f.Detalj(t);
    }
}

/// <summary>
/// Leser kjøretider fra en Prefetch-fil (C:\Windows\Prefetch\*.pf). Windows 10 og 11 komprimerer dem (MAM, Xpress Huffman),
/// som pakkes ut med RtlDecompressBufferEx i ntdll. Bare navnet på programmet og de siste kjøretidene leses.
/// </summary>
public static class Prefetch
{
    public sealed record Resultat(string Exe, List<DateTime> Tider);

    [DllImport("ntdll.dll")] private static extern uint RtlGetCompressionWorkSpaceSize(ushort format, out uint arbeid, out uint fragment);
    [DllImport("ntdll.dll")] private static extern uint RtlDecompressBufferEx(ushort format, byte[] ut, int utLengde, byte[] inn, int innLengde, out int lengde, byte[] arbeid);
    private const ushort XpressHuff = 4;

    public static Resultat? Les(string sti)
    {
        try
        {
            var info = new FileInfo(sti);
            if (info.Length > 4 * 1024 * 1024) { Tilgangslogg.Logg("Fil", sti, Utfall.HoppetOver, "større enn 4 MB"); return null; }
            var b = File.ReadAllBytes(sti);
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest, "bare programnavn og kjøretider");
            var ut = Pakkut(b);
            return ut == null ? null : Tolk(ut);
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return null; }
    }

    /// <summary>Windows 10 og 11 pakker Prefetch-filer (MAM, Xpress Huffman). Ukomprimerte filer gis tilbake som de er.</summary>
    public static byte[]? Pakkut(byte[] b)
    {
        if (b.Length < 8) return null;
        if (b[0] != 'M' || b[1] != 'A' || b[2] != 'M') return b;
        int lengde = BitConverter.ToInt32(b, 4);
        if (lengde <= 0 || lengde > 16 * 1024 * 1024) return null;
        if (RtlGetCompressionWorkSpaceSize(XpressHuff, out var arbeid, out _) != 0) return null;
        var ut = new byte[lengde];
        var inn = new byte[b.Length - 8];
        Buffer.BlockCopy(b, 8, inn, 0, inn.Length);
        return RtlDecompressBufferEx(XpressHuff, ut, ut.Length, inn, inn.Length, out var fikk, new byte[arbeid]) == 0 && fikk > 0 ? ut : null;
    }

    /// <summary>Filene programmet åpnet de første sekundene (seksjonen med filnavn: forskyvning 0x64, lengde 0x68).</summary>
    public static List<string> Filer(byte[] b)
    {
        var liste = new List<string>();
        if (b.Length < 0x6C) return liste;
        int off = BitConverter.ToInt32(b, 0x64), len = BitConverter.ToInt32(b, 0x68);
        if (off <= 0 || len <= 0 || off + len > b.Length) return liste;
        foreach (var s in Encoding.Unicode.GetString(b, off, len).Split('\0')) if (s.Length > 0) liste.Add(s);
        return liste;
    }

    /// <summary>Ukomprimert Prefetch: versjon (0), "SCCA" (4), programnavn UTF-16 (0x10, 60 byte), kjøretider (0x80, 8 × FILETIME).</summary>
    public static Resultat? Tolk(byte[] b)
    {
        if (b.Length < 0x80 + 64 || b[4] != 'S' || b[5] != 'C' || b[6] != 'C' || b[7] != 'A') return null;
        int versjon = BitConverter.ToInt32(b, 0);
        var exe = Encoding.Unicode.GetString(b, 0x10, 60).Split('\0')[0];
        var tider = new List<DateTime>();
        int antall = versjon >= 26 ? 8 : 1;
        int start = versjon >= 26 ? 0x80 : 0x78;
        for (int i = 0; i < antall; i++)
        {
            long ft = BitConverter.ToInt64(b, start + i * 8);
            if (ft > 0) try { tider.Add(DateTime.FromFileTime(ft)); } catch { }
        }
        return new Resultat(exe, tider.OrderByDescending(t => t).ToList());
    }
}
