using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Det korte svaret for oversikten: hvor AI-en ligger, og det viktigste om den på høyst tre ord.
/// Samme tekst på skjermen og i rapporten, så IT, ledere og CISO ser det samme.
/// </summary>
public static class Oversikt
{
    private static readonly Regex StiMonster = new(@"(?:[A-Za-z]:\\|/)[^:*?""<>|()]+[^:*?""<>|()\s]", RegexOptions.Compiled);

    /// <summary>Det viktigste om funnet, høyst tre ord. Det farligste vinner.</summary>
    public static string Punkt(Funn f)
    {
        var detaljer = f.Detaljer;
        if (f.Gruppe == "spor") return SporPunkt(f.Navn);
        if (f.Navn.StartsWith("Farlig AI-modellfil", StringComparison.Ordinal)) return "Skjult kode";
        if (f.Navn.StartsWith("AI slått på manuelt", StringComparison.Ordinal)) return "Slått på manuelt";

        // Sender til et land der dataene ikke bør havne
        var farlig = f.Advarsler.Select(a => Regex.Match(a, @"^Sender data til (?:et selskap i )?(.+?) \(")).FirstOrDefault(m => m.Success);
        if (farlig != null) return Kort("Sender til " + farlig.Groups[1].Value, "Sender data ut");

        if (detaljer.Any(d => d.StartsWith("Utgiver: ukjent", StringComparison.Ordinal))) return "Ukjent utgiver";
        if (f.Navn.StartsWith("Ukjent", StringComparison.Ordinal)) return "Ukjent modell";
        if (detaljer.Any(d => d.StartsWith("Utgiver:", StringComparison.Ordinal) && d.Contains("ikke bekreftet"))) return "Utgiver ikke bekreftet";

        // Sender nå: landet selskapet hører hjemme i, ellers der serveren står
        var mal = f.Trafikk.FirstOrDefault(m => m.EierLand != null) ?? f.Trafikk.FirstOrDefault(m => m.Land is not null and not "LAN" and not "CDN");
        if (mal != null) return Kort("Sender til " + IpLand.Navn(mal.EierLand ?? mal.Land), "Sender data ut");
        if (f.Trafikk.Count > 0) return "Sender data ut";
        if (f.Land != null) return Kort("Data til " + IpLand.Navn(f.Land), "Sender data ut");

        if (detaljer.Any(d => d.StartsWith("AI-API:", StringComparison.Ordinal) && Regex.IsMatch(d, @"· (på|slått på)"))) return "AI-API åpent";
        if (detaljer.Any(d => d.StartsWith("Familie ukjent", StringComparison.Ordinal))) return "Ukjent modell";
        if (f.Merknader.Any(m => m.Contains(" i Kina."))) return "Laget i Kina";

        var utgiver = detaljer.FirstOrDefault(d => d.StartsWith("Utgiver:", StringComparison.Ordinal));
        if (utgiver != null) return Kort("Fra " + Forsteord(utgiver.Substring(8)), "Kjent utgiver");

        var gjenkjent = detaljer.FirstOrDefault(d => d.StartsWith("Gjenkjent som:", StringComparison.Ordinal));
        if (gjenkjent != null)
        {
            var navn = gjenkjent.Substring(14).Trim();
            navn = Regex.Split(navn, @"[,(:]| eller | bygget ")[0].Trim();
            var ord = navn.Split(' ');
            return ord.Length > 3 ? string.Join(" ", ord.Take(2)) : Kort(navn, "Kjent modell");
        }

        if (f.Sist != null && (DateTime.Now - f.Sist.Value).TotalMinutes < 2) return "Kjører nå";
        return f.Kategori switch
        {
            var k when k.StartsWith("Skygge-AI (agent)") => "AI-agent",
            var k when k.StartsWith("Skygge-AI (utvikling)") => "AI i kode",
            var k when k.StartsWith("Skygge-AI (nettleserflagg)") => "Slått på manuelt",
            var k when k.StartsWith("Skygge-AI") && f.Hvor.Any(h => h.Contains("kodeeditor")) => "AI i kodeeditor",
            var k when k.StartsWith("Skygge-AI") => "Skygge-AI",
            var k when k.StartsWith("Lokal") => "Kjører lokalt",
            var k when k.Contains("(nettsted)") => "Brukt i nettleser",
            var k when k.StartsWith("Nettleser") => "Nettleserutvidelse",
            _ => "Innebygd AI",
        };
    }

    /// <summary>
    /// Hva som er funnet, telt opp: AI-modeller, AI-nettsteder, nettleserutvidelser, AI-apper/agenter uten egne modeller,
    /// og programmer med AI som leverandøren har bygget inn. AI-modeller er bare modeller som kan kjøres for seg selv
    /// (modellfiler på disk, farlige modellfiler, språkmodellen i nettleseren og ukjente modellfiler). Små modeller inne i
    /// Office, Teams, Bilder, drivere og nettleserfunksjoner telles ikke som AI-modeller, men som ett program hver.
    /// </summary>
    public static (int Modeller, int Nettsteder, int Utvidelser, int Apper, int Innebygd) Telling(IEnumerable<Funn> funn)
    {
        int modeller = 0, nettsteder = 0, utvidelser = 0, apper = 0, innebygd = 0;
        foreach (var f in funn)
        {
            if (f.Type == "IT-regel" || f.Gruppe == "spor") continue;
            if (f.Modeller > 0) { modeller += f.Modeller; continue; }
            if (f.Type is "AI-nettsted" or "Ukjent AI-nettsted" || f.Kategori.Contains("(nettsted)"))
                nettsteder += Regex.Match(f.Navn, @"\((\d+)\)$") is { Success: true } m ? int.Parse(m.Groups[1].Value) : 1;
            else if (f.Type == "Nettleserutvidelse") utvidelser++;
            else if (f.Innebygde > 0 || f.Kategori.StartsWith("Innebygd AI fra leverandør", StringComparison.Ordinal)) innebygd++;
            else apper++;
        }
        return (modeller, nettsteder, utvidelser, apper, innebygd);
    }

    /// <summary>Navnene på de lokale AI-modellene, så det står hva de er når det bare er én eller to.</summary>
    public static List<string> ModellNavn(IEnumerable<Funn> funn) =>
        funn.Where(f => f.Modeller > 0 && f.Type != "IT-regel" && f.Gruppe != "spor").Select(Navn).Distinct().ToList();

    /// <summary>Tellingen som tekst, som på skjermen: alle AI-funn, og hva de er.</summary>
    public static string TellingTekst(IEnumerable<Funn> funn)
    {
        var (m, n, u, a, i) = Telling(funn);
        int s = funn.Count(f => f.Gruppe == "spor");
        var deler = new List<string>();
        var navn = ModellNavn(funn);
        var hvilke = navn.Count is > 0 and <= 2 ? $" ({string.Join(", ", navn)})" : "";
        if (m > 0) deler.Add((m == 1 ? "1 lokal AI-modell" : $"{m} lokale AI-modeller") + hvilke);
        if (n > 0) deler.Add(n == 1 ? "1 AI-nettsted" : $"{n} AI-nettsteder");
        if (u > 0) deler.Add(u == 1 ? "1 nettleserutvidelse" : $"{u} nettleserutvidelser");
        if (a > 0) deler.Add(a == 1 ? "1 AI-app eller agent" : $"{a} AI-apper og agenter");
        if (i > 0) deler.Add(i == 1 ? "1 program med innebygd AI" : $"{i} programmer med innebygd AI");
        if (s > 0) deler.Add(s == 1 ? "1 ukjent AI-spor" : $"{s} ukjente AI-spor");
        int sum = m + n + u + a + i + s;
        if (sum == 0) return "Ingen AI";
        var hode = sum == 1 ? "1 AI-funn" : $"{sum} AI-funn";
        return deler.Count == 1 ? hode : $"{hode}: " + string.Join(", ", deler.Take(deler.Count - 1)) + " og " + deler.Last();
    }

    /// <summary>Navnet uten forklarende forstavelse: "AI-modell: Llama" blir "Llama".</summary>
    public static string Navn(Funn f)
    {
        foreach (var fs in new[] { "AI-modell: ", "Farlig AI-modellfil: ", "Python-prosjekt med AI: " })
            if (f.Navn.StartsWith(fs, StringComparison.Ordinal)) return f.Navn.Substring(fs.Length);
        return Regex.Replace(f.Navn, @" \([A-Za-z ]+-utvidelse\)$", "");
    }

    /// <summary>Hvor på PC-en AI-en ligger, kort: "Chrome", "Nedlastinger", "Program Files\Lenovo".</summary>
    private static string SporPunkt(string navn) => navn switch
    {
        var n when n.StartsWith("MCP-servere") => "Verktøy for AI-agent",
        var n when n.StartsWith("Godkjenn alt") => "Spør aldri",
        var n when n.StartsWith("Ollama-modeller fra ukjent") => "Ukjent register",
        var n when n.StartsWith("Ollama") || n.StartsWith("LM Studio") || n.StartsWith("AI-server brukt") => "Brukt fra andre maskiner",
        var n when n.StartsWith("Hooks") || n.StartsWith("Oppgave som starter") => "Kjører av seg selv",
        var n when n.StartsWith("Agent-oppsett med .env") => "Agent-.env i prosjekt",
        var n when n.StartsWith("Skript i agentmappe") => "Skript i agentmappe",
        var n when n.StartsWith("Ferdighet") => "Laster ned kode",
        var n when n.StartsWith("Skjulte tegn") => "Skjulte tegn",
        var n when n.StartsWith("Snarveier") => "Lenke til agentoppsett",
        var n when n.StartsWith("Fjernkode") || n.StartsWith("Modellkode") => "Fjernkode",
        var n when n.StartsWith("AI-agent startes") => "Farlige flagg",
        var n when n.StartsWith("Flere AI-agenter") => "Agenter uten menneske",
        var n when n.StartsWith("Domener kjent") => "Kjent domene",
        var n when n.StartsWith("Filer kjent") => "Kjent filnavn",
        var n when n.StartsWith("Utvidelse som kan lese") => "Leser AI-samtaler",
        var n when n.StartsWith("MCP-verktøy med skjulte") => "Skjulte beskjeder",
        var n when n.StartsWith("Modellfil som egentlig") => "Skjult modell",
        var n when n.StartsWith("Python-pakker") => "Kjent dårlig versjon",
        var n when n.StartsWith("Ukjent program") => "Ukjent program",
        var n when n.StartsWith("Agentøkter") => "Nøkler eller kode i økt",
        var n when n.StartsWith("Skript") => "Skript med AI-nøkkel",
        var n when n.StartsWith("Pakker") => "Kjent dårlig versjon",
        var n when n.StartsWith("Fil med kjent navn") => "Kjent filnavn",
        var n when n.StartsWith("Når AI-programmer") => "Sist kjørt",
        _ => "Ukjent AI-spor",
    };

    public static string Lokasjon(Funn f)
    {
        foreach (var d in f.Detaljer)
        {
            if (d.StartsWith("Utgiver:") || d.StartsWith("Gjenkjent") || d.StartsWith("Familie") || d.StartsWith("YARA") || d.StartsWith("AI-API")) continue;
            var m = StiMonster.Match(d.Split(new[] { " · " }, StringSplitOptions.None)[0]);
            if (!m.Success) continue;
            var erFil = d.StartsWith("Fil:") || d.StartsWith("Program:") || d.StartsWith("Kommando:");
            return KortSti(m.Value, erFil);
        }
        foreach (var h in f.Hvor)
        {
            var nl = Nettleser(h);
            if (nl != null) return nl;
        }
        foreach (var d in f.Detaljer)
        {
            var nl = Nettleser(d);
            if (nl != null) return nl;
            if (d.StartsWith("Register") || d.StartsWith("HKEY") || d.StartsWith("HKCU") || d.StartsWith("HKLM")) return "Registeret";
            if (d.StartsWith("Windows har nylig")) return "Nettverk";
        }
        if (f.Hvor.Any(h => h.StartsWith("Register"))) return "Registeret";
        if (f.Trafikk.Count > 0) return "Nettverk";
        return f.Gruppe == "nettleser" ? "Nettleser" : f.Hvor.FirstOrDefault() is { } hv && hv.Length <= 24 ? hv : "PC-en";
    }

    private static string? Nettleser(string s)
    {
        foreach (var n in new[] { "Edge Dev", "Edge Beta", "Edge Canary", "Chrome Beta", "Chrome Dev", "Chrome Canary", "Chrome", "Edge", "Firefox", "Brave", "Opera", "Vivaldi" })
            if (s.StartsWith(n, StringComparison.OrdinalIgnoreCase)) return n;
        return null;
    }

    private static readonly (string Ord, string Navn)[] Nettlesermapper =
    {
        (@"\Microsoft\Edge Dev\", "Edge Dev"), (@"\Microsoft\Edge Beta\", "Edge Beta"), (@"\Microsoft\Edge SxS\", "Edge Canary"), (@"\Microsoft\Edge\", "Edge"),
        (@"\Google\Chrome Beta\", "Chrome Beta"), (@"\Google\Chrome Dev\", "Chrome Dev"), (@"\Google\Chrome SxS\", "Chrome Canary"), (@"\Google\Chrome\", "Chrome"),
        (@"\Mozilla\Firefox\", "Firefox"), (@"\BraveSoftware\", "Brave"), (@"\Opera Software\", "Opera"), (@"\Vivaldi\", "Vivaldi"),
    };

    private static readonly Dictionary<string, string> Kjente = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Downloads"] = "Nedlastinger", ["Documents"] = "Dokumenter", ["Desktop"] = "Skrivebord", ["Pictures"] = "Bilder",
        ["Videos"] = "Videoer", ["Music"] = "Musikk", ["OneDrive"] = "OneDrive",
    };

    /// <summary>To mapper inn fra et kjent sted, uten brukernavn og versjonsnummer.</summary>
    public static string KortSti(string sti, bool erFil)
    {
        var s = sti.Replace('/', '\\');
        foreach (var (ord, navn) in Nettlesermapper)
            if (s.IndexOf(ord, StringComparison.OrdinalIgnoreCase) >= 0) return navn;

        if (s.IndexOf(@"\Start Menu\", StringComparison.OrdinalIgnoreCase) >= 0)
            return s.IndexOf("Chrome Apps", StringComparison.OrdinalIgnoreCase) >= 0 ? "Chrome" : s.IndexOf("Edge", StringComparison.OrdinalIgnoreCase) >= 0 ? "Edge" : "Startmenyen";
        var deler = s.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        if (erFil && deler.Count > 1) deler.RemoveAt(deler.Count - 1);
        if (deler.Count > 0 && deler[0].EndsWith(":")) deler.RemoveAt(0);

        // Kjente rotmapper (AppData, ProgramData, Program Files), så hjemmemappen: alt etter Users\<navn>
        int start = 0;
        foreach (var (variabel, navn) in Rotter)
        {
            var h = Deler(Environment.GetEnvironmentVariable(variabel));
            if (h.Count == 0 || deler.Count <= h.Count || !h.Select((x, i) => string.Equals(x, deler[i], StringComparison.OrdinalIgnoreCase)).All(x => x)) continue;
            deler = new[] { navn }.Concat(deler.Skip(h.Count).Where(x => !x.Equals("Programs", StringComparison.OrdinalIgnoreCase))).ToList();
            break;
        }
        if (deler.Count == 0) return "PC-en";
        if (deler[0] is not ("AppData" or "ProgramData" or "Program Files" or "Program Files (x86)"))
        {
            var h = Deler(Hjem());
            if (h.Count > 0 && deler.Count >= h.Count && h.Select((x, i) => string.Equals(x, deler[i], StringComparison.OrdinalIgnoreCase)).All(x => x))
                start = h.Count;
        }
        if (start == 0)
        {
            int u = deler.FindIndex(x => x.Equals("Users", StringComparison.OrdinalIgnoreCase));
            if (u >= 0 && u + 1 < deler.Count) start = u + 2;
        }
        deler = deler.Skip(start).ToList();
        if (deler.Count == 0) return "Hjemmemappen";

        // AppData\Local\X -> AppData\X
        if (deler.Count >= 3 && deler[0].Equals("AppData", StringComparison.OrdinalIgnoreCase) && deler[1] is "Local" or "Roaming" or "LocalLow") deler.RemoveAt(1);
        if (deler.Count >= 3 && deler[0].Equals("AppData", StringComparison.OrdinalIgnoreCase) && deler[1].Equals("Programs", StringComparison.OrdinalIgnoreCase)) deler.RemoveAt(1);
        // Program Files\WindowsApps\Microsoft.Paint_11.2_x64__8wekyb3d8bbwe -> WindowsApps\Microsoft.Paint
        int w = deler.FindIndex(x => x.Equals("WindowsApps", StringComparison.OrdinalIgnoreCase) || x.Equals("SystemApps", StringComparison.OrdinalIgnoreCase));
        if (w >= 0)
        {
            deler = deler.Skip(w).Take(2).ToList();
            if (deler.Count == 2) deler[1] = Regex.Replace(deler[1], @"_[\d.]+_.*$|_[a-z0-9]{13}$", "");
        }
        if (Kjente.TryGetValue(deler[0], out var norsk)) deler[0] = norsk;
        // Én mappe er nok når den er velkjent (Nedlastinger), ellers to (Program Files\Lenovo)
        int antall = Kjente.ContainsValue(deler[0]) && deler.Count > 1 && deler[0] != "OneDrive" ? 1 : 2;
        if (deler[0].StartsWith(".") && deler.Count > 1) antall = 2;
        return string.Join("\\", deler.Take(antall));
    }

    private static readonly (string Variabel, string Navn)[] Rotter =
    {
        ("LOCALAPPDATA", "AppData"), ("APPDATA", "AppData"), ("ProgramData", "ProgramData"),
        ("ProgramFiles(x86)", "Program Files (x86)"), ("ProgramW6432", "Program Files"), ("ProgramFiles", "Program Files"),
    };

    private static List<string> Deler(string? sti) =>
        string.IsNullOrEmpty(sti) ? new List<string>() : sti!.Replace('/', '\\').Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries).Where(x => !x.EndsWith(":")).ToList();

    private static string? Hjem()
    {
        var h = Environment.GetEnvironmentVariable("USERPROFILE");
        return string.IsNullOrEmpty(h) ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) : h;
    }

    private static string Forsteord(string s)
    {
        s = s.Split(new[] { " · " }, StringSplitOptions.None)[0].Trim();
        var ord = s.Split(' ');
        return ord.Length > 1 && Regex.IsMatch(ord[1], @"^(Corporation|Corp\.?|Inc\.?|Ltd\.?|AS|ASA|LLC|GmbH|Co\.?|Limited|Technologies|Software)$", RegexOptions.IgnoreCase) ? ord[0] : string.Join(" ", ord.Take(2));
    }

    /// <summary>Høyst tre ord, ellers reserven.</summary>
    private static string Kort(string s, string reserve) => s.Split(' ').Length <= 3 && s.Length <= 26 ? s : reserve;
}
