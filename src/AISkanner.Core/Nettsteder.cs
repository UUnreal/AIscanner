using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Finner AI-nettsteder som er brukt i nettleserne, uten å lese historikken.
/// Kilder (bare nettstedsnavn, aldri hele adresser, sideinnhold eller innlogging):
///  - Chromium: nettleserens egen bruksscore per nettsted (site_engagement i Preferences)
///  - Chromium: hvilke nettsteder som har lagret data lokalt (mappenavn under IndexedDB)
///  - Firefox: hvilke nettsteder som har lagret data lokalt (mappenavn under storage\default)
///  - Snarveier til installerte nettapper i Start-menyen (f.eks. "ChatGPT" under "Chrome Apps")
/// </summary>
public sealed partial class Skanner
{
    private static readonly System.Globalization.CultureInfo Norsk = new("nb-NO");

    private sealed class Brukspor
    {
        public double Score;
        public DateTime? Sist;
        public bool LagretData;
        public bool App;
        public int Besok;
        /// <summary>Nettleser, profil og nettstedsnavn, f.eks. "Chrome (Default): chatgpt.com". Aldri hele adresser.</summary>
        public readonly SortedSet<string> Steder = new();
        public long Lagret;
        public readonly SortedSet<string> Nettlesere = new();
    }

    private void Nettsteder()
    {
        var spor = new Dictionary<AiNettsted, Brukspor>();
        Brukspor For(AiNettsted n) => spor.TryGetValue(n, out var s) ? s : spor[n] = new Brukspor();

        foreach (var (nettleser, rotSti) in Chromium)
        {
            foreach (var profil in Mapper(Utvid(rotSti)))
            {
                // 1. Bruksscore per nettsted
                using (var doc = LesJson(Path.Combine(profil, "Preferences")))
                {
                    if (doc != null && Sti(doc.RootElement, "profile", "content_settings", "exceptions", "site_engagement") is { ValueKind: JsonValueKind.Object } eng)
                    {
                        foreach (var p in eng.EnumerateObject())
                        {
                            var vert = VertFraOpprinnelse(p.Name);
                            var n = FinnNettsted(vert);
                            if (n == null) continue;
                            var s = For(n);
                            s.Nettlesere.Add(nettleser);
                            s.Steder.Add($"{nettleser} ({Path.GetFileName(profil)}): {vert}");
                            if (p.Value.TryGetProperty("setting", out var set) && set.ValueKind == JsonValueKind.Object)
                            {
                                if (set.TryGetProperty("rawScore", out var rs) && rs.TryGetDouble(out var score)) s.Score = Math.Max(s.Score, score);
                                if (set.TryGetProperty("lastEngagementTime", out var lt) && lt.TryGetDouble(out var mikro) && mikro > 0)
                                {
                                    var tid = ChromeTid(mikro);
                                    if (tid != null && (s.Sist == null || tid > s.Sist)) s.Sist = tid;
                                }
                            }
                        }
                    }
                }

                // 2. Nettsteder som har lagret data (bare mappenavn, f.eks. https_chatgpt.com_0.indexeddb.leveldb)
                foreach (var d in Mapper(Path.Combine(profil, "IndexedDB")))
                {
                    var navn = Path.GetFileName(d);
                    var m = Regex.Match(navn, @"^https?_(.+?)_\d+\.indexeddb");
                    if (!m.Success) continue;
                    var n = FinnNettsted(m.Groups[1].Value);
                    if (n == null) continue;
                    var s = For(n);
                    s.LagretData = true;
                    s.Lagret += MappeStorrelse(d);
                    s.Nettlesere.Add(nettleser);
                    s.Steder.Add($"{nettleser} ({Path.GetFileName(profil)}): {m.Groups[1].Value}");
                    var endret = Directory.GetLastWriteTime(d);
                    if (s.Sist == null || endret > s.Sist) s.Sist = endret;
                }
            }
        }

        // Firefox: storage\default\https+++chatgpt.com
        foreach (var profil in Mapper(Utvid(@"%APPDATA%\Mozilla\Firefox\Profiles")))
        {
            foreach (var d in Mapper(Path.Combine(profil, "storage", "default")))
            {
                var m = Regex.Match(Path.GetFileName(d), @"^https?\+\+\+([^+^]+)");
                if (!m.Success) continue;
                var n = FinnNettsted(m.Groups[1].Value);
                if (n == null) continue;
                var s = For(n);
                s.LagretData = true;
                s.Lagret += MappeStorrelse(d);
                s.Nettlesere.Add("Firefox");
                s.Steder.Add($"Firefox ({Path.GetFileName(profil)}): {m.Groups[1].Value}");
                var endret = Directory.GetLastWriteTime(d);
                if (s.Sist == null || endret > s.Sist) s.Sist = endret;
            }
        }

        // Installerte nettapper (Start-meny-snarveier fra Chrome/Edge, f.eks. "ChatGPT.lnk")
        foreach (var meny in new[] { @"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Chrome Apps", @"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Edge Apps" })
        {
            var sti = Utvid(meny);
            if (!Directory.Exists(sti)) continue;
            foreach (var lnk in Plattform.Filer(sti, "*.lnk", 3))
            {
                var tittel = Path.GetFileNameWithoutExtension(lnk.Name);
                var n = _regler.AiNettsteder.FirstOrDefault(x => AppOrd(x).Any(o => tittel.Inneholder(o)));
                if (n == null) continue;
                var s = For(n);
                s.App = true;
                s.Nettlesere.Add(meny.Contains("Edge") ? "Edge" : "Chrome");
                s.Steder.Add($"Nettapp: {lnk.FullName}");
            }
        }

        var ukjente = new Dictionary<string, (int Besok, SortedSet<string> Nettlesere)>(StringComparer.OrdinalIgnoreCase);
        var ukjenteSteder = new Dictionary<string, SortedSet<string>>(StringComparer.OrdinalIgnoreCase);
        if (_historikk) Historikk(For, ukjente, ukjenteSteder);

        foreach (var (vert, (besok, nettlesere)) in ukjente.Where(u => u.Value.Besok >= 2).OrderByDescending(u => u.Value.Besok).Take(10))
        {
            var f = LeggTil($"Ukjent AI-nettsted: {vert}", "Nettleser-AI (nettsted)", Risiko.Rod,
                "Ser ut som en AI-tjeneste vi ikke kjenner. Vi vet ikke hvem som står bak eller hvor dataene havner.",
                string.Join(", ", nettlesere), null, enkelt: "Ukjent AI-nettsted", rad: "Ikke lim inn noe viktig før du vet hvem som står bak.");
            f.Bruk = $"Besøkt {besok} ganger i {string.Join(", ", nettlesere)}.";
            f.Privat = true;
            if (ukjenteSteder.TryGetValue(vert, out var st)) foreach (var x in st) f.Detalj(x);
        }

        foreach (var (n, s) in spor)
        {
            // Et nettsted med lav score og uten lagrede data er bare besøkt i forbifarten
            if (!s.LagretData && !s.App && s.Score < 1 && s.Besok < 2) continue;
            var hvor = string.Join(", ", s.Nettlesere);
            var f = LeggTil(n.Navn, "Nettleser-AI (nettsted)", RisikoTekst.Fra(n.Risiko), n.Hvorfor, hvor, null, enkelt: n.Enkelt, rad: n.Rad);
            f.Privat = true;
            var hyppighet = s.App ? "Installert som app" : s.Score >= 15 || s.Besok >= 30 ? "Brukes ofte" : s.Score >= 3 || s.Besok >= 5 ? "Brukes av og til" : "Er brukt";
            if (s.Lagret > 300L * 1024 * 1024)
                f.Advarsel($"Nettstedet har lagret {Gb(s.Lagret)} i nettleseren. Det kan være en AI-modell som kjører i nettleseren.");
            f.Bruk = $"{hyppighet} i {hvor}{(s.Sist is { } t ? ", sist " + t.ToString("d. MMMM", Norsk) : "")}.";
            foreach (var x in s.Steder) f.Detalj(x);
        }
    }

    // ---------- Nettleserhistorikk: leses bare i minnet, bare vertsnavn beholdes, ingenting lagres ----------
    private static readonly Regex AiLignende = new(@"(^|\.)[a-z0-9-]+\.ai$|(^|\.)[a-z0-9-]*(gpt|llm|chatbot)[a-z0-9-]*\.", RegexOptions.IgnoreCase);

    private void Historikk(Func<AiNettsted, Brukspor> forNettsted, Dictionary<string, (int Besok, SortedSet<string> Nettlesere)> ukjente,
                           Dictionary<string, SortedSet<string>> ukjenteSteder)
    {
        var grense = DateTime.UtcNow.AddDays(-90);
        void Tell(string nettleser, string profil, string? url, long antall, DateTime? sist)
        {
            if (url == null || !Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http")) return;
            var vert = u.Host.StartsWith("www.") ? u.Host.Substring(4) : u.Host;
            var n = FinnNettsted(vert);
            if (n != null)
            {
                var s = forNettsted(n);
                s.Besok += (int)Math.Min(antall, 100_000);
                s.Nettlesere.Add(nettleser);
                s.Steder.Add($"{nettleser} ({profil}), historikk: {vert}");
                if (sist != null && (s.Sist == null || sist > s.Sist)) s.Sist = sist;
            }
            else if (AiLignende.IsMatch(vert))
            {
                ukjente.TryGetValue(vert, out var e);
                e.Nettlesere ??= new SortedSet<string>();
                e.Nettlesere.Add(nettleser);
                ukjente[vert] = (e.Besok + (int)Math.Min(antall, 100_000), e.Nettlesere);
                if (!ukjenteSteder.TryGetValue(vert, out var st)) ukjenteSteder[vert] = st = new SortedSet<string>();
                st.Add($"{nettleser} ({profil}), historikk: {vert}");
            }
        }

        long chromeGrense = (grense.ToFileTimeUtc()) / 10;
        foreach (var (nettleser, rotSti) in Chromium)
            foreach (var profil in Mapper(Utvid(rotSti)))
                LesSqlite(Path.Combine(profil, "History"),
                    "SELECT url, visit_count, last_visit_time FROM urls WHERE last_visit_time > $g", chromeGrense,
                    r => Tell(nettleser, Path.GetFileName(profil), r.Tekst(0), r.Tall(1), ChromeTid(r.Tall(2))));

        long firefoxGrense = new DateTimeOffset(grense).ToUnixTimeMilliseconds() * 1000;
        foreach (var profil in Mapper(Utvid(@"%APPDATA%\Mozilla\Firefox\Profiles")))
            LesSqlite(Path.Combine(profil, "places.sqlite"),
                "SELECT url, visit_count, last_visit_date FROM moz_places WHERE last_visit_date > $g", firefoxGrense,
                r => Tell("Firefox", Path.GetFileName(profil), r.Tekst(0), r.Tall(1), DateTimeOffset.FromUnixTimeMilliseconds(r.Tall(2) / 1000).LocalDateTime));
    }

    private static void LesSqlite(string sti, string sql, long grense, Action<WinSqlite.IRad> rad)
    {
        if (!LovligeFiler.Contains(Path.GetFileName(sti)) || !File.Exists(sti)) return;
        try
        {
            using var db = new WinSqlite(sti);
            db.Les(sql, grense, r => { try { if (!r.ErTom(0)) rad(r); } catch { } });
        }
        catch (Exception e) { Debug.WriteLine($"Kunne ikke lese {Path.GetFileName(sti)}: {e.Message}"); }
    }

    /// <summary>Ord som kjennetegner en nettapp: første del av domenet, f.eks. "chatgpt", "gemini", "deepseek".</summary>
    private static IEnumerable<string> AppOrd(AiNettsted n) =>
        n.Domener.Select(d => d.Split('.').FirstOrDefault(del => del is not ("chat" or "www" or "console" or "platform")) ?? "")
                 .Where(o => o.Length >= 4).Distinct();

    private AiNettsted? FinnNettsted(string? vert)
    {
        if (string.IsNullOrEmpty(vert)) return null;
        vert = vert.ToLowerInvariant().TrimEnd('.');
        if (vert.StartsWith("www.")) vert = vert.Substring(4);
        return _regler.AiNettsteder.FirstOrDefault(n => n.Domener.Any(d => vert == d || vert.EndsWith("." + d)));
    }

    /// <summary>"https://chatgpt.com:443,*" blir "chatgpt.com".</summary>
    private static string? VertFraOpprinnelse(string s)
    {
        var del = s.Split(',')[0];
        return Uri.TryCreate(del, UriKind.Absolute, out var u) ? u.Host : null;
    }

    /// <summary>Chrome lagrer tid som mikrosekunder siden 1601.</summary>
    private static DateTime? ChromeTid(double mikro)
    {
        try { return DateTime.FromFileTimeUtc((long)mikro * 10).ToLocalTime(); } catch { return null; }
    }

    private static JsonElement? Sti(JsonElement e, params string[] deler)
    {
        foreach (var d in deler)
        {
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(d, out e)) return null;
        }
        return e;
    }
}
