using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Finner AI-nettsteder som er brukt i nettleserne, med tidspunkt for første og siste bruk.
/// Kilder (bare nettstedsnavn, aldri hele adresser, sideinnhold eller innlogging):
///  - Chromium: nettleserens egen bruksscore per nettsted (site_engagement i Preferences)
///  - Chromium: hvilke nettsteder som har lagret data lokalt (mappenavn under IndexedDB)
///  - Firefox: hvilke nettsteder som har lagret data lokalt (mappenavn under storage\default)
///  - Snarveier til installerte nettapper i Start-menyen (f.eks. "ChatGPT" under "Chrome Apps")
///  - Historikken, hvis bryteren er på (leses i minnet, bare vertsnavn beholdes)
/// </summary>
public sealed partial class Skanner
{
    private static readonly System.Globalization.CultureInfo Norsk = new("nb-NO");

    /// <summary>Spor etter ett nettsted på ett sted (nettleser, profil og kilde).</summary>
    private sealed class Sted
    {
        public DateTime? Forst, Sist;
        public long Besok, Lagret;
    }

    private sealed class Brukspor
    {
        public double Score;
        public DateTime? Forst, Sist;
        public bool LagretData;
        public bool App;
        public long Besok;
        public long Lagret;
        public readonly SortedSet<string> Nettlesere = new();
        /// <summary>Nøkkel: nettleser, profil og nettstedsnavn, f.eks. "Chrome (Default), historikk: chatgpt.com". Aldri hele adresser.</summary>
        public readonly SortedDictionary<string, Sted> Steder = new();

        public void Merk(string nettleser, string sted, DateTime? sist, DateTime? forst = null, long besok = 0, long lagret = 0)
        {
            Nettlesere.Add(nettleser);
            if (!Steder.TryGetValue(sted, out var s)) Steder[sted] = s = new Sted();
            s.Besok += besok;
            s.Lagret += lagret;
            Besok += besok;
            Lagret += lagret;
            forst ??= sist;
            if (sist != null && (s.Sist == null || sist > s.Sist)) s.Sist = sist;
            if (forst != null && (s.Forst == null || forst < s.Forst)) s.Forst = forst;
            if (sist != null && (Sist == null || sist > Sist)) Sist = sist;
            if (forst != null && (Forst == null || forst < Forst)) Forst = forst;
        }

        public IEnumerable<string> Linjer() => Steder.Select(x =>
        {
            var deler = new List<string> { x.Key };
            if (x.Value.Besok > 0) deler.Add($"{x.Value.Besok} besøk");
            if (x.Value.Lagret > 1024 * 1024) deler.Add($"lagret {Rapport.Storrelse(x.Value.Lagret)}");
            if (x.Value.Forst != null && x.Value.Sist != null && x.Value.Forst.Value.Date != x.Value.Sist.Value.Date) deler.Add($"første {Tid(x.Value.Forst)}");
            if (x.Value.Sist != null) deler.Add($"sist {Tid(x.Value.Sist)}");
            return string.Join(" · ", deler);
        });
    }

    /// <summary>"26. okt. 2026 kl. 09:12"</summary>
    public static string Tid(DateTime? t) => t == null ? "" : t.Value.ToString("d. MMM yyyy 'kl.' HH:mm", Norsk);

    private void Nettsteder()
    {
        var spor = new Dictionary<AiNettsted, Brukspor>();
        Brukspor For(AiNettsted n) => spor.TryGetValue(n, out var s) ? s : spor[n] = new Brukspor();

        foreach (var (nettleser, rotSti) in Chromium)
        {
            foreach (var profil in Mapper(Utvid(rotSti)))
            {
                var hvor = $"{nettleser} ({Path.GetFileName(profil)})";
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
                            DateTime? tid = null;
                            if (p.Value.TryGetProperty("setting", out var set) && set.ValueKind == JsonValueKind.Object)
                            {
                                if (set.TryGetProperty("rawScore", out var rs) && rs.TryGetDouble(out var score)) s.Score = Math.Max(s.Score, score);
                                if (set.TryGetProperty("lastEngagementTime", out var lt) && lt.TryGetDouble(out var mikro) && mikro > 0) tid = ChromeTid(mikro);
                            }
                            s.Merk(nettleser, $"{hvor}, i bruk: {vert}", tid);
                        }
                    }
                }

                // 2. Nettsteder som har lagret data (bare mappenavn, f.eks. https_chatgpt.com_0.indexeddb.leveldb)
                foreach (var d in Mapper(Path.Combine(profil, "IndexedDB")))
                {
                    var m = Regex.Match(Path.GetFileName(d), @"^https?_(.+?)_\d+\.indexeddb");
                    if (!m.Success) continue;
                    var n = FinnNettsted(m.Groups[1].Value);
                    if (n == null) continue;
                    var s = For(n);
                    s.LagretData = true;
                    s.Merk(nettleser, $"{hvor}, lagret data: {m.Groups[1].Value}", Directory.GetLastWriteTime(d), Directory.GetCreationTime(d), lagret: MappeStorrelse(d));
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
                s.Merk("Firefox", $"Firefox ({Path.GetFileName(profil)}), lagret data: {m.Groups[1].Value}", Directory.GetLastWriteTime(d), Directory.GetCreationTime(d), lagret: MappeStorrelse(d));
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
                s.Merk(meny.Contains("Edge") ? "Edge" : "Chrome", $"Nettapp: {lnk.FullName}", lnk.LastWriteTime, lnk.CreationTime);
            }
        }

        var ukjente = new Dictionary<string, Brukspor>(StringComparer.OrdinalIgnoreCase);
        if (_historikk) Historikk(For, ukjente);

        // Nettsteder som bare ser ut som AI (.ai-adresse eller "gpt" i navnet). Det er en gjetning, så de står som «Mulig
        // AI-nettsted» og telles som ukjent. Ett nettsted er én rad, så tallene øverst er like mange som radene.
        var mulige = ukjente.Where(u => u.Value.Besok >= 2).OrderByDescending(u => u.Value.Besok).Take(40).ToList();
        foreach (var (vert, sp) in mulige)
        {
            var hvorM = string.Join(", ", sp.Nettlesere);
            var f = LeggTil($"Mulig AI-nettsted: {vert}", "Nettleser-AI (nettsted)", Risiko.Gul,
                "Adressen ser ut som AI (.ai eller «gpt» i navnet), men tjenesten er ikke på listen over kjente AI-tjenester. Kan være AI, kan være noe annet.",
                hvorM, null, enkelt: "Mulig AI-nettsted",
                rad: "Ikke lim inn noe viktig på sider du ikke vet hvem som står bak.");
            f.Bruk = $"Besøkt i {hvorM}{(sp.Sist is { } t ? ", sist " + Tid(t) : "")}.";
            f.Privat = true;
            f.Tidspunkt(sp.Forst, sp.Sist);
            foreach (var x in sp.Linjer()) f.Detalj(x);
        }

        foreach (var (n, s) in spor)
        {
            // Et nettsted med lav score og uten merkbare lagrede data er bare besøkt i forbifarten. Små lagrede data
            // (under 1 MB) er vanligvis statistikk eller innloggingsstatus fra ett besøk, ikke spor etter bruk av AI.
            bool merkbarData = s.LagretData && s.Lagret >= 1024 * 1024;
            if (!merkbarData && !s.App && s.Score < 1 && s.Besok < 2) continue;
            var hvor = string.Join(", ", s.Nettlesere);
            var f = LeggTil(n.Navn, "Nettleser-AI (nettsted)", RisikoTekst.Fra(n.Risiko), n.Hvorfor, hvor, null, enkelt: n.Enkelt, rad: n.Rad);
            f.Privat = true;
            f.Land ??= n.Land;
            f.OpprinnelseLand ??= n.Land;
            f.Tidspunkt(s.Forst, s.Sist);
            var hyppighet = s.App ? "Installert som app" : s.Score >= 15 || s.Besok >= 30 ? "Brukes ofte" : s.Score >= 3 || s.Besok >= 5 ? "Brukes av og til" : "Er brukt";
            if (s.Lagret > 300L * 1024 * 1024)
                f.Advarsel($"Nettstedet har lagret {Gb(s.Lagret)} i nettleseren. Det kan være en AI-modell som kjører i nettleseren.");
            f.Bruk = $"{hyppighet} i {hvor}{(s.Sist is { } t ? ", sist " + Tid(t) : "")}.";
            foreach (var x in s.Linjer()) f.Detalj(x);
        }
    }

    // ---------- Nettleserhistorikk: leses bare i minnet, bare vertsnavn beholdes, ingenting lagres ----------
    private static readonly Regex AiLignende = new(@"(^|\.)[a-z0-9-]+\.ai$|(^|\.)[a-z0-9-]*(gpt|llm|chatbot)[a-z0-9-]*\.", RegexOptions.IgnoreCase);

    private void Historikk(Func<AiNettsted, Brukspor> forNettsted, Dictionary<string, Brukspor> ukjente)
    {
        var grense = DateTime.UtcNow.AddDays(-90);
        void Tell(string nettleser, string profil, string? url, long antall, DateTime? sist, DateTime? forst)
        {
            if (url == null || !Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != "https" && u.Scheme != "http")) return;
            var vert = u.Host.StartsWith("www.") ? u.Host.Substring(4) : u.Host;
            antall = Math.Min(antall, 100_000);
            var n = FinnNettsted(vert);
            if (n != null) forNettsted(n).Merk(nettleser, $"{nettleser} ({profil}), historikk: {vert}", sist, forst, antall);
            else if (AiLignende.IsMatch(vert))
            {
                if (!ukjente.TryGetValue(vert, out var s)) ukjente[vert] = s = new Brukspor();
                s.Merk(nettleser, $"{nettleser} ({profil}), historikk: {vert}", sist, forst, antall);
            }
        }

        // Første besøk hentes fra besøkstabellen. Finnes den ikke, brukes bare siste besøk.
        long chromeGrense = grense.ToFileTimeUtc() / 10;
        foreach (var (nettleser, rotSti) in Chromium)
            foreach (var profil in Mapper(Utvid(rotSti)))
            {
                var p = Path.GetFileName(profil);
                var db = Path.Combine(profil, "History");
                if (!LesSqlite(db, "SELECT u.url, u.visit_count, u.last_visit_time, (SELECT MIN(v.visit_time) FROM visits v WHERE v.url = u.id) FROM urls u WHERE u.last_visit_time > $g", chromeGrense,
                        r => Tell(nettleser, p, r.Tekst(0), r.Tall(1), ChromeTid(r.Tall(2)), r.ErTom(3) ? null : ChromeTid(r.Tall(3)))))
                    LesSqlite(db, "SELECT url, visit_count, last_visit_time FROM urls WHERE last_visit_time > $g", chromeGrense,
                        r => Tell(nettleser, p, r.Tekst(0), r.Tall(1), ChromeTid(r.Tall(2)), null));
            }

        long firefoxGrense = new DateTimeOffset(grense).ToUnixTimeMilliseconds() * 1000;
        DateTime? FirefoxTid(long mikro) => mikro <= 0 ? null : DateTimeOffset.FromUnixTimeMilliseconds(mikro / 1000).LocalDateTime;
        foreach (var profil in Mapper(Utvid(@"%APPDATA%\Mozilla\Firefox\Profiles")))
        {
            var p = Path.GetFileName(profil);
            var db = Path.Combine(profil, "places.sqlite");
            if (!LesSqlite(db, "SELECT p.url, p.visit_count, p.last_visit_date, (SELECT MIN(h.visit_date) FROM moz_historyvisits h WHERE h.place_id = p.id) FROM moz_places p WHERE p.last_visit_date > $g", firefoxGrense,
                    r => Tell("Firefox", p, r.Tekst(0), r.Tall(1), FirefoxTid(r.Tall(2)), r.ErTom(3) ? null : FirefoxTid(r.Tall(3)))))
                LesSqlite(db, "SELECT url, visit_count, last_visit_date FROM moz_places WHERE last_visit_date > $g", firefoxGrense,
                    r => Tell("Firefox", p, r.Tekst(0), r.Tall(1), FirefoxTid(r.Tall(2)), null));
        }
    }

    /// <summary>Kjører en lesende spørring. Returnerer false hvis spørringen ikke kunne kjøres (f.eks. eldre databaseformat).</summary>
    private static bool LesSqlite(string sti, string sql, long grense, Action<WinSqlite.IRad> rad)
    {
        if (!LovligeFiler.Contains(Path.GetFileName(sti)) || !File.Exists(sti)) return true;
        try
        {
            using var db = new WinSqlite(sti);
            db.Les(sql, grense, r => { try { if (!r.ErTom(0)) rad(r); } catch { } });
            Tilgangslogg.Logg("Database", sti, Utfall.Lest, "lest skrivebeskyttet i minnet; ingen adresser logges eller lagres");
            return true;
        }
        catch (Exception e)
        {
            var laast = e.Message.Inneholder("locked") || e.Message.Inneholder("busy");
            Tilgangslogg.Logg("Database", sti, laast ? Utfall.Laast : Tilgangslogg.Fra(e), laast ? "databasen er låst av nettleseren" : Tilgangslogg.Beskriv(e));
            Debug.WriteLine($"Kunne ikke lese {Path.GetFileName(sti)}: {e.Message}");
            return false;
        }
    }

    /// <summary>Ord som kjennetegner en nettapp: første del av domenet, f.eks. "chatgpt", "gemini", "deepseek".</summary>
    private static IEnumerable<string> AppOrd(AiNettsted n) =>
        n.Domener.Select(d => d.Split('.').FirstOrDefault(del => del is not ("chat" or "www" or "console" or "platform")) ?? "")
                 .Where(o => o.Length >= 4).Distinct();

    private AiNettsted? FinnNettsted(string? vert)
    {
        if (string.IsNullOrEmpty(vert)) return null;
        vert = vert!.ToLowerInvariant().TrimEnd('.');
        if (vert.StartsWith("www.")) vert = vert.Substring(4);
        // Mest presise treff vinner: chat.mistral.ai er Le Chat, mistral.ai er selskapet
        AiNettsted? beste = null; int lengde = 0;
        foreach (var n in _regler.AiNettsteder)
            foreach (var d in n.Domener)
                if (d.Length > lengde && (vert.Equals(d, StringComparison.OrdinalIgnoreCase) || vert.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)))
                { beste = n; lengde = d.Length; }
        return beste;
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
        if (mikro <= 0) return null;
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
