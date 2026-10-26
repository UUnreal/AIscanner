using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace AISkanner;

/// <summary>
/// Revisjonslogg og datagrunnlag: hva søket leste, med hvilke regler, og hva det ikke fikk lest.
/// Programmet har ingen AI-modell. Alt som finnes, finnes med faste regler: filformat, YARA-regler, regelfila og kjente adresser.
/// Loggen inneholder bare stier, navn og utfall, aldri adresser fra nettleseren, innhold i filer eller verdier av nøkler.
/// </summary>
public static class Revisjon
{
    public const string IngenAi = "Ingen AI i programmet: funnene kommer fra faste regler (filformat, YARA, regelfil og kjente adresser), ikke fra en AI-modell.";

    /// <summary>Utfall som betyr at noe ikke ble dekket av søket.</summary>
    public static readonly Utfall[] IkkeDekket = { Utfall.Blokkert, Utfall.Nektet, Utfall.Laast, Utfall.Tidsgrense, Utfall.Feil };

    /// <summary>Det programmet aldri åpner, med vilje (sikkerhetssperre i koden).</summary>
    public static readonly string[] AldriLest =
    {
        "Passord, informasjonskapsler og skjemadata i nettleseren (Login Data, Cookies, Web Data)",
        "Lagrede data fra nettleserutvidelser (Local Extension Settings)",
        "Verdier av API-nøkler og miljøvariabler (bare navnene)",
        "Minnet til andre programmer, lsass og kommandolinjer",
        "Andre brukeres profiler (også som administrator)",
    };

    public sealed record Kilde(string Navn, string Hvor, string? Sha256);

    /// <summary>Programmet og regelfilene søket brukte, med SHA-256, så IT kan bevise hvilke regler som ga resultatet.</summary>
    public static List<Kilde> Kilder(Skanner s)
    {
        var liste = new List<Kilde>();
        var exe = Assembly.GetEntryAssembly()?.Location;
        if (string.IsNullOrEmpty(exe)) exe = Environment.GetCommandLineArgs()[0];
        liste.Add(new Kilde("Program", exe!, Fil(exe!)));
        liste.Add(new Kilde("Kjerne", typeof(Revisjon).Assembly.Location, Fil(typeof(Revisjon).Assembly.Location)));
        var r = s.Regelsett;
        liste.Add(r.Kilde == "innebygd" ? new Kilde("regler.json", "innebygd", Ressurs("AISkanner.regler.json")) : new Kilde("regler.json", r.Kilde, Fil(r.Kilde)));
        var y = s.Yara;
        liste.Add(File.Exists(y.Kilde) ? new Kilde("ai-modeller.yar", y.Kilde, Fil(y.Kilde)) : new Kilde("ai-modeller.yar", y.Kilde == "innebygd" ? "innebygd" : y.Kilde, Ressurs("AISkanner.ai-modeller.yar")));
        liste.Add(r.GodkjentKilde != null ? new Kilde("godkjent-ai.txt", r.GodkjentKilde, Fil(r.GodkjentKilde)) : new Kilde("godkjent-ai.txt", "ingen", null));
        return liste;
    }

    private static string? Fil(string sti)
    {
        try
        {
            if (string.IsNullOrEmpty(sti) || !File.Exists(sti)) return null;
            using var fs = new FileStream(sti, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sha = SHA256.Create();
            return Hex(sha.ComputeHash(fs));
        }
        catch { return null; }
    }

    private static string? Ressurs(string navn)
    {
        using var s = typeof(Revisjon).Assembly.GetManifestResourceStream(navn);
        if (s == null) return null;
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(s));
    }

    public static string Hex(byte[] b) => string.Concat(b.Select(x => x.ToString("x2")));

    public static string Sha256(string tekst)
    {
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(Encoding.UTF8.GetBytes(tekst)));
    }

    public static string UtfallTekst(Utfall u) => u switch
    {
        Utfall.Lest => "lest",
        Utfall.IkkeFunnet => "finnes ikke",
        Utfall.Nektet => "nektet tilgang",
        Utfall.Laast => "låst",
        Utfall.Blokkert => "stoppet av antivirus",
        Utfall.HoppetOver => "hoppet over",
        Utfall.Tidsgrense => "tidsgrense",
        _ => "feil",
    };

    /// <summary>Kort linje for rapporten: hvor mye som ble lest, og hvor mye som ikke ble dekket.</summary>
    public static string Kortversjon(Skanner s)
    {
        var sum = s.Logg.Antall.GroupBy(x => x.Utfall).ToDictionary(g => g.Key, g => g.Sum(x => x.Antall));
        int A(Utfall u) => sum.TryGetValue(u, out var n) ? n : 0;
        var ikke = IkkeDekket.Where(u => A(u) > 0).Select(u => $"{A(u)} {UtfallTekst(u)}");
        return $"Datagrunnlag: {A(Utfall.Lest)} lest, {A(Utfall.IkkeFunnet)} fantes ikke, {A(Utfall.HoppetOver)} hoppet over" +
               (ikke.Any() ? $"; ikke dekket: {string.Join(", ", ikke)}." : "; alt søket prøvde å lese, ble lest.");
    }

    /// <summary>
    /// Hele revisjonsloggen som tekst. Siste linje er SHA-256 av alt over, så endringer i fila kan oppdages.
    /// </summary>
    public static string Tekst(IReadOnlyList<Funn> funn, Skanner s, string modus, bool engelsk, string? feil = null)
    {
        var sb = new StringBuilder();
        void L(string t = "") => sb.Append(engelsk ? Engelsk.Til(t) : t).Append("\r\n");
        void Ra(string t) => sb.Append(t).Append("\r\n");
        string T(string? t) => (engelsk ? Engelsk.Til(t) : t) ?? "";
        var versjon = Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? typeof(Revisjon).Assembly.GetName().Version?.ToString(3) ?? "?";

        L("AI-SKANNER REVISJONSLOGG");
        L($"Versjon: {versjon}");
        Ra($"PC: {Environment.MachineName}   {(engelsk ? "User" : "Bruker")}: {Environment.UserDomainName}\\{Environment.UserName}");
        L($"Søkt som: {modus}");
        L($"Språk: {(engelsk ? "engelsk" : "norsk")}");
        L($"Start: {s.Startet:yyyy-MM-dd HH:mm:ss}   Slutt: {s.Ferdig ?? DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        L($"Nettleserhistorikk: {(s.MedHistorikk ? "sjekket i minnet, ingen adresser lagret" : "slått av av IT")}");
        L($"Eksperimentflagg i nettleseren (Local State): {(s.LesNettleserflagg ? "lest (slått på av IT)" : "ikke lest")}");
        L(IngenAi);
        if (feil != null) L($"Søket stoppet: {feil}");
        L(new string('=', 60));

        L();
        L("REGLER OG PROGRAM (SHA-256)");
        foreach (var k in Kilder(s)) Ra($"{T(k.Navn),-16} {k.Sha256 ?? "-",-64}  {T(k.Hvor)}");

        L();
        L("TID PER SJEKK");
        foreach (var (navn, tid) in s.Tider.OrderByDescending(t => t.Value)) Ra($"{tid.TotalSeconds,7:0.00} s  {T(navn)}");

        L();
        L("UTFALL");
        L(Kortversjon(s));
        foreach (var g in s.Logg.Antall.GroupBy(x => x.Sjekk))
            Ra($"{T(g.Key)}: " + string.Join(", ", g.Select(x => $"{T(x.Hva)} {T(UtfallTekst(x.Utfall))} {x.Antall}")));

        L();
        L("ANTIVIRUS (DEFENDER)");
        var av = s.Forsvar;
        if (av == null || !av.Lest) L($"Defender-loggen ble ikke lest: {av?.Grunn ?? "ukjent"}. Filer antivirus stoppet, vises likevel som «stoppet av antivirus» under.");
        else if (av.Vaare.Count == 0) L($"Ingen hendelser fra Defender om dette programmet under søket ({av.AlleUnderSoket} hendelser totalt i perioden).");
        else foreach (var (tid, id, tekst) in av.Vaare) L($"{tid:HH:mm:ss}  {id}  {tekst}");

        L();
        L("ALDRI LEST (MED VILJE)");
        foreach (var a in AldriLest) L("- " + a);

        L();
        L($"FUNN ({funn.Count})");
        foreach (var f in funn.OrderBy(f => f.Risiko))
            Ra($"{T(Rapport.Merke(f.Risiko)),-12}{T(f.Navn)} | {T(f.Type)} | {T(Oversikt.Lokasjon(f))}");

        L();
        L($"ALT SØKET PRØVDE Å LESE ({s.Logg.Oppforinger.Count}{(s.Logg.Avkortet ? $" av flere, lista stopper på {Tilgangslogg.MaksOppforinger}" : "")}; mapper som ble gått gjennom uten feil er bare talt)");
        foreach (var t in s.Logg.Oppforinger.OrderBy(t => t.Tid))
            Ra($"{t.Tid:HH:mm:ss.fff}  {T(UtfallTekst(t.Utfall)),-20} {T(t.Sjekk)} | {T(t.Hva)} | {T(t.Mal)}{(t.Detalj != null ? " | " + T(t.Detalj) : "")}");

        L();
        var innhold = sb.ToString();
        return innhold + (engelsk ? "SHA-256 of everything above: " : "SHA-256 av alt over: ") + Sha256(innhold) + "\r\n";
    }

    /// <summary>Tillegg som skrives til slutt i fila etter oppslag som kommer etter søket (NVD), med ny SHA-256 for hele fila.</summary>
    public static string Tillegg(string tidligere, IEnumerable<Tilgang> nye, bool engelsk)
    {
        var sb = new StringBuilder();
        string T(string? t) => (engelsk ? Engelsk.Til(t) : t) ?? "";
        sb.Append("\r\n").Append(T("TILLEGG: OPPSLAG ETTER SØKET")).Append("\r\n");
        foreach (var t in nye)
            sb.Append($"{t.Tid:HH:mm:ss.fff}  {T(UtfallTekst(t.Utfall)),-20} {T(t.Sjekk)} | {T(t.Hva)} | {T(t.Mal)}{(t.Detalj != null ? " | " + T(t.Detalj) : "")}\r\n");
        var alt = tidligere + sb;
        return sb + (engelsk ? "SHA-256 of the whole file above: " : "SHA-256 av hele fila over: ") + Sha256(alt) + "\r\n";
    }

    /// <summary>Datagrunnlaget for utviklermodus i vinduet (samme innhold som revisjonsloggen, men bare i minnet).</summary>
    public static object Datagrunnlag(Skanner s, bool engelsk, string? revisjonSti)
    {
        string T(string? x) => (engelsk ? Engelsk.Til(x) : x) ?? "";
        string U(Utfall u) => T(Revisjon.UtfallTekst(u));
        var antall = s.Logg.Antall.ToList();
        var poster = s.Logg.Oppforinger.ToList();
        // Opptil 3000 i vinduet: alt som ikke ble lest først, så resten
        var vises = poster.Where(p => p.Utfall != Utfall.Lest).Take(3000).ToList();
        vises.AddRange(poster.Where(p => p.Utfall == Utfall.Lest).Take(3000 - vises.Count));
        object Post(Tilgang p) => new { t = p.Tid.ToString("HH:mm:ss"), u = p.Utfall.ToString().ToLowerInvariant(), ut = U(p.Utfall), s = T(p.Sjekk), h = T(p.Hva), m = T(p.Mal), d = p.Detalj == null ? null : T(p.Detalj) };
        var av = s.Forsvar;
        return new
        {
            totalt = Enum.GetValues(typeof(Utfall)).Cast<Utfall>()
                .Select(u => new { u = u.ToString().ToLowerInvariant(), tekst = U(u), n = antall.Where(x => x.Utfall == u).Sum(x => x.Antall), mangler = Revisjon.IkkeDekket.Contains(u) }),
            sjekker = antall.GroupBy(x => x.Sjekk).Select(g => new
            {
                navn = T(g.Key),
                tid = s.Tider.TryGetValue(g.Key, out var tid) ? tid.TotalSeconds : (double?)null,
                lest = g.Where(x => x.Utfall == Utfall.Lest).Sum(x => x.Antall),
                ikke = g.Where(x => x.Utfall == Utfall.IkkeFunnet).Sum(x => x.Antall),
                hoppet = g.Where(x => x.Utfall == Utfall.HoppetOver).Sum(x => x.Antall),
                mangler = g.Where(x => Revisjon.IkkeDekket.Contains(x.Utfall)).Sum(x => x.Antall),
            }).OrderByDescending(x => x.tid ?? 0),
            ikkeDekket = poster.Where(p => Revisjon.IkkeDekket.Contains(p.Utfall)).Take(1000).Select(Post),
            poster = vises.OrderBy(p => p.Tid).Select(Post),
            antallPoster = poster.Count,
            avkortet = s.Logg.Avkortet,
            defender = av == null ? T("Defender-loggen ble ikke lest.")
                : !av.Lest ? T($"Defender-loggen ble ikke lest: {av.Grunn}. Filer antivirus stoppet, vises likevel som «stoppet av antivirus».")
                : av.Vaare.Count == 0 ? T($"Ingen hendelser fra Defender om dette programmet under søket ({av.AlleUnderSoket} hendelser totalt i perioden).")
                : T($"Defender stoppet noe under søket (hendelser: {av.Vaare.Count})."),
            defenderOk = av != null && av.Lest && av.Vaare.Count == 0,
            defHendelser = av?.Vaare.Select(h => new { t = h.Tid.ToString("HH:mm:ss"), id = h.Id, tekst = T(h.Tekst) }),
            kilder = Revisjon.Kilder(s).Select(k => new { navn = T(k.Navn), hvor = T(k.Hvor), sha = k.Sha256 }),
            aldri = Revisjon.AldriLest.Select(T),
            ingenAi = T(Revisjon.IngenAi),
            revisjon = revisjonSti,
        };
    }
}
