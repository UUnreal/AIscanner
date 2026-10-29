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
    /// <summary>Det søket aldri åpner, verken som bruker eller administrator.</summary>
    public static readonly string[] AldriApnet =
    {
        "Passord, informasjonskapsler og skjemadata i nettleseren (Login Data, Cookies, Web Data)",
        "Lagrede data fra nettleserutvidelser (Local Extension Settings)",
        "Minnet til andre programmer og lsass",
        "Windows Legitimasjonsbehandling og PowerShell-historikken",
        "E-post",
        ".env-filer (bare om de finnes)",
    };

    /// <summary>Det søket leser i minnet for å kjenne igjen AI, men aldri viser, lagrer eller sender.</summary>
    public static readonly string[] LestAldriVist =
    {
        "Verdier av API-nøkler (bare navnet, eller at noe ligner en nøkkel)",
        "Argumentene i kommandolinjer, også i hendelseslogger (bare skriptfila og regelen som slo til)",
        "Kode skrevet på kommandolinjen, også gjemt som base64",
        "De første bytene i filer (filhodet), bare for å kjenne igjen AI-modeller",
        "Teksten i skript, instruksjonsfiler (CLAUDE.md, AGENTS.md), ferdigheter og hooks (bare treff og første ord)",
        "Innholdet i AI-agentenes økter, kommandoer og svar (bare tidspunkter og om en økt nevner nøkler eller systemfiler)",
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
        Utfall.IkkeFunnet => "sjekket, ingenting der",
        Utfall.Nektet => "nektet tilgang",
        Utfall.Laast => "låst",
        Utfall.Blokkert => "stoppet av antivirus",
        Utfall.HoppetOver => "hoppet over",
        Utfall.Tidsgrense => "tidsgrense",
        Utfall.Dekket => "dekket av annen sjekk",
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
        Ra($"PC: {Environment.MachineName}   {(engelsk ? "User" : "Bruker")}: {Bruker.Navn}");
        if (Bruker.KjortAv != null) L($"Kjørt av: {Bruker.KjortAv} (søket gjelder brukeren som er logget inn)");
        if (Bruker.Feil != null) L(Bruker.Feil);
        L($"Søkt som: {modus}");
        L($"Språk: {(engelsk ? "engelsk" : "norsk")}");
        L($"Start: {s.Startet:yyyy-MM-dd HH:mm:ss}   Slutt: {s.Ferdig ?? DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        L($"Nettleserhistorikk: {(s.MedHistorikk ? "sjekket i minnet, ingen adresser lagret" : "slått av av IT")}");
        L($"Eksperimentflagg i nettleseren (Local State): {(s.LesNettleserflagg ? "lest (slått på av IT)" : "ikke lest")}");
        L($"Agentøkter (tidspunkter og treff, aldri innhold): {(s.MedAgentlogger ? "sjekket" : "slått av av IT")}");
        int spor = funn.Count(f => f.Gruppe == "spor");
        L(spor > 0 ? $"Ukjente AI-spor: fant spor ({spor})." : "Ukjente AI-spor: fant ingen spor.");
        L(s.LyttetSekunder > 0
            ? $"Nettverk: lyttet i {s.LyttetSekunder:0} sekunder (TCP-tabellen hvert 250. ms). UDP og QUIC (HTTP/3) vises ikke."
            : "Nettverk: ett øyeblikksbilde av TCP-tabellen. UDP og QUIC (HTTP/3) vises ikke.");
        L("Følg med (datamengde live) logges ikke og lagres ikke.");
        foreach (var b in s.Blindsoner) L($"Blindsone: {b}");
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
        L("ALDRI ÅPNET (MED VILJE)");
        foreach (var a in AldriApnet) L("- " + a);
        L();
        L("LEST I MINNET, ALDRI VIST");
        foreach (var a in LestAldriVist) L("- " + a);

        L();
        L($"FUNN ({funn.Count})");
        foreach (var f in funn.OrderBy(f => f.Risiko))
            // Et mulig AI-nettsted heter det samme som domenet. Domener fra nettleseren skal aldri i revisjonsloggen.
            Ra($"{T(Rapport.Merke(f)),-12}{T(f.Privat && f.Navn.StartsWith("Mulig AI-nettsted", StringComparison.Ordinal) ? "Mulig AI-nettsted" : f.Navn)} | {T(f.Type)} | {T(Oversikt.Lokasjon(f))}");

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

    private static object Disker(Skanner s)
    {
        var talt = s.Logg.Disker.ToDictionary(x => x.Disk, StringComparer.OrdinalIgnoreCase);
        var liste = new List<object>();
        if (!Plattform.ErWindows) return liste;
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (d.DriveType is not (DriveType.Fixed or DriveType.Removable) || !d.IsReady) continue;
                var rot = d.RootDirectory.FullName.ToUpperInvariant();
                talt.TryGetValue(rot, out var t);
                long brukt = d.TotalSize - d.TotalFreeSpace;
                liste.Add(new { disk = rot.TrimEnd('\\'), mapper = t.Mapper, filer = t.Filer, bytes = t.Bytes, brukt, storrelse = d.TotalSize });
            }
            catch { }
        }
        return liste;
    }

    /// <summary>Datagrunnlaget for utviklermodus i vinduet (samme innhold som revisjonsloggen, men bare i minnet).</summary>
    public static object Datagrunnlag(Skanner s, bool engelsk, string? revisjonSti, IReadOnlyList<Funn>? funn = null)
    {
        string T(string? x) => (engelsk ? Engelsk.Til(x) : x) ?? "";
        string U(Utfall u) => T(Revisjon.UtfallTekst(u));
        var antall = s.Logg.Antall.ToList();
        var poster = s.Logg.Oppforinger.ToList();
        // Opptil 3000 i vinduet: alt som ikke ble lest først, så resten
        var vises = poster.Where(p => p.Utfall != Utfall.Lest).Take(3000).ToList();
        vises.AddRange(poster.Where(p => p.Utfall == Utfall.Lest).Take(3000 - vises.Count));
        object Post(Tilgang p) => new { t = p.Tid.ToString("HH:mm:ss"), u = p.Utfall.ToString().ToLowerInvariant(), ut = U(p.Utfall), s = T(p.Sjekk), h = T(p.Hva), m = T(p.Mal), d = p.Detalj == null ? null : T(p.Detalj), k = Kart.Plass(p.Hva, p.Mal) };
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
            // Dekning per disk: det søket listet (mapper, filer, byte) mot det disken har i bruk. Målt, ikke anslått.
            disker = Disker(s),
            filhoder = ModellFormat.Filhoder,
            avkortet = s.Logg.Avkortet,
            defender = av == null ? T("Defender-loggen ble ikke lest.")
                : !av.Lest ? T($"Defender-loggen ble ikke lest: {av.Grunn}. Filer antivirus stoppet, vises likevel som «stoppet av antivirus».")
                : av.Vaare.Count == 0 ? T($"Ingen hendelser fra Defender om dette programmet under søket ({av.AlleUnderSoket} hendelser totalt i perioden).")
                : T($"Defender stoppet noe under søket (hendelser: {av.Vaare.Count})."),
            defenderOk = av != null && av.Lest && av.Vaare.Count == 0,
            defHendelser = av?.Vaare.Select(h => new { t = h.Tid.ToString("HH:mm:ss"), id = h.Id, tekst = T(h.Tekst) }),
            kilder = Revisjon.Kilder(s).Select(k => new { navn = T(k.Navn), hvor = T(k.Hvor), sha = k.Sha256 }),
            aldri = Revisjon.AldriApnet.Select(T),
            lestAldriVist = Revisjon.LestAldriVist.Select(T),
            ingenAi = T(Revisjon.IngenAi),
            revisjon = revisjonSti,
            kart = s.Logg.Kart.Tre(funn, T),
            // Hvert sted per utfall fra kartet, også mappene gjennomgangen bare talte. Alt i tallene skal kunne åpnes.
            steder = s.Logg.Kart.Steder(3000).Select(x => new { u = x.Utfall.ToString().ToLowerInvariant(), ut = U(x.Utfall), s = T(x.Sjekk),
                h = T(x.Rot == Kart.Disk ? "Mappe eller fil" : x.Rot), m = x.Sti, d = x.Detalj == null ? null : T(x.Detalj), n = x.Antall, k = x.Plass }),
        };
    }
}
