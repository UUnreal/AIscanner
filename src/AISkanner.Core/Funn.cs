namespace AISkanner;

public enum Risiko { Rod = 0, Gul = 1, Gronn = 2 }

public static class RisikoTekst
{
    public static Risiko Fra(string s) => s.ToLowerInvariant() switch
    {
        "rod" or "rød" => Risiko.Rod,
        "gronn" or "grønn" => Risiko.Gronn,
        _ => Risiko.Gul,
    };

    public static string Vis(Risiko r) => r switch
    {
        Risiko.Rod => "RØD",
        Risiko.Gul => "GUL",
        _ => "GRØNN",
    };

    /// <summary>Lavere tall er høyere risiko.</summary>
    public static Risiko Hoyeste(Risiko a, Risiko b) => (Risiko)Math.Min((int)a, (int)b);
}

/// <summary>Hva sporene viser om AI-en. Flere kan gjelde samme funn.</summary>
[Flags]
public enum Tilstand { Finnes = 1, SattOpp = 2, BruktFor = 4, KjorerNa = 8, SlattOpp = 16 }

/// <summary>Hvor sikkert det er at funnet er AI, ut fra hvor sterke og hvor mange uavhengige spor som peker dit.</summary>
public enum Sikkerhet { Hoy = 0, Middels = 1, Lav = 2 }

/// <summary>Ett produkt på listen. Samme produkt funnet flere steder slås sammen til ett funn.</summary>
public sealed class Funn
{
    public required string Navn { get; init; }
    public required string Kategori { get; init; }
    public Risiko Risiko { get; set; }

    /// <summary>
    /// Hvor AI-en lever: "lokal" (kjører på PC-en: modeller, motorer, lokale servere),
    /// "nettleser" (nettsteder, utvidelser, innebygd AI) eller "skjult" (alt annet på PC-en: apper og agenter som bruker AI i skyen, kode, nøkler, bakgrunnsprogrammer).
    /// </summary>
    public string Gruppe => Kategori == Skanner.SporKategori ? "spor" : Kategori.StartsWith("Nettleser") ? "nettleser" : Kategori.StartsWith("Lokal") ? "lokal" : "skjult";
    public required string Hvorfor { get; init; }
    public string? Enkelt { get; init; }
    /// <summary>Kort om hvor mye noe brukes, f.eks. "Brukes ofte i Chrome."</summary>
    public string? Bruk { get; set; }
    public List<string> Advarsler { get; } = new();
    /// <summary>
    /// Bygger på nettleserdata (historikk eller DNS). Analyseres i minnet og lagres aldri av seg selv.
    /// Står i rapporten brukeren selv laster ned (AI-domene, nettleser, besøk, tider), men ikke i revisjonsloggen.
    /// </summary>
    public bool Privat { get; set; }
    public List<string> Hvor { get; } = new();
    public List<string> Merknader { get; } = new();
    public List<string> Detaljer { get; } = new();
    public Produkt? Regel { get; init; }
    /// <summary>Hvor programmet er koblet til akkurat nå. Målt fra Windows, ikke anslått.</summary>
    public List<Mal> Trafikk { get; } = new();
    /// <summary>Landet selskapet bak tjenesten hører hjemme i (to bokstaver), når det er kjent fra listene. Der havner det du skriver.</summary>
    public string? Land { get; set; }
    /// <summary>Selskapet som har laget AI-en, og landet det hører hjemme i (to bokstaver), når det er kjent.</summary>
    public string? Opprinnelse { get; set; }
    public string? OpprinnelseLand { get; set; }
    /// <summary>Hva slags AI dette er, kort: "AI-nettsted", "Lokal modell", "Ukjent AI" osv. Settes av Risikoregler.</summary>
    public string Type { get; set; } = "";
    /// <summary>Hvorfor den har den risikoen den har, én setning.</summary>
    public string? RisikoGrunn { get; set; }
    /// <summary>Land (to bokstaver) dataene går til, utenom målte forbindelser: tjenester Windows har slått opp nylig.</summary>
    public List<string> SenderTil { get; } = new();
    /// <summary>Tjenestens adresse nå (skannerens eget oppslag, med land og eier fra OSINT). Ikke sett under søket, ikke bevis for bruk.</summary>
    public List<string> Oppslag { get; } = new();
    private int _modeller;
    /// <summary>Hvor mange AI-modeller (modellfiler eller modellmapper) funnet hører til.</summary>
    public int Modeller => _modeller;
    public void LeggTilModeller(int n) => Interlocked.Add(ref _modeller, n);
    private int _innebygde;
    /// <summary>
    /// Modellfiler en leverandør har bygget inn i et program eller en nettleser (ONNX i Office, Bilder, Teams, små
    /// nettlesermodeller for tale og oversettelse). Telles ikke som AI-modeller i overskriften: programmet telles én gang.
    /// </summary>
    public int Innebygde => _innebygde;
    public void LeggTilInnebygde(int n) => Interlocked.Add(ref _innebygde, n);

    /// <summary>Versjonen slik den står på PC-en (programfila, avinstalleringslista, modellfila, utvidelsens manifest). Bare ekte verdier.</summary>
    public string? Versjon { get; private set; }
    /// <summary>Hvor versjonen ble lest, f.eks. «programfila».</summary>
    public string? VersjonKilde { get; private set; }

    /// <summary>Setter versjonen første gang en ekte verdi finnes. Tomme og meningsløse verdier (0.0.0.0) ignoreres.</summary>
    public void SettVersjon(string? versjon, string kilde)
    {
        versjon = versjon?.Trim();
        if (string.IsNullOrEmpty(versjon) || versjon!.Length > 40 || System.Text.RegularExpressions.Regex.IsMatch(versjon, @"^[0.\s,]*$")) return;
        lock (this) if (Versjon == null) { Versjon = versjon; VersjonKilde = kilde; }
    }

    public void LeggTilHvor(string s) { lock (this) if (!Hvor.Contains(s)) Hvor.Add(s); }

    private int _tilstand;
    /// <summary>Alt sporene viser: finnes på PC-en nå, satt opp til å starte, brukt før, kjører nå. Tom når bare historikken viser den.</summary>
    public Tilstand Tilstander => (Tilstand)Volatile.Read(ref _tilstand);
    public void Merk(Tilstand t) { int gammel; do gammel = _tilstand; while (Interlocked.CompareExchange(ref _tilstand, gammel | (int)t, gammel) != gammel); }

    /// <summary>Det sterkeste sporet: Kjører nå, så Brukt før, så Satt opp, så Bare slått opp (et DNS-navn, ingen bruk sett), ellers Finnes.</summary>
    public Tilstand Status =>
        Tilstander.HasFlag(Tilstand.KjorerNa) ? Tilstand.KjorerNa : Tilstander.HasFlag(Tilstand.BruktFor) ? Tilstand.BruktFor
        : Tilstander.HasFlag(Tilstand.SattOpp) ? Tilstand.SattOpp : Tilstander.HasFlag(Tilstand.SlattOpp) ? Tilstand.SlattOpp : Tilstand.Finnes;

    /// <summary>Spor som kjenner igjen AI på innholdet eller oppførselen (modellhode, import i kode, trafikk til AI-tjeneste, YARA, utvidelses-ID).</summary>
    private int _sterke;
    /// <summary>Spor som bare bygger på et navn eller et ord (mappenavn, «mulig AI-nettsted»).</summary>
    private int _svake;
    public void Sterkt() => Interlocked.Increment(ref _sterke);
    public void Svakt() => Interlocked.Increment(ref _svake);

    /// <summary>Uavhengige spor: steder funnet er sett (installert, kjører, oppstart, historikk …) og målt trafikk.</summary>
    public int Spor { get { lock (this) return Hvor.Count + (Trafikk.Count > 0 && !Hvor.Contains("Koblet til nå") ? 1 : 0); } }

    /// <summary>
    /// Høy: et spor på innholdet eller oppførselen, eller minst to uavhengige spor. Lav: bare svake spor (navn alene).
    /// Middels: ett spor på navnet til en kjent AI (regel).
    /// </summary>
    public Sikkerhet Sikkerhet =>
        Volatile.Read(ref _sterke) > 0 || Spor >= 2 ? Sikkerhet.Hoy
        : Volatile.Read(ref _svake) > 0 && Regel == null ? Sikkerhet.Lav : Sikkerhet.Middels;

    /// <summary>Hva IT har sagt: godkjent, blokkert eller ikke vurdert. Settes av Risikoregler.</summary>
    public string Godkjenning { get; set; } = "Ikke vurdert";
    public void Advarsel(string s) { lock (this) if (!Advarsler.Contains(s)) Advarsler.Add(s); }

    /// <summary>Én setning til vanlige folk: hvordan det brukes, og den viktigste grunnen.</summary>
    public string Kort
    {
        get
        {
            var grunn = Advarsler.FirstOrDefault() ?? ForsteSetning(Hvorfor);
            return string.IsNullOrEmpty(Bruk) ? grunn : $"{Bruk} {grunn}";
        }
    }

    private static string ForsteSetning(string s)
    {
        int i = s.IndexOf(". ", StringComparison.Ordinal);
        return i > 0 ? s.Substring(0, i + 1) : s;
    }

    public void Merknad(string s) { lock (this) if (!Merknader.Contains(s)) Merknader.Add(s); }
    public void Detalj(string s) { lock (this) if (!Detaljer.Contains(s) && Detaljer.Count < 500) Detaljer.Add(s); }
    /// <summary>Erstatter en detaljlinje som starter likt, så tall fra en tidligere lesing ikke blir stående ved siden av nye.</summary>
    public void ErstattDetalj(string start, string s) { lock (this) { Detaljer.RemoveAll(d => d.StartsWith(start, StringComparison.Ordinal)); Detalj(s); } }

    /// <summary>Første og siste spor etter bruk, når det finnes (besøk, filer endret, forbindelse nå).</summary>
    public DateTime? Forst { get; set; }
    public DateTime? Sist { get; set; }

    public void Tidspunkt(DateTime? forst, DateTime? sist)
    {
        lock (this)
        {
            forst ??= sist;
            if (forst != null && (Forst == null || forst < Forst)) Forst = forst;
            if (sist != null && (Sist == null || sist > Sist)) Sist = sist;
        }
    }

    /// <summary>Tar inn alt et annet funn for samme program har sett: kilder, tilstander, styrke, trafikk og land.</summary>
    public void SlaInn(Funn a)
    {
        List<string> d, h, adv, mer; List<Mal> t; List<string> st;
        lock (a) { d = a.Detaljer.ToList(); h = a.Hvor.ToList(); adv = a.Advarsler.ToList(); mer = a.Merknader.ToList(); t = a.Trafikk.ToList(); st = a.SenderTil.ToList(); }
        foreach (var x in d) Detalj(x);
        foreach (var x in h) LeggTilHvor(x);
        foreach (var x in adv) Advarsel(x);
        lock (this)
        {
            foreach (var x in mer) if (!Merknader.Contains(x)) Merknader.Add(x);
            foreach (var x in t) if (!Trafikk.Contains(x)) Trafikk.Add(x);
            foreach (var x in st) if (!SenderTil.Contains(x)) SenderTil.Add(x);
            Land ??= a.Land;
            OpprinnelseLand ??= a.OpprinnelseLand;
            Bruk ??= a.Bruk;
        }
        Merk(a.Tilstander);
        Interlocked.Add(ref _sterke, Volatile.Read(ref a._sterke));
        Interlocked.Add(ref _svake, Volatile.Read(ref a._svake));
        LeggTilModeller(a.Modeller);
        LeggTilInnebygde(a.Innebygde);
        Tidspunkt(a.Forst, a.Sist);
        Risiko = RisikoTekst.Hoyeste(Risiko, a.Risiko);
    }
}

/// <summary>
/// Ett mål på nettet som et AI-program er koblet til nå.
/// Ut og Inn er målte byte i måleperioden, eller null når datamengde ikke kunne måles (krever administrator).
/// </summary>
public sealed class Mal
{
    public required string Adresse { get; init; }
    public string? Tjeneste { get; set; }
    public string? Land { get; set; }
    public string? EierLand { get; set; }
    /// <summary>CDN-en tjenesten skjuler seg bak (Cloudflare, Akamai …). Da er Land "CDN".</summary>
    public string? Cdn { get; set; }
    public int Antall { get; set; }
    public long? Ut { get; set; }
    public long? Inn { get; set; }
    /// <summary>Første og siste gang en forbindelse hit ble sett i lyttevinduet.</summary>
    public DateTime? Forst { get; set; }
    public DateTime? Sist { get; set; }
    /// <summary>IP-adressene forbindelsene gikk til (høyst 8), hver med sitt land.</summary>
    public List<IpSted> Ip { get; } = new();
    /// <summary>Lokale IP-adresser forbindelsene gikk fra (høyst 4).</summary>
    public List<string> KildeIp { get; } = new();
    /// <summary>Programfilene (full sti) som hadde forbindelsene, med PID (høyst 4).</summary>
    public List<Prosessfil> Prosesser { get; } = new();
}

/// <summary>En IP-adresse og landet den er registrert i. Cdn er satt når adressen bare er en kantserver.</summary>
/// Eier er firmaet som har adressen (ASN), fra offentlige rutetabeller (OSINT), ikke målt.
public sealed record IpSted(string Ip, string? Land, string? Cdn, string? Eier = null);

/// <summary>Et program (PID og full sti) som hadde en forbindelse.</summary>
public sealed record Prosessfil(int Pid, string Fil);

/// <summary>
/// Ingen funn uten kilde: hvert funn må ha minst én linje som sier hvor det ble sett (fil, register, buffer, logg,
/// tilkobling), og skannerens egen aktivitet er aldri et bevis. Brukes av --kontroll og lastetesten i CI.
/// </summary>
public static class Kildesjekk
{
    public static List<string> Mangler(IEnumerable<Funn> funn)
    {
        var feil = new List<string>();
        string? egen = null;
        try { egen = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName; } catch { }
        foreach (var f in funn)
        {
            List<string> d;
            lock (f) d = f.Detaljer.ToList();
            if (d.Count == 0 && f.Trafikk.Count == 0) feil.Add($"{f.Navn}: ingen kilde");
            if (d.Any(x => x.IndexOf("AISkanner.exe", StringComparison.OrdinalIgnoreCase) >= 0
                           || (egen != null && x.IndexOf(egen, StringComparison.OrdinalIgnoreCase) >= 0)))
                feil.Add($"{f.Navn}: skannerens egen aktivitet brukt som bevis");
        }
        return feil;
    }
}
