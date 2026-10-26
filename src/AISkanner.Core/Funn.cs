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
    public string Gruppe => Kategori.StartsWith("Nettleser") ? "nettleser" : Kategori.StartsWith("Lokal") ? "lokal" : "skjult";
    public required string Hvorfor { get; init; }
    public string? Enkelt { get; init; }
    public string? Rad { get; init; }
    /// <summary>Kort om hvor mye noe brukes, f.eks. "Brukes ofte i Chrome."</summary>
    public string? Bruk { get; set; }
    public List<string> Advarsler { get; } = new();
    /// <summary>Bygger på nettleserdata. Vises på skjermen, men lagres aldri (heller ikke i rapporten).</summary>
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
    private int _modeller;
    /// <summary>Hvor mange AI-modeller (modellfiler eller modellmapper) funnet hører til.</summary>
    public int Modeller => _modeller;
    public void LeggTilModeller(int n) => Interlocked.Add(ref _modeller, n);

    public void LeggTilHvor(string s) { lock (this) if (!Hvor.Contains(s)) Hvor.Add(s); }
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
    public int Antall { get; set; }
    public long? Ut { get; set; }
    public long? Inn { get; set; }
    /// <summary>IP-adressene forbindelsene gikk til (høyst 8).</summary>
    public List<string> Ip { get; } = new();
}
