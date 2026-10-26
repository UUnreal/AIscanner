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
    public required string Hvorfor { get; init; }
    public List<string> Hvor { get; } = new();
    public List<string> Merknader { get; } = new();
    public List<string> Detaljer { get; } = new();
    public Produkt? Regel { get; init; }

    public void LeggTilHvor(string s) { if (!Hvor.Contains(s)) Hvor.Add(s); }
    public void Merknad(string s) { if (!Merknader.Contains(s)) Merknader.Add(s); }
    public void Detalj(string s) { if (!Detaljer.Contains(s) && Detaljer.Count < 50) Detaljer.Add(s); }
}
