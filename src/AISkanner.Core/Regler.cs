using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AISkanner;

public sealed class Produkt
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("kategori")] public string Kategori { get; set; } = "";
    [JsonPropertyName("risiko")] public string Risiko { get; set; } = "gul";
    [JsonPropertyName("treff")] public List<string> Treff { get; set; } = new();
    [JsonPropertyName("mapper")] public List<string> Mapper { get; set; } = new();
    [JsonPropertyName("porter")] public List<int> Porter { get; set; } = new();
    [JsonPropertyName("kommandoer")] public List<string> Kommandoer { get; set; } = new();
    [JsonPropertyName("kunUtvidelse")] public bool KunUtvidelse { get; set; }
    [JsonPropertyName("nvd")] public string? Nvd { get; set; }
    [JsonPropertyName("hvorfor")] public string Hvorfor { get; set; } = "";
}

public sealed class InnebygdAI
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("nettleser")] public string Nettleser { get; set; } = "";
    [JsonPropertyName("brukerdata")] public string Brukerdata { get; set; } = "";
    [JsonPropertyName("policyNokkel")] public string PolicyNokkel { get; set; } = "";
    [JsonPropertyName("policyVerdi")] public string PolicyVerdi { get; set; } = "";
    [JsonPropertyName("hvorfor")] public string Hvorfor { get; set; } = "";
}

public sealed class Regelsett
{
    [JsonPropertyName("versjon")] public string Versjon { get; set; } = "";
    [JsonPropertyName("produkter")] public List<Produkt> Produkter { get; set; } = new();
    [JsonPropertyName("ukjentUtvidelseOrd")] public List<string> UkjentUtvidelseOrd { get; set; } = new();
    [JsonPropertyName("modellfilEndelser")] public List<string> ModellfilEndelser { get; set; } = new();
    [JsonPropertyName("modellfilMinMB")] public int ModellfilMinMB { get; set; } = 200;
    [JsonPropertyName("nettleserInnebygd")] public List<InnebygdAI> NettleserInnebygd { get; set; } = new();
    [JsonPropertyName("innebygdMappeOrd")] public List<string> InnebygdMappeOrd { get; set; } = new();

    /// <summary>Kilde reglene ble lastet fra, vises i vinduet.</summary>
    [JsonIgnore] public string Kilde { get; private set; } = "innebygd";

    private static readonly JsonSerializerOptions Valg = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>
    /// Bruker regler.json ved siden av programmet hvis den finnes (så bedriften kan tilpasse),
    /// ellers reglene som er bygd inn i programmet.
    /// </summary>
    public static Regelsett Last(string? sti = null)
    {
        sti ??= Path.Combine(AppContext.BaseDirectory, "regler.json");
        if (File.Exists(sti))
        {
            var r = JsonSerializer.Deserialize<Regelsett>(File.ReadAllText(sti), Valg) ?? new Regelsett();
            r.Kilde = sti;
            return r;
        }
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.regler.json")
                      ?? throw new InvalidOperationException("Mangler innebygde regler.");
        return JsonSerializer.Deserialize<Regelsett>(s, Valg) ?? new Regelsett();
    }
}
