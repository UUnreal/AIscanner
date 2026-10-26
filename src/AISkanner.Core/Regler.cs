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
    [JsonPropertyName("enkelt")] public string? Enkelt { get; set; }
    [JsonPropertyName("hvorforEnkelt")] public string? HvorforEnkelt { get; set; }
    [JsonPropertyName("rad")] public string? Rad { get; set; }
}

/// <summary>Et AI-nettsted som kan gjenkjennes fra spor i nettleserne.</summary>
public sealed class AiNettsted
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("domener")] public List<string> Domener { get; set; } = new();
    [JsonPropertyName("risiko")] public string Risiko { get; set; } = "gul";
    /// <summary>Landet selskapet bak tjenesten hører hjemme i (to bokstaver). Viktig når dataene havner hos dem.</summary>
    [JsonPropertyName("land")] public string? Land { get; set; }
    [JsonPropertyName("enkelt")] public string? Enkelt { get; set; }
    [JsonPropertyName("hvorfor")] public string Hvorfor { get; set; } = "";
    [JsonPropertyName("rad")] public string? Rad { get; set; }

    public bool Treffer(string vert) => Domener.Any(d => vert.Equals(d, StringComparison.OrdinalIgnoreCase) || vert.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));
}

/// <summary>En modellfamilie som kan kjennes igjen på innholdet i modellfilen, også uten navn.</summary>
public sealed class ModellFamilie
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("utgiver")] public string Utgiver { get; set; } = "";
    [JsonPropertyName("land")] public string? Land { get; set; }
    [JsonPropertyName("arkitekturer")] public List<string> Arkitekturer { get; set; } = new();
    [JsonPropertyName("vokab")] public List<int> Vokab { get; set; } = new();
    [JsonPropertyName("deltVokab")] public bool DeltVokab { get; set; }
    [JsonPropertyName("ord")] public List<string> Ord { get; set; } = new();
    [JsonPropertyName("type")] public string? Type { get; set; }
}

/// <summary>AI som leverandører legger inn i egne programmer. Gir bare navn: funnet gjøres på innholdet.</summary>
public sealed class LeverandorAi
{
    /// <summary>Biter av mappestien (små bokstaver) som peker på programmet.</summary>
    [JsonPropertyName("ord")] public List<string> Ord { get; set; } = new();
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("utgiver")] public string Utgiver { get; set; } = "";
    [JsonPropertyName("hva")] public string? Hva { get; set; }
    /// <summary>false når mappenavnet ikke er bekreftet på en ekte PC ennå.</summary>
    [JsonPropertyName("bekreftet")] public bool Bekreftet { get; set; }
}

public sealed class InnebygdAI
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("nettleser")] public string Nettleser { get; set; } = "";
    [JsonPropertyName("brukerdata")] public string Brukerdata { get; set; } = "";
    [JsonPropertyName("policyNokkel")] public string PolicyNokkel { get; set; } = "";
    [JsonPropertyName("policyVerdi")] public string PolicyVerdi { get; set; } = "";
    [JsonPropertyName("hvorfor")] public string Hvorfor { get; set; } = "";
    [JsonPropertyName("enkelt")] public string? Enkelt { get; set; }
    [JsonPropertyName("hvorforEnkelt")] public string? HvorforEnkelt { get; set; }
    [JsonPropertyName("rad")] public string? Rad { get; set; }
}

public sealed class Regelsett
{
    [JsonPropertyName("versjon")] public string Versjon { get; set; } = "";
    [JsonPropertyName("produkter")] public List<Produkt> Produkter { get; set; } = new();
    [JsonPropertyName("ukjentUtvidelseOrd")] public List<string> UkjentUtvidelseOrd { get; set; } = new();
    [JsonPropertyName("modellfilEndelser")] public List<string> ModellfilEndelser { get; set; } = new();
    [JsonPropertyName("modellfilMinMB")] public int ModellfilMinMB { get; set; } = 200;
    [JsonPropertyName("nettleserInnebygd")] public List<InnebygdAI> NettleserInnebygd { get; set; } = new();
    [JsonPropertyName("aiNettsteder")] public List<AiNettsted> AiNettsteder { get; set; } = new();
    /// <summary>AI-tjenester programmer snakker med i bakgrunnen (API-er), gjenkjent på vertsnavn.</summary>
    [JsonPropertyName("aiTjenester")] public List<AiNettsted> AiTjenester { get; set; } = new();
    /// <summary>Land der data om bedriften ikke bør havne. AI som sender hit blir rødt.</summary>
    [JsonPropertyName("hoyrisikoLand")] public List<string> HoyrisikoLand { get; set; } = new();
    [JsonPropertyName("modellfamilier")] public List<ModellFamilie> Modellfamilier { get; set; } = new();
    [JsonPropertyName("leverandorAi")] public List<LeverandorAi> LeverandorAi { get; set; } = new();
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
