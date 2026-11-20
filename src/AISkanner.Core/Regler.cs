using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AISkanner;

/// <summary>
/// Felt hver regel i katalogen må ha (§9). --kontroll feiler hvis ett mangler eller en id er dobbel, og kjører
/// testPositiv (må treffe regelen) og testNegativ (må ikke treffe den).
/// </summary>
public abstract class Regelmeta
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("bevistype")] public string Bevistype { get; set; } = "";
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
    [JsonPropertyName("verifisert")] public bool? Verifisert { get; set; }
    [JsonPropertyName("fpMerknad")] public string FpMerknad { get; set; } = "";
    [JsonPropertyName("testPositiv")] public string TestPositiv { get; set; } = "";
    [JsonPropertyName("testNegativ")] public string TestNegativ { get; set; } = "";
    /// <summary>Rødt faresignal regelen alltid gir, f.eks. «Deepfake eller stemmekloning». Godkjenning fjerner det ikke.</summary>
    [JsonPropertyName("fare")] public string? Fare { get; set; }
}

/// <summary>AI-bibliotek (Python-import eller Node-pakke). Agent = lager agenter som kan handle på egen hånd.</summary>
public sealed class Pakke : Regelmeta
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("agent")] public bool Agent { get; set; }
}

/// <summary>Kjent AI-bilde i Docker (navnet før kolon). Slutter på / = prefiks.</summary>
public sealed class DockerBilde : Regelmeta
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
}

public sealed class Produkt : Regelmeta
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
    /// <summary>Arkitekturen deles med en annen familie: teller bare sammen med ordforrådet (GigaChat bruker DeepSeek-arkitektur).</summary>
    [JsonPropertyName("kreverVokab")] public bool KreverVokab { get; set; }
    /// <summary>Offentlige kilder for opphav og kjennetegn. Vises i detaljene.</summary>
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
}

/// <summary>
/// Hva en modell er laget for, kjent igjen på navn og merkelapper: angrep (offensive sikkerhetsmodeller og kriminelle modeller),
/// sensurfri (sikkerhetssperren er fjernet) eller sikkerhet (modeller som vokter AI eller hjelper forsvarere).
/// Selve vektene kan ikke vise dette uten å laste modellen, så funnet sier at det er navnet som viser det.
/// </summary>
public sealed class ModellFormaal
{
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    /// <summary>"angrep", "sensurfri" eller "sikkerhet".</summary>
    [JsonPropertyName("kategori")] public string Kategori { get; set; } = "";
    [JsonPropertyName("utgiver")] public string? Utgiver { get; set; }
    [JsonPropertyName("ord")] public List<string> Ord { get; set; } = new();
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
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
    [JsonPropertyName("policyNokkel")] public string PolicyNokkel { get; set; } = "";
    [JsonPropertyName("policyVerdi")] public string PolicyVerdi { get; set; } = "";
    [JsonPropertyName("hvorfor")] public string Hvorfor { get; set; } = "";
    [JsonPropertyName("enkelt")] public string? Enkelt { get; set; }
    [JsonPropertyName("hvorforEnkelt")] public string? HvorforEnkelt { get; set; }
}

public sealed class DaarligVersjon
{
    /// <summary>npm-pakke (f.eks. "nx", "@bitwarden/cli") eller utvidelse (utgiver.navn).</summary>
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    [JsonPropertyName("versjoner")] public List<string> Versjoner { get; set; } = new();
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
}

/// <summary>AI-verktøy med kjent sikkerhetshull: alle versjoner før <see cref="Retta"/> er sårbare.</summary>
public sealed class SaarbarVersjon
{
    /// <summary>npm- eller PyPI-pakke.</summary>
    [JsonPropertyName("navn")] public string Navn { get; set; } = "";
    /// <summary>"npm" eller "pypi".</summary>
    [JsonPropertyName("type")] public string Type { get; set; } = "npm";
    /// <summary>Første versjon som er retta.</summary>
    [JsonPropertyName("retta")] public string Retta { get; set; } = "";
    [JsonPropertyName("hull")] public string Hull { get; set; } = "";
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
}

public sealed class DaarligUtvidelse
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
}

public sealed class IocFil
{
    /// <summary>Sti med miljøvariabler, f.eks. %TEMP%\tmp.987654321.lock.</summary>
    [JsonPropertyName("sti")] public string Sti { get; set; } = "";
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
}

public sealed class IocDomene
{
    [JsonPropertyName("domene")] public string Domene { get; set; } = "";
    [JsonPropertyName("kilde")] public string? Kilde { get; set; }
}

public sealed class Regelsett
{
    [JsonPropertyName("versjon")] public string Versjon { get; set; } = "";
    [JsonPropertyName("produkter")] public List<Produkt> Produkter { get; set; } = new();
    [JsonPropertyName("pythonPakker")] public List<Pakke> PythonPakker { get; set; } = new();
    [JsonPropertyName("nodePakker")] public List<Pakke> NodePakker { get; set; } = new();
    /// <summary>NuGet-pakker med AI (Semantic Kernel, Microsoft.Extensions.AI, OpenAI …): i prosjektfiler og som DLL i programmer.</summary>
    [JsonPropertyName("dotnetPakker")] public List<Pakke> DotnetPakker { get; set; } = new();
    [JsonPropertyName("dockerBilder")] public List<DockerBilde> DockerBilder { get; set; } = new();
    [JsonPropertyName("ukjentUtvidelseOrd")] public List<string> UkjentUtvidelseOrd { get; set; } = new();
    [JsonPropertyName("modellfilMinMB")] public int ModellfilMinMB { get; set; } = 200;
    [JsonPropertyName("nettleserInnebygd")] public List<InnebygdAI> NettleserInnebygd { get; set; } = new();
    [JsonPropertyName("aiNettsteder")] public List<AiNettsted> AiNettsteder { get; set; } = new();
    /// <summary>AI-tjenester programmer snakker med i bakgrunnen (API-er), gjenkjent på vertsnavn.</summary>
    [JsonPropertyName("aiTjenester")] public List<AiNettsted> AiTjenester { get; set; } = new();
    /// <summary>Land der data om bedriften ikke bør havne. AI som sender hit blir rødt.</summary>
    [JsonPropertyName("hoyrisikoLand")] public List<string> HoyrisikoLand { get; set; } = new();
    /// <summary>AI bedriften har godkjent: navn (som i rapporten) eller domene. Blir grønt. Kan også ligge i godkjent-ai.txt ved siden av programmet.</summary>
    [JsonPropertyName("godkjentAi")] public List<string> GodkjentAi { get; set; } = new();
    /// <summary>AI bedriften har blokkert: navn eller domene, som godkjentAi. Finnes den likevel, blir den rød. Kan også ligge i blokkert-ai.txt.</summary>
    [JsonPropertyName("blokkertAi")] public List<string> BlokkertAi { get; set; } = new();
    /// <summary>Selskap -> land (to bokstaver), for «Kommer fra».</summary>
    [JsonPropertyName("selskapsland")] public Dictionary<string, string> Selskapsland { get; set; } = new();
    /// <summary>Hvor godkjentlista kom fra, for rapporten.</summary>
    [JsonIgnore] public string? GodkjentKilde { get; set; }
    [JsonIgnore] public string? BlokkertKilde { get; set; }
    [JsonPropertyName("modellfamilier")] public List<ModellFamilie> Modellfamilier { get; set; } = new();
    /// <summary>Ordforrådets navn i llama.cpp (GGUF tokenizer.ggml.pre) -> modellfamilie (navn).</summary>
    [JsonPropertyName("preTokenizer")] public Dictionary<string, string> PreTokenizer { get; set; } = new();
    [JsonPropertyName("modellFormaal")] public List<ModellFormaal> ModellFormaal { get; set; } = new();
    [JsonPropertyName("leverandorAi")] public List<LeverandorAi> LeverandorAi { get; set; } = new();
    /// <summary>Pakke- og utvidelsesversjoner som er kjent dårlige (stjal nøkler eller misbrukte AI-agenter). Blir «Ukjent AI-spor».</summary>
    [JsonPropertyName("daarligeVersjoner")] public List<DaarligVersjon> DaarligeVersjoner { get; set; } = new();
    [JsonPropertyName("daarligeUtvidelser")] public List<DaarligUtvidelse> DaarligeUtvidelser { get; set; } = new();
    /// <summary>AI-verktøy med kjente sikkerhetshull før en gitt versjon (CVE/GHSA). Blir «Ukjent AI-spor».</summary>
    [JsonPropertyName("saarbareVersjoner")] public List<SaarbarVersjon> SaarbareVersjoner { get; set; } = new();
    [JsonPropertyName("iocFiler")] public List<IocFil> IocFiler { get; set; } = new();
    [JsonPropertyName("iocDomener")] public List<IocDomene> IocDomener { get; set; } = new();
    /// <summary>false: IT har slått av lesing av kommandolinjer (tolkere og AI-programmer).</summary>
    [JsonPropertyName("lesKommandolinjer")] public bool? LesKommandolinjer { get; set; }

    /// <summary>Kilde reglene ble lastet fra, vises i vinduet.</summary>
    [JsonIgnore] public string Kilde { get; private set; } = "innebygd";

    private static readonly JsonSerializerOptions Valg = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>
    /// Bruker regler.json ved siden av programmet hvis den finnes (så bedriften kan tilpasse), ellers reglene som er
    /// bygd inn i programmet. Ikke når programmet ligger i brukerens profil (Nedlastinger o.l.), se Plattform.Sidefil.
    /// </summary>
    public static Regelsett Last(string? sti = null)
    {
        Regelsett r;
        sti ??= Plattform.Sidefil("regler.json");
        if (sti != null && File.Exists(sti))
        {
            r = JsonSerializer.Deserialize<Regelsett>(File.ReadAllText(sti), Valg) ?? new Regelsett();
            r.Kilde = sti;
        }
        else
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.regler.json")
                          ?? throw new InvalidOperationException("Mangler innebygde regler.");
            r = JsonSerializer.Deserialize<Regelsett>(s, Valg) ?? new Regelsett();
        }
        if (Plattform.Sidefil("godkjent-ai.txt") is { } godkjent) r.LesGodkjentliste(godkjent);
        if (Plattform.Sidefil("blokkert-ai.txt") is { } blokkert && r.LesListe(blokkert, r.BlokkertAi)) r.BlokkertKilde = blokkert;
        return r;
    }

    /// <summary>
    /// IT sin liste over godkjent AI: én per linje, navn (som i rapporten) eller domene. Linjer som starter med # er kommentarer.
    /// </summary>
    public void LesGodkjentliste(string sti) { if (LesListe(sti, GodkjentAi)) GodkjentKilde = sti; }

    /// <summary>Leser en liste med ett navn eller domene per linje inn i <paramref name="liste"/>. # er kommentar.</summary>
    public bool LesListe(string sti, List<string> liste)
    {
        if (!File.Exists(sti)) return false;
        try
        {
            foreach (var linje in File.ReadAllLines(sti))
            {
                var t = linje.Trim();
                if (t.Length == 0 || t.StartsWith("#")) continue;
                if (!liste.Contains(t, StringComparer.OrdinalIgnoreCase)) liste.Add(t);
            }
            return true;
        }
        catch { return false; }
    }
}
