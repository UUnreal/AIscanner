using System.Text;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Hvilken kjent risiko et funn hører til: OWASP Top 10 for LLM (2025), OWASP Top 10 for Agentic Applications (2026)
/// og MITRE ATLAS. Merkene kommer bare fra det funnet faktisk viser (advarslene og linjene med kilde), aldri fra navnet
/// på produktet. ATLAS-ID-ene står allerede i angrepsreglene (ATR, SigmaHQ) og hentes ut derfra.
/// Kilder: https://genai.owasp.org/llm-top-10/ · https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ · https://atlas.mitre.org/
/// </summary>
public static class Rammeverk
{
    private const RegexOptions Ri = RegexOptions.IgnoreCase | RegexOptions.Compiled;

    private const string Llm01 = "OWASP LLM01 Prompt Injection", Llm02 = "OWASP LLM02 Sensitive Information Disclosure",
        Llm03 = "OWASP LLM03 Supply Chain", Llm06 = "OWASP LLM06 Excessive Agency", Llm10 = "OWASP LLM10 Unbounded Consumption",
        Asi01 = "OWASP ASI01 Agent Goal Hijack", Asi02 = "OWASP ASI02 Tool Misuse and Exploitation", Asi03 = "OWASP ASI03 Identity and Privilege Abuse",
        Asi04 = "OWASP ASI04 Agentic Supply Chain Vulnerabilities", Asi05 = "OWASP ASI05 Unexpected Code Execution", Asi10 = "OWASP ASI10 Rogue Agents",
        T0010 = "ATLAS AML.T0010 AI Supply Chain Compromise", T0011 = "ATLAS AML.T0011 User Execution", T0040 = "ATLAS AML.T0040 AI Model Inference API Access",
        T0051 = "ATLAS AML.T0051 LLM Prompt Injection";

    /// <summary>Tekst i advarsler, regelnavn fra Vakt og linjer med kilde → merkene de svarer til.</summary>
    internal static readonly (Regex Monster, string[] Merker)[] Kart =
    {
        // Injeksjon i filer agenter leser
        (new(@"skjulte tegn i en instruksjonsfil|^Instruksjonsfil for AI-agenter som|^Ferdighet for AI-agent som", Ri), new[] { Llm01, Asi01, T0051 }),
        // For mye handlefrihet
        (new(@"«Godkjenn alt»|«tillat alltid»|starter av seg selv uten å spørre|^MCP-server «", Ri), new[] { Llm06, Asi02 }),
        (new(@"Kan se alt på alle nettsider", Ri), new[] { Llm06, Llm02 }),
        // Agentoppsett som følger med prosjekter og kjører kode
        (new(@"^Hooks i en prosjektmappe|^Kommando som kjører av seg selv når prosjektet åpnes|^MCP-oppsett i en prosjektmappe", Ri), new[] { Asi04, Asi05 }),
        // Forsyningskjede
        (new(@"kjente dårlige versjoner|lista over dårlige utvidelser|kjent fil fra AI-misbruk|versjon med kjent sikkerhetshull|legger til ferdigheter", Ri), new[] { Llm03, Asi04, T0010 }),
        (new(@"^YARA: AI_(Pickle_kjorer_kommando|Pickle_nettverk|Pickle_farlig_import|Keras_Lambda|GGUF_mal_med_kode|Modell_med_program|Modell_med_skall)\b|^Kan kjøre skjult kode", Ri), new[] { Llm03, Asi05, T0011 }),
        // AI-server andre kan bruke
        (new(@"åpen mot nettverket|lytter på alle nettverkskort|^Andre maskiner (bruker|har kjørt)|^Ukjent program bruker den lokale AI-modellen", Ri), new[] { Llm10, T0040 }),
        // Data ut
        (new(@"^Sender data til|land der dataene ikke bør havne|^Ukjent program med forbindelse til|^AI-adressen er byttet|^Har tatt opp skjermen|sender filer ut|slår opp en uttakstjeneste", Ri), new[] { Llm02 }),
        // Nøkler og rettigheter
        (new(@"API-nøkkel|AI-nøkkel|henter Windows' passordlager|lager bruker eller svekker vernet|åpnet (SSH-nøkkel|AWS-nøkler|Kubernetes-tilgang|Docker-innlogging|Git-passord|Windows' passordlager|Windows' kontodatabase|nettleserens passord|kryptolommebok|innlogging for AI)", Ri), new[] { Asi03 }),
        // Kode som kjører uventet
        (new(@"skjult eller kodet PowerShell|laster ned med Windows-verktøy|kobler et skall til nettet|henter fra en IP-adresse uten navn|kobler til en IP-adresse uten navn|Koden er gjemt som base64", Ri), new[] { Asi05 }),
        (new(@"sletter alt i en mappe|sender filer ut", Ri), new[] { Asi02 }),
        // Agenter som går sine egne veier
        (new(@"agentøkt uten menneske|Flere AI-agenter startet uten menneske|lager planlagt oppgave eller autostart|sletter spor|AI-agent endret agentoppsett", Ri), new[] { Asi10 }),
        (new(@"startet minst 150 programmer på ett minutt", Ri), new[] { Llm06 }),
        (new(@"instruksjonsfil for AI-agenter kom i Nedlastinger|^Instruksjonsfil for AI-agenter i en nedlastingsmappe", Ri), new[] { Llm01, Asi01 }),
    };

    private static readonly Regex AtlasId = new(@"\bAML\.T\d{4}(?:\.\d{3})?\b", RegexOptions.Compiled);

    /// <summary>OWASP-merkene for én tekst (advarsel, Vakt-regel eller linje).</summary>
    internal static IEnumerable<string> Owasp(string tekst) =>
        Kart.Where(k => k.Monster.IsMatch(tekst)).SelectMany(k => k.Merker).Where(m => m.StartsWith("OWASP", StringComparison.Ordinal));

    /// <summary>Kilden til en Vakt-hendelse med OWASP-merkene lagt til, så risikoen vises live.</summary>
    public static string MedOwasp(string regel, string kilde)
    {
        var o = Owasp(regel).Distinct().Select(m => m.Substring(6, m.IndexOf(' ', 6) - 6)).ToList();
        return o.Count == 0 ? kilde : $"{kilde} · OWASP {string.Join(", ", o)}";
    }

    /// <summary>Alle merker for et funn: OWASP først, så ATLAS. Tom når funnet ikke viser noe som svarer til en kjent risiko.</summary>
    public static List<string> For(Funn f)
    {
        List<string> tekster;
        lock (f) tekster = f.Advarsler.Concat(f.Detaljer).ToList();
        var merker = new List<string>();
        foreach (var t in tekster)
        {
            foreach (var (m, ms) in Kart)
                if (m.IsMatch(t)) merker.AddRange(ms);
            // ATLAS-ID fra angrepsreglene (ATR, SigmaHQ) i linjer med kilde
            foreach (Match a in AtlasId.Matches(t))
                merker.Add("ATLAS " + a.Value);
        }
        // «ATLAS AML.T0051» fra en regel og «ATLAS AML.T0051 LLM Prompt Injection» fra kartet er samme teknikk
        merker = merker.Distinct().Where(m => !(m.StartsWith("ATLAS ", StringComparison.Ordinal) && m.Split(' ').Length == 2
            && merker.Any(x => x.Length > m.Length && x.StartsWith(m + " ", StringComparison.Ordinal)))).ToList();
        return merker.OrderBy(m => m.StartsWith("OWASP LLM", StringComparison.Ordinal) ? 0 : m.StartsWith("OWASP ASI", StringComparison.Ordinal) ? 1 : 2)
            .ThenBy(m => m, StringComparer.Ordinal).ToList();
    }

    /// <summary>Kort form til vinduet: «OWASP LLM06, ASI02 · ATLAS AML.T0051».</summary>
    public static string Kort(IReadOnlyList<string> merker)
    {
        var owasp = merker.Where(m => m.StartsWith("OWASP ", StringComparison.Ordinal)).Select(m => m.Split(' ')[1]).ToList();
        var atlas = merker.Where(m => m.StartsWith("ATLAS ", StringComparison.Ordinal)).Select(m => m.Split(' ')[1]).Distinct().ToList();
        return string.Join(" · ", new[] { owasp.Count > 0 ? "OWASP " + string.Join(", ", owasp) : null, atlas.Count > 0 ? "ATLAS " + string.Join(", ", atlas) : null }.Where(x => x != null));
    }
}

public sealed partial class Skanner
{
    /// <summary>Kontroll av merkene: riktig OWASP/ATLAS for kjente advarsler og Vakt-linjer, ingen merker på vanlige funn.</summary>
    private static (int Ok, int Alle) RammeverkKontroll(StringBuilder sb)
    {
        int ok = 0, alle = 0;
        void Sjekk(bool riktig, string hva) { alle++; if (riktig) ok++; else sb.AppendLine($"FEIL  Kjent risiko: {hva}"); }
        Funn Med(string? advarsel, params string[] detaljer)
        {
            var f = new Funn { Navn = "kontroll", Kategori = "Skygge-AI", Hvorfor = "x" };
            if (advarsel != null) f.Advarsel(advarsel);
            foreach (var d in detaljer) f.Detalj(d);
            return f;
        }
        var godkjenn = Rammeverk.For(Med("«Godkjenn alt» er slått på i en prosjektmappe: gjelder alle som åpner prosjektet."));
        Sjekk(godkjenn.Contains("OWASP LLM06 Excessive Agency") && godkjenn.Contains("OWASP ASI02 Tool Misuse and Exploitation"), "«Godkjenn alt» ga ikke LLM06 og ASI02");
        var injeksjon = Rammeverk.For(Med("3 skjulte tegn i en instruksjonsfil for AI-agenter.", "Mønster: ATLAS AML.T0051"));
        Sjekk(injeksjon.Contains("OWASP LLM01 Prompt Injection") && injeksjon.Count(m => m.StartsWith("ATLAS AML.T0051", StringComparison.Ordinal)) == 1, "skjulte tegn ga ikke LLM01 og én ATLAS AML.T0051");
        var vakt = Rammeverk.For(Med("Sett live: AI-agent gjorde noe kjent fra angrep.", "12:00:00 · sender filer ut · Program: curl.exe (PID 1) · Regel: ATR-2026-02261 · ATLAS AML.T0086"));
        Sjekk(vakt.Contains("OWASP LLM02 Sensitive Information Disclosure") && vakt.Contains("OWASP ASI02 Tool Misuse and Exploitation") && vakt.Contains("ATLAS AML.T0086"), "Vakt «sender filer ut» ga feil merker");
        Sjekk(Rammeverk.For(Med(null, "12:00:00 · åpnet SSH-nøkkel · Program: node.exe (PID 2)")).Contains("OWASP ASI03 Identity and Privilege Abuse"), "agent som åpnet SSH-nøkkel ga ikke ASI03");
        Sjekk(Rammeverk.For(Med("AI-serveren lytter på alle nettverkskort (port 11434) og kan nås fra andre maskiner på nettet.")).Contains("ATLAS AML.T0040 AI Model Inference API Access"), "åpen AI-server ga ikke ATLAS AML.T0040");
        Sjekk(Rammeverk.For(Med(null, "YARA: AI_Pickle_farlig_import · Modellen henter inn moduler")).Contains("OWASP LLM03 Supply Chain"), "farlig pickle ga ikke LLM03");
        Sjekk(Rammeverk.MedOwasp("sender filer ut", "ATR-2026-02261 · ATLAS AML.T0086") == "ATR-2026-02261 · ATLAS AML.T0086 · OWASP LLM02, ASI02", "Vakt-kilden live fikk ikke OWASP");
        Sjekk(Rammeverk.MedOwasp("agentoppsett endret", "ATR-2026-00200") == "ATR-2026-00200", "vanlig Vakt-hendelse fikk OWASP");
        Sjekk(Rammeverk.For(Med(null, @"Fil: C:\Users\x\.ollama\models\blobs\sha256-ab · GGUF · 4,7 GB", "Installert program: Ollama")).Count == 0, "vanlig modell fikk merker");
        Sjekk(Rammeverk.Kort(vakt) == "OWASP LLM02, ASI02 · ATLAS AML.T0086", $"kortform ble feil: {Rammeverk.Kort(vakt)}");
        return (ok, alle);
    }
}
