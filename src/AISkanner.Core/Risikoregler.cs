using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Siste steg i søket: hva slags AI hvert funn er, hvor det kommer fra, og den endelige risikoen.
///   Ukjent AI = alltid rød.
///   Skygge-AI = alltid rød. Skygge-AI er AI som ikke er lagt inn av Windows, en signert leverandør eller IT:
///     AI-nettsteder, nettleserutvidelser, agenter, kodeverktøy, AI-apper og modeller brukeren har lagt inn selv.
///   Godkjent av IT (godkjentAi i regler.json eller godkjent-ai.txt) = grønn, så lenge den ikke er ukjent eller farlig.
///   AI fra Windows og signerte leverandører beholder risikoen fra søket.
/// </summary>
public static class Risikoregler
{
    public const string SkyggeDefinisjon = "AI som ikke er lagt inn av Windows, en signert leverandør eller IT.";

    private static readonly HashSet<string> FraWindows = new(StringComparer.OrdinalIgnoreCase) { "Windows Recall", "Microsoft Copilot" };

    public static void Bruk(IEnumerable<Funn> funn, Regelsett regler)
    {
        foreach (var f in funn)
        {
            var type = Type(f);
            bool ukjent = type.StartsWith("Ukjent", StringComparison.Ordinal);
            bool farlig = f.Navn.StartsWith("Farlig AI-modellfil", StringComparison.Ordinal)
                          || f.Advarsler.Any(a => a.StartsWith("Sender data til", StringComparison.Ordinal));
            OpprinnelseFraNavn(f, regler);

            if (!ukjent && !farlig && Godkjent(f, regler.GodkjentAi))
            {
                f.Type = "Godkjent av IT";
                f.Risiko = Risiko.Gronn;
                f.RisikoGrunn = "Står på IT sin liste over godkjent AI.";
                continue;
            }
            f.Type = type;
            if (ukjent)
            {
                f.Risiko = Risiko.Rod;
                f.RisikoGrunn = f.Navn.StartsWith("Farlig", StringComparison.Ordinal)
                    ? "Modellfilen inneholder kode som kjører når den lastes."
                    : "Ukjent AI: vi vet ikke hvem som har laget den eller hva den gjør.";
            }
            else if (ErSkygge(type))
            {
                f.Risiko = Risiko.Rod;
                f.RisikoGrunn = "Skygge-AI: ikke lagt inn av Windows, en signert leverandør eller IT.";
            }
            else f.RisikoGrunn ??= f.Kort;
            // Data til et høyrisikoland er alltid rødt, uansett type
            if (farlig && f.Risiko != Risiko.Rod) f.Risiko = Risiko.Rod;
            if (farlig && f.Advarsler.FirstOrDefault(a => a.StartsWith("Sender data til")) is { } adv) f.RisikoGrunn = adv;
        }
    }

    public static bool ErSkygge(string type) => type is "AI-nettsted" or "Nettleserutvidelse" or "AI-agent" or "AI i kode" or "Nettleserflagg"
        or "Skygge-AI" or "AI-app" or "Lokal modell" or "Lokal AI-app" or "AI-nøkler";

    private static string Type(Funn f)
    {
        var k = f.Kategori;
        var d = f.Detaljer;
        if (f.Navn == "AI-regler fra IT") return "IT-regel";
        if (f.Navn.StartsWith("Farlig AI-modellfil") || f.Navn.StartsWith("Ukjent") || k == "AI-server") return "Ukjent AI";
        if (f.Navn.StartsWith("Mulige AI-nettsteder")) return "Ukjent AI-nettsted";
        if (d.Any(x => x.StartsWith("Utgiver: ukjent"))) return "Ukjent AI";
        if (d.Any(x => x.StartsWith("Utgiver:") && x.Contains("ikke bekreftet"))) return "Ukjent AI";
        if (k.StartsWith("Lokal AI (modell)") && d.Any(x => x.StartsWith("Familie ukjent"))) return "Ukjent AI";
        if (k.StartsWith("Innebygd AI fra leverandør (nettleser)")) return "Innebygd i nettleser";
        if (k.StartsWith("Innebygd AI fra leverandør")) return "Fra leverandør";
        if (FraWindows.Contains(f.Navn)) return "Fra Windows";
        if (k == "Regler") return "IT-regel";
        if (k.Contains("(nettsted)")) return "AI-nettsted";
        if (k.StartsWith("Nettleser")) return "Nettleserutvidelse";
        if (k.StartsWith("Skygge-AI (agent)")) return "AI-agent";
        if (k.StartsWith("Skygge-AI (utvikling)")) return "AI i kode";
        if (k.StartsWith("Skygge-AI (nettleserflagg)")) return "Nettleserflagg";
        if (f.Navn.StartsWith("AI-nøkler")) return "AI-nøkler";
        if (k.StartsWith("Skygge-AI")) return f.Hvor.Any(h => h.Contains("kodeeditor")) ? "AI i kode" : "AI-app";
        if (k.StartsWith("Lokal AI (modell)") || k == "Disk") return "Lokal modell";
        if (k.StartsWith("Lokal")) return "Lokal AI-app";
        return "Skygge-AI";
    }

    /// <summary>Står funnet på godkjentlista? Navn som i rapporten, eller et domene som funnet er knyttet til.</summary>
    public static bool Godkjent(Funn f, IReadOnlyCollection<string> liste)
    {
        if (liste.Count == 0) return false;
        var navn = Oversikt.Navn(f);
        foreach (var g in liste)
        {
            if (string.Equals(g, f.Navn, StringComparison.OrdinalIgnoreCase) || string.Equals(g, navn, StringComparison.OrdinalIgnoreCase)) return true;
            if (g.Contains('.') && !g.Contains(' '))
            {
                var re = new Regex(@"(?<![\w.-])(?:[\w-]+\.)*" + Regex.Escape(g) + @"(?![\w-])", RegexOptions.IgnoreCase);
                if (f.Detaljer.Any(x => re.IsMatch(x)) || f.Trafikk.Any(m => re.IsMatch(m.Adresse))) return true;
            }
        }
        return false;
    }

    /// <summary>Kommer fra: utgiveren fra signaturen, eller et kjent selskap i navnet.</summary>
    private static void OpprinnelseFraNavn(Funn f, Regelsett regler)
    {
        if (f.Opprinnelse == null)
        {
            var utgiver = f.Detaljer.FirstOrDefault(x => x.StartsWith("Utgiver:") && !x.StartsWith("Utgiver: ukjent"));
            if (utgiver != null) f.Opprinnelse = utgiver.Substring(8).Split(new[] { " · " }, StringSplitOptions.None)[0].Trim();
        }
        foreach (var kilde in new[] { f.Opprinnelse, Oversikt.Navn(f) })
        {
            if (string.IsNullOrEmpty(kilde)) continue;
            // Første kjente navn i teksten vinner: "Sider: ChatGPT Sidebar" kommer fra Sider, ikke OpenAI
            var treff = regler.Selskapsland
                .Select(x => (x.Key, x.Value, M: Regex.Match(kilde!, @"(?<![\p{L}\d])" + Regex.Escape(x.Key) + @"(?![\p{L}\d])", RegexOptions.IgnoreCase)))
                .Where(x => x.M.Success).OrderBy(x => x.M.Index).ThenByDescending(x => x.Key.Length).FirstOrDefault();
            if (treff.Key != null)
            {
                var (nokkel, verdi) = (treff.Key, treff.Value);
                {
                    // "US" eller "US:Anthropic" (produktnavn -> selskap)
                    var deler = verdi.Split(new[] { ':' }, 2);
                    f.OpprinnelseLand ??= deler[0];
                    f.Opprinnelse ??= deler.Length > 1 ? deler[1] : nokkel;
                    return;
                }
            }
        }
    }

    /// <summary>Landene dataene går til (to bokstaver): målte forbindelser, tjenestens land og oppslag Windows har gjort.</summary>
    public static List<string> SenderTil(Funn f)
    {
        var ut = new List<string>();
        void Legg(string? k) { if (!string.IsNullOrEmpty(k) && k is not "LAN" and not "CDN" && !ut.Contains(k!)) ut.Add(k!); }
        foreach (var m in f.Trafikk) Legg(m.EierLand ?? m.Land);
        if (f.Type is "AI-nettsted" or "Ukjent AI-nettsted" || f.Kategori.Contains("(nettsted)")) Legg(f.Land);
        foreach (var k in f.SenderTil) Legg(k);
        return ut;
    }

    /// <summary>Når ingen land er kjent: kjører den bare lokalt, eller er den bare ikke sett sende noe under søket?</summary>
    public static string IngenLand(Funn f) =>
        f.Type is "Lokal modell" or "Lokal AI-app" or "Innebygd i nettleser" || f.Kategori.StartsWith("Lokal") ? "Ingen · lokalt" : "Ikke sett";
}
