using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Siste steg i søket: hva slags AI hvert funn er, hvor det kommer fra, og den endelige risikoen.
///   Ukjent AI = alltid rød.
///   Skygge-AI = alltid rød. Skygge-AI er AI som ikke er lagt inn av Windows, en signert leverandør eller IT:
///     AI-nettsteder, nettleserutvidelser, agenter, kodeverktøy, AI-apper og modeller brukeren har lagt inn selv.
///   Godkjent av IT (godkjentAi i regler.json eller godkjent-ai.txt) = grønn, så lenge den ikke er ukjent eller farlig.
///     Godkjenning fjerner bare risikoen ved at AI-en ikke er godkjent. Faresignaler (åpen mot nettverket,
///     høyrisikoland, nedlastingsmappe, skjult kode) gjelder fortsatt: rød eller gul med grunnen.
///   AI fra Windows og signerte leverandører beholder risikoen fra søket.
/// </summary>
public static class Risikoregler
{

    /// <summary>Faresignaler som gjør en godkjent AI rød: andre kan bruke den, eller data havner der de ikke bør.</summary>
    private static readonly string[] RodeSignaler =
    {
        "Er åpen mot nettverket",
        "Minst én av tjenestene hører hjemme i et land",
        "Forkledd:",
        "Gjemt i en skjult datastrøm",
        "Fila er merket som skjult",
        "Kjører under et annet navn",
        "Åpen mot nettverket",
        "Deler en offentlig lenke",
        "Agent som kjører kommandoer uten å spørre",
        "Kjører kode som følger med modellen",
        "Koden er gjemt som base64",
        "Blokkert av IT",
    };

    /// <summary>Faresignaler som gjør en godkjent AI gul: den er ikke installert slik IT har godkjent den.</summary>
    private static readonly string[] GuleSignaler =
    {
        "Kjører fra en nedlastings",
        "Kan kjøre skjult kode",
        "Ligger i en nedlastings",
        "IT har blokkert modellen",
    };

    private static readonly HashSet<string> FraWindows = new(StringComparer.OrdinalIgnoreCase) { "AI-motorer i Windows' egne filer", "Windows Recall", "Microsoft Copilot" };

    public static void Bruk(IEnumerable<Funn> funn, Regelsett regler)
    {
        foreach (var f in funn)
        {
            var type = Type(f);
            bool ukjent = type.StartsWith("Ukjent", StringComparison.Ordinal);
            bool farlig = f.Navn.StartsWith("Farlig AI-modellfil", StringComparison.Ordinal)
                          || f.Advarsler.Any(a => a.StartsWith("Sender data til", StringComparison.Ordinal));
            OpprinnelseFraNavn(f, regler);
            // IT sin blokkeringsliste (samme sterke identitet som godkjentlista), og AI som IT har slått av med en regel
            bool blokkert = Godkjent(f, regler.BlokkertAi);
            if (blokkert) f.Advarsel("Blokkert av IT, men finnes på PC-en.");
            f.Godkjenning = blokkert || f.Bruk?.StartsWith("Blokkert av IT", StringComparison.Ordinal) == true
                            || f.Advarsler.Concat(f.Merknader).Any(a => a.StartsWith("IT har blokkert", StringComparison.Ordinal))
                ? "Blokkert av IT" : "Ikke vurdert";

            if (!ukjent && !farlig && !blokkert && Godkjent(f, regler.GodkjentAi))
            {
                f.Type = "Godkjent av IT";
                f.Godkjenning = "Godkjent av IT";
                var rod = f.Advarsler.FirstOrDefault(a => RodeSignaler.Any(s => a.StartsWith(s, StringComparison.Ordinal)));
                var gul = f.Advarsler.FirstOrDefault(a => GuleSignaler.Any(s => a.StartsWith(s, StringComparison.Ordinal)));
                f.Risiko = rod != null ? Risiko.Rod : gul != null ? Risiko.Gul : Risiko.Gronn;
                f.RisikoGrunn = (rod ?? gul) is { } signal
                    ? $"Godkjent av IT, men: {signal}"
                    : "Står på IT sin liste over godkjent AI.";
                continue;
            }
            f.Type = type;
            if (ukjent)
            {
                f.Risiko = Risiko.Rod;
                f.RisikoGrunn = f.Navn.StartsWith("Farlig", StringComparison.Ordinal)
                    ? "Modellfilen inneholder kode som kjører når den lastes."
                    : type == "Ukjent AI-spor"
                    ? "Ukjent AI-spor: vi vet ikke hvem som satte det opp eller hva det er brukt til."
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
            if (blokkert) { f.Risiko = Risiko.Rod; f.RisikoGrunn = "Blokkert av IT, men finnes på PC-en."; }
        }
    }

    public static bool ErSkygge(string type) => type is "AI-nettsted" or "Nettleserutvidelse" or "AI-agent" or "AI i kode" or "Nettleserflagg"
        or "Skygge-AI" or "AI-app" or "Lokal modell" or "Lokal AI-app" or "AI-nøkler";

    private static string Type(Funn f)
    {
        var k = f.Kategori;
        var d = f.Detaljer;
        if (f.Navn == "AI-regler fra IT") return "IT-regel";
        if (k == Skanner.SporKategori) return "Ukjent AI-spor";
        // "Lokal AI-server (...)" er navnet på et ukjent program som svarer som en AI-tjeneste (gjenkjente servere får sitt eget navn).
        // (k == "AI-server" slo aldri til: "AI-server" settes som lokasjon, ikke kategori.)
        if (f.Navn.StartsWith("Farlig AI-modellfil") || f.Navn.StartsWith("Ukjent") || f.Navn.StartsWith("Lokal AI-server", StringComparison.Ordinal)) return "Ukjent AI";
        if (f.Navn.StartsWith("Mulig AI-nettsted", StringComparison.Ordinal)) return "Ukjent AI-nettsted";
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
        // AI-app fra PC-produsenten eller en annen kjent leverandør, bekreftet med signatur (f.eks. Lenovo AI Now): ikke skygge-AI
        if (k.StartsWith("Lokal") && d.Any(Skanner.SignertAvKjent)) return "Fra leverandør";
        if (k.StartsWith("Lokal")) return "Lokal AI-app";
        return "Skygge-AI";
    }

    /// <summary>Står funnet på godkjentlista? Navn som i rapporten, eller et domene som funnet er knyttet til.</summary>
    public static bool Godkjent(Funn f, IReadOnlyCollection<string> liste)
    {
        if (liste.Count == 0) return false;
        // Sikkerhet: godkjenn bare på navn vi stoler på, altså navn fra regelsettet (gjenkjent produkt/utvidelse)
        // eller et gjenkjent nettsted. Et visningsnavn som kommer fra et filnavn, mappenavn eller en utvidelses
        // egen manifest.json kan en angriper styre – da kunne en ukjent utvidelse som kaller seg «<godkjent navn>»
        // blitt grønn. Slike navn godtas ikke her; de forblir røde (ukjent/skygge-AI).
        bool nettsted = f.Kategori.Contains("(nettsted)") && !f.Navn.StartsWith("Mulig AI-nettsted", StringComparison.Ordinal);
        bool trygtNavn = f.Regel != null || nettsted;
        var navn = Oversikt.Navn(f);
        foreach (var g in liste)
        {
            if (trygtNavn && (string.Equals(g, f.Navn, StringComparison.OrdinalIgnoreCase) || string.Equals(g, navn, StringComparison.OrdinalIgnoreCase))) return true;
            if (g.Contains('.') && !g.Contains(' '))
            {
                var re = new Regex(@"(?<![\w.-])(?:[\w-]+\.)*" + Regex.Escape(g) + @"(?![\w-])", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
                // Domene bare mot målte forbindelser (og nettstedsbevis), aldri mot filstier i Detaljer –
                // en modell i en mappe som tilfeldigvis heter et godkjent domene skal ikke bli grønn.
                if (f.Trafikk.Any(m => re.IsMatch(m.Adresse))) return true;
                if (nettsted && f.Detaljer.Any(x => re.IsMatch(x))) return true;
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
