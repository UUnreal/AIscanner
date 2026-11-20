using System.Globalization;

namespace AISkanner;

/// <summary>
/// Status per kategori i dekningskartet A–T (§5T). Regnes ut av utfallet til sjekkene som dekker kategorien:
/// SCANNED, PARTIAL, NOT_SCANNED, ACCESS_DENIED, TIME_LIMIT, UNSUPPORTED eller NOT_APPLICABLE. En kategori med kjent
/// hull i dekningen er PARTIAL selv om alt ble lest, og hullet står i begrensningen. Alle 20 får alltid én status.
/// </summary>
public static class Kategoristatus
{
    public sealed record Status(string Bokstav, string Navn, string Kode, string? Begrensning);

    // Sjekkene (stegnavn i Skanner.KjorAsync) som dekker hver kategori, og kjente hull. Fjern hullet når det er tettet.
    private static readonly (string B, string Navn, string[] Steg, string? Hull)[] Kart =
    {
        ("A", "AI-modeller", new[] { "Leter gjennom filene" }, "Endret metadata sjekkes ikke mot tensorstrukturen."),
        ("B", "Modellformater", new[] { "Leter gjennom filene" }, "MNN, RKNN og Caffe kjennes bare på endelsen (Mulig spor). Andre JAX-filer enn flax_model.msgpack kjennes ikke igjen."),
        ("C", "Bilde, lyd og video", new[] { "Leter gjennom filene", "Ser etter AI som kjører nå" }, "Deepfake og stemmekloning kjennes på programmer, mapper og pakker, ikke på tensornavn. Videomodeller (Wan, HunyuanVideo, LTX) kjennes på arkitektur og pakker, ikke på tensorstruktur."),
        ("D", "Kjøremotorer", new[] { "Ser etter AI som kjører nå", "Leter gjennom filene" }, "TensorFlow.js og WebNN kjennes ikke igjen. En motor alene er bare Mulig spor."),
        ("E", "Utviklermiljø", new[] { "Leter gjennom filene", "Ser etter AI-verktøy" }, "Avhengighetsfiler leses for Python og Node (bare pakkenavn); Cargo, go.mod, Maven, Gradle og .NET-prosjekter leses ikke. Jupyter-kjerner vises ikke."),
        ("F", "AI-apper og kodeagenter", new[] { "Sjekker installerte programmer", "Ser etter AI som kjører nå", "Ser etter AI-verktøy" }, "Cody, Qodo, Blackbox og Augment kjennes ikke igjen."),
        ("G", "Agenter og MCP", new[] { "Ser etter ukjente AI-spor", "Sjekker hva som starter av seg selv" }, null),
        ("H", "RAG og vektordatabaser", new[] { "Spør lokale programmer", "Leter gjennom filene" }, "Vektorfiler på disk kjennes ikke igjen på innholdet."),
        ("I", "Innebygd AI i programmer", new[] { "Leter etter AI som leverandører har lagt inn", "Sjekker registeret" }, "AI-motorer i programmer som ikke kjører, finnes bare via leverandørlista."),
        ("J", "Nettleser-AI", new[] { "Sjekker utvidelser i nettleserne", "Ser etter AI-nettsteder", "Sjekker innebygd AI i Chrome og Edge", "Ser etter AI-modeller som nettsider kjører" }, null),
        ("K", "Windows' egen AI", new[] { "Sjekker registeret", "Sjekker installerte programmer" }, "Copilot Studio, AI Builder og Designer kjennes ikke igjen."),
        ("L", "AI fra maskinvareprodusenter", new[] { "Leter etter AI som leverandører har lagt inn" }, null),
        ("M", "Tredjepartsprogrammer med AI", new[] { "Sjekker installerte programmer", "Sjekker utvidelser i nettleserne" }, "Rene skyfunksjoner (Webex, Slack, Box) gir bare navnetreff og tas ikke med."),
        ("N", "WSL, beholdere og VM-er", new[] { "Spør lokale programmer" }, "WSL leses bare når Linux allerede kjører (modeller, Python-miljøer, Claude Code og Gemini CLI). VM-disker åpnes aldri. Podman og Dev Containers vises ikke."),
        ("O", "Portabel og ukjent AI", new[] { "Leter gjennom filene" }, ".7z og .rar åpnes ikke."),
        ("P", "Nettverk", new[] { "Ser hvor AI sender data", "Spør lokale programmer" }, null),
        ("Q", "Identitet og rettigheter", new[] { "Ser etter AI som kjører nå", "Ser i Windows' historikk" }, null),
        ("R", "Opprinnelse", new[] { "Leter gjennom filene" }, "Avstamning utover base_model og lisens for safetensors leses ikke."),
        ("S", "Sikkerhet", new[] { "Ser etter ukjente AI-spor", "Leter gjennom filene" }, "Utgåtte versjoner (EOL), typosquatting og kjente ondsinnede hasher sjekkes ikke."),
        ("T", "Dekning", Array.Empty<string>(), null),
    };

    public static List<Status> Regn(IEnumerable<(string Sjekk, string Hva, Utfall Utfall, int Antall)> antall, IReadOnlyList<Sjekkstatus> sjekker, bool windows)
    {
        var liste = antall.ToList();
        var ut = new List<Status>();
        foreach (var (b, navn, steg, hull) in Kart)
        {
            if (b == "T") { ut.Add(new(b, navn, "SCANNED", null)); continue; }
            var mine = liste.Where(x => steg.Any(s => x.Sjekk.StartsWith(s, StringComparison.Ordinal))).ToList();
            int N(Func<Utfall, bool> u) => mine.Where(x => u(x.Utfall)).Sum(x => x.Antall);
            int lest = N(u => u is Utfall.Lest or Utfall.IkkeFunnet or Utfall.Dekket or Utfall.HoppetOver);
            int nektet = N(u => u is Utfall.Nektet or Utfall.Laast or Utfall.Blokkert);
            int tid = N(u => u == Utfall.Tidsgrense), feil = N(u => u == Utfall.Feil);
            string kode;
            if (b == "N" && sjekker.Any(x => x.Navn == "Docker" && x.Tekst == "kjører ikke") && sjekker.Any(x => x.Navn == "WSL" && x.Tekst == "ikke installert")) kode = "NOT_APPLICABLE";
            else if (mine.Count == 0) kode = windows ? "NOT_SCANNED" : "UNSUPPORTED";
            else if (lest == 0 && nektet > 0) kode = "ACCESS_DENIED";
            else if (tid > 0) kode = "TIME_LIMIT";
            else if (nektet > 0 || feil > 0 || hull != null) kode = "PARTIAL";
            else kode = "SCANNED";
            var grunn = new List<string>();
            if (nektet > 0 && kode != "ACCESS_DENIED") grunn.Add($"{nektet} steder uten tilgang");
            if (tid > 0) grunn.Add("tidsgrensen ble nådd");
            if (feil > 0) grunn.Add($"{feil} lesefeil");
            if (hull != null) grunn.Add(hull);
            ut.Add(new(b, navn, kode, grunn.Count > 0 ? string.Join(" · ", grunn) : null));
        }
        return ut;
    }

    /// <summary>«Reglene er fra …», og etter 90 dager en lenke til ny versjon (ingen oppslag på nett).</summary>
    public static string Regelalder(string versjon, DateTime na)
    {
        if (!DateTime.TryParseExact(versjon.Length >= 10 ? versjon.Substring(0, 10) : versjon, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d))
            return $"Reglene er versjon {versjon}.";
        var t = $"Reglene er fra {d:dd.MM.yyyy}.";
        return (na - d).TotalDays > 90 ? t + " De er over 90 dager gamle: hent ny versjon på https://findhiddenai.com" : t;
    }
}
