using System.Text;
using System.Text.Json;

namespace AISkanner;

public static class Rapport
{
    public const string Begrensning =
        "Skanneren finner kjente spor. Forbindelser vises bare mens programmene er åpne, og et tomt resultat betyr ikke at PC-en er fri for AI.";

    /// <summary>
    /// Rapport som ren tekst, for Notisblokk. Alle AI-funn med risiko og hvor de ble funnet.
    /// Nettleserfunn viser bare nettleser, profil og nettstedsnavn, aldri hele adresser.
    /// </summary>
    public static string Tekst(IReadOnlyList<Funn> liste, Skanner? skanner = null)
    {
        var sb = new StringBuilder();
        void L(string s = "") => sb.Append(s).Append("\r\n");
        string strek = new('-', 60);
        L("AI-SKANNER RAPPORT");
        L($"PC: {Environment.MachineName}   Bruker: {Environment.UserName}   Tid: {DateTime.Now:dd.MM.yyyy HH:mm}");
        int Ant(Risiko r) => liste.Count(f => f.Risiko == r);
        L($"Funnet: {liste.Count} AI   (høy risiko: {Ant(Risiko.Rod)}, middels: {Ant(Risiko.Gul)}, lav: {Ant(Risiko.Gronn)})");
        if (skanner != null)
            L(skanner.DataMalt ? $"Datamengde: målt av Windows i {skanner.MaleSekunder:0} sekunder under søket."
                               : "Datamengde: ikke målt (krever at programmet kjøres som administrator).");
        if (skanner != null)
            L(skanner.AiRegler.Count == 0 ? "AI-regler fra IT: ingen funnet." : "AI-regler fra IT: " + string.Join("; ", skanner.AiRegler) + ".");
        L(new string('=', 60));
        foreach (var (gruppe, tittel) in Grupper)
        {
            var del = liste.Where(f => f.Gruppe == gruppe).OrderBy(f => f.Risiko).ToList();
            L();
            L($"{tittel.ToUpperInvariant()} ({del.Count})");
            L(new string('=', 60));
            if (del.Count == 0) L("Ingen funn.");
        foreach (var f in del)
        {
            L();
            L($"[{Merke(f.Risiko)}] {f.Navn}");
            L($"  {f.Kort}");
            if (!string.IsNullOrEmpty(f.Rad)) L($"  Råd: {f.Rad}");
            foreach (var a in f.Advarsler.Skip(1)) L($"  Advarsel: {a}");
            if (f.Trafikk.Count > 0)
            {
                L("  Sender til nå:");
                foreach (var m in f.Trafikk) L($"    - {MalTekst(m)}");
            }
            if (f.Detaljer.Count > 0)
            {
                L("  Funnet her:");
                foreach (var d in f.Detaljer) L($"    - {d}");
            }
            foreach (var m in f.Merknader) L($"  Merk: {m}");
            L(strek);
        }
        }
        L();
        L(Begrensning);
        L("Land for IP-adresser: IP to Country Lite fra DB-IP.com (CC BY 4.0). For store skytjenester viser landet hvor serveren står.");
        return sb.ToString();
    }

    public static readonly (string Id, string Tittel)[] Grupper =
    {
        ("lokal", "Lokal AI (kjører på PC-en)"), ("nettleser", "AI i nettleseren"), ("skjult", "Skjult på PC-en (apper, agenter og bakgrunnsprogrammer)"),
    };

    private static string Merke(Risiko r) => r switch { Risiko.Rod => "HØY", Risiko.Gul => "MIDDELS", _ => "LAV" };

    public static string MalTekst(Mal m)
    {
        var deler = new List<string> { m.Adresse };
        if (m.Tjeneste != null && !m.Adresse.Contains(m.Tjeneste)) deler.Add(m.Tjeneste);
        deler.Add(m.Land == "LAN" ? "lokalt nett" : m.Land == "CDN" ? "via Cloudflare" : $"server i {IpLand.Navn(m.Land)}");
        if (m.EierLand != null && m.EierLand != m.Land) deler.Add($"selskap i {IpLand.Navn(m.EierLand)}");
        deler.Add(m.Antall == 1 ? "1 forbindelse" : $"{m.Antall} forbindelser");
        if (m.Ut != null) deler.Add($"sendt {Storrelse(m.Ut.Value)}, mottatt {Storrelse(m.Inn ?? 0)}");
        return string.Join(" · ", deler);
    }

    public static string Storrelse(long b)
    {
        var nb = new System.Globalization.CultureInfo("nb-NO");
        if (b < 1024) return $"{b} B";
        if (b < 1024 * 1024) return (b / 1024.0).ToString("0", nb) + " kB";
        if (b < 1024L * 1024 * 1024) return (b / 1048576.0).ToString(b < 10 * 1048576 ? "0.0" : "0", nb) + " MB";
        return (b / 1073741824.0).ToString("0.0", nb) + " GB";
    }

    public static string Json(IReadOnlyList<Funn> liste, Skanner? skanner = null) => JsonSerializer.Serialize(new
    {
        pc = Environment.MachineName,
        aiRegler = skanner?.AiRegler ?? new List<string>(),
        tid = DateTimeOffset.Now,
        funn = liste.Select(f => new
        {
            risiko = f.Risiko.ToString().ToLowerInvariant(),
            navn = f.Navn, gruppe = f.Gruppe, kort = f.Privat ? f.Enkelt : f.Kort, kategori = f.Kategori, enkelt = f.Enkelt, hvorfor = f.Hvorfor, rad = f.Rad,
            advarsler = f.Privat ? new List<string>() : f.Advarsler,
            hvor = f.Privat ? new List<string>() : f.Hvor,
            merknader = f.Privat ? new List<string>() : f.Merknader,
            detaljer = f.Privat ? new List<string>() : f.Detaljer,
            trafikk = f.Privat ? new List<Mal>() : f.Trafikk,
        }),
    }, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
}
