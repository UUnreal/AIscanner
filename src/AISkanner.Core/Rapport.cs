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
    public static string Tekst(IReadOnlyList<Funn> liste, Skanner? skanner = null, bool engelsk = false)
    {
        var sb = new StringBuilder();
        void L(string s = "") => sb.Append(engelsk ? Engelsk.Til(s) : s).Append("\r\n");
        // Linjer som allerede er på riktig språk (tabellen og navn), skal ikke gjennom oversettelsen
        void Ra(string s) => sb.Append(s).Append("\r\n");
        string T(string s) => engelsk ? Engelsk.Til(s)! : s;
        string strek = new('-', 60);
        L("AI-SKANNER RAPPORT");
        Ra($"PC: {Environment.MachineName}   {(engelsk ? "User" : "Bruker")}: {Environment.UserName}");
        L($"Søket kjørt: {(skanner?.Startet ?? DateTime.Now):dd.MM.yyyy HH:mm:ss}   Rapport laget: {DateTime.Now:dd.MM.yyyy HH:mm:ss}");
        L($"Søkt som: {(Nettverk.ErAdmin() ? "administrator (mer data)" : "bruker (mindre data, uten datamengde og programmer som kjører som administrator)")}");
        int Ant(Risiko r) => liste.Count(f => f.Risiko == r);
        L($"Funnet: {Oversikt.TellingTekst(liste)}");
        L($"Funn i lista: {liste.Count}   (🔴 høy risiko: {Ant(Risiko.Rod)}, 🟡 middels: {Ant(Risiko.Gul)}, 🟢 lav: {Ant(Risiko.Gronn)})");
        if (skanner != null)
            L(skanner.DataMalt ? $"Datamengde: målt av Windows i {skanner.MaleSekunder:0} sekunder under søket."
                               : "Datamengde: ikke målt (krever at programmet kjøres som administrator).");
        if (skanner != null && skanner.Tider.TryGetValue("Totalt", out var totalt))
        {
            var treg = skanner.Tider.Where(t => t.Key != "Totalt").OrderByDescending(t => t.Value).Take(3)
                              .Select(t => $"{t.Key} {t.Value.TotalSeconds:0.0} s");
            L($"Søketid: {totalt.TotalSeconds:0.0} sekunder (tregest: {string.Join(", ", treg)}).");
        }
        if (skanner != null)
            L($"YARA-regler for AI-modeller: {skanner.Yara.Regler.Count} regler ({(skanner.Yara.Kilde == "innebygd" ? "innebygde" : skanner.Yara.Kilde)}).");
        if (skanner != null)
            L(skanner.AiRegler.Count == 0 ? "AI-regler fra IT: ingen funnet." : "AI-regler fra IT: " + string.Join("; ", skanner.AiRegler) + ".");
        if (skanner != null) L(Revisjon.Kortversjon(skanner));
        int spor = liste.Count(f => f.Gruppe == "spor");
        L(spor > 0 ? $"Ukjente AI-spor: fant spor ({spor})." : "Ukjente AI-spor: fant ingen spor.");
        if (skanner != null) L(skanner.LyttetSekunder > 0
            ? $"Nettverk: lyttet i {skanner.LyttetSekunder:0} sekunder (TCP-tabellen hvert 250. ms). UDP og QUIC (HTTP/3) vises ikke."
            : "Nettverk: ett øyeblikksbilde av TCP-tabellen. UDP og QUIC (HTTP/3) vises ikke.");
        if (skanner != null) foreach (var b in skanner.Blindsoner) L($"Blindsone: {b}");
        L(Revisjon.IngenAi);
        L(new string('=', 60));
        // Oversikten: én linje per AI, samme som på skjermen. Detaljene følger under.
        if (liste.Count > 0)
        {
            L();
            L("OVERSIKT");
            Ra(engelsk ? $"{"Risk",-12}{"AI model",-38}{"Location",-26}Key point" : $"{"Risiko",-12}{"AI-modell",-38}{"Lokasjon",-26}Viktigst");
            L(new string('-', 99));
            foreach (var f in liste.OrderBy(f => f.Risiko))
                Ra($"{T(Merke(f.Risiko)),-12}{Klipp(T(Oversikt.Navn(f)), 36),-38}{Klipp(T(Oversikt.Lokasjon(f)), 24),-26}{T(Oversikt.Punkt(f))}");
        }
        foreach (var (gruppe, tittel) in Grupper)
        {
            var del = liste.Where(f => f.Gruppe == gruppe).OrderBy(f => f.Risiko).ToList();
            L();
            L($"{tittel.ToUpperInvariant()} ({del.Count})");
            L(new string('=', 60));
            if (del.Count == 0) L(gruppe == "spor" ? "Fant ingen spor." : "Ingen funn.");
        foreach (var f in del)
        {
            L();
            L($"[{Merke(f.Risiko)}] {f.Navn}");
            L($"  {f.Kort}");
            if (f.Sist != null)
                L(f.Forst != null && f.Forst.Value.Date != f.Sist.Value.Date ? $"  Tid: først {Skanner.Tid(f.Forst)}, sist {Skanner.Tid(f.Sist)}" : $"  Tid: {Skanner.Tid(f.Sist)}");
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
        ("spor", "Ukjente AI-spor (oppsett og logger med ukjent opphav)"),
    };

    private static string Klipp(string s, int maks) => s.Length <= maks ? s : s.Substring(0, maks - 1) + "…";

    internal static string Merke(Risiko r) => r switch { Risiko.Rod => "🔴 HØY", Risiko.Gul => "🟡 MIDDELS", _ => "🟢 LAV" };

    public static string MalTekst(Mal m)
    {
        var deler = new List<string> { m.Adresse };
        if (m.Tjeneste != null && !m.Adresse.Contains(m.Tjeneste)) deler.Add(m.Tjeneste);
        deler.Add(m.Land == "LAN" ? "lokalt nett" : m.Land == "CDN" ? $"tjenesten skjuler IP-en (bak {m.Cdn ?? "CDN"})" : $"server i {IpLand.Navn(m.Land)}");
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
            navn = f.Navn, gruppe = f.Gruppe, kort = f.Kort, kategori = f.Kategori, enkelt = f.Enkelt, hvorfor = f.Hvorfor, punkt = Oversikt.Punkt(f), lokasjon = Oversikt.Lokasjon(f), type = f.Type, kommerFra = f.Opprinnelse, kommerFraLand = f.OpprinnelseLand, senderTil = Risikoregler.SenderTil(f), risikoGrunn = f.RisikoGrunn,
            // Nettleserfunn er med, som i tekstrapporten: AI-domene, nettleser og profil, antall besøk, første og siste gang.
            // Aldri hele adresser eller sidetitler: de leses aldri inn i minnet som funn.
            forst = f.Forst, sist = f.Sist,
            advarsler = f.Advarsler,
            hvor = f.Hvor,
            merknader = f.Merknader,
            detaljer = f.Detaljer,
            trafikk = f.Trafikk,
        }),
    }, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
}
