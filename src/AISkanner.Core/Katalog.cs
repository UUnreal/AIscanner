using System.Text;

namespace AISkanner;

/// <summary>
/// Regelkatalogen (§9): hver regel har id, bevistype, kilde, verifisert, falsk-positiv-merknad og en positiv og en
/// negativ test. --kontroll kjører testene mot den ekte matchingen, så en regel som aldri kan treffe (skygget av en
/// annen) eller treffer for bredt, stopper bygget.
/// </summary>
public sealed partial class Skanner
{
    /// <summary>Alle regler i katalogen med testen som sier om en tekst treffer akkurat denne regelen.</summary>
    internal IEnumerable<(string Liste, Regelmeta Regel, Func<string, bool> Treffer)> Katalog()
    {
        foreach (var p in _regler.Produkter) yield return ("produkter", p, t => FinnRegel(t) == p || FinnRegel(t, utvidelse: true) == p);
        foreach (var p in _regler.PythonPakker) yield return ("pythonPakker", p, t => PythonAi.TryGetValue(t, out _) && string.Equals(t, p.Navn, StringComparison.OrdinalIgnoreCase));
        foreach (var p in _regler.NodePakker) yield return ("nodePakker", p, t => NodeAi.TryGetValue(t, out _) && string.Equals(t, p.Navn, StringComparison.OrdinalIgnoreCase));
        foreach (var b in _regler.DockerBilder) yield return ("dockerBilder", b, t => ErAiBilde(t) && new[] { b.Navn.ToLowerInvariant() }.Any(a => Bildetreff(t.ToLowerInvariant().Split(':')[0], a)));
    }

    private static (int Ok, int Alle) KatalogKontroll(Regelsett regler, StringBuilder sb)
    {
        int ok = 0, alle = 0;
        void Sjekk(bool riktig, string hva) { alle++; if (riktig) ok++; else sb.AppendLine($"FEIL  Regelkatalog: {hva}"); }
        var s = new Skanner(regler);
        var ider = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (liste, r, treffer) in s.Katalog())
        {
            var hvem = $"{liste}/{(r.Id.Length > 0 ? r.Id : "(uten id)")}";
            Sjekk(r.Id.Length > 0 && ider.Add(r.Id), $"{hvem}: mangler id eller id-en er dobbel");
            Sjekk(r.Bevistype.Length > 0 && !string.IsNullOrWhiteSpace(r.Kilde) && r.Verifisert != null && r.FpMerknad.Length > 0
                  && r.TestPositiv.Length > 0 && r.TestNegativ.Length > 0, $"{hvem}: mangler bevistype, kilde, verifisert, fpMerknad eller test");
            Sjekk(r.TestPositiv.Length > 0 && treffer(r.TestPositiv), $"{hvem}: positiv test «{r.TestPositiv}» treffer ikke regelen (skygget eller feil)");
            Sjekk(r.TestNegativ.Length > 0 && !treffer(r.TestNegativ), $"{hvem}: negativ test «{r.TestNegativ}» treffer regelen (for bred)");
        }
        // Status per kategori A–T (§5T): alltid 20, nektet tilgang → ACCESS_DENIED, ingen WSL og Docker → NOT_APPLICABLE
        var nektet = new List<(string, string, Utfall, int)> { ("Leter gjennom filene etter AI-modeller og AI-kode", "Mappe", Utfall.Nektet, 3), ("Spør lokale programmer om de er AI", "Port", Utfall.Lest, 1) };
        var ingen = new[] { new Sjekkstatus("Docker", "kjører ikke", 0), new Sjekkstatus("WSL", "ikke installert", 0) };
        var k1 = Kategoristatus.Regn(nektet, ingen, true);
        Sjekk(k1.Count == 20 && k1.Select(k => k.Bokstav).Distinct().Count() == 20, "ikke alle 20 kategoriene fikk én status");
        Sjekk(k1.First(k => k.Bokstav == "A").Kode == "ACCESS_DENIED" && k1.First(k => k.Bokstav == "N").Kode == "NOT_APPLICABLE"
              && k1.First(k => k.Bokstav == "J").Kode == "NOT_SCANNED", "nektet tilgang ble ikke ACCESS_DENIED, ingen WSL ikke NOT_APPLICABLE, eller uskannet ikke NOT_SCANNED");
        var k2 = Kategoristatus.Regn(new List<(string, string, Utfall, int)> { ("Ser etter ukjente AI-spor", "Fil", Utfall.Tidsgrense, 1) }, Array.Empty<Sjekkstatus>(), false);
        Sjekk(k2.First(k => k.Bokstav == "G").Kode == "TIME_LIMIT" && k2.First(k => k.Bokstav == "A").Kode == "UNSUPPORTED", "tidsgrense ble ikke TIME_LIMIT, eller ikke Windows ble ikke UNSUPPORTED");
        Sjekk(Kategoristatus.Regelalder("2026-01-01", new DateTime(2026, 6, 1)).Contains("over 90 dager") && !Kategoristatus.Regelalder("2026-05-20", new DateTime(2026, 6, 1)).Contains("over 90"),
            "regelalderen varsler ikke etter 90 dager (eller for tidlig)");
        return (ok, alle);
    }
}
