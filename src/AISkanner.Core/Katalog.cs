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
        return (ok, alle);
    }
}
