using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Svake spor etter samme ukjente program (en DNS-hendelse, AI-biblioteker i Prefetch, en tilkobling, modeller i mappa)
/// blir ett «Ukjent AI»-funn. Hvert spor står fortsatt som egen linje under «Funnet her», og sammen gir de flere
/// uavhengige spor og dermed høyere treffsikkerhet. Kjente produkter (regler) slås aldri sammen her.
/// </summary>
public sealed partial class Skanner
{
    private static readonly Regex ExeSti = new(@"[A-Za-z]:\\[^·""|<>\r\n]*?\.exe\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    internal static bool ErUkjentProgram(Funn f) =>
        f.Regel == null && (f.Gruppe == "spor" || f.Navn.StartsWith("Program som har slått opp AI:", StringComparison.Ordinal)
                            || f.Navn.StartsWith("Ukjent program", StringComparison.Ordinal));

    internal void SlaSammenSpor()
    {
        List<Funn> kandidater;
        lock (_funn) kandidater = _funn.Values.Where(ErUkjentProgram).ToList();
        var perProgram = new Dictionary<string, List<Funn>>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in kandidater)
        {
            List<string> d;
            lock (f) d = f.Detaljer.ToList();
            foreach (var sti in d.SelectMany(x => ExeSti.Matches(x).Cast<Match>().Select(m => m.Value.Trim())).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!perProgram.TryGetValue(sti, out var l)) perProgram[sti] = l = new();
                if (!l.Contains(f)) l.Add(f);
            }
        }
        var tatt = new HashSet<Funn>();
        foreach (var (sti, liste) in perProgram.OrderByDescending(x => x.Value.Count))
        {
            var igjen = liste.Where(f => !tatt.Contains(f)).ToList();
            if (igjen.Count < 2) continue;
            // Hovedfunnet: høyest risiko, så flest kilder
            var hoved = igjen.OrderBy(f => (int)f.Risiko).ThenByDescending(f => f.Detaljer.Count).First();
            foreach (var f in igjen.Where(f => f != hoved))
            {
                hoved.SlaInn(f);
                tatt.Add(f);
                lock (_funn) foreach (var k in _funn.Where(x => x.Value == f).Select(x => x.Key).ToList()) _funn.Remove(k);
            }
            tatt.Add(hoved);
            hoved.Detalj($"Samme program ({sti}): {igjen.Count} spor slått sammen til ett funn");
        }
    }
}
