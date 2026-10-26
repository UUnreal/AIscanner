using System.Text.Json;

namespace AISkanner;

/// <summary>
/// Oppslag i NVD (nvd.nist.gov). Sender BARE produktordet fra regelfilen, f.eks. "ollama".
/// Aldri PC-navn, brukernavn eller filstier.
/// </summary>
public static class Nvd
{
    private static readonly HttpClient Klient = new() { Timeout = TimeSpan.FromSeconds(20) };

    public static async Task SjekkAsync(IEnumerable<Funn> funn, IProgress<string>? status, CancellationToken ct, Action<Funn>? ferdig = null)
    {
        var liste = funn.Where(f => !string.IsNullOrWhiteSpace(f.Regel?.Nvd)).ToList();
        Tilgangslogg.Sjekk.Value = "NVD";
        for (int i = 0; i < liste.Count; i++)
        {
            var f = liste[i];
            var ord = f.Regel!.Nvd!;
            status?.Report($"Sjekker kjente sårbarheter for {f.Navn} ({i + 1} av {liste.Count})... sender kun ordet \"{ord}\"");
            try
            {
                var url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&keywordSearch=" + Uri.EscapeDataString(ord);
                using var svar = await Klient.GetAsync(url, ct);
                svar.EnsureSuccessStatusCode();
                using var doc = JsonDocument.Parse(await svar.Content.ReadAsStringAsync());
                int antall = doc.RootElement.TryGetProperty("totalResults", out var t) ? t.GetInt32() : 0;
                Tilgangslogg.Logg("Nettverk", $"services.nvd.nist.gov ord=\"{ord}\"", Utfall.Lest, $"{antall} CVE");
                f.Merknad(antall > 0
                    ? $"NVD: {antall} kjente sårbarheter (CVE) nevner \"{ord}\". Hold programmet oppdatert."
                    : $"NVD: ingen kjente sårbarheter funnet for \"{ord}\".");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception e) { Tilgangslogg.Feil("Nettverk", $"services.nvd.nist.gov ord=\"{ord}\"", e); f.Merknad("NVD: oppslaget feilet (ingen nett eller for mange forespørsler)."); }
            ferdig?.Invoke(f);

            // NVD tillater 5 forespørsler per 30 sekunder uten API-nøkkel: de fem første går med en gang
            if (i >= 4 && i < liste.Count - 1) await Task.Delay(TimeSpan.FromSeconds(6.5), ct);
        }
    }
}
