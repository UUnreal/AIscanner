using System.Net.Http.Json;
using System.Text.Json;

namespace AISkanner;

/// <summary>
/// Valgfritt oppslag i NVD (nvd.nist.gov). Sender BARE produktordet fra regelfilen, f.eks. "ollama".
/// Aldri PC-navn, brukernavn eller filstier.
/// </summary>
public static class Nvd
{
    private static readonly HttpClient Klient = new() { Timeout = TimeSpan.FromSeconds(20) };

    public static async Task SjekkAsync(IEnumerable<Funn> funn, IProgress<string>? status, CancellationToken ct)
    {
        var liste = funn.Where(f => !string.IsNullOrWhiteSpace(f.Regel?.Nvd)).ToList();
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
                var json = await svar.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
                int antall = json.TryGetProperty("totalResults", out var t) ? t.GetInt32() : 0;
                f.Merknad(antall > 0
                    ? $"NVD: {antall} kjente sårbarheter (CVE) nevner \"{ord}\". Hold programmet oppdatert."
                    : $"NVD: ingen kjente sårbarheter funnet for \"{ord}\".");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { f.Merknad("NVD: oppslaget feilet (ingen nett eller for mange forespørsler)."); }

            // NVD tillater 5 forespørsler per 30 sekunder uten API-nøkkel
            if (i < liste.Count - 1) await Task.Delay(TimeSpan.FromSeconds(6.5), ct);
        }
    }
}
