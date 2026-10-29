using System.Net;
using System.Text.Json;

namespace AISkanner;

/// <summary>
/// Navn på forbindelser som Windows' DNS-buffer ikke kjenner. Nettlesere slår ofte opp navn selv (egen DNS eller
/// sikker DNS, DoH), så bufferen mangler navnet og forbindelsen til ChatGPT ser ut som en ukjent IP-adresse.
/// Løsningen: programmet slår selv opp adressene til de kjente AI-tjenestene (vanlige DNS-oppslag, samme som når
/// en nettside åpnes; ingenting om PC-en sendes med) og sammenligner med forbindelsene som er åpne.
/// Fordi mange tjenester deler IP-adresser på samme CDN, regnes et treff bare når nettleseren selv har tjenesten
/// i nettverkslageret sitt (Network Persistent State). Ingenting lagres.
/// </summary>
internal static class AiAdresser
{
    /// <summary>Slår opp alle vertsnavnene samtidig. Det som ikke har svart innen fristen, tas ikke med.</summary>
    public static Dictionary<IPAddress, List<string>> SlaOpp(IEnumerable<string> verter, TimeSpan frist)
    {
        var kart = new Dictionary<IPAddress, List<string>>();
        var liste = verter.Select(v => v.Trim('.').ToLowerInvariant()).Where(v => v.Contains('.')).Distinct().ToList();
        // Egne DNS-spørringer rett til DNS-serveren, ikke via Windows: da havner navnene ikke i Windows' DNS-buffer, som
        // skanneren leser som bevis på at PC-en har brukt tjenesten. (Før 2.30.0 forurenset oppslagene bufferen.)
        var servere = EgenDns.Servere();
        if (servere.Count == 0)
        {
            Tilgangslogg.Logg("Nettverk", "DNS-oppslag av kjente AI-adresser", Utfall.HoppetOver, "fant ingen DNS-server; slår ikke opp via Windows for ikke å fylle DNS-bufferen");
            return kart;
        }
        var oppslag = liste.Select(v => (Vert: v, Svar: EgenDns.SlaOppAsync(v, servere, frist))).ToList();
        try { Task.WaitAll(oppslag.Select(o => (Task)o.Svar).ToArray(), frist); } catch { }
        int svarte = 0;
        foreach (var (vert, svar) in oppslag)
        {
            if (svar.Status != TaskStatus.RanToCompletion) continue;
            svarte++;
            foreach (var ip in svar.Result)
            {
                var nokkel = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
                if (!kart.TryGetValue(nokkel, out var l)) kart[nokkel] = l = new List<string>();
                if (!l.Contains(vert)) l.Add(vert);
            }
        }
        Tilgangslogg.Logg("Nettverk", "DNS-oppslag av kjente AI-adresser", svarte > 0 ? Utfall.Lest : Utfall.IkkeFunnet,
            $"{svarte} av {liste.Count} navn svarte; brukes bare til å kjenne igjen forbindelser nettleseren selv har slått opp");
        return kart;
    }

    private static readonly ISet<string> Filer = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Network Persistent State", "Local State" };

    /// <summary>
    /// Vertsnavn Chromium-nettleseren har i nettverkslageret sitt (servere den nylig har snakket HTTP/2 eller QUIC med).
    /// Bare navnene sammenlignes med AI-listene; alt annet forkastes med en gang.
    /// </summary>
    public static HashSet<string> NettleserVerter(IEnumerable<(string Nettleser, string Rot)> rotter, Func<string, bool> erAi)
    {
        var verter = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (nettleser, rotSti) in rotter)
        {
            var rot = Environment.ExpandEnvironmentVariables(rotSti);
            if (!Directory.Exists(rot)) continue;
            LesDoh(nettleser, rot);
            foreach (var profil in Skanner.Mapper(rot))
            {
                foreach (var fil in new[] { Path.Combine(profil, "Network", "Network Persistent State"), Path.Combine(profil, "Network Persistent State") })
                {
                    if (!File.Exists(fil)) continue;
                    using var doc = Skanner.LesJson(fil, Filer);
                    if (doc == null) continue;
                    try
                    {
                        if (!doc.RootElement.TryGetProperty("net", out var net) || !net.TryGetProperty("http_server_properties", out var hsp)) continue;
                        if (!hsp.TryGetProperty("servers", out var servere) || servere.ValueKind != JsonValueKind.Array) continue;
                        foreach (var s in servere.EnumerateArray())
                        {
                            if (!s.TryGetProperty("server", out var v) || v.ValueKind != JsonValueKind.String) continue;
                            if (!Uri.TryCreate(v.GetString(), UriKind.Absolute, out var uri)) continue;
                            if (erAi(uri.Host)) verter.Add(uri.Host);
                        }
                    }
                    catch { }
                }
            }
        }
        return verter;
    }

    /// <summary>Om nettleseren bruker sikker DNS (DoH). Da mangler navnene i Windows' DNS-buffer. Logges i datagrunnlaget.</summary>
    private static void LesDoh(string nettleser, string rot)
    {
        using var doc = Skanner.LesJson(Path.Combine(rot, "Local State"), Filer);
        if (doc == null) return;
        string modus = "automatisk (standard)";
        try
        {
            if (doc.RootElement.TryGetProperty("dns_over_https", out var d) && d.TryGetProperty("mode", out var m) && m.ValueKind == JsonValueKind.String)
                modus = m.GetString() switch { "secure" => "på (sikker DNS)", "off" => "av", "automatic" => "automatisk", var x => x ?? "ukjent" };
        }
        catch { }
        Tilgangslogg.Logg("Nettverk", $"{nettleser}: sikker DNS (DoH)", Utfall.Lest,
            $"{modus}; navn nettleseren slår opp selv, mangler i Windows' DNS-buffer og kjennes igjen på IP-adressen");
    }
}
