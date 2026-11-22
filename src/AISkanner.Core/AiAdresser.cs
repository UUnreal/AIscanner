using System.Net;
using System.Text.Json;

namespace AISkanner;

/// <summary>
/// Navn på forbindelser til kjente AI-tjenester, bare fra Windows' egen DNS-buffer (navn PC-en allerede har slått opp).
/// Skanneren spør aldri en DNS-server og sender ingenting ut. Nettlesere med sikker DNS (DoH) fyller ikke bufferen,
/// så de forbindelsene kjennes ikke igjen på navn. Fordi mange tjenester deler IP-adresser på samme CDN, regnes et
/// IP-treff bare når nettleseren selv har tjenesten i nettverkslageret sitt (Network Persistent State). Ingenting lagres.
/// </summary>
internal static class AiAdresser
{
    /// <summary>IP-adressene i DNS-bufferen som hører til de kjente AI-vertsnavnene (eller underdomener av dem).</summary>
    public static Dictionary<IPAddress, List<string>> FraBuffer(IEnumerable<string> verter)
    {
        var kjente = verter.Select(v => v.Trim('.').ToLowerInvariant()).Where(v => v.Contains('.')).ToList();
        bool Ai(string n) => kjente.Any(d => n == d || n.EndsWith("." + d, StringComparison.Ordinal));
        var kart = new Dictionary<IPAddress, List<string>>();
        foreach (var (ip, navn) in Nettverk.DnsBuffer(out _, logg: false))
        {
            var ai = navn.Where(Ai).ToList();
            if (ai.Count > 0) kart[ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip] = ai;
        }
        Tilgangslogg.Logg("Nettverk", "Kjente AI-adresser i DNS-bufferen", kart.Count > 0 ? Utfall.Lest : Utfall.IkkeFunnet,
            "bare navn Windows allerede har slått opp; skanneren spør aldri en DNS-server");
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
