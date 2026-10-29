using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>Hva vi vet om hvem en modell er, og hvor sikre vi er.</summary>
public sealed class ModellIdentitet
{
    /// <summary>Familien modellen er bygget på, lest av innholdet (arkitektur og ordforråd).</summary>
    public ModellFamilie? Familie { get; init; }
    /// <summary>Familien navnet peker på, hvis den er en annen (f.eks. DeepSeek-R1-Distill bygget på Qwen).</summary>
    public ModellFamilie? NavneFamilie { get; init; }
    /// <summary>"sikker", "sannsynlig" eller "ukjent".</summary>
    public string Sikkerhet { get; init; } = "ukjent";
    public List<string> Bevis { get; } = new();
    /// <summary>SHA-256 av hele filen når den er kjent uten å lese filen (Ollama og Hugging Face lagrer filene under sin egen SHA-256).</summary>
    public string? Sha256 { get; init; }
    /// <summary>Fingeravtrykk av størrelse, første og siste MB. Samme fil gir samme fingeravtrykk på alle PC-er.</summary>
    public string? Fingeravtrykk { get; init; }
    /// <summary>Navn fra programmet som lastet ned modellen (Ollama-navn eller Hugging Face-navn).</summary>
    public string? Kildenavn { get; init; }

    public string? FamilieTekst =>
        Familie == null ? NavneFamilie?.Navn
        : NavneFamilie != null && NavneFamilie != Familie ? $"{NavneFamilie.Navn}, bygget på {Familie.Navn}"
        : Familie.Navn;
}

/// <summary>
/// Kjenner igjen modeller med og uten navn. Det finnes ingen felles ID som alle modeller bærer, så vi kombinerer:
///  1. Eksakt identitet: SHA-256 av filen (gratis for Ollama og Hugging Face, som lagrer filene under hashen sin), ellers et raskt fingeravtrykk.
///  2. Metadata i filen: navn, organisasjon og hvilken modell den er laget fra.
///  3. Modellens «DNA»: arkitektur og størrelsen på ordforrådet. Det følger familien selv når filen får nytt navn eller finjusteres.
/// Alt regnes ut på nytt i hvert søk. Ingenting lagres.
/// </summary>
internal static class ModellGjenkjenning
{
    private static readonly Regex OllamaBlob = new(@"[\\/]blobs[\\/]sha256[-:]([0-9a-f]{64})$", RegexOptions.IgnoreCase);
    private static readonly Regex HfBlob = new(@"[\\/]models--[^\\/]+[\\/]blobs[\\/]([0-9a-f]{64})$", RegexOptions.IgnoreCase);

    internal static string Norm(string? s) => Regex.Replace((s ?? "").ToLowerInvariant(), "[^a-z0-9]", "");

    public static ModellIdentitet Finn(ModellFormat.Modell m, string sti, Regelsett regler, string? kildenavn)
    {
        // 1. Identitet
        string? sha = null, fingeravtrykk = null;
        var treff = OllamaBlob.Match(sti);
        if (!treff.Success) treff = HfBlob.Match(sti);
        if (treff.Success) sha = treff.Groups[1].Value.ToLowerInvariant();
        else fingeravtrykk = Fingeravtrykk(sti);

        // 2. Supplér med config.json ved siden av (Hugging Face-format)
        string? ark = m.Arkitektur;
        int? vokab = m.Vokab, lag = m.Lag, bredde = m.Bredde;
        string? configNavn = null;
        var config = FinnConfig(sti);
        if (config != null)
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(config));
                Tilgangslogg.Logg("Fil", config, Utfall.Lest, "config.json ved modellen");
                var r = doc.RootElement;
                if (ark == null && r.TryGetProperty("model_type", out var mt) && mt.ValueKind == JsonValueKind.String) ark = mt.GetString();
                if (vokab == null && r.TryGetProperty("vocab_size", out var vs) && vs.TryGetInt32(out var v)) vokab = v;
                if (lag == null && r.TryGetProperty("num_hidden_layers", out var nl) && nl.TryGetInt32(out var l)) lag = l;
                if (bredde == null && r.TryGetProperty("hidden_size", out var hs) && hs.TryGetInt32(out var b)) bredde = b;
                if (r.TryGetProperty("_name_or_path", out var np) && np.ValueKind == JsonValueKind.String) configNavn = np.GetString();
            }
            catch (Exception e) { Tilgangslogg.Feil("Fil", config, e); }
        }

        // 3. Familie fra innholdet
        ModellFamilie? beste = null;
        int besteScore = 0;
        bool arkTreff = false, vokabTreff = false;
        foreach (var f in regler.Modellfamilier)
        {
            bool a = ark != null && f.Arkitekturer.Any(x => Norm(x) == Norm(ark));
            bool v = vokab != null && f.Vokab.Contains(vokab.Value);
            int score = (a ? 2 : 0) + (v ? (f.DeltVokab ? 1 : 2) : 0);
            if (score > besteScore) { beste = f; besteScore = score; arkTreff = a; vokabTreff = v; }
        }
        if (besteScore < 2) beste = null;
        // Bare arkitekturen, og flere familier bruker den (f.eks. "llama"): for svakt til å sette navn
        if (beste != null && !vokabTreff && regler.Modellfamilier.Count(f => f.Arkitekturer.Any(x => Norm(x) == Norm(ark))) > 1) beste = null;

        // Familien navnet peker på
        var navn = string.Join(" ", new[] { m.Navn, kildenavn, configNavn, m.BaseModell, Path.GetFileNameWithoutExtension(sti) }.Where(x => x != null)).ToLowerInvariant();
        // Navnet kan peke på en annen familie enn innholdet (DeepSeek-R1-Distill-Qwen er DeepSeek-trent, men bygget på Qwen)
        var iNavnet = regler.Modellfamilier.Where(f => f.Ord.Any(o => navn.Contains(o.ToLowerInvariant()))).ToList();
        var navneFamilie = iNavnet.FirstOrDefault(f => f != beste) ?? iNavnet.FirstOrDefault();

        string sikkerhet = beste != null && arkTreff && vokabTreff && besteScore >= 4 ? "sikker"
                         : beste != null ? "sannsynlig"
                         : navneFamilie != null ? "bare navnet"
                         : "ukjent";
        var id = new ModellIdentitet
        {
            Familie = beste, NavneFamilie = navneFamilie, Sikkerhet = sikkerhet,
            Sha256 = sha, Fingeravtrykk = fingeravtrykk, Kildenavn = kildenavn ?? configNavn,
        };
        if (ark != null) id.Bevis.Add($"arkitektur {ark}");
        if (vokab != null) id.Bevis.Add($"ordforråd {vokab.Value.ToString("N0", new System.Globalization.CultureInfo("nb-NO"))} ord");
        if (lag != null) id.Bevis.Add($"{lag} lag");
        if (bredde != null) id.Bevis.Add($"bredde {bredde}");
        if (m.BaseModell != null) id.Bevis.Add($"laget fra {m.BaseModell}");
        if (m.Organisasjon != null) id.Bevis.Add($"organisasjon {m.Organisasjon}");
        if (m.Produsent != null) id.Bevis.Add($"laget med {m.Produsent}");
        return id;
    }

    /// <summary>SHA-256 av størrelse + første og siste MB. Leser 2 MB uansett hvor stor modellen er.</summary>
    internal static string? Fingeravtrykk(string sti)
    {
        try
        {
            using var fs = Admintilgang.AapneLes(sti, 1 << 16);
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest, "fingeravtrykk (2 MB)");
            using var sha = SHA256.Create();
            const int Blokk = 1 << 20;
            var buf = new byte[Blokk];
            var lengde = BitConverter.GetBytes(fs.Length);
            sha.TransformBlock(lengde, 0, lengde.Length, null, 0);
            int n = fs.Read(buf, 0, Blokk);
            sha.TransformBlock(buf, 0, n, null, 0);
            if (fs.Length > 2L * Blokk)
            {
                fs.Position = fs.Length - Blokk;
                n = fs.Read(buf, 0, Blokk);
                sha.TransformBlock(buf, 0, n, null, 0);
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return string.Concat(sha.Hash!.Take(8).Select(b => b.ToString("x2")));
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return null; }
    }

    /// <summary>config.json i samme mappe, eller i Hugging Face-lagerets snapshots-mappe for en blob.</summary>
    private static string? FinnConfig(string sti)
    {
        try
        {
            var mappe = Path.GetDirectoryName(sti);
            if (mappe == null) return null;
            var her = Path.Combine(mappe, "config.json");
            if (File.Exists(her) && new FileInfo(her).Length < 256 * 1024) return her;
            if (HfBlob.IsMatch(sti))
            {
                var snapshots = Path.Combine(Path.GetDirectoryName(mappe)!, "snapshots");
                foreach (var s in Directory.EnumerateDirectories(snapshots))
                {
                    var c = Path.Combine(s, "config.json");
                    if (File.Exists(c) && new FileInfo(c).Length < 256 * 1024) return c;
                }
            }
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Ollama-navn (f.eks. "qwen2.5:7b") for hver blob, fra Ollamas egne manifester ved siden av blobs-mappa.
    /// Leser bare manifestfiler (små JSON-filer), ingenting annet.
    /// </summary>
    public static Dictionary<string, string> OllamaNavn(string blobsMappe)
    {
        var kart = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var manifester = Path.Combine(Path.GetDirectoryName(blobsMappe)!, "manifests");
            if (!Directory.Exists(manifester)) return kart;
            int teller = 0;
            foreach (var fil in Plattform.Filer(manifester, "*", 6))
            {
                if (++teller > 2000 || fil.Length > 64 * 1024) continue;
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(fil.FullName));
                    Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName);
                    if (!doc.RootElement.TryGetProperty("layers", out var lag) || lag.ValueKind != JsonValueKind.Array) continue;
                    // .../manifests/registry.ollama.ai/library/qwen2.5/7b  ->  qwen2.5:7b
                    var deler = fil.FullName.Substring(manifester.Length).Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
                    if (deler.Length < 2) continue;
                    var modell = deler[deler.Length - 2];
                    if (deler.Length >= 3 && deler[deler.Length - 3] != "library") modell = deler[deler.Length - 3] + "/" + modell;
                    var navn = $"{modell}:{deler[deler.Length - 1]}";
                    foreach (var l in lag.EnumerateArray())
                        if (l.TryGetProperty("mediaType", out var mt) && mt.GetString()?.EndsWith(".model") == true &&
                            l.TryGetProperty("digest", out var d) && d.GetString() is { } digest)
                        {
                            var hex = digest.Replace("sha256:", "");
                            kart[hex] = kart.TryGetValue(hex, out var fra) ? fra + ", " + navn : navn;
                        }
                }
                catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); }
            }
        }
        catch { }
        return kart;
    }
}
