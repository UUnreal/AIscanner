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
    /// <summary>Hva modellen er laget for (angrep, sensurfri, sikkerhet), kjent på navn og merkelapper.</summary>
    public ModellFormaal? Formaal { get; init; }
    /// <summary>Hvorfor modellen har egen kode som kjører når den lastes (auto_map i config.json, Python-filer ved siden av).</summary>
    public string? EgenKode { get; init; }
    public string? Kvantisering { get; init; }

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
        string? configNavn = null, configKlasse = null, kvant = m.Kvantisering, egenKode = null;
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
                if (r.TryGetProperty("architectures", out var ar) && ar.ValueKind == JsonValueKind.Array && ar.GetArrayLength() > 0 && ar[0].ValueKind == JsonValueKind.String) configKlasse = ar[0].GetString();
                // quant_method: gptq, awq, exl2, bitsandbytes, fp8 … Kilde: huggingface.co/docs/transformers/main_classes/quantization
                if (r.TryGetProperty("quantization_config", out var qc) && qc.ValueKind == JsonValueKind.Object && qc.TryGetProperty("quant_method", out var qm) && qm.ValueKind == JsonValueKind.String) kvant ??= qm.GetString()!.ToUpperInvariant();
                // auto_map: modellen har egen Python-kode som kjøres når den lastes med trust_remote_code=True.
                // Kilde: https://huggingface.co/docs/transformers/custom_models (auto_map, trust_remote_code)
                if (r.TryGetProperty("auto_map", out var am) && am.ValueKind == JsonValueKind.Object) egenKode = "auto_map i config.json";
            }
            catch (Exception e) { Tilgangslogg.Feil("Fil", config, e); }
        }

        // Python-filer med modellkode ved siden av modellen (modeling_*.py, configuration_*.py, tokenization_*.py)
        if (egenKode == null && config != null)
            try
            {
                var py = Directory.EnumerateFiles(Path.GetDirectoryName(config)!, "*.py").Select(Path.GetFileName).FirstOrDefault(x => Regex.IsMatch(x!, @"^(modeling|configuration|tokenization)_\w+\.py$", RegexOptions.IgnoreCase));
                if (py != null) egenKode = py;
            }
            catch { }
        var kort = Modellkort(sti);

        // 3. Familie fra innholdet: arkitektur, ordforrådets størrelse og ordforrådets navn i llama.cpp (tokenizer.ggml.pre)
        string? preFamilie = m.PreTokenizer != null && regler.PreTokenizer.TryGetValue(m.PreTokenizer, out var pf) ? pf : null;
        ModellFamilie? beste = null;
        int besteScore = 0;
        bool arkTreff = false, vokabTreff = false;
        foreach (var f in regler.Modellfamilier)
        {
            bool a = ark != null && f.Arkitekturer.Any(x => Norm(x) == Norm(ark));
            bool v = vokab != null && f.Vokab.Contains(vokab.Value);
            bool p = preFamilie == f.Navn;
            if (f.KreverVokab && !(a && v) && !p) continue;
            // Ordforrådets navn veier litt mer enn en delt arkitektur alene (en «llama» med Qwen-ordforråd er Qwen)
            int score = (a ? 2 : 0) + (v ? (f.DeltVokab ? 1 : 2) : 0) + (p ? 3 : 0);
            if (score > besteScore) { beste = f; besteScore = score; arkTreff = a; vokabTreff = v || p; }
        }
        if (besteScore < 2) beste = null;
        // Bare arkitekturen, og flere familier bruker den (f.eks. "llama"): for svakt til å sette navn
        if (beste != null && !vokabTreff && regler.Modellfamilier.Count(f => !f.KreverVokab && f.Arkitekturer.Any(x => Norm(x) == Norm(ark))) > 1) beste = null;

        // Familien navnet peker på
        var navn = string.Join(" ", new[] { m.Navn, kildenavn, configNavn, m.BaseModell, m.Organisasjon, m.Finjustering, m.Inni, Path.GetFileNameWithoutExtension(sti) }
            .Concat(m.Merker).Concat(kort).Where(x => x != null)).ToLowerInvariant();
        // Hva modellen er laget for: angrep veier tyngst, så sensurfri, så sikkerhet
        var formaal = regler.ModellFormaal.Where(f => f.Ord.Any(o => navn.Contains(o.ToLowerInvariant())))
            .OrderBy(f => f.Kategori switch { "angrep" => 0, "sensurfri" => 1, _ => 2 }).FirstOrDefault();
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
            Formaal = formaal, EgenKode = egenKode, Kvantisering = kvant,
        };
        if (ark != null) id.Bevis.Add($"arkitektur {ark}");
        if (vokab != null) id.Bevis.Add($"ordforråd {vokab.Value.ToString("N0", new System.Globalization.CultureInfo("nb-NO"))} ord");
        if (lag != null) id.Bevis.Add($"{lag} lag");
        if (bredde != null) id.Bevis.Add($"bredde {bredde}");
        if (m.BaseModell != null) id.Bevis.Add($"laget fra {m.BaseModell}");
        if (m.Organisasjon != null) id.Bevis.Add($"organisasjon {m.Organisasjon}");
        if (m.Produsent != null) id.Bevis.Add($"laget med {m.Produsent}");
        if (m.PreTokenizer != null) id.Bevis.Add($"ordforrådet heter {m.PreTokenizer}{(preFamilie != null ? $" ({preFamilie})" : "")}");
        if (configKlasse != null) id.Bevis.Add($"klasse {configKlasse}");
        if (m.Finjustering != null) id.Bevis.Add($"finjustering {m.Finjustering}");
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

    /// <summary>
    /// Merkelapper og grunnmodell fra modellkortet (README.md ved modellen): bare linjene under «tags:» og «base_model:» i hodet mellom «---».
    /// Resten av kortet leses ikke. Kilde: https://huggingface.co/docs/hub/model-cards (metadata i YAML-hodet).
    /// </summary>
    internal static List<string> Modellkort(string sti)
    {
        var ut = new List<string>();
        var kort = FinnVed(sti, "README.md", 256 * 1024);
        if (kort == null) return ut;
        try
        {
            using var r = new StreamReader(Admintilgang.AapneLes(kort));
            Tilgangslogg.Logg("Fil", kort, Utfall.Lest, "modellkort: bare tags og base_model");
            if (r.ReadLine()?.Trim() != "---") return ut;
            string? felt = null;
            for (int i = 0; i < 300 && r.ReadLine() is { } l; i++)
            {
                if (l.Trim() == "---") break;
                var kv = Regex.Match(l, @"^([A-Za-z_]+):\s*(.*)$");
                if (kv.Success)
                {
                    felt = kv.Groups[1].Value is "tags" or "base_model" ? kv.Groups[1].Value : null;
                    if (felt != null && kv.Groups[2].Value.Trim() is { Length: > 0 } v)
                        ut.AddRange(v.Trim('[', ']').Split(',').Select(x => x.Trim().Trim('"', '\'')).Where(x => x.Length is > 0 and < 120));
                    continue;
                }
                var punkt = Regex.Match(l, @"^\s*-\s*(.+)$");
                if (felt != null && punkt.Success && ut.Count < 60) ut.Add(punkt.Groups[1].Value.Trim().Trim('"', '\''));
                else if (!punkt.Success && !l.StartsWith(" ")) felt = null;
            }
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", kort, e); }
        return ut;
    }

    /// <summary>config.json i samme mappe, eller i Hugging Face-lagerets snapshots-mappe for en blob.</summary>
    private static string? FinnConfig(string sti) => FinnVed(sti, "config.json", 256 * 1024);

    private static string? FinnVed(string sti, string filnavn, long maks)
    {
        try
        {
            var mappe = Path.GetDirectoryName(sti);
            if (mappe == null) return null;
            var her = Path.Combine(mappe, filnavn);
            if (File.Exists(her) && new FileInfo(her).Length < maks) return her;
            if (HfBlob.IsMatch(sti))
            {
                var snapshots = Path.Combine(Path.GetDirectoryName(mappe)!, "snapshots");
                foreach (var s in Directory.EnumerateDirectories(snapshots))
                {
                    var c = Path.Combine(s, filnavn);
                    if (File.Exists(c) && new FileInfo(c).Length < maks) return c;
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
                    {
                        // Lag av typen model, adapter (LoRA-tillegg) og projector (bildedel). Lag med systemprompt eller mal leses aldri.
                        // Kilde: github.com/ollama/ollama server/images.go (application/vnd.ollama.image.model/.adapter/.projector)
                        var type = l.TryGetProperty("mediaType", out var mt) ? mt.GetString() : null;
                        var tillegg = type?.EndsWith(".model") == true ? "" : type?.EndsWith(".adapter") == true ? " (LoRA-tillegg)" : type?.EndsWith(".projector") == true ? " (bildedel)" : null;
                        if (tillegg != null && l.TryGetProperty("digest", out var d) && d.GetString() is { } digest)
                        {
                            var hex = digest.Replace("sha256:", "");
                            kart[hex] = kart.TryGetValue(hex, out var fra) ? fra + ", " + navn + tillegg : navn + tillegg;
                        }
                    }
                }
                catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); }
            }
        }
        catch { }
        return kart;
    }
}
