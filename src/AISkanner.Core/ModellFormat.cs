using System.Text;
using System.Text.Json;

namespace AISkanner;

/// <summary>
/// Kjenner igjen AI-modeller på innholdet i filen, ikke på navnet.
/// Leser bare de første bytene (og for GGUF/safetensors: metadata-hodet), aldri selve modellvektene.
/// </summary>
public static class ModellFormat
{
    public sealed record Modell(string Format, string? Navn, string? Arkitektur, long? Parametre, bool KanKjoreKode)
    {
        /// <summary>Antall ord i ordforrådet (tokenizer). Følger modellfamilien selv når filen får nytt navn eller finjusteres.</summary>
        public int? Vokab { get; init; }
        /// <summary>Antall lag og bredde (skjult dimensjon).</summary>
        public int? Lag { get; init; }
        public int? Bredde { get; init; }
        /// <summary>Modellen den er laget fra, hvis filen sier det (finjusteringer).</summary>
        public string? BaseModell { get; init; }
        public string? Organisasjon { get; init; }
        /// <summary>"språkmodell", "bildemodell", "LoRA-tillegg", "søkemodell" osv., når det kan leses av innholdet.</summary>
        public string? Type { get; init; }
        /// <summary>Programmet som laget filen (ONNX).</summary>
        public string? Produsent { get; init; }
    }

    public static Modell? Gjenkjenn(string sti)
    {
        try
        {
            using var fs = new FileStream(sti, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
            var hode = new byte[64];
            int n = fs.Read(hode, 0, hode.Length);
            if (n < 16) return null;
            var ext = Path.GetExtension(sti).ToLowerInvariant();

            if (Ascii(hode, 0, 4) == "GGUF") return Gguf(fs);
            if (Ascii(hode, 0, 4) is "lmgg" or "fmgg" or "tjgg") return new Modell("GGML", null, null, null, false);
            if (Ascii(hode, 4, 4) == "TFL3") return new Modell("TensorFlow Lite", null, null, null, false);

            // safetensors: 8 byte lengde på JSON-hodet, så '{'
            ulong hodeLengde = BitConverter.ToUInt64(hode, 0);
            if (hode[8] == (byte)'{' && hodeLengde > 2 && hodeLengde < 100_000_000) return Safetensors(fs, (long)hodeLengde);

            // PyTorch (zip med data.pkl) og rene pickle-filer kan kjøre kode når de lastes
            if (hode[0] == 'P' && hode[1] == 'K' && hode[2] == 3 && hode[3] == 4)
            {
                int navnLengde = BitConverter.ToUInt16(hode, 26);
                fs.Position = 30;
                var navn = new byte[Math.Min(navnLengde, 512)];
                fs.LesAlt(navn);
                var s = Encoding.UTF8.GetString(navn);
                if (s.EndsWith("data.pkl") || s.Contains("/data/") || s.EndsWith("/version") || s.EndsWith("/byteorder"))
                    return new Modell("PyTorch", null, null, null, true);
                return null;
            }
            if (hode[0] == 0x80 && hode[1] is >= 2 and <= 5 && ext is ".pt" or ".pth" or ".bin" or ".ckpt" or ".pkl")
                return new Modell("PyTorch (pickle)", null, null, null, true);

            if (ext == ".onnx" && hode[0] == 0x08) return Onnx(fs);
            if (ext is ".h5" or ".keras" && Ascii(hode, 1, 3) == "HDF") return new Modell("Keras", null, null, null, false);
            return null;
        }
        catch { return null; }
    }

    private static string Ascii(byte[] b, int fra, int lengde) => Encoding.ASCII.GetString(b, fra, lengde);

    // ---------- GGUF ----------
    private static Modell Gguf(FileStream fs)
    {
        string? navn = null, arkitektur = null, storrelse = null, basenavn = null, base0 = null, baseOrg = null, org = null;
        int? vokab = null, lag = null, bredde = null;
        var tall = new Dictionary<string, long>();
        try
        {
            fs.Position = 4;
            using var r = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            uint versjon = r.ReadUInt32();
            if (versjon < 2) return new Modell("GGUF", null, null, null, false);
            r.ReadUInt64();                 // antall tensorer
            ulong antall = r.ReadUInt64();  // antall metadata-felt
            for (ulong i = 0; i < antall && i < 4096 && fs.Position < 64 * 1024 * 1024; i++)
            {
                var nokkel = Streng(r);
                uint type = r.ReadUInt32();
                if (type == 8)
                {
                    var verdi = Streng(r);
                    switch (nokkel)
                    {
                        case "general.name": navn = verdi; break;
                        case "general.architecture": arkitektur = verdi; break;
                        case "general.size_label": storrelse = verdi; break;
                        case "general.basename": basenavn = verdi; break;
                        case "general.organization": org = verdi; break;
                        case "general.base_model.0.name": base0 = verdi; break;
                        case "general.base_model.0.organization": baseOrg = verdi; break;
                    }
                }
                else if (type == 9 && nokkel == "tokenizer.ggml.tokens")
                {
                    uint elementType = r.ReadUInt32();
                    ulong n = r.ReadUInt64();
                    vokab = (int)Math.Min(n, int.MaxValue);
                    for (ulong k = 0; k < n; k++) HoppOver(r, elementType);
                }
                else if (type is 4 or 5 && (nokkel.EndsWith(".block_count") || nokkel.EndsWith(".embedding_length") || nokkel.EndsWith(".vocab_size")))
                    tall[nokkel.Substring(nokkel.LastIndexOf('.') + 1)] = type == 4 ? r.ReadUInt32() : r.ReadInt32();
                else HoppOver(r, type);
            }
        }
        catch { }
        if (tall.TryGetValue("block_count", out var bc)) lag = (int)bc;
        if (tall.TryGetValue("embedding_length", out var el)) bredde = (int)el;
        if (vokab == null && tall.TryGetValue("vocab_size", out var vs)) vokab = (int)vs;
        var visning = navn ?? basenavn;
        if (visning != null && storrelse != null && !visning.Inneholder(storrelse)) visning += " " + storrelse;
        var slag = arkitektur is "bert" or "nomic-bert" or "jina-bert-v2" or "xlm-roberta" ? "søkemodell (embedding)"
                 : arkitektur is "clip" ? "bildeforståelse (CLIP)" : arkitektur is "whisper" ? "talemodell" : "språkmodell";
        return new Modell("GGUF", visning, arkitektur, null, false)
        {
            Vokab = vokab, Lag = lag, Bredde = bredde, Organisasjon = org, Type = slag,
            BaseModell = base0 == null ? null : baseOrg != null ? $"{baseOrg}/{base0}" : base0,
        };
    }

    private static string Streng(BinaryReader r)
    {
        ulong lengde = r.ReadUInt64();
        if (lengde > 1_000_000) throw new InvalidDataException();
        return Encoding.UTF8.GetString(r.ReadBytes((int)lengde));
    }

    private static void HoppOver(BinaryReader r, uint type)
    {
        switch (type)
        {
            case 0: case 1: case 7: r.BaseStream.Position += 1; break;
            case 2: case 3: r.BaseStream.Position += 2; break;
            case 4: case 5: case 6: r.BaseStream.Position += 4; break;
            case 10: case 11: case 12: r.BaseStream.Position += 8; break;
            case 8: Streng(r); break;
            case 9:
                uint elementType = r.ReadUInt32();
                ulong antall = r.ReadUInt64();
                int fast = elementType switch { 0 or 1 or 7 => 1, 2 or 3 => 2, 4 or 5 or 6 => 4, 10 or 11 or 12 => 8, _ => 0 };
                if (fast > 0) r.BaseStream.Position += (long)antall * fast;
                else for (ulong i = 0; i < antall; i++) HoppOver(r, elementType);
                break;
            default: throw new InvalidDataException();
        }
    }

    // ---------- safetensors ----------
    private static readonly System.Text.RegularExpressions.Regex LagNr = new(@"(?:^|\.)(?:layers|h|blocks|layer)\.(\d+)\.", System.Text.RegularExpressions.RegexOptions.Compiled);

    private static Modell? Safetensors(FileStream fs, long hodeLengde)
    {
        if (hodeLengde > 20_000_000) return new Modell("safetensors", null, null, null, false);
        fs.Position = 8;
        var buf = new byte[hodeLengde];
        fs.LesAlt(buf);
        using var doc = JsonDocument.Parse(buf);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
        long parametre = 0;
        string? navn = null, type = null;
        int? vokab = null, bredde = null;
        int maksLag = -1;
        bool lora = false, diffusjon = false, flux = false;
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (p.Name == "__metadata__")
            {
                if (p.Value.ValueKind == JsonValueKind.Object)
                    foreach (var m in p.Value.EnumerateObject())
                        if (m.Name is "modelspec.title" or "name" or "ss_output_name" && m.Value.ValueKind == JsonValueKind.String) navn ??= m.Value.GetString();
                continue;
            }
            if (p.Name.Contains("lora_")) lora = true;
            if (p.Name.StartsWith("model.diffusion_model.") || p.Name.StartsWith("down_blocks.")) diffusjon = true;
            if (p.Name.StartsWith("double_blocks.") || p.Name.StartsWith("transformer_blocks.") && p.Name.Contains("attn.add_q_proj")) flux = true;
            var lagTreff = LagNr.Match(p.Name);
            if (lagTreff.Success) maksLag = Math.Max(maksLag, int.Parse(lagTreff.Groups[1].Value));
            if (p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty("shape", out var shape) && shape.ValueKind == JsonValueKind.Array)
            {
                var dims = shape.EnumerateArray().Select(d => d.GetInt64()).ToList();
                long produkt = 1;
                foreach (var d in dims) produkt *= d;
                parametre += produkt;
                // Inndata-tabellen [ordforråd, bredde] avslører modellfamilien
                if (vokab == null && dims.Count == 2 && (p.Name.EndsWith("embed_tokens.weight") || p.Name.EndsWith("wte.weight") || p.Name.EndsWith("tok_embeddings.weight") || p.Name.EndsWith("word_embeddings.weight")))
                {
                    vokab = (int)dims[0];
                    bredde = (int)dims[1];
                }
            }
        }
        type = lora ? "LoRA-tillegg (endrer en annen modell)" : flux ? "bildemodell (FLUX)" : diffusjon ? "bildemodell (Stable Diffusion)" : vokab != null || maksLag >= 0 ? "språkmodell" : null;
        return new Modell("safetensors", navn, null, parametre > 0 ? parametre : null, false)
        {
            Vokab = vokab, Bredde = bredde, Lag = maksLag >= 0 ? maksLag + 1 : null, Type = type,
        };
    }

    // ---------- ONNX: les produsentnavnet fra starten av filen (protobuf) ----------
    private static Modell Onnx(FileStream fs)
    {
        string? produsent = null;
        try
        {
            fs.Position = 0;
            var buf = new byte[4096];
            int n = fs.Read(buf, 0, buf.Length), i = 0;
            ulong Varint() { ulong v = 0; int skift = 0; while (i < n) { byte b = buf[i++]; v |= (ulong)(b & 0x7F) << skift; if (b < 0x80) break; skift += 7; } return v; }
            while (i < n)
            {
                var nokkel = Varint();
                int felt = (int)(nokkel >> 3), wire = (int)(nokkel & 7);
                if (wire == 0) { Varint(); continue; }
                if (wire != 2) break;
                int lengde = (int)Varint();
                if (felt == 2 && lengde < 200 && i + lengde <= n) { produsent = Encoding.UTF8.GetString(buf, i, lengde); break; }
                if (felt == 7) break;   // selve grafen
                i += lengde;
            }
        }
        catch { }
        return new Modell("ONNX", null, null, null, false) { Produsent = produsent };
    }

    /// <summary>"7,2 mrd. parametre" o.l.</summary>
    public static string? ParametreTekst(long? p) => p switch
    {
        null or 0 => null,
        >= 1_000_000_000 => $"{p / 1e9:0.#} mrd. parametre",
        >= 1_000_000 => $"{p / 1e6:0} mill. parametre",
        _ => null,
    };
}
