using System.Text;
using System.Text.Json;

namespace AISkanner;

/// <summary>
/// Kjenner igjen AI-modeller på innholdet i filen, ikke på navnet.
/// Leser bare de første bytene (og for GGUF/safetensors: metadata-hodet), aldri selve modellvektene.
/// </summary>
public static class ModellFormat
{
    public sealed record Modell(string Format, string? Navn, string? Arkitektur, long? Parametre, bool KanKjoreKode);

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
                fs.ReadExactly(navn);
                var s = Encoding.UTF8.GetString(navn);
                if (s.EndsWith("data.pkl") || s.Contains("/data/") || s.EndsWith("/version") || s.EndsWith("/byteorder"))
                    return new Modell("PyTorch", null, null, null, true);
                return null;
            }
            if (hode[0] == 0x80 && hode[1] is >= 2 and <= 5 && ext is ".pt" or ".pth" or ".bin" or ".ckpt" or ".pkl")
                return new Modell("PyTorch (pickle)", null, null, null, true);

            if (ext == ".onnx" && hode[0] == 0x08) return new Modell("ONNX", null, null, null, false);
            if (ext is ".h5" or ".keras" && Ascii(hode, 1, 3) == "HDF") return new Modell("Keras", null, null, null, false);
            return null;
        }
        catch { return null; }
    }

    private static string Ascii(byte[] b, int fra, int lengde) => Encoding.ASCII.GetString(b, fra, lengde);

    // ---------- GGUF ----------
    private static Modell Gguf(FileStream fs)
    {
        string? navn = null, arkitektur = null, storrelse = null, basenavn = null;
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
                    }
                }
                else HoppOver(r, type);
                if (navn != null && arkitektur != null && storrelse != null) break;
            }
        }
        catch { }
        var visning = navn ?? basenavn;
        if (visning != null && storrelse != null && !visning.Contains(storrelse, StringComparison.OrdinalIgnoreCase)) visning += " " + storrelse;
        return new Modell("GGUF", visning, arkitektur, null, false);
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
    private static Modell? Safetensors(FileStream fs, long hodeLengde)
    {
        if (hodeLengde > 20_000_000) return new Modell("safetensors", null, null, null, false);
        fs.Position = 8;
        var buf = new byte[hodeLengde];
        fs.ReadExactly(buf);
        using var doc = JsonDocument.Parse(buf);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
        long parametre = 0;
        string? navn = null;
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (p.Name == "__metadata__")
            {
                if (p.Value.ValueKind == JsonValueKind.Object)
                    foreach (var m in p.Value.EnumerateObject())
                        if (m.Name is "modelspec.title" or "name" or "ss_output_name" && m.Value.ValueKind == JsonValueKind.String) navn ??= m.Value.GetString();
                continue;
            }
            if (p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty("shape", out var shape) && shape.ValueKind == JsonValueKind.Array)
            {
                long produkt = 1;
                foreach (var d in shape.EnumerateArray()) produkt *= d.GetInt64();
                parametre += produkt;
            }
        }
        return new Modell("safetensors", navn, null, parametre > 0 ? parametre : null, false);
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
