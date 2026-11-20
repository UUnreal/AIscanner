using System.Security.Cryptography;
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
        /// <summary>Versjonen modellen selv oppgir (GGUF general.version), når den står i fila.</summary>
        public string? Versjon { get; init; }
        /// <summary>Hvordan modellen er endret (GGUF general.finetune, f.eks. «abliterated» eller «instruct»).</summary>
        public string? Finjustering { get; init; }
        /// <summary>Merkelapper i fila (GGUF general.tags).</summary>
        public IReadOnlyList<string> Merker { get; init; } = Array.Empty<string>();
        /// <summary>Navnet llama.cpp gir ordforrådet (GGUF tokenizer.ggml.pre, f.eks. «qwen2»). Følger familien selv om fila får nytt navn.</summary>
        public string? PreTokenizer { get; init; }
        /// <summary>SHA-256 av hele ordlista (GGUF tokenizer.ggml.tokens). Lik for alle modeller med samme ordforråd.</summary>
        public string? VokabId { get; init; }
        public string? Lisens { get; init; }
        /// <summary>Hvor modellen sier den kommer fra (GGUF general.source.url, general.repo_url …).</summary>
        public string? KildeUrl { get; init; }
        /// <summary>Modellen ligger inni en annen fil (llamafile eller zip): navnet på fila inni.</summary>
        public string? Inni { get; init; }
        /// <summary>Komprimering av vektene (GPTQ, AWQ, EXL2, MLX …), lest av tensornavn eller metadata.</summary>
        public string? Kvantisering { get; init; }
        /// <summary>Antall tensorer (vekter) i en GGUF-fil. 0 = bare ordforråd, ingen modell.</summary>
        public ulong? Tensorer { get; init; }
    }

    private static long _filhoder;
    /// <summary>Antall filer der filhodet er lest i dette søket (innholdet sjekket, ikke bare navnet).</summary>
    public static long Filhoder => Interlocked.Read(ref _filhoder);
    public static void NullstillTelling() => Interlocked.Exchange(ref _filhoder, 0);

    public static Modell? Gjenkjenn(string sti)
    {
        Interlocked.Increment(ref _filhoder);
        try
        {
            using var fs = Admintilgang.AapneLes(sti, 4096, FileOptions.SequentialScan);
            Tilgangslogg.Logg("Fil", sti, Utfall.Lest, "filhode (format)");
            var hode = new byte[64];
            int n = fs.Read(hode, 0, hode.Length);
            if (n < 16) return null;
            var ext = Path.GetExtension(sti).ToLowerInvariant();

            if (Ascii(hode, 0, 4) == "GGUF") return Gguf(fs, 0);
            if (Ascii(hode, 0, 4) is "lmgg" or "fmgg" or "tjgg") return new Modell("GGML", null, null, null, false);
            if (Ascii(hode, 4, 4) == "TFL3") return new Modell("TensorFlow Lite", null, null, null, false);
            // ONNX Runtime-format: flatbuffer med filmerket «ORTM» på plass 4. Kilde: onnxruntime/core/flatbuffers/schema/ort.fbs (file_identifier)
            if (Ascii(hode, 4, 4) == "ORTM") return new Modell("ONNX Runtime", null, null, null, false);
            // ExecuTorch: «ET» og to sifre på plass 4. Kilde: https://docs.pytorch.org/executorch/0.7/pte-file-format.html
            if (ext == ".pte" && hode[4] == 'E' && hode[5] == 'T' && char.IsDigit((char)hode[6]) && char.IsDigit((char)hode[7])) return new Modell("ExecuTorch", null, null, null, false);
            // llamafile (og andre «Actually Portable Executable»): starter med MZqFpD, modellen ligger i en zip bakerst i programmet.
            // Kilde: https://docs.mozilla.ai/llamafile/reference/technical_details og https://justine.lol/ape.html
            if (Ascii(hode, 0, 6) == "MZqFpD") return ModellIZip(fs, "llamafile", program: true);
            if (hode[0] == 'P' && hode[1] == 'K' && hode[2] == 3 && hode[3] == 4 && ext == ".zip" && ModellIZip(fs, "zip-fil", program: false) is { } zip) return zip;
            if (Bekreft(sti, ext, hode, fs) is { } bekreftet) return bekreftet;
            if (UtenMagi.TryGetValue(ext, out var formatNavn)) return new Modell(formatNavn, null, null, null, false) { Type = KjentPaEndelsen };
            if (ext == ".nemo" && fs.Length > 512) { fs.Position = 257; var t = new byte[5]; fs.LesAlt(t); if (Ascii(t, 0, 5) == "ustar") return new Modell("NVIDIA NeMo", null, null, null, true); }
            if (ext == ".bin" && Nabo(sti, ".xml", "<net ", 300)) return new Modell("OpenVINO", null, null, null, false);
            // ncnn (Tencent): .param-fila ved siden av starter med tallet 7767517. Kilde: github.com/Tencent/ncnn docs/developer-guide/param-and-model-file-structure.md
            if (ext == ".bin" && Nabo(sti, ".param", "7767517", 8)) return new Modell("ncnn (Tencent)", null, null, null, false);
            if (ext == ".weights" && File.Exists(Path.ChangeExtension(sti, ".cfg"))) return new Modell("Darknet (YOLO)", null, null, null, false);
            fs.Position = n;

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
                // Bare oppsettet PyTorch selv lager (<navn>/data.pkl, <navn>/data/0, <navn>/version, <navn>/byteorder).
                // «/data/» hvor som helst i stien traff vanlige zip-filer (.nupkg, .vsix, .jar) med en data-mappe.
                // Kilde: https://github.com/pytorch/pytorch/blob/main/torch/serialization.py (_save: archive_name/data.pkl)
                if (System.Text.RegularExpressions.Regex.IsMatch(s, @"^[^/]+/(?:data\.pkl|data/\d+|version|byteorder|\.data/version)$") || s == "data.pkl")
                    return new Modell("PyTorch", null, null, null, true);
                return null;
            }
            if (hode[0] == 0x80 && hode[1] is >= 2 and <= 5 && ext is ".pt" or ".pth" or ".bin" or ".ckpt" or ".pkl")
                return new Modell("PyTorch (pickle)", null, null, null, true);

            if (ext == ".onnx" && hode[0] == 0x08) return Onnx(fs);
            // ONNX med annen endelse: ir_version (felt 1) og så produsentnavnet (felt 2, merke 0x12) helt først, slik onnx selv skriver fila
            if (hode[0] == 0x08 && hode[1] is >= 3 and <= 15 && hode[2] == 0x12 && Onnx(fs) is { Produsent: { } p } onnx
                && System.Text.RegularExpressions.Regex.IsMatch(p, @"^[A-Za-z][\w.\- ]{1,60}$")) return onnx;
            if (Ascii(hode, 1, 3) == "HDF" && (ext is ".h5" or ".keras" or ".hdf5" || Inneholder(fs, "keras_version", 65536))) return new Modell("Keras", null, null, null, false);
            return null;
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return null; }
    }

    private static string Ascii(byte[] b, int fra, int lengde) => Encoding.ASCII.GetString(b, fra, lengde);

    /// <summary>Formatet er bare kjent på endelsen: bevisstandarden gjør det til Mulig spor.</summary>
    public const string KjentPaEndelsen = "AI-modell (kjent på endelsen)";

    /// <summary>
    /// Formater som kan bekreftes på innholdet, ikke bare endelsen (plan PR 5). Kilder:
    /// Core ML: coremltools/mlmodel/format/Model.proto (felt 1 specificationVersion, felt 2 description).
    /// MindSpore: mindspore/core/proto/mind_ir.proto (producer_name «MindSpore» først i ModelProto).
    /// Paddle: paddle/fluid/framework/framework.proto (ProgramDesc, felt 1 blocks) + .pdiparams ved siden av.
    /// TensorRT: serialisert motor starter med «ftrt» (NVIDIA TensorRT-plan). SavedModel: tensorflow/core/protobuf/saved_model.proto
    /// (saved_model_schema_version = 1) med variables/ ved siden av. Flax: flax/serialization.py (msgpack-kart), Hugging Face flax_model.msgpack.
    /// </summary>
    private static Modell? Bekreft(string sti, string ext, byte[] hode, Stream fs)
    {
        var navn = Path.GetFileName(sti);
        if (ext == ".mlmodel" && hode[0] == 0x08 && hode[1] is >= 1 and <= 12 && hode[2] == 0x12) return new Modell("Core ML", null, null, null, false);
        if (ext == ".mindir" && Inneholder(fs, "MindSpore", 4096)) return new Modell("MindSpore (Huawei)", null, null, null, false);
        if (ext == ".pdmodel" && hode[0] == 0x0A && File.Exists(Path.ChangeExtension(sti, ".pdiparams"))) return new Modell("PaddlePaddle (Baidu)", null, null, null, false);
        if (ext == ".pdiparams" && File.Exists(Path.ChangeExtension(sti, ".pdmodel"))) return new Modell("PaddlePaddle (Baidu)", null, null, null, false);
        if (ext is ".engine" or ".plan" or ".trt" && Ascii(hode, 0, 4) == "ftrt") return new Modell("TensorRT-motor", null, null, null, false);
        if (navn.Equals("saved_model.pb", StringComparison.OrdinalIgnoreCase) && hode[0] == 0x08 && hode[1] == 0x01
            && Directory.Exists(Path.Combine(Path.GetDirectoryName(sti) ?? "", "variables"))) return new Modell("TensorFlow SavedModel", null, null, null, false);
        if (navn.Equals("flax_model.msgpack", StringComparison.OrdinalIgnoreCase) && (hode[0] is >= 0x80 and <= 0x8f || hode[0] is 0xde or 0xdf))
            return new Modell("JAX/Flax (msgpack)", null, null, null, false);
        return null;
    }

    /// <summary>
    /// Formater uten kjent filmerke. Endelsen brukes bare av disse AI-formatene, og fila må være stor (sjekket før).
    /// PaddlePaddle (Baidu), MindSpore (Huawei), MNN (Alibaba) og RKNN (Rockchip) er kinesiske rammeverk.
    /// Kilder: paddlepaddle.org.cn (inference model .pdmodel/.pdiparams), mindspore.cn (MindIR), github.com/alibaba/MNN (schema uten file_identifier),
    /// github.com/airockchip/rknn-toolkit2, caffe.berkeleyvision.org, developer.apple.com/documentation/coreml.
    /// </summary>
    internal static readonly Dictionary<string, string> UtenMagi = new(StringComparer.OrdinalIgnoreCase)
    {
        [".pdiparams"] = "PaddlePaddle (Baidu)", [".pdmodel"] = "PaddlePaddle (Baidu)", [".mindir"] = "MindSpore (Huawei)",
        [".mnn"] = "MNN (Alibaba)", [".rknn"] = "RKNN (Rockchip)", [".caffemodel"] = "Caffe", [".mlmodel"] = "Core ML",
    };

    /// <summary>Formater fra selskaper i Kina. Vises som merknad: formatet sier hvem som laget verktøyet, ikke sikkert hvem som laget modellen.</summary>
    internal static string? KinesiskFormat(string format) => format switch
    {
        "PaddlePaddle (Baidu)" => "Baidu", "MindSpore (Huawei)" => "Huawei", "MNN (Alibaba)" => "Alibaba", "ncnn (Tencent)" => "Tencent", "RKNN (Rockchip)" => "Rockchip",
        _ => null,
    };

    /// <summary>Fila med samme navn og en annen endelse finnes og starter med (eller har tidlig) en bestemt tekst.</summary>
    private static bool Nabo(string sti, string endelse, string tekst, int innen)
    {
        try
        {
            var nabo = Path.ChangeExtension(sti, endelse);
            if (!File.Exists(nabo)) return false;
            using var s = Admintilgang.AapneLes(nabo);
            var buf = new byte[Math.Min(4096, innen + tekst.Length)];
            int n = s.Read(buf, 0, buf.Length);
            return Encoding.ASCII.GetString(buf, 0, n).IndexOf(tekst, StringComparison.Ordinal) is >= 0 and var i && i <= innen;
        }
        catch { return false; }
    }

    private static bool Inneholder(Stream fs, string tekst, int bytes)
    {
        fs.Position = 0;
        var buf = new byte[Math.Min(bytes, (int)Math.Min(fs.Length, int.MaxValue))];
        int n = fs.Read(buf, 0, buf.Length);
        return Encoding.ASCII.GetString(buf, 0, n).IndexOf(tekst, StringComparison.Ordinal) >= 0;
    }

    // ---------- Modell inni en zip (llamafile, .zip) ----------
    private static readonly string[] ModellEndelserIZip = { ".gguf", ".safetensors", ".onnx", ".pt", ".pth", ".ckpt", ".tflite", ".llamafile", ".bin" };

    /// <summary>
    /// Leser bare zip-katalogen bakerst i fila (navn og størrelser), aldri innholdet, unntatt GGUF-hodet når modellen ligger ukomprimert.
    /// Tar med modellfiler på minst 20 MB, eller en .gguf av alle størrelser i en llamafile.
    /// Kilde for zip-katalogen: PKWARE APPNOTE.TXT 4.3.12–4.3.16 (sentral katalog, ZIP64).
    /// </summary>
    private static Modell? ModellIZip(Stream fs, string format, bool program)
    {
        var filer = ZipKatalog(fs);
        var treff = filer.Where(f => ModellEndelserIZip.Any(e => f.Navn.EndsWith(e, StringComparison.OrdinalIgnoreCase))
                                     && (f.Storrelse >= 20L * 1024 * 1024 || program && f.Navn.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase)))
                         .OrderByDescending(f => f.Storrelse).FirstOrDefault();
        if (treff.Navn == null) return null;
        Modell? inni = null;
        if (treff.Metode == 0 && treff.Navn.EndsWith(".gguf", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                fs.Position = treff.Lokal;
                var lh = new byte[30];
                fs.LesAlt(lh);
                if (BitConverter.ToUInt32(lh, 0) == 0x04034b50)
                {
                    long data = treff.Lokal + 30 + BitConverter.ToUInt16(lh, 26) + BitConverter.ToUInt16(lh, 28);
                    fs.Position = data;
                    var m = new byte[4];
                    fs.LesAlt(m);
                    if (Ascii(m, 0, 4) == "GGUF") inni = Gguf(fs, data);
                }
            }
            catch { }
        }
        // Navnet inni zip-en kan ha tegn som ikke er lov i stier (.NET Framework kaster da), så stien deles for hånd
        var filnavn = treff.Navn.Replace('\\', '/').Split('/').Last();
        int punktum = filnavn.LastIndexOf('.');
        var navn = Rens(punktum > 0 ? filnavn.Substring(0, punktum) : filnavn);
        var endelse = punktum > 0 ? filnavn.Substring(punktum + 1).ToUpperInvariant() : "";
        var slag = program ? "AI-modell og program i én fil" : "AI-modell pakket i en zip-fil";
        return inni != null
            ? inni with { Format = $"{format} (GGUF inni)", Navn = inni.Navn ?? navn, KanKjoreKode = program, Inni = Rens(treff.Navn), Type = $"{slag} ({inni.Type})" }
            : new Modell($"{format} ({Rens(endelse)} inni)", navn, null, null, program) { Inni = Rens(treff.Navn), Type = slag };
    }

    internal static List<(string Navn, int Metode, long Storrelse, long Lokal)> ZipKatalog(Stream fs)
    {
        var liste = new List<(string, int, long, long)>();
        try
        {
            long lengde = fs.Length;
            int hale = (int)Math.Min(lengde, 65536 + 22);
            if (hale < 22) return liste;
            var buf = new byte[hale];
            fs.Position = lengde - hale;
            fs.LesAlt(buf);
            int eocd = -1;
            for (int i = hale - 22; i >= 0; i--) if (BitConverter.ToUInt32(buf, i) == 0x06054b50) { eocd = i; break; }
            if (eocd < 0) return liste;
            long eocdPlass = lengde - hale + eocd;
            long antall = BitConverter.ToUInt16(buf, eocd + 10), storrelse = BitConverter.ToUInt32(buf, eocd + 12), start = BitConverter.ToUInt32(buf, eocd + 16);
            long katalogSlutt = eocdPlass;
            // ZIP64: locator rett før EOCD peker på ZIP64-EOCD (56 byte) med 64-bits tall
            if (eocd >= 20 && BitConverter.ToUInt32(buf, eocd - 20) == 0x07064b50)
            {
                katalogSlutt = eocdPlass - 20 - 56;
                fs.Position = katalogSlutt;
                var z = new byte[56];
                fs.LesAlt(z);
                if (BitConverter.ToUInt32(z, 0) != 0x06064b50) return liste;
                antall = (long)BitConverter.ToUInt64(z, 32); storrelse = (long)BitConverter.ToUInt64(z, 40); start = (long)BitConverter.ToUInt64(z, 48);
            }
            // En llamafile kan ha programmet foran zip-en: plassene i katalogen regnes da fra der zip-en starter
            long forskyvning = katalogSlutt - storrelse - start;
            if (storrelse <= 0 || storrelse > 8 * 1024 * 1024 || forskyvning < 0) return liste;
            var kat = new byte[storrelse];
            fs.Position = start + forskyvning;
            fs.LesAlt(kat);
            int p = 0;
            for (long k = 0; k < Math.Min(antall, 5000) && p + 46 <= kat.Length && BitConverter.ToUInt32(kat, p) == 0x02014b50; k++)
            {
                int metode = BitConverter.ToUInt16(kat, p + 10);
                long komp = BitConverter.ToUInt32(kat, p + 20), ukomp = BitConverter.ToUInt32(kat, p + 24), lokal = BitConverter.ToUInt32(kat, p + 42);
                int nl = BitConverter.ToUInt16(kat, p + 28), el = BitConverter.ToUInt16(kat, p + 30), cl = BitConverter.ToUInt16(kat, p + 32);
                if (p + 46 + nl + el > kat.Length) break;
                var navn = Encoding.UTF8.GetString(kat, p + 46, nl);
                // ZIP64-tillegg (id 1): ukomprimert størrelse, komprimert størrelse og lokal plass, i den rekkefølgen, bare de som er 0xFFFFFFFF
                for (int e = p + 46 + nl, slutt = e + el; e + 4 <= slutt;)
                {
                    int id = BitConverter.ToUInt16(kat, e), len = BitConverter.ToUInt16(kat, e + 2), q = e + 4;
                    if (id == 1)
                    {
                        if (ukomp == 0xFFFFFFFF && q + 8 <= slutt) { ukomp = (long)BitConverter.ToUInt64(kat, q); q += 8; }
                        if (komp == 0xFFFFFFFF && q + 8 <= slutt) q += 8;
                        if (lokal == 0xFFFFFFFF && q + 8 <= slutt) lokal = (long)BitConverter.ToUInt64(kat, q);
                        break;
                    }
                    e = q + len;
                }
                liste.Add((navn, metode, ukomp, lokal + forskyvning));
                p += 46 + nl + el + cl;
            }
        }
        catch { }
        return liste;
    }

    // ---------- GGUF ----------
    private static Modell Gguf(Stream fs, long start)
    {
        string? navn = null, arkitektur = null, storrelse = null, basenavn = null, base0 = null, baseOrg = null, org = null, modellVersjon = null;
        ulong? tensorer = null;
        string? ggufType = null, finjustering = null, pre = null, lisens = null, url = null, vokabId = null;
        var merker = new List<string>();
        int? vokab = null, lag = null, bredde = null;
        var tall = new Dictionary<string, long>();
        try
        {
            fs.Position = start + 4;
            using var r = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);
            uint versjon = r.ReadUInt32();
            if (versjon < 2) return new Modell("GGUF", null, null, null, false);
            tensorer = r.ReadUInt64();      // antall tensorer
            ulong antall = r.ReadUInt64();  // antall metadata-felt
            for (ulong i = 0; i < antall && i < 4096 && fs.Position - start < 64 * 1024 * 1024; i++)
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
                        case "general.version": modellVersjon = verdi; break;
                        case "general.base_model.0.name": base0 = verdi; break;
                        case "general.base_model.0.organization": baseOrg = verdi; break;
                        case "general.type": ggufType = verdi; break;
                        case "general.finetune": finjustering = verdi; break;
                        case "general.license": lisens = verdi; break;
                        case "tokenizer.ggml.pre": pre = verdi; break;
                        case "general.source.repo_url" or "general.repo_url" or "general.source.url" or "general.base_model.0.repo_url": url ??= verdi; break;
                    }
                }
                else if (type == 9 && nokkel == "tokenizer.ggml.tokens")
                {
                    uint elementType = r.ReadUInt32();
                    ulong n = r.ReadUInt64();
                    vokab = (int)Math.Min(n, int.MaxValue);
                    if (elementType == 8)
                    {
                        // Ordlista leses uansett for å komme forbi den; SHA-256 av den gir en ID for ordforrådet
                        using var h = SHA256.Create();
                        var skille = new byte[] { 0 };
                        for (ulong k = 0; k < n; k++)
                        {
                            ulong l = r.ReadUInt64();
                            if (l > 1_000_000 || fs.Position - start > 64 * 1024 * 1024) throw new InvalidDataException();
                            var b = r.ReadBytes((int)l);
                            h.TransformBlock(b, 0, b.Length, null, 0);
                            h.TransformBlock(skille, 0, 1, null, 0);
                        }
                        h.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                        vokabId = string.Concat(h.Hash!.Take(8).Select(x => x.ToString("x2")));
                    }
                    else for (ulong k = 0; k < n; k++) HoppOver(r, elementType);
                }
                else if (type == 9 && nokkel == "general.tags")
                {
                    uint elementType = r.ReadUInt32();
                    ulong n = r.ReadUInt64();
                    for (ulong k = 0; k < n && fs.Position - start < 64 * 1024 * 1024; k++)
                        if (elementType == 8 && merker.Count < 50) merker.Add(Streng(r)); else HoppOver(r, elementType);
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
        // general.type: model, adapter (LoRA) eller mmproj (bildedel). Kilde: ggml docs/gguf.md og gguf-py constants.py (GGUFType)
        var slag = ggufType == "adapter" ? "LoRA-tillegg (endrer en annen modell)"
                 : ggufType == "mmproj" ? "bildedel til en språkmodell (mmproj)"
                 : arkitektur is "bert" or "nomic-bert" or "jina-bert-v2" or "xlm-roberta" ? "søkemodell (embedding)"
                 : arkitektur is "clip" ? "bildeforståelse (CLIP)" : arkitektur is "whisper" ? "talemodell" : "språkmodell";
        return new Modell("GGUF", visning, arkitektur, null, false)
        {
            Vokab = vokab, Lag = lag, Bredde = bredde, Organisasjon = org, Type = slag, Versjon = modellVersjon,
            BaseModell = base0 == null ? null : baseOrg != null ? $"{baseOrg}/{base0}" : base0,
            Tensorer = tensorer, Finjustering = Rens(finjustering), Merker = merker, PreTokenizer = Rens(pre), VokabId = vokabId, Lisens = Rens(lisens), KildeUrl = Rens(url),
        };
    }

    /// <summary>Tekst fra fila vises i vinduet og rapporten: kontrolltegn (linjeskift o.l.) blir mellomrom, og lengden kuttes.</summary>
    private static string? Rens(string? s) => s == null ? null : System.Text.RegularExpressions.Regex.Replace(s.Length > 300 ? s.Substring(0, 300) : s, @"\p{C}", " ").Trim();

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

    private static Modell? Safetensors(Stream fs, long hodeLengde)
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
        bool lora = false, diffusjon = false, flux = false, sd3 = false, sdxl = false, kontroll = false, ipBilde = false, ipLag = false, vaeInn = false, vaeUt = false;
        string? kvant = null;
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (p.Name == "__metadata__")
            {
                if (p.Value.ValueKind == JsonValueKind.Object)
                    foreach (var m in p.Value.EnumerateObject())
                    {
                        if (m.Name is "modelspec.title" or "name" or "ss_output_name" && m.Value.ValueKind == JsonValueKind.String) navn ??= m.Value.GetString();
                        // MLX skriver {"format": "mlx"}. Kilde: github.com/ml-explore/mlx (mx.save_safetensors metadata)
                        if (m.Name == "format" && m.Value.ValueKind == JsonValueKind.String && m.Value.GetString() == "mlx") kvant ??= "MLX";
                    }
                continue;
            }
            if (p.Name.Contains("lora_")) lora = true;
            // GPTQ og AWQ: qweight/qzeros/scales. EXL2: q_weight, q_invperm. Kilder: AutoGPTQ/AutoAWQ (QuantLinear), turboderp/exllamav2 (ext_q_tensor)
            if (p.Name.EndsWith(".q_invperm") || p.Name.EndsWith(".q_weight")) kvant ??= "EXL2";
            else if (p.Name.EndsWith(".qweight")) kvant ??= doc.RootElement.EnumerateObject().Any(x => x.Name.EndsWith(".g_idx")) ? "GPTQ" : "GPTQ eller AWQ";
            if (p.Name.StartsWith("model.diffusion_model.") || p.Name.StartsWith("down_blocks.")) diffusjon = true;
            if (p.Name.StartsWith("double_blocks.") || p.Name.StartsWith("transformer_blocks.") && p.Name.Contains("attn.add_q_proj")) flux = true;
            // Bildemodeller på tensornavn. Kilder: ComfyUI comfy/model_detection.py (joint_blocks = SD3, conditioner.embedders.1 = SDXL,
            // control_model = ControlNet), tencent-ailab/IP-Adapter (image_proj + ip_adapter), CompVis/latent-diffusion (encoder.down/decoder.up = VAE)
            if (p.Name.StartsWith("model.diffusion_model.joint_blocks.") || p.Name.StartsWith("joint_blocks.")) sd3 = true;
            if (p.Name.StartsWith("conditioner.embedders.1.")) sdxl = true;
            if (p.Name.StartsWith("control_model.") || p.Name.StartsWith("controlnet_cond_embedding.")) kontroll = true;
            if (p.Name.StartsWith("image_proj.")) ipBilde = true;
            if (p.Name.StartsWith("ip_adapter.")) ipLag = true;
            if (p.Name.StartsWith("encoder.down.") || p.Name.StartsWith("first_stage_model.encoder.")) vaeInn = true;
            if (p.Name.StartsWith("decoder.up.") || p.Name.StartsWith("first_stage_model.decoder.")) vaeUt = true;
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
        type = lora ? "LoRA-tillegg (endrer en annen modell)" : kontroll ? "ControlNet (styrer en bildemodell)" : ipBilde && ipLag ? "IP-Adapter (bilde som mal for stil eller ansikt)"
            : flux ? "bildemodell (FLUX)" : sd3 ? "bildemodell (Stable Diffusion 3)" : diffusjon && sdxl ? "bildemodell (SDXL)" : diffusjon ? "bildemodell (Stable Diffusion)"
            : vaeInn && vaeUt ? "VAE (bildekoder til bildemodeller)" : vokab != null || maksLag >= 0 ? "språkmodell" : null;
        return new Modell("safetensors", navn, null, parametre > 0 ? parametre : null, false)
        {
            Vokab = vokab, Bredde = bredde, Lag = maksLag >= 0 ? maksLag + 1 : null, Type = type, Kvantisering = kvant,
        };
    }

    /// <summary>
    /// ONNX-fil uten .onnx-endelse (f.eks. i nettleserens egen lagring): protobuf-start og et lesbart produsentnavn
    /// («pytorch», «onnx.quantize», «tf2onnx» …). Uten produsentnavn regnes fila ikke som modell.
    /// </summary>
    public static bool ErOnnxUtenEndelse(string sti)
    {
        try
        {
            using var fs = Admintilgang.AapneLes(sti);
            if (fs.ReadByte() != 0x08) return false;
            var p = Onnx(fs).Produsent;
            return p != null && System.Text.RegularExpressions.Regex.IsMatch(p, @"^[A-Za-z][\w.\- ]{1,60}$");
        }
        catch { return false; }
    }

    // ---------- ONNX: les produsentnavnet fra starten av filen (protobuf) ----------
    private static Modell Onnx(Stream fs)
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
