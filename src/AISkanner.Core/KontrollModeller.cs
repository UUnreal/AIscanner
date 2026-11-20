using System.Diagnostics;
using System.Text;

namespace AISkanner;

/// <summary>
/// Kontroll av modellgjenkjenningen fra 2.53: formål (angrep, sensurfri, sikkerhet), ordforrådets navn, nye formater,
/// modeller inni andre filer (llamafile, zip), modellkort, egen kode, ModelScope og LM Studio, små LoRA-tillegg og pakker.
/// Alle filene lages i den midlertidige mappa og er bare noen få byte.
/// </summary>
public sealed partial class Skanner
{
    private static (int Ok, int Alle) ModellhullKontroll(Regelsett regler, StringBuilder sb, string rot)
    {
        int ok = 0, alle = 0;
        void Sjekk(bool riktig, string hva) { alle++; if (riktig) ok++; else sb.AppendLine($"FEIL  Modeller: {hva}"); }
        var mappe = Path.Combine(rot, "modeller");
        Directory.CreateDirectory(mappe);
        ModellIdentitet Id(string sti, string? kilde = null, ModellFormat.Modell? m = null) =>
            ModellGjenkjenning.Finn(m ?? new ModellFormat.Modell("GGUF", null, null, null, false), sti, regler, kilde);

        // Formål på navnet: angrep veier tyngst, så sensurfri, så sikkerhet. Familien beholdes.
        Sjekk(Id(@"C:\m\x.gguf", "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B").Formaal?.Kategori == "angrep", "WhiteRabbitNeo blir ikke angrepsmodell");
        Sjekk(Id(@"C:\m\DeepHat-V1-7B.Q4_K_M.gguf").Formaal?.Kategori == "angrep", "DeepHat blir ikke angrepsmodell");
        var abl = Id(@"C:\m\x.gguf", "huihui-ai/Qwen2.5-7B-Instruct-abliterated");
        Sjekk(abl.Formaal?.Kategori == "sensurfri" && abl.NavneFamilie?.Land == "CN", "abliterated Qwen blir ikke sensurfri og kinesisk");
        Sjekk(Id(@"C:\m\x.gguf", "dolphin-mistral:latest").Formaal?.Kategori == "sensurfri", "Dolphin blir ikke sensurfri");
        Sjekk(Id(@"C:\m\Llama-Guard-3-8B.gguf").Formaal?.Kategori == "sikkerhet", "Llama Guard blir ikke sikkerhetsmodell");
        Sjekk(Id(@"C:\m\x.gguf", "e12ex2/foundation-sec-8b-heretic").Formaal?.Kategori == "sensurfri", "sensurfri versjon av en sikkerhetsmodell blir ikke sensurfri");
        Sjekk(Id(@"C:\m\Meta-Llama-3-8B-Instruct.Q4_K_M.gguf").Formaal == null, "vanlig Llama fikk et formål");
        // Formål og merkelapper inne i GGUF-fila (general.finetune, general.tags)
        var gguf = LagGguf(("general.name", "Kontroll 7B"), ("general.finetune", "abliterated"), ("tokenizer.ggml.pre", "qwen2"), ("general.architecture", "llama"), ("general.type", "adapter"));
        var gfil = Path.Combine(mappe, "kontroll.gguf");
        File.WriteAllBytes(gfil, gguf);
        var gm = ModellFormat.Gjenkjenn(gfil);
        Sjekk(gm?.Finjustering == "abliterated" && Id(gfil, m: gm).Formaal?.Kategori == "sensurfri", "general.finetune = abliterated gir ikke sensurfri");
        Sjekk(gm?.Type?.StartsWith("LoRA") == true, "general.type = adapter blir ikke LoRA-tillegg");
        // Ordforrådets navn (tokenizer.ggml.pre) peker på familien selv når arkitekturen er delt (llama)
        var pre = Id(gfil, m: gm);
        Sjekk(pre.Familie?.Navn == "Qwen" && pre.Sikkerhet == "sannsynlig", $"llama + ordforråd qwen2 blir ikke sannsynlig Qwen (ble {pre.Familie?.Navn ?? "ukjent"} {pre.Sikkerhet})");
        Sjekk(Id(@"C:\m\x.gguf", m: new ModellFormat.Modell("GGUF", null, "qwen3", null, false) { PreTokenizer = "qwen2" }).Sikkerhet == "sikker", "qwen3 + ordforråd qwen2 blir ikke sikkert Qwen");
        Sjekk(Id(@"C:\m\x.gguf", m: new ModellFormat.Modell("GGUF", null, "llama", null, false)).Familie == null, "bare arkitekturen llama satte en familie");
        Sjekk(Id(@"C:\m\x.gguf", m: new ModellFormat.Modell("GGUF", null, "deepseek2", null, false) { PreTokenizer = "gigachat" }).Familie?.Navn == "GigaChat", "deepseek2 + ordforråd gigachat blir ikke GigaChat");
        Sjekk(regler.PreTokenizer.Values.All(v => regler.Modellfamilier.Any(f => f.Navn == v)), "preTokenizer peker på en familie som ikke finnes");
        // Ordlista gir en ID (SHA-256), lik hver gang
        var medOrd = LagGguf(("general.name", "Ord"));
        var ordFil = Path.Combine(mappe, "ord.gguf");
        File.WriteAllBytes(ordFil, LeggTilOrd(medOrd, new[] { "a", "b", "<s>" }));
        var o1 = ModellFormat.Gjenkjenn(ordFil)?.VokabId;
        Sjekk(o1 != null && o1 == ModellFormat.Gjenkjenn(ordFil)?.VokabId && ModellFormat.Gjenkjenn(ordFil)?.Vokab == 3, "ordforråds-ID mangler eller endrer seg");

        // Nye familier: Kina og Russland på navnet, og navn som ikke skal treffe
        foreach (var (navn, land) in new[] { ("stepfun-ai/Step-Audio-2-mini", "CN"), ("Skywork/Skywork-OR1-7B", "CN"), ("Wan-AI/Wan2.2-T2V-A14B", "CN"), ("XiaomiMiMo/MiMo-7B-RL", "CN"),
                     ("meituan-longcat/LongCat-Flash-Chat", "CN"), ("Tele-AI/TeleChat2-7B", "CN"), ("FunAudioLLM/CosyVoice2-0.5B", "CN"), ("PaddlePaddle/PaddleOCR-VL", "CN"),
                     ("kandinskylab/Kandinsky-5.0-T2V-Lite", "RU"), ("gigaam-v2-ctc", "RU") })
            Sjekk(Id(@"C:\m\x.safetensors", navn).NavneFamilie?.Land == land, $"{navn} merkes ikke {land}");
        foreach (var navn in new[] { "checkpoint-step3000", "youtube-dl-whisper", "orion-nebula-sd15" })
            Sjekk(Id($@"C:\m\{navn}.safetensors").NavneFamilie?.Land is not ("CN" or "RU"), $"{navn} ble feilaktig kinesisk eller russisk");
        foreach (var f in regler.Modellfamilier.Where(f => f.Land is "CN" or "RU" && f.Kilde != null))
            Sjekk(f.Kilde!.Contains("https://"), $"modellfamilie {f.Navn} mangler lenke i kilden");
        foreach (var f in regler.ModellFormaal)
            Sjekk(f.Kilde?.Contains("https://") == true && f.Kategori is "angrep" or "sensurfri" or "sikkerhet", $"formål {f.Navn} mangler kilde eller har ukjent kategori");

        // Funnet: angrep blir rødt, sensurfri får advarsel uten å endre fargen, sikkerhetsmodell får merknad
        var sk = new Skanner(regler);
        var ollama = Path.Combine(mappe, ".ollama", "models", "blobs");
        Directory.CreateDirectory(ollama);
        foreach (var (navn, filnavn) in new[] { ("WhiteRabbitNeo 7B", "a.gguf"), ("Mistral 7B uncensored", "b.gguf"), ("ShieldGemma 2B", "c.gguf") })
        {
            var sti = Path.Combine(ollama, filnavn);
            File.WriteAllBytes(sti, LagGguf(("general.name", navn)));
            sk.LeggTilModell(sti, 64, ModellFormat.Gjenkjenn(sti)!);
        }
        Funn? F(string navn) => sk._funn.Values.FirstOrDefault(x => x.Navn.Contains(navn));
        Sjekk(F("WhiteRabbitNeo") is { Risiko: Risiko.Rod } wr && wr.Advarsler.Any(a => a.StartsWith("Angrepsmodell:")), "angrepsmodell ble ikke rød med advarsel");
        Sjekk(F("uncensored") is { Risiko: Risiko.Gul } un && un.Advarsler.Any(a => a.StartsWith("Sensurfri:")), "sensurfri modell i Ollama fikk ikke advarsel, eller fikk feil farge");
        Sjekk(F("ShieldGemma") is { } sg && sg.Merknader.Any(a => a.StartsWith("Sikkerhetsmodell:")), "sikkerhetsmodell fikk ikke merknad");

        // llamafile: program (MZqFpD) med ukomprimert GGUF i en zip bakerst. Navn og innhold leses fra GGUF-en inni.
        var lf = Path.Combine(mappe, "kontroll.exe");
        var program = Encoding.ASCII.GetBytes("MZqFpD='\n" + new string('x', 200));
        File.WriteAllBytes(lf, program.Concat(LagZip(("kontroll.gguf", LagGguf(("general.name", "Llamafile-modell"), ("general.architecture", "qwen2")), null))).ToArray());
        var lm = ModellFormat.Gjenkjenn(lf);
        Sjekk(lm != null && lm.Format.StartsWith("llamafile") && lm.Navn == "Llamafile-modell" && lm.KanKjoreKode, $"llamafile ble ikke kjent igjen med navnet fra GGUF-en inni ({lm?.Format ?? "ingenting"})");
        Sjekk(lm != null && Id(lf, m: lm).Familie?.Navn == "Qwen", "familien i en llamafile ble ikke lest");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "vanlig.exe"), Encoding.ASCII.GetBytes("MZ" + new string('\0', 100)))) == null, "vanlig program ble kalt modell");
        // Zip: bare katalogen leses. En stor .safetensors inni er en modell, små filer og andre filer er ikke det.
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "modell.zip"), LagZip(("qwen.safetensors", new byte[16], 30L * 1024 * 1024)))) is { Inni: "qwen.safetensors" }, "modell i zip-fil ble ikke funnet");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "bilder.zip"), LagZip(("ferie.jpg", new byte[16], 30L * 1024 * 1024), ("liten.gguf", new byte[16], 1024)))) == null, "zip uten modell ble kalt modell");

        // Formater på filmerket, også uten endelse (ONNX, Keras), og formater bare kjent på endelsen
        byte[] Hode(string a, int plass) { var b = new byte[64]; Encoding.ASCII.GetBytes(a).CopyTo(b, plass); return b; }
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "m.ort"), Hode("ORTM", 4)))?.Format == "ONNX Runtime", "ORT-fil ble ikke kjent igjen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "m.pte"), Hode("ET12", 4)))?.Format == "ExecuTorch", "ExecuTorch-fil ble ikke kjent igjen");
        var onnx = new byte[] { 0x08, 0x07, 0x12, 0x07 }.Concat(Encoding.ASCII.GetBytes("pytorch")).Concat(new byte[] { 0x1A, 0x03 }).Concat(Encoding.ASCII.GetBytes("2.1")).Concat(new byte[64]).ToArray();
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "vekter.dat"), onnx))?.Format == "ONNX", "ONNX-fil uten .onnx ble ikke kjent igjen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "tilfeldig.dat"), new byte[] { 0x08, 0x07, 0x12, 0x03, 0xFF, 0xFE, 0x00 }.Concat(new byte[64]).ToArray())) == null, "tilfeldige bytes ble kalt ONNX");
        var hdf = new byte[] { 0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A };
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "k.dat"), hdf.Concat(Encoding.ASCII.GetBytes(new string(' ', 100) + "keras_version")).ToArray()))?.Format == "Keras", "Keras-fil uten .h5 ble ikke kjent igjen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "maling.dat"), hdf.Concat(new byte[100]).ToArray())) == null, "vanlig HDF5-datafil ble kalt Keras");
        var pd = ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "inference.pdiparams"), new byte[64]));
        Sjekk(pd?.Format == "PaddlePaddle (Baidu)" && ModellFormat.KinesiskFormat(pd.Format) == "Baidu" && pd.Type == ModellFormat.KjentPaEndelsen, "PaddlePaddle-fil alene ble ikke kjent igjen som Baidu-format bare på endelsen (Mulig spor)");
        // PR 5: formater bekreftet på innholdet. Riktig endelse med feil innhold blir bare «kjent på endelsen» (Mulig spor) eller ingen treff
        byte[] B(params byte[] b) => b.Concat(new byte[64]).ToArray();
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "inference.pdmodel"), B(0x0A, 0x10)))?.Type == null, "Paddle .pdmodel + .pdiparams ble ikke bekreftet på innholdet");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "m.mlmodel"), B(0x08, 0x04, 0x12, 0x05)))?.Format == "Core ML", "Core ML (protobuf-start) ble ikke kjent igjen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "falsk.mlmodel"), B(0x50, 0x4B, 0x00)))?.Type == ModellFormat.KjentPaEndelsen, ".mlmodel med feil innhold ble mer enn kjent på endelsen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "m.mindir"), B(0x0A, 0x05).Concat(Encoding.ASCII.GetBytes("MindSpore")).ToArray()))?.Type == null, "MindIR med «MindSpore» ble ikke bekreftet");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "falsk.mindir"), B(0x01)))?.Type == ModellFormat.KjentPaEndelsen, ".mindir uten MindSpore ble mer enn kjent på endelsen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "m.engine"), Hode("ftrt", 0)))?.Format == "TensorRT-motor", "TensorRT-motor (ftrt) ble ikke kjent igjen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "spill.engine"), B(0x01, 0x02))) == null, ".engine uten ftrt ble kalt modell");
        var sm = Directory.CreateDirectory(Path.Combine(mappe, "sm")).FullName; Directory.CreateDirectory(Path.Combine(sm, "variables"));
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(sm, "saved_model.pb"), B(0x08, 0x01, 0x12)))?.Format == "TensorFlow SavedModel", "SavedModel (saved_model.pb + variables/) ble ikke kjent igjen");
        var sm2 = Directory.CreateDirectory(Path.Combine(mappe, "sm2")).FullName;
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(sm2, "saved_model.pb"), B(0x08, 0x01, 0x12))) == null, "saved_model.pb uten variables/ ble kalt modell");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "flax_model.msgpack"), B(0x82, 0xA1)))?.Format == "JAX/Flax (msgpack)", "Flax-modell (msgpack) ble ikke kjent igjen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "data.msgpack"), B(0x82, 0xA1))) == null, "vanlig msgpack-fil ble kalt modell");
        File.WriteAllText(Path.Combine(mappe, "yolo.param"), "7767517\n3 3\nInput input 0 1 data\n");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "yolo.bin"), new byte[64]))?.Format == "ncnn (Tencent)", "ncnn-modell (.param + .bin) ble ikke kjent igjen");
        File.WriteAllText(Path.Combine(mappe, "ov.xml"), "<?xml version=\"1.0\"?>\n<net name=\"kontroll\" version=\"11\">");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "ov.bin"), new byte[64]))?.Format == "OpenVINO", "OpenVINO-modell (.xml + .bin) ble ikke kjent igjen");
        Sjekk(ModellFormat.Gjenkjenn(WriteAll(Path.Combine(mappe, "annet.bin"), new byte[64])) == null, ".bin uten modell ved siden av ble kalt modell");

        // PR 6: bildemodeller på tensornavn (bare hodet i safetensors leses)
        string St(string navn, params string[] nokler)
        {
            var json = "{" + string.Join(",", nokler.Select(k => $"\"{k}\":{{\"dtype\":\"F16\",\"shape\":[4,4],\"data_offsets\":[0,32]}}")) + "}";
            var h = Encoding.UTF8.GetBytes(json);
            return WriteAll(Path.Combine(mappe, navn), BitConverter.GetBytes((ulong)h.Length).Concat(h).Concat(new byte[32]).ToArray());
        }
        string? Ty(string sti) => ModellFormat.Gjenkjenn(sti)?.Type;
        Sjekk(Ty(St("sdxl.safetensors", "model.diffusion_model.input_blocks.0.0.weight", "conditioner.embedders.1.model.ln_final.weight")) == "bildemodell (SDXL)", "SDXL ble ikke kjent igjen på tensornavn");
        Sjekk(Ty(St("sd3.safetensors", "model.diffusion_model.joint_blocks.0.x_block.attn.qkv.weight")) == "bildemodell (Stable Diffusion 3)", "SD3 ble ikke kjent igjen på tensornavn");
        Sjekk(Ty(St("cn.safetensors", "control_model.input_blocks.0.0.weight")) == "ControlNet (styrer en bildemodell)", "ControlNet ble ikke kjent igjen");
        Sjekk(Ty(St("ip.safetensors", "image_proj.proj.weight", "ip_adapter.1.to_k_ip.weight")) == "IP-Adapter (bilde som mal for stil eller ansikt)", "IP-Adapter ble ikke kjent igjen");
        Sjekk(Ty(St("vae.safetensors", "encoder.down.0.block.0.conv1.weight", "decoder.up.0.block.0.conv1.weight")) == "VAE (bildekoder til bildemodeller)", "VAE ble ikke kjent igjen");
        Sjekk(Ty(St("sd15.safetensors", "model.diffusion_model.input_blocks.0.0.weight")) == "bildemodell (Stable Diffusion)" && Ty(St("ip-halv.safetensors", "image_proj.proj.weight")) == null,
            "vanlig SD 1.5 ble noe annet, eller halv IP-Adapter ble kjent igjen");

        Sjekk(new[] { ("llava", "LLaVA (bilde + tekst)"), ("whisper", "Whisper"), ("siglip", "SigLIP"), ("sam2", "SAM (Segment Anything)"), ("florence2", "Florence-2") }
            .All(x => Id(@"C:\m\x.gguf", m: new ModellFormat.Modell("GGUF", null, x.Item1, null, false)).Familie?.Navn == x.Item2), "bilde- eller lydmodell ble ikke kjent igjen på arkitekturen");

        // config.json og modellkort: egen kode, komprimering og merkelapper
        var hf = Path.Combine(mappe, "hf");
        Directory.CreateDirectory(hf);
        File.WriteAllText(Path.Combine(hf, "config.json"), "{\"model_type\":\"qwen2\",\"auto_map\":{\"AutoModel\":\"modeling_x.Modell\"},\"quantization_config\":{\"quant_method\":\"awq\"}}");
        File.WriteAllText(Path.Combine(hf, "README.md"), "---\nlicense: apache-2.0\ndatasets:\n- cognitivecomputations/dolphin\ntags:\n- uncensored\n- chat\n---\n# Modell\n");
        var kort = Id(Path.Combine(hf, "model.safetensors"), m: new ModellFormat.Modell("safetensors", null, null, null, false));
        Sjekk(kort.EgenKode == "auto_map i config.json", "auto_map i config.json ble ikke sett som egen kode");
        Sjekk(kort.Kvantisering == "AWQ", "quant_method i config.json ble ikke lest");
        Sjekk(kort.Formaal?.Kategori == "sensurfri", "tags: uncensored i modellkortet ga ikke sensurfri");
        File.WriteAllText(Path.Combine(hf, "README.md"), "---\ndatasets:\n- cognitivecomputations/dolphin\n---\n");
        Sjekk(Id(Path.Combine(hf, "model.safetensors"), m: new ModellFormat.Modell("safetensors", null, null, null, false)).Formaal == null, "datasett-navnet i modellkortet ga et formål (bare tags og base_model skal leses)");
        var hf2 = Path.Combine(mappe, "hf2");
        Directory.CreateDirectory(hf2);
        File.WriteAllText(Path.Combine(hf2, "config.json"), "{\"model_type\":\"llama\"}");
        File.WriteAllText(Path.Combine(hf2, "modeling_kontroll.py"), "# kontroll");
        Sjekk(Id(Path.Combine(hf2, "model.safetensors"), m: new ModellFormat.Modell("safetensors", null, null, null, false)).EgenKode == "modeling_kontroll.py", "modeling_*.py ved modellen ble ikke sett som egen kode");

        // ModelScope og LM Studio gir organisasjon og navn, så kinesiske modeller merkes uten Hugging Face
        Sjekk(sk.Kildenavn(@"C:\Users\a\.cache\modelscope\hub\models\Qwen\Qwen2___5-7B-Instruct\model.safetensors") == "Qwen/Qwen2.5-7B-Instruct", "ModelScope-stien ga ikke organisasjon og navn");
        Sjekk(sk.Kildenavn(@"C:\Users\a\.lmstudio\models\lmstudio-community\gemma-3-4b-it-GGUF\gemma-3-4b-it-Q4_K_M.gguf") == "lmstudio-community/gemma-3-4b-it-GGUF", "LM Studio-stien ga ikke utgiver og repo");
        // Ollama: LoRA-tillegg i manifestet får navn
        var om = Path.Combine(mappe, "ollama2", "models");
        var omf = Path.Combine(om, "manifests", "registry.ollama.ai", "library", "kontroll");
        Directory.CreateDirectory(omf); Directory.CreateDirectory(Path.Combine(om, "blobs"));
        File.WriteAllText(Path.Combine(omf, "latest"), "{\"layers\":[{\"mediaType\":\"application/vnd.ollama.image.model\",\"digest\":\"sha256:" + new string('1', 64) + "\"},{\"mediaType\":\"application/vnd.ollama.image.adapter\",\"digest\":\"sha256:" + new string('2', 64) + "\"},{\"mediaType\":\"application/vnd.ollama.image.system\",\"digest\":\"sha256:" + new string('3', 64) + "\"}]}");
        var ok2 = ModellGjenkjenning.OllamaNavn(Path.Combine(om, "blobs"));
        Sjekk(ok2.TryGetValue(new string('2', 64), out var an) && an == "kontroll:latest (LoRA-tillegg)" && !ok2.ContainsKey(new string('3', 64)), "Ollama-lag med LoRA-tillegg ble ikke navngitt, eller systemprompt-laget ble tatt med");

        // Små filer: LoRA over 1 MB finnes, GGUF uten vekter (bare ordforråd) ikke. Kjente modellmapper med punktum gås gjennom.
        var smaa = Path.Combine(mappe, "smaa", ".paddleocr");
        Directory.CreateDirectory(smaa);
        var lora = new List<byte>();
        var lh = Encoding.ASCII.GetBytes("{\"base_model.model.layers.0.q_proj.lora_A.weight\":{\"dtype\":\"F16\",\"shape\":[8,4096],\"data_offsets\":[0,65536]}}");
        lora.AddRange(BitConverter.GetBytes((ulong)lh.Length)); lora.AddRange(lh); lora.AddRange(new byte[1536 * 1024]);
        File.WriteAllBytes(Path.Combine(smaa, "adapter_model.safetensors"), lora.ToArray());
        File.WriteAllBytes(Path.Combine(smaa, "ggml-vocab-kontroll.gguf"), LagGguf(("general.name", "vocab")).Concat(new byte[1536 * 1024]).ToArray());
        var ffs = new FilFunn();
        new Skanner(regler).Gaa(Path.Combine(mappe, "smaa"), 4, ffs, new HashSet<string>(), 20L * 1024 * 1024, Stopwatch.StartNew());
        Sjekk(ffs.Modeller.Count == 1 && ffs.Modeller[0].Modell.Type?.StartsWith("LoRA") == true, $"lite LoRA-tillegg i .paddleocr ble ikke funnet alene ({ffs.Modeller.Count} funn)");

        // Motorer, pakker, MCP, Docker og Windows' egen AI
        Sjekk(new[] { "tensorflowlite_c.dll", "libvosk.dll", "stable-diffusion.dll", "TNN.dll" }.All(n => Motorer.Any(x => x.Mønster.IsMatch(n))) && !Motorer.Any(x => x.Mønster.IsMatch("vosk-ui.dll") || x.Mønster.IsMatch("stable.dll") || x.Mønster.IsMatch("tnnplugin.dll")), "nye AI-motorer (LiteRT, Vosk, stable-diffusion.cpp, TNN) kjennes ikke igjen, eller feil fil traff");
        Sjekk(Motorer.Any(x => x.Mønster.IsMatch("paddle_inference.dll") && x.Motor.Contains("Baidu")) && Motorer.Any(x => x.Mønster.IsMatch("nvinfer_10.dll")) && Motorer.Any(x => x.Mønster.IsMatch("ncnn.dll")), "nye AI-motorer (Paddle, TensorRT, ncnn) kjennes ikke igjen");
        var vill = sk.LeggTilMiljo(Path.Combine(mappe, "angrep", ".venv", "Lib", "site-packages"), new SortedSet<string> { "villager", "openai" }, true, "Python");
        Sjekk(vill.Risiko == Risiko.Rod && vill.Advarsler.Any(a => a.StartsWith("Angrepsverktøy med AI")), "Villager ble ikke rødt angrepsverktøy");
        var ds = sk.LeggTilMiljo(Path.Combine(mappe, "kina", ".venv", "Lib", "site-packages"), new SortedSet<string> { "dashscope" }, false, "Python");
        Sjekk(ds.Risiko == Risiko.Rod && ds.Advarsler.Any(a => a.StartsWith("Laget av Alibaba i Kina")), "dashscope ble ikke rødt med Kina");
        var gr = sk.LeggTilMiljo(Path.Combine(mappe, "test", ".venv", "Lib", "site-packages"), new SortedSet<string> { "garak", "torch" }, false, "Python");
        Sjekk(gr.Risiko == Risiko.Gul && gr.Merknader.Any(a => a.Contains("red team")), "garak fikk ikke red team-merknad, eller ble rød");
        // Avhengighetsfiler: bare pakkenavn, kommentarer og versjoner telles ikke
        Sjekk(AvhengighetNavn("requirements.txt", "# openai i en kommentar\nlangchain-openai>=0.1 # x\n-r base.txt\nnumpy").SequenceEqual(new[] { "langchain-openai", "numpy" }), "requirements.txt leses feil (kommentar eller valg tatt med)");
        Sjekk(AvhengighetNavn("pyproject.toml", "[project]\nname = \"openai\"\ndependencies = [\n  \"torch>=2\",\n]\n[tool.poetry.dependencies]\npython = \"^3.11\"\nllama-cpp-python = \"^0.3\"\n[tool.ruff]\nselect = [\"transformers\"]").SequenceEqual(new[] { "torch", "llama-cpp-python" }), "pyproject.toml leses feil (prosjektnavn eller annen seksjon tatt med)");
        Sjekk(AvhengighetNavn("package.json", "{\"name\":\"openai\",\"scripts\":{\"openai\":\"x\"},\"devDependencies\":{\"@anthropic-ai/sdk\":\"1\"}}").SequenceEqual(new[] { "@anthropic-ai/sdk" }), "package.json leses feil");
        Sjekk(AvhengighetNavn("uv.lock", "[[package]]\nname = \"openai\"\n[package.metadata]\nname = \"torch\"").SequenceEqual(new[] { "openai" }), "uv.lock leses feil");
        Sjekk(AvhengighetNavn("environment.yml", "dependencies:\n  - python=3.11\n  - pip:\n    - Torch==2 # x").SequenceEqual(new[] { "python", "Torch" }), "environment.yml leses feil");
        Sjekk(Avhengighetsfil("requirements-dev.txt") == "Python" && Avhengighetsfil("Pipfile") == "Python" && Avhengighetsfil("readme.txt") == null && Avhengighetsfil("tsconfig.json") == null, "avhengighetsfil kjennes ikke igjen på navnet");
        Sjekk(AiPakker(new[] { "Llama.CPP", "numpy" }, new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase) { ["llama_cpp"] = false }, true).Pakker.SequenceEqual(new[] { "llama_cpp" }), "Python-navn med - eller . kjennes ikke igjen");
        var avhMappe = Path.Combine(mappe, "avh");
        Directory.CreateDirectory(Path.Combine(avhMappe, "ai-prosjekt"));
        Directory.CreateDirectory(Path.Combine(avhMappe, "vanlig"));
        File.WriteAllText(Path.Combine(avhMappe, "ai-prosjekt", "requirements.txt"), "openai==1.0\n");
        File.WriteAllText(Path.Combine(avhMappe, "vanlig", "requirements.txt"), "# openai\nrequests\n");
        var ffa = new FilFunn();
        new Skanner(regler).Gaa(avhMappe, 4, ffa, new HashSet<string>(), 20L * 1024 * 1024, Stopwatch.StartNew());
        Sjekk(ffa.Avhengigheter.Count == 1 && ffa.Avhengigheter[0].Pakker.Contains("openai"), $"avhengighetsfil med AI ble ikke funnet, eller kommentaren ga funn ({ffa.Avhengigheter.Count})");
        var avf = sk.LeggTilMiljo(Path.Combine(avhMappe, "ai-prosjekt"), new SortedSet<string> { "openai" }, false, "Python", Path.Combine(avhMappe, "ai-prosjekt", "requirements.txt"));
        Sjekk(avf.Hvor.Contains("Avhengighetsfil") && !avf.Hvor.Contains("Installert pakke") && avf.Bevisniva == Bevisniva.Sannsynlig, "avhengighetsfil ga feil spor eller bevisnivå");
        // WSL innvendig (Linux kjører): Python-miljø med AI i et prosjekt gir funn, et vanlig miljø gir ikke
        var wslRot = Path.Combine(mappe, "wsl");
        Directory.CreateDirectory(Path.Combine(wslRot, "home", "jo", "ai", ".venv", "lib", "python3.12", "site-packages", "openai"));
        Directory.CreateDirectory(Path.Combine(wslRot, "home", "jo", "vanlig", ".venv", "lib", "python3.12", "site-packages", "requests"));
        var ws = new Skanner(regler);
        ws.WslInnhold(wslRot, "Ubuntu");
        var wsf = ws._funn.Values.Where(f => f.Navn.StartsWith("Python-prosjekt med AI")).ToList();
        Sjekk(wsf.Count == 1 && wsf[0].Merknader.Contains("I Linux (WSL).") && wsf[0].Detaljer.Any(d => d.Contains("openai")), $"Python-miljø i WSL ble ikke funnet, eller vanlig miljø ga funn ({wsf.Count})");
        // Mulig typosquatting: én bokstav unna en kjent AI-pakke, bare lange navn, ekte nabopakker unntatt
        Sjekk(Ligner("transformerz", PythonAi) == "transformers" && Ligner("langchainn", PythonAi) == "langchain" && Ligner("transformer", PythonAi) == null
              && Ligner("numpy", PythonAi) == null && Ligner("transformers-4.46.0.dist-info", PythonAi) == null && Ligner("ctransformers", PythonAi) == null, "typosquatting-sjekken treffer feil");
        var tyMappe = Path.Combine(mappe, "typo", "site-packages");
        Directory.CreateDirectory(Path.Combine(tyMappe, "langchainn"));
        var ffy = new FilFunn();
        Miljo(tyMappe, PythonAi, "Python", ffy);
        var tys = new Skanner(regler); tys.LeggTilTypo(ffy);
        var tyf = tys._funn.Values.SingleOrDefault(f => f.Navn == "Mulig forfalsket Python-pakke: langchainn");
        Sjekk(tyf != null && tyf.Bevisniva == Bevisniva.Spor && tyf.Ukjentspor == false && ffy.Miljoer.Count == 0, "mulig forfalsket pakke ble ikke Mulig spor");
        // Modell i minnet: Ollama /api/ps og LM Studio /api/v0/models (bare «loaded»); feil form gir null
        Sjekk(Lastet("/api/ps", "{\"models\":[{\"name\":\"qwen2.5:0.5b\"}]}")?.SequenceEqual(new[] { "qwen2.5:0.5b" }) == true
              && Lastet("/api/v0/models", "{\"data\":[{\"id\":\"a\",\"state\":\"loaded\"},{\"id\":\"b\",\"state\":\"not-loaded\"}]}")?.SequenceEqual(new[] { "a" }) == true
              && Lastet("/api/ps", "[1,2]") == null && Lastet("/api/v0/models", "ikke json") == null, "lastet modell leses feil");
        Sjekk(AngrepMcp.IsMatch("hexstrike-ai python3 hexstrike_mcp.py") && !AngrepMcp.IsMatch("filesystem npx @modelcontextprotocol/server-filesystem"), "MCP-regelen for angrepsverktøy treffer feil");
        Sjekk(ErAiBilde("ai/smollm2:latest") && ErAiBilde("docker/model-runner:latest") && !ErAiBilde("aiden/app:1"), "Docker Model Runner-bilder kjennes ikke igjen, eller feil bilde traff");
        Sjekk(Mappenavn(@"\\wsl.localhost\Ubuntu\usr\share\ollama\.ollama\models\blobs\sha256-" + new string('a', 64)) == "i Linux (WSL)", "modell i WSL vises ikke som Linux (WSL)");
        Sjekk(System.Text.RegularExpressions.Regex.IsMatch("<systemai:Capability Name=\"systemAIModels\"/>", @"Capability\s+Name\s*=\s*""systemAIModels""", System.Text.RegularExpressions.RegexOptions.IgnoreCase), "systemAIModels i AppxManifest kjennes ikke igjen");
        // Microsofts egne apper med systemAIModels: ett grønt funn, ikke ett gult per app. Andre utgivere er gule.
        var wa = new Skanner(regler);
        foreach (var (d, navn) in new[] { ("Microsoft.Paint_11.2_x64__8wekyb3d8bbwe", "Paint"), ("Microsoft.WindowsNotepad_11.2_x64__8wekyb3d8bbwe", "Notisblokk"), ("Clipchamp.Clipchamp_4.7_x64__yxz26nhyzhsrt", "Clipchamp") })
        {
            var pk = Path.Combine(mappe, "WindowsApps", d);
            Directory.CreateDirectory(pk);
            var man = Path.Combine(pk, "AppxManifest.xml");
            File.WriteAllText(man, $"<Package><Properties><DisplayName>{navn}</DisplayName><PublisherDisplayName>Microsoft Corporation</PublisherDisplayName></Properties><Capabilities><systemai:Capability Name=\"systemAIModels\"/></Capabilities></Package>");
            wa.WindowsAiApp(pk, man);
        }
        var waMs = wa._funn.Values.Where(x => x.Navn == "Microsofts apper bruker Windows' egen AI").ToList();
        Sjekk(waMs.Count == 1 && waMs[0].Risiko == Risiko.Gronn && waMs[0].Detaljer.Count(x => x.Contains("systemAIModels")) == 2, "Microsofts apper med Windows' egen AI ble ikke samlet i ett grønt funn");
        Sjekk(wa._funn.Values.Count(x => x.Navn.StartsWith("Bruker Windows' egen AI")) == 1 && wa._funn.Values.First(x => x.Navn.StartsWith("Bruker Windows' egen AI")).Risiko == Risiko.Gul, "app fra ikke-bekreftet utgiver med Windows' egen AI ble ikke gul");
        Sjekk(ErMicrosoftPakke("Microsoft.Paint_11.2_x64__8wekyb3d8bbwe") && !ErMicrosoftPakke("Falsk.App_1.0_x64__8wekyb3d8bbwex") && !ErMicrosoftPakke("Microsoft.Fake_1.0_x64__abcdefghijklm"), "Microsoft-pakke kjennes feil igjen");
        return (ok, alle);
    }

    private static string WriteAll(string sti, byte[] b) { File.WriteAllBytes(sti, b); return sti; }

    /// <summary>GGUF v3 uten vekter, med tekstfelt.</summary>
    private static byte[] LagGguf(params (string Nokkel, string Verdi)[] felt)
    {
        var g = new List<byte>();
        void U32(uint v) => g.AddRange(BitConverter.GetBytes(v));
        void U64(ulong v) => g.AddRange(BitConverter.GetBytes(v));
        void Str(string t) { var b = Encoding.UTF8.GetBytes(t); U64((ulong)b.Length); g.AddRange(b); }
        g.AddRange(Encoding.ASCII.GetBytes("GGUF")); U32(3); U64(0); U64((ulong)felt.Length);
        foreach (var (n, v) in felt) { Str(n); U32(8); Str(v); }
        return g.ToArray();
    }

    /// <summary>Legger til tokenizer.ggml.tokens (liste med tekst) i en GGUF fra LagGguf.</summary>
    private static byte[] LeggTilOrd(byte[] gguf, string[] ord)
    {
        var g = new List<byte>(gguf);
        ulong antall = BitConverter.ToUInt64(gguf, 16) + 1;
        BitConverter.GetBytes(antall).CopyTo(gguf, 16);
        g = new List<byte>(gguf);
        void U32(uint v) => g.AddRange(BitConverter.GetBytes(v));
        void U64(ulong v) => g.AddRange(BitConverter.GetBytes(v));
        void Str(string t) { var b = Encoding.UTF8.GetBytes(t); U64((ulong)b.Length); g.AddRange(b); }
        Str("tokenizer.ggml.tokens"); U32(9); U32(8); U64((ulong)ord.Length);
        foreach (var o in ord) Str(o);
        return g.ToArray();
    }

    /// <summary>Enkel zip uten komprimering. Oppgitt størrelse i katalogen kan settes større enn innholdet (bare katalogen leses).</summary>
    private static byte[] LagZip(params (string Navn, byte[] Innhold, long? Oppgitt)[] filer)
    {
        var z = new List<byte>();
        var kat = new List<byte>();
        void U16(List<byte> l, int v) => l.AddRange(BitConverter.GetBytes((ushort)v));
        void U32(List<byte> l, uint v) => l.AddRange(BitConverter.GetBytes(v));
        foreach (var (navn, innhold, oppgitt) in filer)
        {
            var n = Encoding.UTF8.GetBytes(navn);
            uint plass = (uint)z.Count, str = (uint)(oppgitt ?? innhold.Length);
            U32(z, 0x04034b50); U16(z, 20); U16(z, 0); U16(z, 0); U16(z, 0); U16(z, 0); U32(z, 0); U32(z, (uint)innhold.Length); U32(z, (uint)innhold.Length); U16(z, n.Length); U16(z, 0);
            z.AddRange(n); z.AddRange(innhold);
            U32(kat, 0x02014b50); U16(kat, 20); U16(kat, 20); U16(kat, 0); U16(kat, 0); U16(kat, 0); U16(kat, 0); U32(kat, 0); U32(kat, (uint)innhold.Length); U32(kat, str);
            U16(kat, n.Length); U16(kat, 0); U16(kat, 0); U16(kat, 0); U16(kat, 0); U32(kat, 0); U32(kat, plass); kat.AddRange(n);
        }
        uint start = (uint)z.Count;
        z.AddRange(kat);
        U32(z, 0x06054b50); U16(z, 0); U16(z, 0); U16(z, filer.Length); U16(z, filer.Length); U32(z, (uint)kat.Count); U32(z, start); U16(z, 0);
        return z.ToArray();
    }
}
