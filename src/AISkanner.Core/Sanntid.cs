using System.Diagnostics;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Finner AI uten navneliste: på filinnhold, AI-motorer, svar fra lokale servere,
/// AI-biblioteker i Python/Node og AI-nøkler. Navnelista brukes bare til å gi kjente ting et pent navn.
/// </summary>
public sealed partial class Skanner
{
    // AI-motorer (filnavn i programmappa). Finnes de, kan programmet kjøre AI lokalt.
    private static readonly (Regex Mønster, string Motor)[] Motorer =
    {
        (new(@"^(lib)?ggml.*\.(dll|so|dylib)$", RegexOptions.IgnoreCase), "llama.cpp"),
        (new(@"^(lib)?llama\.(dll|so|dylib)$", RegexOptions.IgnoreCase), "llama.cpp"),
        (new(@"^(lib)?whisper\.(dll|so)$", RegexOptions.IgnoreCase), "whisper.cpp"),
        (new(@"^onnxruntime.*\.dll$", RegexOptions.IgnoreCase), "ONNX Runtime"),
        (new(@"^(torch_cpu|torch_cuda|c10)\.dll$", RegexOptions.IgnoreCase), "PyTorch"),
        (new(@"^tensorflow.*\.dll$|^_pywrap_tensorflow", RegexOptions.IgnoreCase), "TensorFlow"),
        (new(@"^openvino.*\.dll$", RegexOptions.IgnoreCase), "OpenVINO"),
        (new(@"^DirectML\.dll$", RegexOptions.IgnoreCase), "DirectML"),
        (new(@"^ctranslate2\.dll$", RegexOptions.IgnoreCase), "CTranslate2"),
        (new(@"^(tvm_runtime|mlc_llm)\.dll$", RegexOptions.IgnoreCase), "MLC/TVM"),
        (new(@"^Qnn(Htp|Cpu)\.dll$", RegexOptions.IgnoreCase), "Qualcomm NPU"),
        (new(@"^cudnn.*\.dll$", RegexOptions.IgnoreCase), "cuDNN"),
    };

    private static readonly string[] KjenteUtgivere = { "Microsoft", "Google", "Adobe", "NVIDIA", "Intel", "Apple", "Mozilla", "Zoom", "AMD", "Qualcomm" };

    // AI-biblioteker. Verdien sier om biblioteket lager agenter som kan handle på egen hånd.
    private static readonly Dictionary<string, bool> PythonAi = new(StringComparer.OrdinalIgnoreCase)
    {
        ["torch"] = false, ["tensorflow"] = false, ["transformers"] = false, ["diffusers"] = false, ["accelerate"] = false,
        ["onnxruntime"] = false, ["llama_cpp"] = false, ["vllm"] = false, ["sentence_transformers"] = false, ["mlx"] = false,
        ["gpt4all"] = false, ["ctransformers"] = false, ["openai"] = false, ["anthropic"] = false, ["mistralai"] = false,
        ["cohere"] = false, ["ollama"] = false, ["groq"] = false, ["chromadb"] = false, ["faiss"] = false,
        ["langchain"] = true, ["langchain_core"] = true, ["langgraph"] = true, ["llama_index"] = true, ["autogen"] = true,
        ["autogen_agentchat"] = true, ["crewai"] = true, ["smolagents"] = true, ["haystack"] = true,
        ["interpreter"] = true, ["browser_use"] = true, ["pydantic_ai"] = true, ["agents"] = true,
    };

    private static readonly Dictionary<string, bool> NodeAi = new(StringComparer.OrdinalIgnoreCase)
    {
        ["openai"] = false, ["@anthropic-ai/sdk"] = false, ["@google/generative-ai"] = false, ["@google/genai"] = false,
        ["ollama"] = false, ["@huggingface/transformers"] = false, ["@xenova/transformers"] = false, ["@mlc-ai/web-llm"] = false,
        ["onnxruntime-node"] = false, ["node-llama-cpp"] = false, ["ai"] = false, ["@ai-sdk/openai"] = false,
        ["langchain"] = true, ["@langchain/core"] = true, ["@langchain/langgraph"] = true, ["llamaindex"] = true,
        ["@modelcontextprotocol/sdk"] = true, ["@openai/agents"] = true, ["@anthropic-ai/claude-agent-sdk"] = true,
    };

    private static readonly Regex NokkelNavn = new(
        @"^(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_GENAI|MISTRAL|GROQ|DEEPSEEK|COHERE|PERPLEXITY|XAI|OPENROUTER|TOGETHER|FIREWORKS|AZURE_OPENAI|LANGCHAIN|LANGSMITH|ELEVENLABS|REPLICATE|STABILITY)_(API_)?(KEY|TOKEN)$|^(HF_TOKEN|HUGGINGFACE_HUB_TOKEN|HUGGING_FACE_HUB_TOKEN|HF_API_TOKEN)$",
        RegexOptions.IgnoreCase);

    private static readonly CultureInfo2 Nb = new();
    private sealed class CultureInfo2 { public readonly System.Globalization.CultureInfo C = new("nb-NO"); }
    private static string Gb(long b) => (b / 1073741824.0).ToString(b >= 10L * 1073741824 ? "0" : "0.0", Nb.C) + " GB";

    // ---------- AI-motorer ved siden av programmer som kjører ----------
    private void MotorerIProsesser()
    {
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                var sti = ProsessSti.Hent(p);
                if (sti == null || p.Id == Plattform.EgenPid) continue;
                var mappe = Path.GetDirectoryName(sti);
                if (mappe == null || ErSystemmappe(mappe) || UnderLeverandorRot(mappe) || !sett.Add(mappe)) continue;
                var motorer = FinnMotorer(mappe, 2);
                if (motorer.Count > 0) LeggTilMotorFunn(sti, motorer, kjorer: true);
            }
        }
    }

    private static bool ErSystemmappe(string mappe)
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return !string.IsNullOrEmpty(win) && mappe.StartsWith(win, StringComparison.OrdinalIgnoreCase);
    }

    private static SortedSet<string> FinnMotorer(string mappe, int dybde)
    {
        var funnet = new SortedSet<string>();
        try
        {
            int teller = 0;
            foreach (var fil in Plattform.Filer(mappe, "*.dll", dybde))
            {
                if (++teller > 5000) break;
                var navn = fil.Name;
                foreach (var (m, motor) in Motorer) if (m.IsMatch(navn)) funnet.Add(motor);
            }
        }
        catch { }
        return funnet;
    }

    private void LeggTilMotorFunn(string exe, SortedSet<string> motorer, bool kjorer)
    {
        string produkt = Path.GetFileNameWithoutExtension(exe), utgiver = "";
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(exe);
            if (!string.IsNullOrWhiteSpace(vi.ProductName)) produkt = vi.ProductName.Trim();
            utgiver = vi.CompanyName ?? "";
        }
        catch { }
        // Kjente produkter får navnet fra regelfila
        var regel = FinnRegel($"{produkt} {exe}");
        var navn = regel?.Navn ?? produkt;
        bool kjentUtgiver = KjenteUtgivere.Any(u => utgiver.Inneholder(u));
        bool fraNedlasting = ErRisikabelPlass(exe);
        // Ukjent = høy risiko. Kjente produkter og store kjente utgivere får lavere.
        var risiko = fraNedlasting ? Risiko.Rod : kjentUtgiver ? Risiko.Gronn : regel != null ? RisikoTekst.Fra(regel.Risiko) : Risiko.Rod;
        var hvorfor = kjentUtgiver
            ? $"Innebygd AI fra {utgiver.Trim()}. Kjører lokalt i programmet."
            : "Ukjent program med egen AI-motor. Det kan kjøre AI-modeller på PC-en uten at noen vet hva det gjør.";
        var f = regel != null ? FraRegel(regel, "AI-motor", null!) : LeggTil(navn, "Lokal AI", risiko, hvorfor, "AI-motor", null);
        f.Risiko = RisikoTekst.Hoyeste(f.Risiko, risiko);
        f.Detalj($"Program: {exe} (AI-motor: {string.Join(", ", motorer)})");
        if (kjorer) HuskMappe(exe, f);
        if (fraNedlasting) f.Advarsel("Kjører fra en nedlastings- eller midlertidig mappe, ikke fra en vanlig installasjon.");
        if (kjorer && f.Bruk == null) f.Bruk = "Kjører nå.";
    }

    private static bool ErRisikabelPlass(string sti) =>
        Regex.IsMatch(sti, @"[\\/](Downloads|Nedlastinger|Desktop|Skrivebord|Temp|tmp)[\\/]", RegexOptions.IgnoreCase);

    // ---------- Spør lokale servere om de er AI ----------
    private void LokaleServere()
    {
        var lyttere = TcpTabell.Hent()
            .Where(l => l.Pid > 4 && l.Pid != Plattform.EgenPid && l.Port >= 1024)
            .Where(l => IPAddress.IsLoopback(l.Adresse) || l.Adresse.Equals(IPAddress.Any) || l.Adresse.Equals(IPAddress.IPv6Any))
            .GroupBy(l => l.Port).Select(g => g.OrderBy(l => IPAddress.IsLoopback(l.Adresse) ? 1 : 0).First())
            .Take(80).ToList();
        if (lyttere.Count == 0) return;

        // MaxResponseContentBufferSize: et ondsinnet lokalt program kan ikke svare med et svar på flere GB og spise opp minnet.
        using var klient = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMilliseconds(800), MaxResponseContentBufferSize = 4 * 1024 * 1024 };
        // Alle portene spørres samtidig (16 om gangen). Før tok det 0,8 s per port som ikke svarte, én etter én.
        // Helt asynkront: ingen tråd står og venter på et svar. (2.19 ventet med .GetResult() i 16 tråder samtidig, mens de
        // andre sjekkene også brukte trådpoolen. På .NET Framework kan det sulte ut trådpoolen så søket stopper opp.)
        var svar = new List<string>?[lyttere.Count];
        using (var ko = new SemaphoreSlim(16))
        {
            async Task Ett(int i)
            {
                await ko.WaitAsync().ConfigureAwait(false);
                try { svar[i] = await SporAsync(klient, lyttere[i].Port).ConfigureAwait(false); } finally { ko.Release(); }
            }
            Task.WhenAll(Enumerable.Range(0, lyttere.Count).Select(Ett)).GetAwaiter().GetResult();
        }
        for (int i = 0; i < lyttere.Count; i++)
        {
            var l = lyttere[i];
            var modeller = svar[i];
            if (modeller == null) continue;
            string prosess = "ukjent program", sti = "";
            try { using var p = Process.GetProcessById(l.Pid); prosess = p.ProcessName; sti = ProsessSti.Hent(p) ?? ""; } catch { }
            var regel = FinnRegel($"{prosess} {sti}");
            var navn = regel?.Navn ?? $"Lokal AI-server ({prosess})";
            bool apen = l.Adresse.Equals(IPAddress.Any) || l.Adresse.Equals(IPAddress.IPv6Any);
            var f = regel != null ? FraRegel(regel, "AI-server", null!)
                : LeggTil(navn, "Lokal AI", Risiko.Rod, "Ukjent program som svarer som en AI-tjeneste. Andre programmer kan bruke det.", "AI-server", null,
                          rad: "Finn ut hva programmet er. Slå det av hvis du ikke bruker det.");
            f.Detalj($"Nettverksport {l.Port} på {l.Adresse}, program: {(sti.Length > 0 ? sti : prosess)}");
            HuskMappe(sti, f);
            if (modeller.Count > 0) f.Detalj($"Modeller: {string.Join(", ", modeller.Take(10))}");
            if (modeller.Count > 0) f.Bruk = $"Har {modeller.Count} {(modeller.Count == 1 ? "modell" : "modeller")} lastet: {string.Join(", ", modeller.Take(3))}{(modeller.Count > 3 ? " …" : "")}.";
            if (apen)
            {
                f.Risiko = Risiko.Rod;
                f.Advarsel("Er åpen mot nettverket. Andre på samme nett kan bruke den uten passord.");
            }
        }
    }

    /// <summary>Ett lesende GET-kall mot vanlige AI-adresser. Returnerer modellnavn, eller null hvis det ikke er AI.</summary>
    internal static List<string>? Spor(HttpClient klient, int port) => SporAsync(klient, port).GetAwaiter().GetResult();

    internal static async Task<List<string>?> SporAsync(HttpClient klient, int port)
    {
        foreach (var sti in new[] { "/api/tags", "/v1/models", "/sdapi/v1/sd-models" })
        {
            try
            {
                using var svar = await klient.GetAsync($"http://127.0.0.1:{port}{sti}").ConfigureAwait(false);
                Tilgangslogg.Logg("Port", $"127.0.0.1:{port}{sti}", svar.IsSuccessStatusCode ? Utfall.Lest : Utfall.IkkeFunnet, $"HTTP {(int)svar.StatusCode}");
                if (!svar.IsSuccessStatusCode) continue;
                var tekst = await svar.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (tekst.Length > 2_000_000) continue;
                using var doc = JsonDocument.Parse(tekst);
                var rot = doc.RootElement;
                var navn = new List<string>();
                if (rot.ValueKind == JsonValueKind.Object && rot.TryGetProperty("models", out var m) && m.ValueKind == JsonValueKind.Array)
                    navn.AddRange(m.EnumerateArray().Select(x => Str(x, "name") ?? Str(x, "model")).OfType<string>());
                else if (rot.ValueKind == JsonValueKind.Object && rot.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array && Str(rot, "object") == "list")
                    navn.AddRange(d.EnumerateArray().Select(x => Str(x, "id")).OfType<string>());
                else if (rot.ValueKind == JsonValueKind.Array && sti.StartsWith("/sdapi"))
                    navn.AddRange(rot.EnumerateArray().Select(x => Str(x, "model_name") ?? Str(x, "title")).OfType<string>());
                else continue;
                return navn;
            }
            catch (Exception e)
            {
                Tilgangslogg.Logg("Port", $"127.0.0.1:{port}{sti}", e is TaskCanceledException ? Utfall.Tidsgrense : Utfall.IkkeFunnet, e is TaskCanceledException ? "svarte ikke innen 0,8 s; de andre adressene på porten ble ikke prøvd" : "svarte ikke som en AI-tjeneste");
                // Et program som ikke svarer på HTTP innen 0,8 s, svarer heller ikke på neste adresse. Spar 1,6 s per port.
                if (e is TaskCanceledException) break;
            }
        }
        return null;
    }

    // ---------- AI-nøkler (bare navnet på variabelen, aldri verdien) ----------
    private void Nokler()
    {
        var navn = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
            if (e.Key is string k && NokkelNavn.IsMatch(k)) navn.Add(k);
        if (Plattform.ErWindows)
        {
            // Bare navnene på variablene i registeret, aldri verdiene
            using (var env = Tilgangslogg.Nokkel(Microsoft.Win32.Registry.CurrentUser, "Environment"))
                foreach (var k in env?.GetValueNames() ?? Array.Empty<string>()) if (NokkelNavn.IsMatch(k)) navn.Add(k);
            using (var env = Tilgangslogg.Nokkel(Microsoft.Win32.Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
                foreach (var k in env?.GetValueNames() ?? Array.Empty<string>()) if (NokkelNavn.IsMatch(k)) navn.Add(k);
        }
        // Filer som bare finnes når man har logget inn med en nøkkel (vi sjekker at de finnes, åpner dem ikke)
        var hfToken = Utvid(@"%USERPROFILE%\.cache\huggingface\token");
        if (File.Exists(hfToken)) navn.Add("Hugging Face-innlogging");
        if (navn.Count == 0) return;
        var f = LeggTil("AI-nøkler lagret på PC-en", "Skygge-AI", Risiko.Gul,
            "Programmer på PC-en kan bruke AI-tjenester med disse nøklene, på eierens regning og med eierens data.", null, null,
            rad: "Fjern nøkler du ikke bruker. På jobb: bruk bare nøkler bedriften har godkjent.");
        f.Bruk = $"{navn.Count} {(navn.Count == 1 ? "nøkkel" : "nøkler")}: {string.Join(", ", navn.Take(4))}{(navn.Count > 4 ? " …" : "")}.";
        foreach (var n in navn)
            f.Detalj(n == "Hugging Face-innlogging" ? $"Fil: {hfToken} (innholdet er ikke lest)" : $"Miljøvariabel: {n} (verdien er ikke lest)");
    }

    // ---------- Gjennomgang av filer: modeller, AI-motorer, Python/Node ----------
    private sealed class FilFunn
    {
        public readonly List<(string Sti, long Lengde, ModellFormat.Modell Modell)> Modeller = new();
        public readonly Dictionary<string, SortedSet<string>> Motorer = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, (SortedSet<string> Pakker, bool Agent, string Sprak)> Miljoer = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Filer der en farlig YARA-regel slo til.</summary>
        public readonly List<(string Sti, long Lengde, List<YaraRegler.Regel> Treff)> Farlige = new();
    }

    private const FileAttributes Skyfil = (FileAttributes)0x00400000 | (FileAttributes)0x00040000 | FileAttributes.Offline;

    private void Gjennomgang()
    {
        var ff = new FilFunn();
        var frist = Stopwatch.StartNew();
        long minLengde = Math.Max(20, _regler.ModellfilMinMB / 10) * 1024L * 1024L;
        var hopp = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // AppData gås gjennom av LeverandorAi, som også finner hvem som har lagt AI-en der
            Utvid(@"%LOCALAPPDATA%"), Utvid(@"%APPDATA%"), Utvid(@"%USERPROFILE%\AppData\LocalLow"),
        };
        var rotter = new List<(string Sti, int Dybde)> { (Utvid("%USERPROFILE%"), 10) };
        if (Plattform.ErWindows)
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                    var rot = d.RootDirectory.FullName;
                    if (rot.StartsWith("C", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var m in new[] { @"C:\models", @"C:\AI", @"C:\llm", @"C:\ComfyUI", @"C:\stable-diffusion-webui" })
                            if (Directory.Exists(m)) rotter.Add((m, 8));
                    }
                    else rotter.Add((rot, 6));
                }
                catch { }
            }
        }
        // Hver toppmappe gjennomgås parallelt. Diskene er raskest med noen få samtidige lesere.
        var jobber = new List<(string Sti, int Dybde)>();
        foreach (var (rot, dybde) in rotter)
        {
            GaaFiler(rot, ff, minLengde);
            foreach (var d in Mapper(rot)) jobber.Add((d, dybde - 1));
        }
        Parallel.ForEach(jobber, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, Math.Min(8, Environment.ProcessorCount)) },
            j => Gaa(j.Sti, j.Dybde, ff, hopp, minLengde, frist));

        LeggTilFarlige(ff);
        // AI-oppsett i prosjektmapper (.mcp.json, .vscode\mcp.json, .claude\settings.json) som gjennomgangen fant
        ProsjektOppsett();

        // Modeller
        var modeller = ff.Modeller.OrderByDescending(m => m.Lengde).ToList();
        foreach (var (sti, lengde, m) in modeller.Take(15)) LeggTilModell(sti, lengde, m);
        if (modeller.Count > 15)
        {
            var resten = modeller.Skip(15).ToList();
            var f = LeggTil($"Flere AI-modeller ({resten.Count})", "Lokal AI", Risiko.Rod, "Flere AI-modeller ligger lagret på PC-en.", "Disk", null);
            f.Bruk = $"Til sammen {Gb(resten.Sum(x => x.Lengde))}.";
            f.LeggTilModeller(resten.Count);
            foreach (var r in resten)
            {
                var id = ModellGjenkjenning.Finn(r.Modell, r.Sti, _regler, Kildenavn(r.Sti));
                f.Detalj($"Fil: {r.Sti} · {r.Modell.Format} · {Gb(r.Lengde)}{(id.FamilieTekst != null ? " · " + id.FamilieTekst : "")} · ID {id.Sha256?.Substring(0, 16) ?? id.Fingeravtrykk}");
            }
        }

        // AI-motorer i programmer som ikke kjører nå
        foreach (var (mappe, motorer) in ff.Motorer)
        {
            var exe = Filer(mappe).FirstOrDefault(x => x.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                      ?? Path.Combine(mappe, Path.GetFileName(mappe) + ".exe");
            LeggTilMotorFunn(exe, motorer, kjorer: false);
        }

        // Python- og Node-miljøer med AI
        foreach (var (sti, (pakker, agent, sprak)) in ff.Miljoer)
        {
            var prosjekt = Prosjektnavn(sti);
            var f = LeggTil($"{sprak}-prosjekt med AI: {prosjekt}", "Skygge-AI (utvikling)", agent ? Risiko.Rod : Risiko.Gul,
                agent ? "Ukjent AI-agent: kode som kan handle på egen hånd med AI." : "Kode som bruker AI-biblioteker.",
                sprak, $"Mappe: {sti} ({string.Join(", ", pakker)})",
                rad: agent ? "Sjekk hva agenten har tilgang til, og at den ikke bruker jobbdata uten avtale." : "Ingenting å gjøre hvis du vet hva prosjektet er.");
            f.Bruk = $"Bruker {string.Join(", ", pakker.Take(4))}{(pakker.Count > 4 ? " …" : "")}.";
        }
    }

    private void Gaa(string mappe, int dybde, FilFunn ff, HashSet<string> hopp, long minLengde, Stopwatch frist)
    {
        if (hopp.Contains(mappe)) return;
        if (dybde < 0) { Tilgangslogg.TellMappe(mappe, Utfall.HoppetOver, detalj: "dybdegrensen for gjennomgangen er nådd"); return; }
        if (frist.Elapsed > TimeSpan.FromSeconds(45))
        {
            Tilgangslogg.EnGang("disk-45", "Mappe", mappe, Utfall.Tidsgrense, "45 sekunder brukt på disken; resten av mappene ble ikke gått gjennom");
            Tilgangslogg.TellMappe(mappe, Utfall.Tidsgrense, detalj: "45 sekunder brukt på disken");
            return;
        }
        var navn = Path.GetFileName(mappe);
        if (navn is "site-packages" or "dist-packages") { SjekkPip(mappe); Miljo(mappe, PythonAi, "Python", ff); return; }
        if (navn == "node_modules") { Miljo(mappe, NodeAi, "Node", ff); return; }
        if (navn.StartsWith(".") && navn is not (".ollama" or ".lmstudio" or ".cache" or ".local" or ".venv" or ".env" or ".conda" or ".foundry" or ".aitk" or ".docker" or ".vscode" or ".cursor" or ".claude" or ".gemini" or ".github" or ".codex")) { Tilgangslogg.TellMappe(mappe, Utfall.HoppetOver, detalj: "mappe som starter med punktum, ikke en kjent AI-mappe"); return; }
        if (navn is "Windows" or "$Recycle.Bin" or "System Volume Information" or "Program Files" or "Program Files (x86)" or "ProgramData") { Tilgangslogg.Logg("Mappe", mappe, Utfall.HoppetOver, "hoppes over av regel (systemmappe eller sjekkes av egen sjekk)"); return; }

        IEnumerable<FileSystemInfo> innhold;
        try { innhold = new DirectoryInfo(mappe).EnumerateFileSystemInfos(); } catch (Exception e) { Tilgangslogg.Feil("Mappe", mappe, e); return; }
        long filer = 0, bytes = 0, sky = 0;
        try
        {
            foreach (var e in innhold)
            {
                FileAttributes a;
                try { a = e.Attributes; } catch { continue; }
                if ((a & Skyfil) != 0) { Tilgangslogg.Tell("Fil", Utfall.HoppetOver); sky++; continue; }   // aldri last ned skyfiler (OneDrive)
                if ((a & FileAttributes.ReparsePoint) != 0) { SjekkLenke(e); continue; }
                if (e is DirectoryInfo d) Gaa(d.FullName, dybde - 1, ff, hopp, minLengde, frist);
                else if (e is FileInfo fil)
                {
                    filer++;
                    try { bytes += fil.Length; } catch { }
                    SjekkFil(fil, mappe, ff, minLengde);
                }
            }
            Tilgangslogg.TellMappe(mappe, Utfall.Lest, filer, bytes);
            if (sky > 0) Tilgangslogg.BareKart("Mappe", mappe, Utfall.HoppetOver, $"{sky} skyfiler (OneDrive) som ikke er lastet ned, åpnes aldri");
        }
        catch (Exception e) { Tilgangslogg.Feil("Mappe", mappe, e); }
    }

    /// <summary>Bare filene i selve mappa (brukes for rotmappene, der undermappene gås gjennom parallelt).</summary>
    private void GaaFiler(string mappe, FilFunn ff, long minLengde)
    {
        FileInfo[] filer;
        try { filer = new DirectoryInfo(mappe).GetFiles(); } catch (Exception e) { Tilgangslogg.Feil("Mappe", mappe, e); return; }
        Tilgangslogg.Logg("Mappe", mappe, Utfall.Lest, "startpunkt for gjennomgangen");
        foreach (var fil in filer)
        {
            try { if ((fil.Attributes & (FileAttributes.ReparsePoint | Skyfil)) != 0) continue; } catch { continue; }
            SjekkFil(fil, mappe, ff, minLengde);
        }
    }

    private void SjekkFil(FileInfo fil, string mappe, FilFunn ff, long minLengde)
    {
        if (fil.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) SjekkProsjektOppsett(fil);
        SjekkAgentfil(fil);
        var ext = fil.Extension.ToLowerInvariant();
        if (ext == ".dll")
        {
            foreach (var (m, motor) in Motorer)
            {
                if (!m.IsMatch(fil.Name)) continue;
                lock (ff)
                {
                    if (!ff.Motorer.TryGetValue(mappe, out var s)) ff.Motorer[mappe] = s = new SortedSet<string>();
                    s.Add(motor);
                }
            }
            return;
        }
        long lengde;
        try { lengde = fil.Length; } catch { return; }
        bool liten = ext is ".onnx" or ".tflite" && lengde > 5 * 1024 * 1024;
        if (lengde < minLengde && !liten) { SjekkLitenModell(fil, ff); return; }
        if (ext is ".zip" or ".7z" or ".rar" or ".iso" or ".mp4" or ".mkv" or ".mov" or ".avi" or ".exe" or ".msi" or ".vhdx" or ".pst" or ".ost" or ".jpg" or ".png") return;
        var modell = ModellFormat.Gjenkjenn(fil.FullName);
        if (modell != null) lock (ff) ff.Modeller.Add((fil.FullName, lengde, modell));
    }

    private static void Miljo(string sti, Dictionary<string, bool> kjente, string sprak, FilFunn ff)
    {
        var pakker = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        bool agent = false;
        foreach (var d in Mapper(sti))
        {
            var navn = Path.GetFileName(d);
            var kandidater = navn.StartsWith("@") ? Mapper(d).Select(u => $"{navn}/{Path.GetFileName(u)}") : new[] { navn };
            foreach (var k in kandidater)
            {
                if (!kjente.TryGetValue(k, out var erAgent)) continue;
                // "agents" og "ai" er vanlige ord; tell dem bare sammen med andre AI-pakker
                pakker.Add(k);
                agent |= erAgent;
            }
        }
        if (pakker.Count == 0 || pakker.All(p => p is "ai" or "agents")) return;
        lock (ff) ff.Miljoer[sti] = (pakker, agent, sprak);
    }

    /// <summary>Gir et forståelig prosjektnavn: mappa over venv/node_modules, ikke "Lib" eller ".venv".</summary>
    private static string Prosjektnavn(string sti)
    {
        var deler = sti.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
        var stopp = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "site-packages", "dist-packages", "node_modules", "lib", "Lib", ".venv", "venv", "env", "Scripts" };
        for (int i = deler.Length - 1; i >= 0; i--)
            if (!stopp.Contains(deler[i]) && !deler[i].StartsWith("python3", StringComparison.OrdinalIgnoreCase)) return deler[i];
        return sti;
    }

    private readonly Dictionary<string, Dictionary<string, string>> _ollamaNavn = new(StringComparer.OrdinalIgnoreCase);

    private string? Kildenavn(string sti)
    {
        var hf = Regex.Match(sti, @"models--([^\\/]+?)--([^\\/]+)");
        if (hf.Success) return $"{hf.Groups[1].Value}/{hf.Groups[2].Value}";
        var blob = Regex.Match(sti, @"^(.*[\\/]blobs)[\\/]sha256[-:]([0-9a-f]{64})$", RegexOptions.IgnoreCase);
        if (!blob.Success) return null;
        Dictionary<string, string> kart;
        lock (_ollamaNavn)
            if (!_ollamaNavn.TryGetValue(blob.Groups[1].Value, out kart!))
                _ollamaNavn[blob.Groups[1].Value] = kart = ModellGjenkjenning.OllamaNavn(blob.Groups[1].Value);
        return kart.TryGetValue(blob.Groups[2].Value, out var navn) ? navn : null;
    }

    private static string Land(string? kode) => string.IsNullOrEmpty(kode) ? "" : ", " + IpLand.Navn(kode);

    private void LeggTilModell(string sti, long lengde, ModellFormat.Modell m)
    {
        var kilde = Kildenavn(sti);
        var id = ModellGjenkjenning.Finn(m, sti, _regler, kilde);
        var filnavn = Modellnavn(sti);
        bool ollamaBlob = Regex.IsMatch(sti, @"[\\/]blobs[\\/]sha256", RegexOptions.IgnoreCase);
        // Navn: fra programmet som lastet den ned, fra filen selv, ellers familien den tilhører
        var navn = kilde ?? m.Navn
                   ?? (id.FamilieTekst != null && (ollamaBlob || Regex.IsMatch(filnavn, @"^[0-9a-f]{16,}$|^(model|weights|out|output|checkpoint)", RegexOptions.IgnoreCase))
                       ? $"uten navn ({id.FamilieTekst})" : ollamaBlob ? "Ollama-modell" : filnavn);
        bool farligPlass = ErRisikabelPlass(sti);
        // Modeller i kjente programmer (Ollama, LM Studio, GPT4All, Hugging Face-lageret) er gule. Alle andre er ukjente og røde.
        bool kjentSted = Regex.IsMatch(sti, @"\.ollama|lmstudio|lm-studio|nomic\.ai|huggingface|\.foundry", RegexOptions.IgnoreCase);
        var risiko = kjentSted && !m.KanKjoreKode ? Risiko.Gul : Risiko.Rod;
        var hvorfor = m.KanKjoreKode
            ? "AI-modell i et format som kan kjøre skjult kode når den åpnes."
            : "AI-modell som kan kjøres på PC-en uten internett og uten kontroll.";
        DateTime? opprettet = null, endret = null;
        try { var fi = new FileInfo(sti); opprettet = fi.CreationTime; endret = fi.LastWriteTime; } catch { }
        var f = LeggTil($"AI-modell: {Kutt(navn, 50)}", "Lokal AI (modell)", risiko, hvorfor, m.Format, $"Fil: {sti} · {m.Format} · {Gb(lengde)} · endret {Tid(endret)}",
                        rad: m.KanKjoreKode ? "Slett den hvis du ikke vet hvor den kommer fra." : "Slett den hvis du ikke bruker den.");
        f.LeggTilModeller(1);

        f.Tidspunkt(opprettet < endret ? opprettet : endret, endret);
        var info = new List<string>();
        var fam = id.Familie ?? id.NavneFamilie;
        // Kommer fra: navnet i filen (DeepSeek) veier tyngre enn arkitekturen den bygger på (Qwen)
        if ((id.NavneFamilie ?? id.Familie) is { } opp) { f.Opprinnelse ??= opp.Utgiver; f.OpprinnelseLand ??= opp.Land; }
        if (id.Familie != null && id.NavneFamilie != null && id.Familie != id.NavneFamilie)
            info.Add($"{id.FamilieTekst} ({id.Sikkerhet})");
        else if (fam != null)
            info.Add($"{id.FamilieTekst} fra {fam.Utgiver}{Land(fam.Land)} ({id.Sikkerhet})");
        else if (m.Type != null) info.Add(char.ToUpper(m.Type[0]) + m.Type.Substring(1) + " av ukjent familie");
        info.Add(Gb(lengde));
        if (ModellFormat.ParametreTekst(m.Parametre) is { } p) info.Add(p);
        info.Add(Mappenavn(sti));
        f.Bruk = string.Join(", ", info) + ".";

        f.Detalj(fam != null
            ? $"Gjenkjent som: {id.FamilieTekst} ({id.Sikkerhet}){(id.Bevis.Count > 0 ? ": " + string.Join(", ", id.Bevis) : "")}"
            : $"Familie ukjent{(id.Bevis.Count > 0 ? ": " + string.Join(", ", id.Bevis) : "")}");
        if (m.Type != null && m.Type != "språkmodell") f.Detalj($"Type: {m.Type}");
        if (id.Sha256 != null) f.Detalj($"Modell-ID (SHA-256, lik på alle PC-er): {id.Sha256}");
        else if (id.Fingeravtrykk != null) f.Detalj($"Modell-ID (fingeravtrykk, likt på alle PC-er): {id.Fingeravtrykk}");
        if (m.KanKjoreKode && farligPlass) f.Advarsel("Kan kjøre skjult kode, og ligger i en nedlastingsmappe.");
        YaraPaModell(sti, f);
        if (id.NavneFamilie?.Land == "CN" || id.Familie?.Land == "CN") f.Merknad($"Laget av {(id.NavneFamilie?.Land == "CN" ? id.NavneFamilie : id.Familie)!.Utgiver} i Kina. Kjører lokalt, så data sendes ikke dit, men sjekk om bedriften tillater modellen.");
    }

    /// <summary>Gir generiske filnavn ("model", "pytorch_model-00001-of-00004") et bedre navn fra mappene rundt.</summary>
    private static string Modellnavn(string sti)
    {
        var navn = Path.GetFileNameWithoutExtension(sti);
        var hf = Regex.Match(sti, @"models--([^\\/]+?)--([^\\/]+)");
        if (hf.Success) return $"{hf.Groups[1].Value}/{hf.Groups[2].Value}";
        if (Regex.IsMatch(navn, @"^(model|pytorch_model|diffusion_pytorch_model|consolidated|weights|adapter_model)([-_.].*)?$", RegexOptions.IgnoreCase))
            return Path.GetFileName(Path.GetDirectoryName(sti)) ?? navn;
        return navn;
    }

    private static string Mappenavn(string sti)
    {
        if (Regex.IsMatch(sti, @"[\\/](Downloads|Nedlastinger)[\\/]", RegexOptions.IgnoreCase)) return "i Nedlastinger";
        if (Regex.IsMatch(sti, @"[\\/](Desktop|Skrivebord)[\\/]", RegexOptions.IgnoreCase)) return "på skrivebordet";
        if (sti.Inneholder(".ollama")) return "i Ollama";
        if (sti.Inneholder("lmstudio") || sti.Inneholder("lm-studio")) return "i LM Studio";
        if (sti.Inneholder("huggingface")) return "i Hugging Face-lageret";
        return "i " + (Path.GetFileName(Path.GetDirectoryName(sti)) ?? "en mappe");
    }
}
