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

    internal static bool ErNokkelNavn(string navn) => NokkelNavn.IsMatch(navn);

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
                if (sti == null || Plattform.ErEgen(p.Id)) continue;
                var mappe = Path.GetDirectoryName(sti);
                if (mappe == null || ErSystemmappe(mappe) || UnderLeverandorRot(mappe) || !sett.Add(mappe)) continue;
                var motorer = FinnMotorer(mappe, 2);
                if (motorer.Count > 0 && !BareGrafikkMotor(motorer)) LeggTilMotorFunn(sti, motorer, kjorer: true);
            }
        }
    }

    /// <summary>
    /// DirectML alene er ikke AI: det er Windows' grafikkbibliotek for maskinlæring, og følger med Edge, WebView2, Teams,
    /// spill og videoprogrammer som aldri kjører en AI-modell. Det teller bare sammen med en ekte AI-motor eller modellfiler.
    /// Kilde: https://learn.microsoft.com/windows/ai/directml/dml
    /// </summary>
    internal static bool BareGrafikkMotor(IReadOnlyCollection<string> motorer) => motorer.Count > 0 && motorer.All(m => m == "DirectML");

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
        string? versjon = null;
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(exe);
            if (!string.IsNullOrWhiteSpace(vi.ProductName)) produkt = vi.ProductName.Trim();
            utgiver = vi.CompanyName ?? "";
            versjon = vi.ProductVersion ?? vi.FileVersion;
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
        f.SettVersjon(versjon, "programfila");
        f.Risiko = RisikoTekst.Hoyeste(f.Risiko, risiko);
        f.Detalj($"Program: {exe} (AI-motor: {string.Join(", ", motorer)})");
        if (kjorer) HuskMappe(exe, f);
        if (fraNedlasting) f.Advarsel("Kjører fra en nedlastings- eller midlertidig mappe, ikke fra en vanlig installasjon.");
        if (kjorer && f.Bruk == null) f.Bruk = "Kjører nå.";
        if (kjorer) f.Merk(Tilstand.KjorerNa);
    }

    // Utgiver fra filinfo, ellers fra signaturen (Windows-filer i SystemApps og WinSxS mangler ofte filinfo)
    private static string Utgiver(string exe)
    {
        string? u = null;
        try { u = FileVersionInfo.GetVersionInfo(exe).CompanyName; } catch { }
        return string.IsNullOrWhiteSpace(u) ? Signatur.Utgiver(exe) ?? "" : u!;
    }

    private static bool ErRisikabelPlass(string sti) =>
        Regex.IsMatch(sti, @"[\\/](Downloads|Nedlastinger|Desktop|Skrivebord|Temp|tmp)[\\/]", RegexOptions.IgnoreCase);

    // ---------- Spør lokale servere om de er AI ----------
    private void LokaleServere()
    {
        var lyttere = TcpTabell.Hent()
            .Where(l => l.Pid > 4 && !Plattform.ErEgen(l.Pid) && l.Port >= 1024)
            .Where(l => IPAddress.IsLoopback(l.Adresse) || l.Adresse.Equals(IPAddress.Any) || l.Adresse.Equals(IPAddress.IPv6Any))
            .GroupBy(l => l.Port).Select(g => g.OrderBy(l => IPAddress.IsLoopback(l.Adresse) ? 1 : 0).First())
            .Take(80).ToList();
        // Hvem lytter? Windows' egne tjenester (programfila ligger i Windows-mappa) er ikke AI og spørres ikke.
        var system = Utvid("%SystemRoot%").TrimEnd('\\') + "\\";
        var eiere = new Dictionary<int, (string Navn, string Sti)>();
        foreach (var pid in lyttere.Select(l => l.Pid).Distinct())
        {
            string navn = "ukjent program", sti = "";
            try { using var p = Process.GetProcessById(pid); navn = p.ProcessName; sti = ProsessSti.Hent(p) ?? Admintilgang.ProsessBilde(pid) ?? ""; } catch { }
            eiere[pid] = (navn, sti);
        }
        if (Plattform.ErWindows)
            lyttere = lyttere.Where(l =>
            {
                var (navn, sti) = eiere[l.Pid];
                if (!sti.StartsWith(system, StringComparison.OrdinalIgnoreCase) || FinnRegel($"{navn} {sti}") != null) return true;
                Tilgangslogg.Logg("Port", $"127.0.0.1:{l.Port}", Utfall.IkkeFunnet, $"Windows' egen tjeneste ({navn}), ikke AI; ikke spurt");
                return false;
            }).ToList();
        if (lyttere.Count == 0) return;

        // MaxResponseContentBufferSize: et ondsinnet lokalt program kan ikke svare med et svar på flere GB og spise opp minnet.
        using var klient = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMilliseconds(Fullt ? 3000 : 800), MaxResponseContentBufferSize = 4 * 1024 * 1024 };
        // Alle portene spørres samtidig (16 om gangen). Før tok det 0,8 s per port som ikke svarte, én etter én.
        // Helt asynkront: ingen tråd står og venter på et svar. (2.19 ventet med .GetResult() i 16 tråder samtidig, mens de
        // andre sjekkene også brukte trådpoolen. På .NET Framework kan det sulte ut trådpoolen så søket stopper opp.)
        var svar = new List<string>?[lyttere.Count];
        var lastet = new List<string>?[lyttere.Count];
        using (var ko = new SemaphoreSlim(16))
        {
            async Task Ett(int i)
            {
                await ko.WaitAsync().ConfigureAwait(false);
                try
                {
                    svar[i] = await SporAsync(klient, lyttere[i].Port).ConfigureAwait(false);
                    // Ollama: modellene som er lastet i minnet akkurat nå
                    if (svar[i] != null) lastet[i] = await LastetNaAsync(klient, lyttere[i].Port).ConfigureAwait(false);
                }
                finally { ko.Release(); }
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
                : LeggTil(navn, "Lokal AI", Risiko.Rod, "Ukjent program som svarer som en AI-tjeneste. Andre programmer kan bruke det.", "AI-server", null);
            f.Detalj($"Nettverksport {l.Port} på {l.Adresse}, program: {(sti.Length > 0 ? sti : prosess)}");
            f.Sterkt();   // svarte som en AI-tjeneste
            HuskMappe(sti, f);
            if (modeller.Count > 0) f.Detalj($"Modeller: {string.Join(", ", modeller.Take(10))}");
            if (modeller.Count > 0) f.Bruk = $"Har {modeller.Count} {(modeller.Count == 1 ? "modell" : "modeller")}: {string.Join(", ", modeller.Take(3))}{(modeller.Count > 3 ? " …" : "")}.";
            if (lastet[i] is { Count: > 0 } ilast) { f.Detalj($"Lastet i minnet nå: {string.Join(", ", ilast)}"); f.Bruk = $"Kjører {string.Join(", ", ilast.Take(2))} nå. " + (f.Bruk ?? ""); }
            if (modeller.Count > 0) { f.Merk(Tilstand.KjorerNa); f.Sterkt(); }
            if (apen)
            {
                f.Risiko = Risiko.Rod;
                f.Advarsel("Er åpen mot nettverket. Andre på samme nett kan bruke den uten passord.");
            }
        }
    }

    /// <summary>Ett lesende GET-kall mot vanlige AI-adresser. Returnerer modellnavn, eller null hvis det ikke er AI.</summary>
    internal static List<string>? Spor(HttpClient klient, int port) => SporAsync(klient, port).GetAwaiter().GetResult();

    /// <summary>Ollama /api/ps: modellene som ligger i minnet nå. Null når serveren ikke har denne adressen.</summary>
    internal static async Task<List<string>?> LastetNaAsync(HttpClient klient, int port)
    {
        try
        {
            using var svar = await klient.GetAsync($"http://127.0.0.1:{port}/api/ps").ConfigureAwait(false);
            Tilgangslogg.Logg("Port", $"127.0.0.1:{port}/api/ps", svar.IsSuccessStatusCode ? Utfall.Lest : Utfall.IkkeFunnet, $"HTTP {(int)svar.StatusCode}");
            if (!svar.IsSuccessStatusCode) return null;
            var tekst = await svar.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (tekst.Length > 1_000_000) return null;
            using var doc = JsonDocument.Parse(tekst);
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("models", out var m) || m.ValueKind != JsonValueKind.Array) return null;
            return m.EnumerateArray().Select(x => Str(x, "name") ?? Str(x, "model")).OfType<string>().ToList();
        }
        catch { return null; }
    }

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
                // En AI-server svarer på HTTP med en gang. Svarer porten ikke på HTTP, er den ikke en AI-tjeneste for HTTP.
                Tilgangslogg.Logg("Port", $"127.0.0.1:{port}{sti}", Utfall.IkkeFunnet, e is TaskCanceledException ? $"svarte ikke på HTTP innen {klient.Timeout.TotalSeconds:0.#} s, så ikke en AI-tjeneste for HTTP; de andre adressene på porten ble ikke prøvd" : "svarte ikke som en AI-tjeneste");
                // Et program som ikke svarer på HTTP innen 0,8 s, svarer heller ikke på neste adresse. Spar 1,6 s per port.
                if (e is TaskCanceledException) break;
            }
        }
        return null;
    }

    // ---------- AI-nøkler (bare navnet på variabelen, aldri verdien) ----------
    private static readonly Regex EnvLinje = new(@"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", RegexOptions.Compiled);

    /// <summary>
    /// .env-filer: navnene på AI-nøkler som har en verdi. Verdien sjekkes bare for om den er tom, og kastes med en gang.
    /// </summary>
    private void EnvNokler(IEnumerable<string> filer)
    {
        var treff = new List<(string Fil, string Navn)>();
        foreach (var fil in filer)
        {
            try
            {
                var fi = new FileInfo(fil);
                if (fi.Length > 256 * 1024) { Tilgangslogg.Tell("Fil", Utfall.HoppetOver, sted: fil, detalj: ".env større enn 256 kB"); continue; }
                using var fs = Admintilgang.AapneLes(fil);
                using var r = new StreamReader(fs);
                string? linje;
                while ((linje = r.ReadLine()) != null)
                {
                    var m = EnvLinje.Match(linje);
                    if (!m.Success || !NokkelNavn.IsMatch(m.Groups[1].Value)) continue;
                    var verdi = m.Groups[2].Value.Trim().Trim('"', '\'');
                    bool har = verdi.Length > 0 && !verdi.StartsWith("#") && !verdi.StartsWith("${") && !verdi.StartsWith("<");
                    verdi = "";
                    if (har) treff.Add((fil, m.Groups[1].Value));
                }
                Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil, detalj: ".env: bare navnene på AI-nøkler, aldri verdiene");
            }
            catch (Exception e) { Tilgangslogg.Feil("Fil", fil, e); }
        }
        if (treff.Count == 0) return;
        var f = NokkelFunn(treff.Select(t => t.Navn));
        foreach (var g in treff.GroupBy(t => t.Fil))
            f.Detalj($"Fil: {g.Key} · {string.Join(", ", g.Select(t => t.Navn).Distinct())} (verdien vises aldri)");
    }

    private readonly SortedSet<string> _nokkelNavn = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Ett funn for alle AI-nøkler. «Bruk» telles fra alle kildene (miljøvariabler, .env, innlogging).</summary>
    private Funn NokkelFunn(IEnumerable<string> navn)
    {
        var f = LeggTil("AI-nøkler lagret på PC-en", "Skygge-AI", Risiko.Gul,
            "Programmer på PC-en kan bruke AI-tjenester med disse nøklene, på eierens regning og med eierens data.", null, null);
        lock (_nokkelNavn)
        {
            foreach (var n in navn) _nokkelNavn.Add(n);
            f.Bruk = $"{_nokkelNavn.Count} {(_nokkelNavn.Count == 1 ? "nøkkel" : "nøkler")}: {string.Join(", ", _nokkelNavn.Take(4))}{(_nokkelNavn.Count > 4 ? " …" : "")}.";
        }
        return f;
    }

    private void Nokler()
    {
        var navn = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        // Når en annen konto (IT) kjører programmet, er prosessens miljø IT-kontoens. Da telles bare brukerens register.
        if (!Bruker.Annen)
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables())
                if (e.Key is string k && NokkelNavn.IsMatch(k)) navn.Add(k);
        if (Plattform.ErWindows)
        {
            // Bare navnene på variablene i registeret, aldri verdiene
            using (var env = Tilgangslogg.Nokkel(Bruker.Hkcu, "Environment"))
                foreach (var k in env?.GetValueNames() ?? Array.Empty<string>()) if (NokkelNavn.IsMatch(k)) navn.Add(k);
            using (var env = Tilgangslogg.Nokkel(Microsoft.Win32.Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
                foreach (var k in env?.GetValueNames() ?? Array.Empty<string>()) if (NokkelNavn.IsMatch(k)) navn.Add(k);
        }
        // Filer som bare finnes når man har logget inn med en nøkkel (vi sjekker at de finnes, åpner dem ikke)
        var hfToken = Utvid(@"%USERPROFILE%\.cache\huggingface\token");
        if (File.Exists(hfToken)) navn.Add("Hugging Face-innlogging");
        if (navn.Count == 0) return;
        var f = NokkelFunn(navn);
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
        /// <summary>Modellfiler som bare ligger i skyen (OneDrive), funnet på navn og størrelse. Innholdet lastes aldri ned.</summary>
        public readonly List<(string Sti, long Lengde)> SkyModeller = new();
    }

    private static readonly HashSet<string> SkyModellEndelser = new(StringComparer.OrdinalIgnoreCase)
        { ".gguf", ".safetensors", ".onnx", ".tflite", ".ckpt", ".pt", ".pth", ".llamafile", ".mlmodel", ".h5", ".keras" };

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
        var rotter = new List<(string Sti, int Dybde)> { (Utvid("%USERPROFILE%"), Dybde(10)) };
        // Modellmapper flyttet med miljøvariabler (vanlig når C: blir full) følges, også utenfor profilen
        foreach (var v in new[] { "OLLAMA_MODELS", "HF_HOME", "HF_HUB_CACHE", "TRANSFORMERS_CACHE" })
            if (Environment.GetEnvironmentVariable(v) is { Length: > 0 } mv && Directory.Exists(mv)
                && !rotter.Any(r => mv.StartsWith(r.Sti.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
                rotter.Add((mv, Dybde(10)));
        if (Plattform.ErWindows && Fullt) rotter.AddRange(FulltRotter());
        else if (Plattform.ErWindows)
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
            foreach (var d in Mapper(rot))
            {
                if (Lenke(d)) continue;
                jobber.Add((d, dybde - 1));
            }
        }
        MappeKo(jobber, (j, legg) => Gaa(j.Sti, j.Dybde, ff, hopp, minLengde, frist, (m, d) => legg((m, d))));

        LeggTilFarlige(ff);
        // AI-oppsett i prosjektmapper (.mcp.json, .vscode\mcp.json, .claude\settings.json) som gjennomgangen fant
        ProsjektOppsett();

        // Modeller
        var modeller = ff.Modeller.OrderByDescending(m => m.Lengde).ToList();
        // Hver modell er én rad, så tallet øverst er like mange som radene (ingen samlerad «Flere AI-modeller»)
        foreach (var (sti, lengde, m) in modeller) LeggTilModell(sti, lengde, m);
        foreach (var (sti, lengde) in ff.SkyModeller.OrderByDescending(x => x.Lengde))
        {
            var f = LeggTil($"AI-modell i OneDrive: {Kutt(Modellnavn(sti), 50)}", "Lokal AI (modell)", Risiko.Gul,
                "AI-modell som ligger i OneDrive og lastes ned til PC-en når den åpnes.", Path.GetExtension(sti).TrimStart('.').ToUpperInvariant(),
                $"Fil: {sti} · {Gb(lengde)} · bare i skyen, innholdet er ikke lest");
            f.LeggTilModeller(1);
            f.Bruk = $"{Gb(lengde)}, bare i OneDrive (ikke lastet ned).";
        }

        // AI-motorer i programmer som ikke kjører nå
        foreach (var (mappe, motorer) in ff.Motorer)
        {
            if (BareGrafikkMotor(motorer)) continue;
            var exe = Filer(mappe).FirstOrDefault(x => x.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
            // Windows' egne filer (WinSxS, System32, DriverStore, Installer) er del av Windows: ett grønt funn med mappene
            // Uten utgiver i filinfo eller innebygd signatur er Windows-filer katalogsignert; mappene kan bare TrustedInstaller skrive i
            if (ErSystemmappe(mappe) && (exe == null || Utgiver(exe) is var wu && (wu == "" || wu.Inneholder("Microsoft"))))
            {
                var w = LeggTil("AI-motorer i Windows' egne filer", "Lokal AI", Risiko.Gronn,
                    "AI-biblioteker som følger med Windows (Windows ML, ONNX Runtime, DirectML). Del av Windows, ikke et eget program.", "AI-motor", null);
                w.Detalj($"{(exe != null ? "Program: " + exe : "Mappe: " + mappe)} (AI-motor: {string.Join(", ", motorer)})");
                continue;
            }
            // Windows\Installer: lagrede installasjonsfiler (oppdateringer), ikke et installert program. Det installerte programmet finnes andre steder.
            if (ErSystemmappe(mappe) && mappe.IndexOf(@"\Installer\", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                var u = exe != null ? Utgiver(exe) : "";
                var i = LeggTil($"Lagret installasjonsfil{(u != "" ? " fra " + u.Trim() : "")}", "Innebygd AI fra leverandør", Risiko.Gronn,
                    "Kopi av et installasjonsprogram som Windows har lagret for oppdateringer. Ikke et installert program, og det kjører ikke.", "AI-motor", null);
                i.Detalj($"{(exe != null ? "Program: " + exe : "Mappe: " + mappe)} (AI-motor: {string.Join(", ", motorer)})");
                continue;
            }
            if (exe == null)
            {
                // Ingen program i mappa: vis mappa, aldri et oppdiktet programnavn
                var m = LeggTil(Path.GetFileName(mappe), "Lokal AI", Risiko.Rod, "Mappe med egen AI-motor uten program. Kan brukes av et program et annet sted.", "AI-motor", null);
                m.Detalj($"Mappe: {mappe} (AI-motor: {string.Join(", ", motorer)})");
                continue;
            }
            LeggTilMotorFunn(exe, motorer, kjorer: false);
        }

        // Python- og Node-miljøer med AI
        foreach (var (sti, (pakker, agent, sprak)) in ff.Miljoer)
        {
            var prosjekt = Prosjektnavn(sti);
            var f = LeggTil($"{sprak}-prosjekt med AI: {prosjekt}", "Skygge-AI (utvikling)", agent ? Risiko.Rod : Risiko.Gul,
                agent ? "Ukjent AI-agent: kode som kan handle på egen hånd med AI." : "Kode som bruker AI-biblioteker.",
                sprak, $"Mappe: {sti} ({string.Join(", ", pakker)})");
            f.Bruk = $"Bruker {string.Join(", ", pakker.Take(4))}{(pakker.Count > 4 ? " …" : "")}.";
        }
    }

    /// <summary>
    /// Går gjennom mappetrær med faste lesetråder. Hver mappe er en egen jobb i en felles kø, så én stor mappe (C:\Windows,
    /// Documents) ikke holder igjen resten: alle trådene jobber til siste mappe er lest. Samme mapper og regler som før.
    /// </summary>
    private static readonly int Lesere = Math.Max(16, Math.Min(32, Environment.ProcessorCount * 4));

    internal static void MappeKo<T>(IEnumerable<T> start, Action<T, Action<T>> gjor)
    {
        using var ko = new System.Collections.Concurrent.BlockingCollection<T>(new System.Collections.Concurrent.ConcurrentStack<T>());
        int igjen = 1;   // holder køen åpen til startmappene er lagt inn
        Exception? feil = null;
        void Legg(T x) { Interlocked.Increment(ref igjen); ko.Add(x); }
        void Ferdig() { if (Interlocked.Decrement(ref igjen) == 0) ko.CompleteAdding(); }
        foreach (var x in start) Legg(x);
        Ferdig();
        // Mappelisting og filoppslag venter på disken, ikke på prosessoren: mange samtidige lesere holder disken (NVMe og
        // skydisker) i arbeid. Målt på byggemaskinen: tiden går nesten bare til å vente på disken.
        Task.WaitAll(Enumerable.Range(0, Lesere).Select(_ => Task.Factory.StartNew(() =>
        {
            foreach (var x in ko.GetConsumingEnumerable())
                try { gjor(x, Legg); }
                catch (Exception e) { Interlocked.CompareExchange(ref feil, e, null); }
                finally { Ferdig(); }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray());
        // Resten av mappene er gått gjennom; feilen vises som før («Sjekken stoppet»)
        if (feil != null) throw feil;
    }

    private void Gaa(string mappe, int dybde, FilFunn ff, HashSet<string> hopp, long minLengde, Stopwatch frist, Action<string, int>? videre = null)
    {
        if (hopp.Contains(mappe)) return;
        if (dybde < 0) { Tilgangslogg.TellMappe(mappe, Utfall.HoppetOver, detalj: "dybdegrensen for gjennomgangen er nådd"); return; }
        if (frist.Elapsed > Frist(45))
        {
            var brukt = Fullt ? "30 minutter" : "45 sekunder";
            Tilgangslogg.EnGang("disk-45", "Mappe", mappe, Utfall.Tidsgrense, $"{brukt} brukt på disken; resten av mappene ble ikke gått gjennom");
            Tilgangslogg.TellMappe(mappe, Utfall.Tidsgrense, detalj: $"{brukt} brukt på disken");
            return;
        }
        var navn = Path.GetFileName(mappe);
        if (navn is "site-packages" or "dist-packages") { SjekkPip(mappe); Miljo(mappe, PythonAi, "Python", ff); return; }
        if (navn == "node_modules") { Miljo(mappe, NodeAi, "Node", ff); SjekkNodeModules(mappe); return; }
        if (Fullt && navn is ".git" or ".svn" or ".hg") { Tilgangslogg.TellMappe(mappe, Utfall.HoppetOver, detalj: "versjonskontroll (git), ikke AI"); return; }
        if (!Fullt && navn.StartsWith(".") && navn is not (".ollama" or ".lmstudio" or ".cache" or ".local" or ".venv" or ".env" or ".conda" or ".foundry" or ".aitk" or ".docker" or ".vscode" or ".cursor" or ".claude" or ".gemini" or ".github" or ".codex")) { Tilgangslogg.TellMappe(mappe, Utfall.HoppetOver, detalj: "mappe som starter med punktum, ikke en kjent AI-mappe"); return; }
        if (!Fullt && navn is "Windows" or "$Recycle.Bin" or "System Volume Information" or "Program Files" or "Program Files (x86)" or "ProgramData") { Tilgangslogg.Logg("Mappe", mappe, Utfall.HoppetOver, "hoppes over av regel (systemmappe eller sjekkes av egen sjekk)"); return; }

        IEnumerable<FileSystemInfo> innhold;
        try { innhold = new DirectoryInfo(mappe).EnumerateFileSystemInfos(); } catch (Exception e) { Tilgangslogg.Feil("Mappe", mappe, e); return; }
        long filer = 0, bytes = 0, sky = 0;
        try
        {
            Interlocked.Increment(ref _mapperLest);
            foreach (var e in innhold)
            {
                FileAttributes a;
                try { a = e.Attributes; } catch { continue; }
                if ((a & Skyfil) != 0)
                {
                    // Skyfiler (OneDrive) lastes aldri ned. Navn og størrelse ligger på PC-en og sjekkes.
                    Tilgangslogg.Tell("Fil", Utfall.Lest);
                    sky++;
                    if (e is FileInfo sf && SkyModellEndelser.Contains(sf.Extension))
                        try { if (sf.Length >= 50L * 1024 * 1024) lock (ff) ff.SkyModeller.Add((sf.FullName, sf.Length)); } catch { }
                    continue;
                }
                if ((a & FileAttributes.ReparsePoint) != 0)
                {
                    // Hugging Face-lageret med symlenker (utviklermodus eller administrator): snapshots\<rev>\fil -> ..\..\blobs\<sha>.
                    // Målet leses under lenkens navn, så modellen får repo og filnavn. Blob-mappa hoppes over (se under).
                    if (e is FileInfo lf && HfMal(lf.FullName) is { } blob) { filer++; SjekkFil(lf, mappe, ff, minLengde, blob.Length); }
                    else SjekkLenke(e);
                    continue;
                }
                if (e is DirectoryInfo hb && hb.Name == "blobs" && (Path.GetFileName(mappe).StartsWith("models--", StringComparison.OrdinalIgnoreCase)
                    ? Directory.Exists(Path.Combine(mappe, "snapshots")) : Directory.EnumerateDirectories(mappe, "models--*").Any()))
                { Tilgangslogg.TellMappe(hb.FullName, Utfall.HoppetOver, detalj: "Hugging Face-blobber leses via navnene i snapshots"); continue; }
                if (e is DirectoryInfo d) { if (videre != null) videre(d.FullName, dybde - 1); else Gaa(d.FullName, dybde - 1, ff, hopp, minLengde, frist); }
                else if (e is FileInfo fil)
                {
                    filer++;
                    try { bytes += fil.Length; } catch { }
                    Profil.Tid("gaa: fil totalt", () => SjekkFil(fil, mappe, ff, minLengde));
                    if (Fullt) Profil.Tid("gaa: strømmer (ADS)", () => SjekkStrommer(fil, ff));
                }
            }
            Profil.Tid("gaa: TellMappe", () => Tilgangslogg.TellMappe(mappe, Utfall.Lest, filer, bytes));
            if (sky > 0) Tilgangslogg.BareKart("Mappe", mappe, Utfall.Lest, $"{sky} skyfiler (OneDrive): navn og størrelse sjekket, innholdet ligger i skyen og lastes aldri ned");
        }
        catch (Exception e) { Tilgangslogg.Feil("Mappe", mappe, e); }
    }

    /// <summary>
    /// Fullt søk: alle andre brukerprofiler, alt i roten av C:\ (unntatt Windows, Program Files, ProgramData og papirkurv,
    /// som har egne sjekker eller ikke har AI), og alle faste og flyttbare disker. Nettverksdisker tas ikke med.
    /// </summary>
    private List<(string Sti, int Dybde)> FulltRotter()
    {
        var liste = new List<(string, int)>();
        var hjem = Utvid("%USERPROFILE%");
        var brukere = Path.GetDirectoryName(hjem.TrimEnd('\\'));
        if (brukere != null)
            foreach (var p in Mapper(brukere))
            {
                if (p.Equals(hjem, StringComparison.OrdinalIgnoreCase) || Lenke(p)) continue;
                liste.Add((p, 64));
            }
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (d.DriveType is not (DriveType.Fixed or DriveType.Removable) || !d.IsReady) continue;
                var rot = d.RootDirectory.FullName;
                if (!rot.StartsWith(Path.GetPathRoot(Utvid("%SystemRoot%")) ?? "C:\\", StringComparison.OrdinalIgnoreCase)) { liste.Add((rot, 64)); continue; }
                // Filene i roten av C: (pagefile.sys, hiberfil.sys …) telles med i dekningen
                RotFiler(rot);
                foreach (var m in Mapper(rot))
                {
                    var n = Path.GetFileName(m);
                    if (brukere != null && m.Equals(brukere, StringComparison.OrdinalIgnoreCase)) continue;
                    // Program Files og ProgramData gås gjennom av sjekken for leverandør-AI (som også finner hvem som la AI-en der).
                    // Alt annet, også Windows, papirkurven og Config.Msi, gås gjennom her: AI-filer kan gjemmes overalt.
                    if (n is "Program Files" or "Program Files (x86)" or "ProgramData")
                    {
                        Tilgangslogg.Logg("Mappe", m, Utfall.Dekket, "gås gjennom av sjekken «Leter etter AI som leverandører har lagt inn»");
                        continue;
                    }
                    if (Lenke(m)) continue;
                    liste.Add((m, 64));
                }
            }
            catch { }
        }
        return liste;
    }

    /// <summary>
    /// Lenker følges aldri. Windows har kompatibilitetslenker i profilen (Mine dokumenter, Cookies, Maler, Recent,
    /// Programdata, Lokale innstillinger, AndrMask …) som peker på ekte mapper og nekter listing for alle, også admin.
    /// De logges som lenke med målet, ikke som «nektet tilgang».
    /// </summary>
    private bool Lenke(string mappe)
    {
        try { if ((File.GetAttributes(mappe) & FileAttributes.ReparsePoint) == 0) return false; }
        catch { return false; }
        var mal = Reparse.Mal(mappe);
        var hjem = Utvid("%USERPROFILE%");
        // Målet søkes direkte når det er i profilen, eller (fullt søk) på en lokal disk. Lenken følges ikke, så ingenting telles to ganger.
        bool dekket = mal != null && (mal.StartsWith(hjem.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)
                                      || Fullt && LokalDisk(mal) && Directory.Exists(mal));
        Tilgangslogg.Logg("Mappe", mappe, dekket ? Utfall.Dekket : Utfall.HoppetOver,
            dekket ? $"lenke til {mal}, som søkes direkte"
            : mal == null ? "lenke til en annen mappe, følges ikke"
            : $"lenke til {mal}, følges ikke");
        SjekkLenke(new DirectoryInfo(mappe));
        return true;
    }

    private static bool LokalDisk(string sti)
    {
        try
        {
            var rot = Path.GetPathRoot(sti);
            return rot != null && rot.Length <= 3 && new DriveInfo(rot).DriveType is DriveType.Fixed or DriveType.Removable;
        }
        catch { return false; }
    }

    /// <summary>
    /// Filene i roten av systemdisken: bare navn og størrelse, så dekningen per disk blir riktig.
    /// pagefile.sys, hiberfil.sys og swapfile.sys er Windows' minnefiler og holdes låst av Windows.
    /// </summary>
    private void RotFiler(string rot)
    {
        long filer = 0, bytes = 0;
        try
        {
            foreach (var f in new DirectoryInfo(rot).GetFiles())
            {
                filer++;
                try { bytes += f.Length; } catch { }
            }
        }
        catch (Exception e) { Tilgangslogg.Feil("Mappe", rot, e); return; }
        Tilgangslogg.TellMappe(rot, Utfall.Lest, filer, bytes, "filene i roten av disken (navn og størrelse; Windows' minnefiler er låst av Windows)");
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

    /// <summary>
    /// Fullt søk: en AI-modell kan gjemmes i en skjult datastrøm (ADS) i en helt vanlig fil. Strømmer på minst 50 MB
    /// får filhodet sjekket. Vanlige små strømmer (Zone.Identifier fra nettleseren) hoppes over på størrelse.
    /// </summary>
    private void SjekkStrommer(FileInfo fil, FilFunn ff)
    {
        List<(string Navn, long Lengde)> strommer;
        try { strommer = Admintilgang.Strommer(fil.FullName); } catch { return; }
        foreach (var (navn, lengde) in strommer)
        {
            if (lengde < 50L * 1024 * 1024) continue;
            var sti = $"{fil.FullName}:{navn}";
            var modell = ModellFormat.Gjenkjenn(sti);
            if (modell != null) lock (ff) ff.Modeller.Add((sti, lengde, modell));
        }
    }

    private static readonly HashSet<string> Forkledning = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mp4", ".mkv", ".mov", ".avi", ".mp3", ".wav", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".7z", ".rar", ".iso",
        ".exe", ".msi", ".dll", ".txt", ".log", ".pdf", ".docx", ".xlsx", ".pptx", ".vhdx", ".pst", ".ost",
    };

    /// <summary>Målet til en symlenke i Hugging Face-lageret (models--…\snapshots\…). Nyere huggingface_hub lenker blobben videre til
    /// hub\blobs\xx\&lt;sha&gt;, så kjeden følges noen ledd, men bare innenfor modellmappa eller hub-mappas felles blobs.</summary>
    private static FileInfo? HfMal(string sti)
    {
        var m = Regex.Match(sti, @"^((.*)[\\/]models--[^\\/]+)[\\/]snapshots[\\/]", RegexOptions.IgnoreCase);
        if (!m.Success) return null;
        var lov = new[] { Path.Combine(m.Groups[1].Value, "blobs"), Path.Combine(m.Groups[2].Value, "blobs") };
        try
        {
            for (int i = 0; i < 4; i++)
            {
                if (Reparse.Mal(sti) is not { Length: > 0 } mal) return null;
                sti = Path.GetFullPath(Path.IsPathRooted(mal) ? mal : Path.Combine(Path.GetDirectoryName(sti)!, mal));
                if (!lov.Any(b => sti.StartsWith(b + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))) return null;
                var fi = new FileInfo(sti);
                if (!fi.Exists) return null;
                if ((fi.Attributes & FileAttributes.ReparsePoint) == 0) return fi;
            }
        }
        catch { }
        return null;
    }

    private void SjekkFil(FileInfo fil, string mappe, FilFunn ff, long minLengde, long? malLengde = null)
    {
        if (fil.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) SjekkProsjektOppsett(fil);
        Profil.Tid("gaa: agentfil", () => SjekkAgentfil(fil));
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
        try { lengde = malLengde ?? fil.Length; } catch { return; }
        bool liten = ext is ".onnx" or ".tflite" && lengde > 5 * 1024 * 1024;
        if (lengde < minLengde && !liten) { Profil.Tid("gaa: liten modell", () => SjekkLitenModell(fil, ff, lengde)); return; }
        // Fullt søk: filhodet sjekkes uansett endelse, så en modell omdøpt til .zip, .mp4 eller .png blir funnet
        if (!Fullt && ext is ".zip" or ".7z" or ".rar" or ".iso" or ".mp4" or ".mkv" or ".mov" or ".avi" or ".exe" or ".msi" or ".vhdx" or ".pst" or ".ost" or ".jpg" or ".png") return;
        var modell = Profil.Tid("gaa: filhode", () => ModellFormat.Gjenkjenn(fil.FullName));
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
        var f = LeggTil($"AI-modell: {Kutt(navn, 50)}", "Lokal AI (modell)", risiko, hvorfor, m.Format, $"Fil: {sti} · {m.Format} · {Gb(lengde)} · endret {Tid(endret)}");
        f.Sterkt();   // kjent igjen på innholdet i fila, ikke på navnet
        f.LeggTilModeller(1);
        f.SettVersjon(m.Versjon, "modellfila");
        // Hugging Face-lageret: mappa under snapshots er revisjonen (commit) modellen ble lastet ned fra
        var rev = Regex.Match(sti, @"[\\/]snapshots[\\/]([0-9a-f]{40})[\\/]", RegexOptions.IgnoreCase);
        if (rev.Success) f.SettVersjon("revisjon " + rev.Groups[1].Value.Substring(0, 7), "Hugging Face-lageret");

        f.Tidspunkt(opprettet < endret ? opprettet : endret, endret);
        Nedlastingskilde(f, sti);
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
        foreach (var k in new[] { id.NavneFamilie, id.Familie }.Where(x => x?.Kilde != null).Select(x => x!.Kilde).Distinct()) f.Detalj($"Kilde for gjenkjenningen: {k}");
        if (m.Type != null && m.Type != "språkmodell") f.Detalj($"Type: {m.Type}");
        if (id.Sha256 != null) f.Detalj($"Modell-ID (SHA-256, lik på alle PC-er): {id.Sha256}");
        else if (id.Fingeravtrykk != null) f.Detalj($"Modell-ID (fingeravtrykk, likt på alle PC-er): {id.Fingeravtrykk}");
        if (m.KanKjoreKode && farligPlass) f.Advarsel("Kan kjøre skjult kode, og ligger i en nedlastingsmappe.");
        // Gjemt: skjult datastrøm, skjult fil, eller en modell med endelsen til en film, et bilde eller et dokument
        int kolon = sti.IndexOf(':', 2);
        if (kolon > 0)
        {
            f.Risiko = Risiko.Rod;
            f.Advarsel($"Gjemt i en skjult datastrøm i {Path.GetFileName(sti.Substring(0, kolon))}. Utforsker viser den ikke.");
        }
        else
        {
            try
            {
                if ((File.GetAttributes(sti) & (FileAttributes.Hidden | FileAttributes.System)) != 0)
                {
                    f.Risiko = Risiko.Rod;
                    f.Advarsel("Fila er merket som skjult, så Utforsker viser den ikke.");
                }
            }
            catch { }
            var endelse = Path.GetExtension(sti);
            if (Forkledning.Contains(endelse))
            {
                f.Risiko = Risiko.Rod;
                f.Advarsel($"Forkledd: AI-modell ({m.Format}) med endelsen {endelse.ToLowerInvariant()}.");
            }
        }
        YaraPaModell(sti, f);
        // Modeller fra høyrisikoland (Kina, Russland …): navnet (finjusteringen) teller før innholdet (grunnmodellen)
        if (new[] { id.NavneFamilie, id.Familie }.FirstOrDefault(x => x?.Land is { } l && _regler.HoyrisikoLand.Contains(l)) is { } hf)
            f.Merknad($"Laget av {hf.Utgiver} i {IpLand.Navn(hf.Land!)}. Kjører lokalt, så data sendes ikke dit, men sjekk om bedriften tillater modellen.");
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
