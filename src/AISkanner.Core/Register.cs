using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// AI-spor i Windows-registeret. Leser bare nøkkelnavn og noen få kjente verdier.
/// Rører aldri passord, legitimasjon eller sikkerhetsdatabaser (SAM, SECURITY, Credentials).
/// </summary>
public sealed partial class Skanner
{
    /// <summary>AI-regler IT har satt på PC-en (gruppepolicy/Intune), f.eks. "Windows Copilot: slått av". Tom hvis ingen.</summary>
    public List<string> AiRegler { get; } = new();

    private static readonly string[] ModellEndelser = { ".gguf", ".safetensors", ".ggml", ".ckpt", ".llamafile", ".onnx", ".tflite", ".mlmodel" };

    private void Register()
    {
        if (!Plattform.ErWindows) return;
        Policyer();
        foreach (var rot in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            Protokoller(rot);
            Filtilknytninger(rot);
            AppPaths(rot);
            Hoyreklikk(rot);
        }
        OllamaOppsett();
        Recall();
    }

    private static object? Verdi(string sti, string navn)
    {
        foreach (var rot in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            try
            {
                using var k = Tilgangslogg.Nokkel(rot, sti);
                if (k?.GetValue(navn) is { } v) return v;
            }
            catch { }
        }
        return null;
    }

    // ---------- AI-regler fra IT ----------
    private void Policyer()
    {
        void Regel(string sti, string navn, Func<object, string?> tolk)
        {
            var v = Verdi(sti, navn);
            if (v != null && tolk(v) is { } tekst) lock (AiRegler) AiRegler.Add(tekst);
        }
        static int Tall(object v) => v is int i ? i : int.TryParse(v.ToString(), out var t) ? t : -1;

        Regel(@"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot", "TurnOffWindowsCopilot", v => Tall(v) == 1 ? "Windows Copilot: slått av" : null);
        Regel(@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableAIDataAnalysis", v => Tall(v) == 1 ? "Windows Recall: skjermbilder slått av" : "Windows Recall: tillatt");
        Regel(@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "AllowRecallEnablement", v => Tall(v) == 0 ? "Windows Recall: fjernet" : null);
        Regel(@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", "DisableClickToDo", v => Tall(v) == 1 ? "Klikk for å gjøre (Click to Do): slått av" : null);
        Regel(@"SOFTWARE\Policies\Microsoft\Edge", "HubsSidebarEnabled", v => Tall(v) == 0 ? "Copilot i Edge-sidepanelet: slått av" : "Copilot i Edge-sidepanelet: tillatt");
        Regel(@"SOFTWARE\Policies\Microsoft\Edge", "CopilotPageContext", v => Tall(v) == 0 ? "Copilot i Edge kan ikke lese nettsiden" : "Copilot i Edge kan lese nettsiden");
        Regel(@"SOFTWARE\Policies\Microsoft\Edge", "GenAILocalFoundationalModelSettings", v => Tall(v) == 1 ? "AI-modell i Edge: blokkert" : "AI-modell i Edge: tillatt");
        Regel(@"SOFTWARE\Policies\Google\Chrome", "GenAILocalFoundationalModelSettings", v => Tall(v) == 1 ? "Gemini Nano i Chrome: blokkert" : "Gemini Nano i Chrome: tillatt");
        Regel(@"SOFTWARE\Policies\Google\Chrome", "GeminiSettings", v => Tall(v) == 1 ? "Gemini i Chrome: slått av" : "Gemini i Chrome: tillatt");
        Regel(@"SOFTWARE\Policies\Google\Chrome", "GenAiDefaultSettings", v => Tall(v) == 2 ? "AI-funksjoner i Chrome: slått av" : "AI-funksjoner i Chrome: tillatt");
        Regel(@"SOFTWARE\Policies\Microsoft\Office\16.0\Common\AI", "DisableCopilot", v => Tall(v) == 1 ? "Copilot i Office: slått av" : null);

        if (AiRegler.Count == 0) return;
        var f = LeggTil("AI-regler fra IT", "Regler", Risiko.Gronn,
            "IT har satt regler for innebygd AI på denne PC-en.", "Registeret", null,
            enkelt: "Regler fra IT", rad: "Ingenting å gjøre. Reglene viser hva bedriften har bestemt.");
        f.Bruk = $"{AiRegler.Count} {(AiRegler.Count == 1 ? "regel" : "regler")}.";
        foreach (var r in AiRegler) f.Detalj($"Regel: {r}");
    }

    // ---------- Lenker som åpner AI-apper (f.eks. cursor://, claude://) ----------
    private void Protokoller(RegistryKey rot)
    {
        try
        {
            using var klasser = Tilgangslogg.Nokkel(rot, @"SOFTWARE\Classes");
            foreach (var navn in klasser?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                if (navn.StartsWith(".") || navn.Contains(".") || navn.Length > 40) continue;
                using var k = klasser!.OpenSubKey(navn);
                if (k?.GetValue("URL Protocol") == null) continue;
                using var cmd = k.OpenSubKey(@"shell\open\command");
                var kommando = cmd?.GetValue(null) as string ?? "";
                var r = FinnRegel($"{navn} {kommando}");
                if (r != null) FraRegel(r, "Registrert i Windows", $"Registeret: lenker som starter med {navn}:// åpner {Exe(kommando) ?? r.Navn}");
            }
        }
        catch { }
    }

    // ---------- Programmer som er satt til å åpne modellfiler ----------
    private void Filtilknytninger(RegistryKey rot)
    {
        foreach (var ext in ModellEndelser)
        {
            try
            {
                var progIder = new List<string>();
                using (var k = Tilgangslogg.Nokkel(rot, $@"SOFTWARE\Classes\{ext}"))
                {
                    if (k?.GetValue(null) is string standard && standard.Length > 0) progIder.Add(standard);
                    using var ow = k?.OpenSubKey("OpenWithProgids");
                    progIder.AddRange(ow?.GetValueNames() ?? Array.Empty<string>());
                }
                foreach (var id in progIder.Distinct())
                {
                    using var cmd = Registry.ClassesRoot.OpenSubKey($@"{id}\shell\open\command");
                    var kommando = cmd?.GetValue(null) as string;
                    var exe = Exe(kommando);
                    if (exe == null) continue;
                    var r = FinnRegel($"{id} {kommando}");
                    var detalj = $"Registeret: åpner {ext}-filer: {exe}";
                    if (r != null) { FraRegel(r, "Registrert i Windows", detalj); continue; }
                    // Et ukjent program som er satt opp til å åpne AI-modeller
                    var navn = Path.GetFileNameWithoutExtension(exe);
                    try { var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(exe); if (!string.IsNullOrWhiteSpace(vi.ProductName)) navn = vi.ProductName.Trim(); } catch { }
                    var f = LeggTil($"Program for AI-modeller: {navn}", "Lokal AI", Risiko.Rod,
                        "Ukjent program som er satt opp til å åpne AI-modellfiler. Det kan kjøre AI på PC-en.", "Registeret", detalj,
                        rad: "Finn ut hva programmet er. Avinstaller det hvis ingen vet.");
                    HuskMappe(exe, f);
                }
            }
            catch { }
        }
    }

    // ---------- App Paths: programmer Windows kan starte på navn ----------
    private void AppPaths(RegistryKey rot)
    {
        try
        {
            using var k = Tilgangslogg.Nokkel(rot, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths");
            foreach (var navn in k?.GetSubKeyNames() ?? Array.Empty<string>())
            {
                using var app = k!.OpenSubKey(navn);
                var sti = app?.GetValue(null) as string;
                var r = FinnRegel($"{navn} {sti}");
                if (r != null) FraRegel(r, "Registrert i Windows", $"Registeret: kan startes som {navn}{(sti != null ? $" ({sti.Trim('"')})" : "")}");
            }
        }
        catch { }
    }

    // ---------- Høyreklikkmenyer (f.eks. «Åpne med Cursor», «Spør Copilot») ----------
    private void Hoyreklikk(RegistryKey rot)
    {
        foreach (var type in new[] { "*", "Directory", @"Directory\Background", "Folder" })
        {
            foreach (var del in new[] { "shell", @"shellex\ContextMenuHandlers" })
            {
                try
                {
                    using var k = Tilgangslogg.Nokkel(rot, $@"SOFTWARE\Classes\{type}\{del}");
                    foreach (var navn in k?.GetSubKeyNames() ?? Array.Empty<string>())
                    {
                        using var verb = k!.OpenSubKey(navn);
                        var tekst = $"{navn} {verb?.GetValue(null)} {verb?.GetValue("MUIVerb")}";
                        using var cmd = verb?.OpenSubKey("command");
                        var r = FinnRegel($"{tekst} {cmd?.GetValue(null)}");
                        if (r != null) FraRegel(r, "Registrert i Windows", $"Registeret: høyreklikkmeny «{navn}»");
                    }
                }
                catch { }
            }
        }
    }

    // ---------- Ollama satt opp til å være åpen mot nettverket ----------
    private void OllamaOppsett()
    {
        var regel = _regler.Produkter.FirstOrDefault(p => p.Navn == "Ollama");
        if (regel == null) return;
        foreach (var navn in new[] { "OLLAMA_HOST", "OLLAMA_ORIGINS" })
        {
            var verdier = new[]
            {
                Environment.GetEnvironmentVariable(navn),
                Verdi(@"Environment", navn) as string,
                Verdi(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", navn) as string,
            };
            foreach (var v in verdier.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct())
            {
                bool apen = navn == "OLLAMA_HOST" ? v!.Contains("0.0.0.0") || v.Contains("[::]") : v!.Trim() == "*";
                if (!apen) continue;
                var f = FraRegel(regel, "Registrert i Windows", $"Miljøvariabel: {navn}={v}");
                f.Risiko = Risiko.Rod;
                f.Advarsel(navn == "OLLAMA_HOST"
                    ? "Ollama er satt opp til å være åpen mot nettverket. Andre kan bruke den uten passord."
                    : "Ollama tillater forespørsler fra alle nettsider (OLLAMA_ORIGINS=*). En hvilken som helst nettside kan bruke den.");
            }
        }
    }

    // ---------- Windows Recall: tar skjermbilder av alt du gjør ----------
    private void Recall()
    {
        var mappe = Utvid(@"%LOCALAPPDATA%\CoreAIPlatform.00\UKP");
        if (!Directory.Exists(mappe)) return;
        bool av = AiRegler.Any(r => r.StartsWith("Windows Recall") && !r.EndsWith("tillatt"));
        var f = LeggTil("Windows Recall", "Skygge-AI", av ? Risiko.Gul : Risiko.Rod,
            "Windows tar skjermbilder av alt du gjør og lar AI søke i dem. Det kan fange passord, kundedata og meldinger.",
            "Windows", $"Mappe: {mappe} (innholdet er ikke lest)",
            enkelt: "Skjermbilder av alt du gjør", rad: "Slå av Recall i Innstillinger > Personvern hvis du ikke trenger det. På jobb bør IT bestemme.");
        f.Bruk = av ? "Har vært i bruk, men IT har slått av skjermbildene." : "Er satt opp på denne PC-en.";
    }

    /// <summary>Filstien til programmet i en kommandolinje fra registeret.</summary>
    private static string? Exe(string? kommando)
    {
        if (string.IsNullOrWhiteSpace(kommando)) return null;
        var k = kommando!.Trim();
        if (k.StartsWith("\"")) { int slutt = k.IndexOf('"', 1); return slutt > 1 ? k.Substring(1, slutt - 1) : null; }
        int exe = k.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? k.Substring(0, exe + 4) : k.Split(' ')[0];
    }
}
