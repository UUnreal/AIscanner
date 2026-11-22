using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Docker og WSL. Docker: bare lesende spørringer til Docker-motorens eget API (\\.\pipe\docker_engine), og bare når
/// motoren allerede kjører: lista over bilder og beholdere. Starter aldri Docker. ~/.docker/config.json åpnes aldri
/// (der ligger innlogginger). WSL: Linux-distribusjonene fra registeret; filene leses bare når Linux allerede kjører,
/// så søket aldri starter Linux.
/// </summary>
public sealed partial class Skanner
{
    // Kjente AI-bilder (dockerBilder i regler.json, navnet før kolon/tag). Treff i regelfila brukes også.
    private static string[] AiBilder = Array.Empty<string>();

    private void Beholdere()
    {
        if (!Plattform.ErWindows) return;
        try { Docker(); } catch (Exception e) { Tilgangslogg.Logg("Sjekk", "Docker", Utfall.Feil, Tilgangslogg.Beskriv(e)); }
        try { Wsl(); } catch (Exception e) { Tilgangslogg.Logg("Sjekk", "WSL", Utfall.Feil, Tilgangslogg.Beskriv(e)); }
        try { AndreMiljoer(); } catch (Exception e) { Tilgangslogg.Logg("Sjekk", "Conda, Jupyter, pipx og bun", Utfall.Feil, Tilgangslogg.Beskriv(e)); }
    }

    /// <summary>
    /// Miljøer som kan ligge utenfor brukermappa eller i mapper hurtigsøket hopper over: Conda-miljøer (environments.txt),
    /// Jupyter-kjerner (python-stien i kernel.json), pipx-verktøy og globale bun-pakker. Bare pakkenavn leses, som ellers.
    /// Kilder: docs.conda.io (environments.txt), jupyter-client.readthedocs.io (kernel specs), pipx.pypa.io (PIPX_HOME), bun.sh/docs/install/global
    /// </summary>
    private void AndreMiljoer()
    {
        var ff = new FilFunn();
        var hvor = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Py(string? rot, string kilde)
        {
            if (string.IsNullOrEmpty(rot)) return;
            var sp = Path.Combine(rot, "Lib", "site-packages");
            if (Directory.Exists(sp) && !hvor.ContainsKey(sp)) { hvor[sp] = kilde; Miljo(sp, PythonAi, "Python", ff); }
        }
        var conda = Utvid(@"%USERPROFILE%\.conda\environments.txt");
        if (File.Exists(conda)) LesLinjer(conda, 1, l => { var t = l.Trim(); if (t.Length > 3 && Path.IsPathRooted(t)) Py(t, "Conda-miljø"); });
        foreach (var k in new[] { @"%APPDATA%\jupyter\kernels", @"%ProgramData%\jupyter\kernels" }.SelectMany(m => Mapper(Utvid(m))).Take(100))
        {
            var kj = Path.Combine(k, "kernel.json");
            if (!File.Exists(kj) || new FileInfo(kj).Length > 64 * 1024) continue;
            try
            {
                using var d = System.Text.Json.JsonDocument.Parse(File.ReadAllText(kj));
                if (d.RootElement.TryGetProperty("argv", out var a) && a.ValueKind == System.Text.Json.JsonValueKind.Array && a.GetArrayLength() > 0
                    && a[0].GetString() is { } py && Path.IsPathRooted(py))
                {
                    var mappe = Path.GetDirectoryName(py);
                    if (Path.GetFileName(mappe ?? "").Equals("Scripts", StringComparison.OrdinalIgnoreCase)) mappe = Path.GetDirectoryName(mappe);
                    Py(mappe, $"Jupyter-kjerne «{Path.GetFileName(k)}»");
                }
                Tilgangslogg.Tell("Fil", Utfall.Lest, sted: kj, detalj: "Jupyter-kjerne: bare python-stien");
            }
            catch (Exception e) { Tilgangslogg.Feil("Fil", kj, e); }
        }
        foreach (var v in new[] { @"%USERPROFILE%\pipx\venvs", @"%USERPROFILE%\.local\pipx\venvs", @"%LOCALAPPDATA%\pipx\pipx\venvs" }.SelectMany(m => Mapper(Utvid(m))).Take(200))
            Py(v, "pipx-verktøy");
        var bun = Utvid(@"%USERPROFILE%\.bun\install\global\node_modules");
        if (Directory.Exists(bun)) { hvor[bun] = "globale bun-pakker"; Miljo(bun, NodeAi, "Node", ff); }
        foreach (var (sti, (pakker, agent, sprak)) in ff.Miljoer)
            LeggTilMiljo(sti, pakker, agent, sprak).Merknad($"Funnet via {(hvor.TryGetValue(sti, out var h) ? h : "miljølista")}.");
    }

    private static string? DockerGet(string sti)
    {
        using var r = new NamedPipeClientStream(".", "docker_engine", PipeDirection.InOut);
        try { r.Connect(500); }
        catch (Exception e) when (e is TimeoutException or IOException or UnauthorizedAccessException)
        {
            Tilgangslogg.Logg("Nettverk", @"\\.\pipe\docker_engine", e is UnauthorizedAccessException ? Utfall.Nektet : Utfall.IkkeFunnet,
                e is UnauthorizedAccessException ? "Docker kjører, men kontoen har ikke tilgang til Docker-motoren" : "Docker kjører ikke; startes aldri av søket");
            return null;
        }
        var q = Encoding.ASCII.GetBytes($"GET {sti} HTTP/1.0\r\nHost: docker\r\n\r\n");
        r.Write(q, 0, q.Length);
        using var ms = new MemoryStream();
        var buf = new byte[65536];
        int n;
        while ((n = r.Read(buf, 0, buf.Length)) > 0 && ms.Length < 8 * 1024 * 1024) ms.Write(buf, 0, n);
        var tekst = Encoding.UTF8.GetString(ms.ToArray());
        var i = tekst.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (i < 0 || !tekst.StartsWith("HTTP/1.", StringComparison.Ordinal) || tekst.IndexOf(" 200 ", StringComparison.Ordinal) < 0) return null;
        Tilgangslogg.Logg("Nettverk", $@"\\.\pipe\docker_engine {sti}", Utfall.Lest, "Docker-API, bare lesing");
        return tekst.Substring(i + 4);
    }

    private void Docker()
    {
        var bilder = DockerGet("/images/json");
        if (bilder == null) return;
        var kjorer = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (DockerGet("/containers/json") is { } bj)
        {
            using var cd = JsonDocument.Parse(bj);
            foreach (var c in cd.RootElement.EnumerateArray())
            {
                var img = Str(c, "Image") ?? "";
                var porter = c.TryGetProperty("Ports", out var ps) && ps.ValueKind == JsonValueKind.Array
                    ? ps.EnumerateArray().Where(p => p.TryGetProperty("PublicPort", out _)).Select(p => $"{Str(p, "IP") ?? ""}:{p.GetProperty("PublicPort")}") : Enumerable.Empty<string>();
                if (!kjorer.TryGetValue(img, out var l)) kjorer[img] = l = new List<string>();
                l.AddRange(porter);
            }
        }
        using var doc = JsonDocument.Parse(bilder);
        foreach (var b in doc.RootElement.EnumerateArray())
        {
            var tagger = Liste(b, "RepoTags").Where(t => t.ValueKind == JsonValueKind.String).Select(t => t.GetString()!).Where(t => t != "<none>:<none>").ToList();
            var ai = tagger.FirstOrDefault(ErAiBilde);
            if (ai == null) continue;
            var navn = ai.Split(':')[0];
            var regel = FinnRegel(navn);
            long storrelse = b.TryGetProperty("Size", out var sz) && sz.TryGetInt64(out var v) ? v : 0;
            DateTime? laget = b.TryGetProperty("Created", out var cr) && cr.TryGetInt64(out var sek) ? DateTimeOffset.FromUnixTimeSeconds(sek).LocalDateTime : null;
            var f = regel != null
                ? LeggTil($"{regel.Navn} (Docker)", regel.Kategori, RisikoTekst.Fra(regel.Risiko), regel.HvorforEnkelt ?? regel.Hvorfor, "Docker", null, regel, regel.Enkelt)
                : LeggTil($"AI i Docker: {navn}", "Skygge-AI (utvikling)", Risiko.Gul, "Et Docker-bilde for å kjøre AI-modeller eller AI-tjenester lokalt.", "Docker", null, enkelt: "AI i Docker");
            f.Detalj($"Docker-bilde: {string.Join(", ", tagger.Take(4))} · {Rapport.Storrelse(storrelse)}{(laget != null ? " · laget " + Nar(laget.Value, "Docker") : "")}");
            f.Merk(Tilstand.Finnes);
            var kj = kjorer.Where(k => tagger.Contains(k.Key) || k.Key.Split(':')[0] == navn).ToList();
            if (kj.Count > 0)
            {
                var porter = kj.SelectMany(k => k.Value).Distinct().ToList();
                f.Detalj($"Beholder kjører nå{(porter.Count > 0 ? $" · åpne porter: {string.Join(", ", porter)}" : "")}");
                f.Merk(Tilstand.KjorerNa);
                if (porter.Any(p => p.StartsWith("0.0.0.0:") || p.StartsWith(":::"))) f.Advarsel("Beholderen er åpen mot nettverket (0.0.0.0), ikke bare denne PC-en.");
            }
            f.Sterkt();
        }
    }

    internal static bool ErAiBilde(string tag)
    {
        var t = tag.ToLowerInvariant().Split(':')[0];
        return AiBilder.Any(a => Bildetreff(t, a));
    }

    private static bool Bildetreff(string t, string a) => t == a || t.EndsWith("/" + a) || (a.EndsWith("/") ? t.StartsWith(a) : t.Contains(a) && a.IndexOf('/') < 0);

    private void Wsl()
    {
        using var lxss = Tilgangslogg.Nokkel(Bruker.Hkcu, @"Software\Microsoft\Windows\CurrentVersion\Lxss");
        if (lxss == null) return;
        if (lxss.GetSubKeyNames().Length == 0) return;
        // WSL2 kjører i en VM (vmmem/vmmemWSL). WSL1 har ingen VM: Linux-prosessene er pico-prosesser uten Windows-fil, og «init» finnes så lenge en distribusjon kjører.
        // wsl.exe/wslhost.exe lever bare så lenge en Linux-økt kjører (gjelder både WSL1 og WSL2).
        static bool Finnes(string n) { var p = System.Diagnostics.Process.GetProcessesByName(n); foreach (var x in p) x.Dispose(); return p.Length > 0; }
        bool linuxKjorer = Finnes("vmmemWSL") || Finnes("vmmem") || Finnes("wsl") || Finnes("wslhost")
                           || System.Diagnostics.Process.GetProcessesByName("init").Any(p => { using (p) return ProsessSti.Hent(p) == null; });
        if (!linuxKjorer)
            lock (Blindsoner) Blindsoner.Add($"WSL (Linux i Windows) er installert ({lxss.GetSubKeyNames().Length}), men kjørte ikke. AI inne i WSL er ikke sjekket; søket starter aldri Linux.");
        foreach (var id in lxss.GetSubKeyNames())
        {
            using var d = lxss.OpenSubKey(id);
            var navn = d?.GetValue("DistributionName") as string;
            var basis = d?.GetValue("BasePath") as string;
            if (navn == null) continue;
            if (!linuxKjorer)
            {
                Tilgangslogg.Logg("Mappe", $@"\\wsl.localhost\{navn}", Utfall.HoppetOver, "Linux (WSL) kjører ikke; søket starter den aldri. Disken (ext4.vhdx) kan ikke leses fra Windows.");
                continue;
            }
            WslInnhold($@"\\wsl.localhost\{navn}", navn);
            if (basis != null) Tilgangslogg.Logg("Mappe", basis, Utfall.Lest, $"WSL-distribusjon {navn}");
        }
    }

    /// <summary>Linux-delen av en WSL-distribusjon som allerede kjører: modeller, Python-miljøer og agentoppsett.</summary>
    internal void WslInnhold(string rot, string navn)
    {
        // Ollama som Linux-tjeneste lagrer modellene under brukeren «ollama»: /usr/share/ollama/.ollama/models. Kilde: https://docs.ollama.com/faq
        var hjem = new[] { Path.Combine(rot, "root"), Path.Combine(rot, "usr", "share", "ollama") }.Concat(Mapper(Path.Combine(rot, "home")));
        foreach (var h in hjem)
        {
            foreach (var (under, hva) in new[] { (@".ollama\models", "Ollama-modeller"), (@".cache\huggingface\hub", "Hugging Face-modeller"), (@".cache\lm-studio\models", "LM Studio-modeller"), (@".cache\modelscope\hub", "ModelScope-modeller") })
            {
                var m = Path.Combine(h, under);
                if (!Directory.Exists(m)) continue;
                var filer = Plattform.Filer(m, "*", 6).Take(5000).ToList();
                if (filer.Count == 0) continue;
                // Hver modell kjennes igjen på innholdet som på Windows, så familie og land (Kina, Russland) blir med
                int kjent = 0;
                foreach (var fil in filer.Where(x => x.Length >= 20L * 1024 * 1024))
                    if (ModellFormat.Gjenkjenn(fil.FullName) is { } modell) { LeggTilModell(fil.FullName, fil.Length, modell); kjent++; }
                if (kjent > 0) continue;
                var f = LeggTil($"AI-modeller i Linux (WSL): {navn}", "Lokal AI", Risiko.Gul, "AI-modeller lagret i Linux-delen av Windows (WSL). De kan kjøres uten at Windows ser programmet.", "WSL", null, enkelt: "AI i WSL");
                f.Detalj($"{hva}: {m} · {filer.Count} filer");
                f.Merk(Tilstand.Finnes);
                f.Sterkt();
            }
        }
        // Agenter og Python-miljøer i Linux: samme sjekker som på Windows, bare når Linux allerede kjører
        var ff = new FilFunn();
        var py = new List<string>();
        foreach (var lib in new[] { Path.Combine(rot, "usr", "lib"), Path.Combine(rot, "usr", "local", "lib") })
            py.AddRange(Mapper(lib).Where(x => Path.GetFileName(x).StartsWith("python3")).Select(x => Path.Combine(x, "dist-packages")));
        foreach (var h in Mapper(Path.Combine(rot, "home")).Append(Path.Combine(rot, "root")))
        {
            LesMcpFil(Path.Combine(h, ".claude.json"), "Claude Code (WSL)", prosjekt: false);
            LesMcpFil(Path.Combine(h, ".gemini", "settings.json"), "Gemini CLI (WSL)", prosjekt: false);
            foreach (var s in new[] { "settings.json", "settings.local.json" }) ClaudeInnstillinger(Path.Combine(h, ".claude", s), prosjekt: false);
            // ~/.local (pip --user) og prosjekter rett under hjemmemappa med .venv eller venv
            foreach (var v in Mapper(h).Take(500).SelectMany(p => new[] { Path.Combine(p, ".venv"), Path.Combine(p, "venv") }).Prepend(Path.Combine(h, ".local")))
                py.AddRange(Mapper(Path.Combine(v, "lib")).Where(x => Path.GetFileName(x).StartsWith("python3")).Select(x => Path.Combine(x, "site-packages")));
        }
        foreach (var pm in py.Where(Directory.Exists).Take(200)) Miljo(pm, PythonAi, "Python", ff);
        foreach (var (sti, (pakker, agent, sprak)) in ff.Miljoer) LeggTilMiljo(sti, pakker, agent, sprak).Merknad("I Linux (WSL).");
    }
}
