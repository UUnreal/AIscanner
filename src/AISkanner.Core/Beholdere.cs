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
    // Kjente AI-bilder (navnet før kolon/tag). Treff i regelfila brukes også.
    private static readonly string[] AiBilder =
    {
        "ollama/ollama", "vllm/vllm-openai", "huggingface/text-generation-inference", "open-webui/open-webui", "localai/localai",
        "ggerganov/llama.cpp", "ggml-org/llama.cpp", "nvidia/tritonserver", "berriai/litellm", "qdrant/qdrant", "chromadb/chroma",
        "mintplexlabs/anythingllm", "danny-avila/librechat", "flowiseai/flowise", "langgenius/dify-api", "langgenius/dify-web",
        "milvusdb/milvus", "semitechnologies/weaviate", "comfyui", "stable-diffusion-webui", "invokeai/invokeai", "h2oai/h2ogpt",
        "lmsysorg/sglang", "michaelf34/infinity", "ghcr.io/huggingface/text-embeddings-inference", "nvcr.io/nim/",
    };

    private void Beholdere()
    {
        if (!Plattform.ErWindows) return;
        try { Docker(); } catch (Exception e) { Tilgangslogg.Logg("Sjekk", "Docker", Utfall.Feil, Tilgangslogg.Beskriv(e)); }
        try { Wsl(); } catch (Exception e) { Tilgangslogg.Logg("Sjekk", "WSL", Utfall.Feil, Tilgangslogg.Beskriv(e)); }
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
        return AiBilder.Any(a => t == a || t.EndsWith("/" + a) || (a.EndsWith("/") ? t.StartsWith(a) : t.Contains(a) && a.IndexOf('/') < 0));
    }

    private void Wsl()
    {
        using var lxss = Tilgangslogg.Nokkel(Bruker.Hkcu, @"Software\Microsoft\Windows\CurrentVersion\Lxss");
        if (lxss == null) return;
        if (lxss.GetSubKeyNames().Length == 0) return;
        bool linuxKjorer = System.Diagnostics.Process.GetProcessesByName("vmmemWSL").Length > 0 || System.Diagnostics.Process.GetProcessesByName("vmmem").Length > 0;
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
            var rot = $@"\\wsl.localhost\{navn}";
            var hjem = new[] { Path.Combine(rot, "root") }.Concat(Mapper(Path.Combine(rot, "home")));
            foreach (var h in hjem)
            {
                foreach (var (under, hva) in new[] { (@".ollama\models\manifests", "Ollama-modeller"), (@".cache\huggingface\hub", "Hugging Face-modeller"), (@".cache\lm-studio\models", "LM Studio-modeller") })
                {
                    var m = Path.Combine(h, under);
                    if (!Directory.Exists(m)) continue;
                    var antall = Plattform.Filer(m, "*", 4).Count();
                    if (antall == 0) continue;
                    var f = LeggTil($"AI-modeller i Linux (WSL): {navn}", "Lokal AI", Risiko.Gul, "AI-modeller lagret i Linux-delen av Windows (WSL). De kan kjøres uten at Windows ser programmet.", "WSL", null, enkelt: "AI i WSL");
                    f.Detalj($"{hva}: {m} · {antall} filer");
                    f.Merk(Tilstand.Finnes);
                    f.Sterkt();
                }
            }
            if (basis != null) Tilgangslogg.Logg("Mappe", basis, Utfall.Lest, $"WSL-distribusjon {navn}");
        }
    }
}
