using System.Text;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// AI-modeller som nettsider har lastet ned og kjører i nettleseren med WebGPU eller WebAssembly (WebLLM, Transformers.js,
/// ONNX Runtime Web, MediaPipe, wllama). Ingenting installeres, så dette er skygge-AI som ellers bare ser ut som et besøk.
/// Kilder, bare metadata:
///  - Chromium, Cache Storage (Service Worker\CacheStorage og WebStorage\*\CacheStorage): nettstedet fra index.txt og
///    QuotaManager, og adressen i filhodet til hver stor fil. Bare adresser til modellfiler beholdes, resten forkastes straks.
///  - Chromium, IndexedDB-blobber og File System (OPFS), og Firefox storage\default: filhodet (modellformat), størrelse, dato.
///  - Firefox, caches.sqlite: bare adressene til modellfiler.
///  - Mens søket går: om nettleserens prosesser bruker GPU til beregning (ytelsestellere, bare tall).
/// Leser aldri samtaler, skjemadata, informasjonskapsler eller sideinnhold.
/// </summary>
public sealed partial class Skanner
{
    // Modellfiler fra WebLLM (MLC), Transformers.js/ONNX, MediaPipe/LiteRT, GGUF (wllama) og safetensors
    internal static readonly Regex ModellAdresse = new(
        @"https?://([^/\s""']+)((?:/[^/\s?#""']+)*?)/([^/\s?#""']*?(?:params_shard_\d+\.bin|mlc-chat-config\.json|ndarray-cache\.json|\.onnx(?:_data)?|\.gguf|\.task|\.tflite|\.litertlm|\.safetensors))(?=[?#\s""']|$)",
        RegexOptions.IgnoreCase);
    private const ulong SimpleCacheMagi = 0xfcfb6d1ba7725c30;
    private const long StorModell = 50L * 1024 * 1024;

    private sealed class Nettsidemodell
    {
        public long Storrelse;
        public int Filer;
        public bool Sprak;
        public DateTime? Forst, Sist;
        public readonly SortedSet<string> Modeller = new(), Bibliotek = new();
        public readonly List<string> Linjer = new();

        public void Legg(string bibliotek, string? modell, string linje, FileInfo f, bool sprak) =>
            Legg(bibliotek, modell, linje, f.Length, f.CreationTime, f.LastWriteTime, sprak);

        public void Legg(string bibliotek, string? modell, string linje, long storrelse, DateTime forst, DateTime sist, bool sprak)
        {
            lock (this)
            {
                Storrelse += storrelse;
                Filer++;
                Sprak |= sprak;
                Bibliotek.Add(bibliotek);
                if (modell != null) Modeller.Add(modell);
                if (Linjer.Count < 30) Linjer.Add(linje);
                if (Forst == null || forst < Forst) Forst = forst;
                if (Sist == null || sist > Sist) Sist = sist;
            }
        }
    }

    private readonly List<string> _nettsideLinjer = new();

    /// <summary>Hvilket bibliotek modellen er laget for, ut fra adressen eller formatet.</summary>
    internal static string Bibliotek(string t) =>
        Regex.IsMatch(t, @"webllm|-MLC\b|mlc-chat-config|params_shard_|ndarray-cache", RegexOptions.IgnoreCase) ? "WebLLM"
        : Regex.IsMatch(t, @"\.gguf|GGUF", RegexOptions.IgnoreCase) ? "llama.cpp i nettleseren (GGUF)"
        : Regex.IsMatch(t, @"\.onnx|ONNX", RegexOptions.IgnoreCase) ? "Transformers.js / ONNX Runtime Web"
        : Regex.IsMatch(t, @"\.task|\.tflite|\.litertlm|TensorFlow Lite", RegexOptions.IgnoreCase) ? "MediaPipe / LiteRT"
        : "safetensors";

    private static bool ErSprak(string bibliotek) => bibliotek is "WebLLM" or "llama.cpp i nettleseren (GGUF)";

    /// <summary>"huggingface.co/mlc-ai/Llama-3.2-1B-Instruct-q4f16_1-MLC" fra adressen til en modellfil.</summary>
    internal static string ModellNavnFraAdresse(Match m)
    {
        var sti = Regex.Replace(m.Groups[2].Value, @"/(resolve|blob|raw)/[^/]+(/.*)?$|/onnx$", "");
        var navn = m.Groups[1].Value.ToLowerInvariant() + sti;
        return navn.Length > 120 ? navn.Substring(0, 120) + "…" : navn;
    }

    private void NettsideModeller()
    {
        lock (_nettsideLinjer) _nettsideLinjer.Clear();
        var funnet = new Dictionary<(string Nettleser, string Hvor, string Sted), Nettsidemodell>();
        Nettsidemodell For(string nettleser, string hvor, string sted)
        {
            lock (funnet) return funnet.TryGetValue((nettleser, hvor, sted), out var x) ? x : funnet[(nettleser, hvor, sted)] = new Nettsidemodell();
        }
        int lest = 0;

        foreach (var (nettleser, rotSti) in ChromiumRotter())
            foreach (var profil in Mapper(Utvid(rotSti)))
            {
                var hvor = $"{nettleser} ({Path.GetFileName(profil)})";
                // Nye Chromium: én mappe per lagringsbotte, nettstedet står i QuotaManager
                var botter = new Dictionary<long, string>();
                LesSqlite(Path.Combine(profil, "WebStorage", "QuotaManager"), "SELECT id, host FROM buckets", 0,
                    r => { if (r.Tekst(1) is { Length: > 0 } h) botter[r.Tall(0)] = h; });
                var cacher = Mapper(Path.Combine(profil, "Service Worker", "CacheStorage")).Select(d => (Mappe: d, Sted: (string?)null))
                    .Concat(Mapper(Path.Combine(profil, "WebStorage")).Select(d => (Mappe: d, Sted: long.TryParse(Path.GetFileName(d), out var id) && botter.TryGetValue(id, out var h) ? h : null)));
                foreach (var (mappe, botte) in cacher)
                {
                    var cs = Directory.Exists(Path.Combine(mappe, "CacheStorage")) ? Path.Combine(mappe, "CacheStorage") : mappe;
                    var sted = botte ?? OpprinnelseFraIndeks(Path.Combine(cs, "index.txt")) ?? "ukjent nettsted";
                    foreach (var f in Plattform.Filer(mappe, "*", 4).Where(f => f.Length > 1024 * 1024).Take(5000))
                    {
                        Interlocked.Increment(ref lest);
                        var (adresse, gguf) = CacheNokkel(f.FullName);
                        var m = adresse != null ? ModellAdresse.Match(adresse) : Match.Empty;
                        var format = !m.Success && !gguf && adresse == null ? ModellFormat.Gjenkjenn(f.FullName)?.Format : null;
                        if (!m.Success && !gguf && format == null) continue;   // ikke en modellfil: adressen forkastes
                        var bib = Bibliotek(m.Success ? m.Value : format ?? "GGUF");
                        var modell = m.Success ? ModellNavnFraAdresse(m) : null;
                        var hva = m.Success ? $"{m.Groups[1].Value.ToLowerInvariant()}{m.Groups[2].Value}/{m.Groups[3].Value}" : format ?? "GGUF-modell";
                        For(nettleser, hvor, sted).Legg(bib, modell, $"Modellfil: {hva} · {Rapport.Storrelse(f.Length)} · lagret {Tid(f.LastWriteTime)} · {f.FullName}", f, ErSprak(bib));
                    }
                }
                // IndexedDB-blobber: nettstedet står i mappenavnet (https_chat.webllm.ai_0.indexeddb.blob)
                foreach (var d in Mapper(Path.Combine(profil, "IndexedDB")))
                {
                    var n = Regex.Match(Path.GetFileName(d), @"^https?_(.+?)_\d+\.indexeddb\.blob$");
                    if (n.Success) Formatfiler(d, n.Groups[1].Value, nettleser, hvor, For, ref lest);
                }
                Formatfiler(Path.Combine(profil, "File System"), "ukjent nettsted (File System)", nettleser, hvor, For, ref lest);
            }

        foreach (var (ffNavn, profil) in FirefoxProfiler())
        {
            var hvor = $"{ffNavn} ({Path.GetFileName(profil)})";
            foreach (var d in Mapper(Path.Combine(profil, "storage", "default")))
            {
                var n = Regex.Match(Path.GetFileName(d), @"^https?\+\+\+([^+^]+)");
                if (!n.Success) continue;
                var sted = n.Groups[1].Value;
                var adresser = new List<Match>();
                LesSqlite(Path.Combine(d, "cache", "caches.sqlite"), "SELECT request_url_no_query FROM entries", 0,
                    r => { var m = ModellAdresse.Match(r.Tekst(0) ?? ""); if (m.Success) adresser.Add(m); });
                if (adresser.Count > 0)
                {
                    // Innholdet ligger i cache\morgue; størrelsen og datoene er hele cachen til nettstedet
                    var morgue = Plattform.Filer(Path.Combine(d, "cache", "morgue"), "*", 3).ToList();
                    var x = For(ffNavn, hvor, sted);
                    var forst = morgue.Count > 0 ? morgue.Min(f => f.CreationTime) : Directory.GetCreationTime(d);
                    var sist = morgue.Count > 0 ? morgue.Max(f => f.LastWriteTime) : Directory.GetLastWriteTime(d);
                    for (int i = 0; i < adresser.Count; i++)
                    {
                        var m = adresser[i];
                        x.Legg(Bibliotek(m.Value), ModellNavnFraAdresse(m), $"Modellfil: {m.Groups[1].Value.ToLowerInvariant()}{m.Groups[2].Value}/{m.Groups[3].Value} · i {Path.Combine(d, "cache")}",
                            i == 0 ? morgue.Sum(f => f.Length) : 0, forst, sist, ErSprak(Bibliotek(m.Value)));
                    }
                }
                Formatfiler(Path.Combine(d, "idb"), sted, ffNavn, hvor, For, ref lest);
            }
        }

        // Mens søket går: bruker nettleserne GPU til beregning? Viser ikke hvilken fane, bare at nettleseren gjør det.
        var gpu = funnet.Count > 0 && TestNett == null ? GpuBeregning(navn => Nettleserprosesser.ContainsKey(navn)) : null;

        foreach (var ((nettleser, hvor, sted), x) in funnet)
        {
            if (x.Filer == 0) continue;
            bool stor = x.Sprak || x.Storrelse >= StorModell;
            var f = LeggTil($"AI-modell kjører i nettleseren: {sted}", "Lokal AI (modell i nettleseren)", Risiko.Rod,
                $"Nettstedet {sted} har lastet ned en AI-modell som kjører på PC-en inne i {nettleser} ({string.Join(", ", x.Bibliotek)}). Ingenting er installert, så IT ser det ikke som et program.",
                nettleser, null, enkelt: stor ? "Språkmodell kjører i nettleseren" : "AI-modell kjører i nettleseren");
            f.Bruk = $"{(stor ? "Språkmodell" : "AI-modell")} fra {sted}, {Rapport.Storrelse(x.Storrelse)} lagret i {hvor}" +
                     (x.Modeller.Count > 0 ? $": {string.Join(", ", x.Modeller.Take(3))}{(x.Modeller.Count > 3 ? " …" : "")}." : ".");
            f.Tidspunkt(x.Forst, x.Sist);
            f.Detalj($"Nettsted: {sted} · {hvor} · {x.Filer} modellfiler · {Rapport.Storrelse(x.Storrelse)} · bibliotek: {string.Join(", ", x.Bibliotek)}");
            foreach (var m in x.Modeller) f.Detalj($"Modell: {m}");
            foreach (var l in x.Linjer) f.Detalj(l);
            var familie = Nettleserprosesser.FirstOrDefault(p => p.Value == nettleser.Split(' ')[0]).Key;
            var bruk = gpu == null || familie == null ? null : gpu.Where(g => g.Value.Navn.Equals(familie, StringComparison.OrdinalIgnoreCase)).ToList();
            f.Detalj(bruk == null ? $"GPU-bruk for {nettleser} ble ikke målt (ikke bekreftet om modellen kjører nå)."
                : bruk.Count > 0 ? $"{nettleser} bruker GPU til beregning nå: {Math.Min(100, bruk.Sum(g => g.Value.Prosent)):0} % (PID {string.Join(", ", bruk.Select(g => g.Key))}). Hvilken fane kan ikke ses, så det er ikke bekreftet at det er denne modellen."
                : $"{nettleser} brukte ikke GPU til beregning under søket (ikke bekreftet at modellen kjører nå).");
            f.LeggTilModeller(Math.Max(1, x.Modeller.Count));
            lock (_nettsideLinjer) _nettsideLinjer.Add($"{sted} · {hvor} · {Rapport.Storrelse(x.Storrelse)} · {string.Join(", ", x.Bibliotek)}");
        }
        Tilgangslogg.Logg("Mappe", "nettleserlagring (Cache Storage, IndexedDB, File System, Firefox storage)", Utfall.Lest,
            $"{lest} store filer: bare filhode, størrelse og dato; adresser som ikke er modellfiler forkastes");
    }

    /// <summary>Store filer med kjent modellformat (GGUF, ONNX, TFLite …) i en mappe som hører til ett nettsted.</summary>
    private static void Formatfiler(string mappe, string sted, string nettleser, string hvor, Func<string, string, string, Nettsidemodell> For, ref int lest)
    {
        if (!Directory.Exists(mappe)) return;
        foreach (var f in Plattform.Filer(mappe, "*", 5).Where(f => f.Length > 1024 * 1024).Take(2000))
        {
            lest++;
            if (ModellFormat.Gjenkjenn(f.FullName) is not { } m) continue;
            var bib = Bibliotek(m.Format);
            For(nettleser, hvor, sted).Legg(bib, null, $"Modellfil: {m.Format} · {Rapport.Storrelse(f.Length)} · lagret {Tid(f.LastWriteTime)} · {f.FullName}", f, ErSprak(bib));
        }
    }

    /// <summary>Nettstedet som eier en Cache Storage-mappe, fra index.txt ("https://chat.webllm.ai/").</summary>
    private static string? OpprinnelseFraIndeks(string sti)
    {
        try
        {
            if (!File.Exists(sti)) return null;
            using var fs = Admintilgang.AapneLes(sti);
            var b = new byte[Math.Min(fs.Length, 64 * 1024)];
            int n = fs.Read(b, 0, b.Length);
            var m = Regex.Match(Encoding.ASCII.GetString(b, 0, n), @"https?://([A-Za-z0-9.\-]+)(:\d+)?/");
            return m.Success ? m.Groups[1].Value.ToLowerInvariant() : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// Adressen en fil i Chromiums diskcache er lagret under (filhodet: magisk tall, nøkkellengde i byte 12, nøkkelen fra byte 24),
    /// og om innholdet starter med GGUF. Leser bare de første kilobytene.
    /// </summary>
    internal static (string? Adresse, bool Gguf) CacheNokkel(string sti)
    {
        try
        {
            using var fs = Admintilgang.AapneLes(sti);
            var b = new byte[24 + 4096 + 4];
            int n = 0, r;
            while (n < b.Length && (r = fs.Read(b, n, b.Length - n)) > 0) n += r;
            if (n < 28 || BitConverter.ToUInt64(b, 0) != SimpleCacheMagi) return (null, false);
            var lengde = (int)BitConverter.ToUInt32(b, 12);
            if (lengde <= 0 || lengde > 4096 || 24 + lengde > n) return (null, false);
            var nokkel = Encoding.UTF8.GetString(b, 24, lengde);
            bool gguf = 24 + lengde + 4 <= n && Encoding.ASCII.GetString(b, 24 + lengde, 4) == "GGUF";
            // Nøkkelen kan ha et prefiks; adressen er det som står fra siste "http"
            var i = nokkel.LastIndexOf("http", StringComparison.OrdinalIgnoreCase);
            return (i >= 0 ? nokkel.Substring(i) : nokkel, gguf);
        }
        catch { return (null, false); }
    }
}
