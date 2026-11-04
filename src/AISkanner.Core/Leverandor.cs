using System.Text.Json;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// AI som leverandører har lagt inn på PC-en uten å si fra: modeller og AI-motorer inne i Windows-apper,
/// Office, Teams, drivere og verktøy fra PC-produsenten. Finnes på innholdet (modellfiler og AI-motorer),
/// ikke på navn. Hvert funn knyttes til leverandøren og datoen det kom på PC-en.
/// Leser bare mappenavn, størrelser, datoer, de første bytene av modellfiler, filinfo og signatur på programmer.
/// </summary>
public sealed partial class Skanner
{
    private const string LeverandorKategori = "Innebygd AI fra leverandør";

    /// <summary>Modellformater som programmer bygger inn. Gjenkjennes på endelsen, og må være minst 1 MB.</summary>
    private static readonly Regex Installasjonsprogram = new(
        @"(?:^|[\\/])(?:installer|setup|install|update|updater|uninst\w*|elevation_service|notification_helper|crashpad\w*)(?:[\\/.]|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Dictionary<string, string> InnebygdeFormater = new(StringComparer.OrdinalIgnoreCase)
    {
        [".onnx"] = "ONNX", [".ort"] = "ONNX Runtime", [".tflite"] = "TensorFlow Lite", [".lite"] = "TensorFlow Lite",
        [".litertlm"] = "LiteRT-LM", [".dlc"] = "Qualcomm SNPE", [".engine"] = "TensorRT", [".pte"] = "ExecuTorch",
        [".mlmodel"] = "Core ML", [".gguf"] = "GGUF", [".safetensors"] = "safetensors",
    };

    /// <summary>Mapper som bare samler programmer fra samme firma. Programmet er neste mappe.</summary>
    private static readonly HashSet<string> Samlemapper = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Programs", "Google", "NVIDIA Corporation", "NVIDIA", "Intel", "Intel Corporation", "AMD", "Advanced Micro Devices, Inc",
        "Adobe", "Common Files", "Packages", "Lenovo", "Dell", "HP", "Hewlett-Packard", "ASUS", "Qualcomm", "Apps", "Logitech", "Apple",
        // En ProgramData-mappe inne i AppData samler firmaer, som igjen samler programmer (ProgramData\Google\Chrome)
        "ProgramData",
    };

    // Antivirusets egne mapper røres aldri, heller ikke i fullt søk
    private static bool AntivirusMappe(string navn) => navn.StartsWith("Windows Defender", StringComparison.OrdinalIgnoreCase);

    private static readonly HashSet<string> LeverandorHopp = new(StringComparer.OrdinalIgnoreCase)
    {
        "Temp", "INetCache", "INetCookies", "Cache", "Code Cache", "GPUCache", "CacheStorage", "Service Worker", "IndexedDB", "Crashpad",
        "CrashDumps", "WinSxS", "Installer", "Package Cache", "Windows Defender", "Windows Defender Advanced Threat Protection",
        "$Recycle.Bin", "WER", "History", "Logs", ".git",
        // Spill: enorme mapper, sjelden AI. Holder søket raskt.
        "steamapps", "Epic Games", "SteamLibrary",
    };

    /// <summary>Firma vi kjenner. Regnes bare som kjent når signaturen er gyldig, eller mappa er beskyttet av Windows.</summary>
    // Egenskap, ikke felt: rekkefølgen statiske felt i ulike filer settes i er ikke garantert
    private static string[] KjenteLeverandorer => _kjenteLeverandorer ??=
        KjenteUtgivere.Concat(new[] { "Lenovo", "Dell", "HP", "Hewlett", "ASUS", "ASUSTeK", "Logitech", "Grammarly", "Acer", "Micro-Star", "Samsung", "Realtek" }).ToArray();
    private static string[]? _kjenteLeverandorer;

    private sealed class AppAi
    {
        public required string Rot;
        public bool Beskyttet, Kopi;
        public readonly List<(string Sti, long Lengde, string Format, DateTime Opprettet, DateTime Endret)> Filer = new();
        public readonly SortedSet<string> Motorer = new();
        public readonly List<string> MotorFiler = new();
        public readonly SortedSet<string> AiPakker = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> AsarFiler = new();
    }

    /// <summary>
    /// Electron-apper pakker koden i resources\app.asar. Bare innholdslista (JSON øverst i fila) og package.json leses:
    /// navnene på node_modules og avhengighetene. Koden leses ikke.
    /// </summary>
    internal static (SortedSet<string> Pakker, bool Agent)? AsarPakker(string sti)
    {
        try
        {
            using var fs = Admintilgang.AapneLes(sti);
            var hode = new byte[16];
            if (fs.Read(hode, 0, 16) != 16 || BitConverter.ToUInt32(hode, 0) != 4) return null;
            uint pickle = BitConverter.ToUInt32(hode, 4), lengde = BitConverter.ToUInt32(hode, 12);
            if (lengde == 0 || lengde > 32 * 1024 * 1024 || lengde > pickle) return null;
            var json = new byte[lengde];
            int n = 0, r;
            while (n < json.Length && (r = fs.Read(json, n, json.Length - n)) > 0) n += r;
            using var doc = JsonDocument.Parse(new ReadOnlyMemory<byte>(json, 0, n));
            var navn = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (doc.RootElement.TryGetProperty("files", out var filer))
            {
                if (filer.TryGetProperty("node_modules", out var nm) && nm.TryGetProperty("files", out var moduler))
                    foreach (var m in moduler.EnumerateObject())
                        if (m.Name.StartsWith("@") && m.Value.TryGetProperty("files", out var under))
                            foreach (var u in under.EnumerateObject()) navn.Add($"{m.Name}/{u.Name}");
                        else navn.Add(m.Name);
                // package.json: avhengighetene, også de som er pakket ut ved siden av (app.asar.unpacked)
                if (filer.TryGetProperty("package.json", out var pj) && pj.TryGetProperty("size", out var st) && st.TryGetInt32(out var størrelse)
                    && størrelse is > 0 and < 1024 * 1024 && pj.TryGetProperty("offset", out var off) && long.TryParse(off.GetString(), out var forskyvning))
                {
                    fs.Position = 8 + pickle + forskyvning;
                    var b = new byte[størrelse];
                    n = 0;
                    while (n < b.Length && (r = fs.Read(b, n, b.Length - n)) > 0) n += r;
                    using var pdoc = JsonDocument.Parse(new ReadOnlyMemory<byte>(b, 0, n), new JsonDocumentOptions { AllowTrailingCommas = true });
                    foreach (var felt in new[] { "dependencies", "optionalDependencies" })
                        if (pdoc.RootElement.TryGetProperty(felt, out var avh) && avh.ValueKind == JsonValueKind.Object)
                            foreach (var a in avh.EnumerateObject()) navn.Add(a.Name);
                }
            }
            var pakker = new SortedSet<string>(navn.Where(NodeAi.ContainsKey), StringComparer.OrdinalIgnoreCase);
            Tilgangslogg.Tell("Fil", Utfall.Lest, sted: sti, detalj: "app.asar: bare innholdslista og package.json");
            if (pakker.Count == 0 || pakker.All(p => p is "ai" or "agents")) return null;
            return (pakker, pakker.Any(p => NodeAi[p]));
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return null; }
    }

    /// <summary>Hvor leverandørene legger programmene sine. Brukes også så andre sjekker ikke melder det samme to ganger.</summary>
    private static List<(string Sti, int Dybde, bool Pakker, bool Beskyttet)>? _rotter;

    internal static List<(string Sti, int Dybde, bool Pakker, bool Beskyttet)> LeverandorRotter() => _rotter ??= FinnLeverandorRotter();

    private static List<(string Sti, int Dybde, bool Pakker, bool Beskyttet)> FinnLeverandorRotter()
    {
        var liste = new List<(string, int, bool, bool)>
        {
            (Utvid(@"%LOCALAPPDATA%"), 8, false, false),
            (Utvid(@"%APPDATA%"), 7, false, false),
            (Utvid(@"%USERPROFILE%\AppData\LocalLow"), 7, false, false),
            (Utvid(@"%ProgramData%"), 7, false, false),
            (Utvid(@"%ProgramFiles%"), 8, false, true),
            (Utvid(@"%ProgramW6432%"), 8, false, true),
            (Utvid(@"%ProgramFiles(x86)%"), 8, false, true),
            (Utvid(@"%ProgramFiles%\WindowsApps"), 7, true, true),
            (Utvid(@"%ProgramW6432%\WindowsApps"), 7, true, true),
            (Utvid(@"%SystemRoot%\SystemApps"), 6, true, true),
        };
        if (Plattform.ErWindows)
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady || d.Name.StartsWith("C", StringComparison.OrdinalIgnoreCase)) continue;
                    foreach (var pf in new[] { "Program Files", "Program Files (x86)" })
                        liste.Add((Path.Combine(d.RootDirectory.FullName, pf), 8, false, true));
                }
                catch { }
            }
        }
        return liste.Where(r => !r.Item1.Contains('%') && Directory.Exists(r.Item1))
                    .GroupBy(r => Path.GetFullPath(r.Item1).TrimEnd('\\', '/'), StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
    }

    internal static bool UnderLeverandorRot(string sti) =>
        LeverandorRotter().Any(r => sti.StartsWith(r.Sti.TrimEnd('\\', '/') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));

    private void LeverandorAi()
    {
        var frist = Stopwatch.StartNew();
        var rotter = LeverandorRotter();
        var hopp = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Utvid(@"%LOCALAPPDATA%\CoreAIPlatform.00"), Utvid(@"%LOCALAPPDATA%\Temp") };
        // Nettleserdata sjekkes av InnebygdAi
        foreach (var (_, sti) in Nettleserdata) hopp.Add(Utvid(sti));
        // Programfilene inne i AppData sjekkes her, ikke to ganger
        var apper = new Dictionary<string, AppAi>(StringComparer.OrdinalIgnoreCase);
        var ff = new FilFunn();

        var jobber = new List<(string Mappe, string AppRot, int Dybde, bool Beskyttet)>();
        foreach (var (rot, dybde, pakker, beskyttet) in rotter)
        {
            foreach (var d in Mapper(rot))
            {
                if (hopp.Contains(d) || rotter.Any(r => r.Sti.Equals(d, StringComparison.OrdinalIgnoreCase)) || Lenke(d)) continue;
                var navn = Path.GetFileName(d);
                if (LeverandorHopp.Contains(navn) && (!Fullt || AntivirusMappe(navn))) continue;
                // Samlemapper (Microsoft, Programs, Packages osv.): hver undermappe er et eget program
                if (!pakker && Samlemapper.Contains(navn))
                    foreach (var u in Mapper(d).Where(u => !Lenke(u)))
                    {
                        // Samlemappe i samlemappe (ProgramData\Microsoft): programmet er et nivå lenger ned, så et program
                        // i én undermappe ikke får æren for modellene i en annen (GitHub-exe og Chrome-modeller i samme rot)
                        if (Samlemapper.Contains(Path.GetFileName(u)))
                            foreach (var uu in Mapper(u).Where(uu => !Lenke(uu))) jobber.Add((uu, uu, dybde - 3, beskyttet));
                        else jobber.Add((u, u, dybde - 2, beskyttet));
                    }
                else jobber.Add((d, d, dybde - 1, beskyttet));
            }
        }
        Parallel.ForEach(jobber, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(2, Math.Min(8, Environment.ProcessorCount)) }, j =>
        {
            var app = new AppAi { Rot = j.AppRot, Beskyttet = j.Beskyttet };
            LeverandorGaa(j.Mappe, Fullt ? 64 : j.Dybde, app, ff, hopp, frist);
            if (app.Filer.Count > 0 || app.AiPakker.Count > 0 || (app.Motorer.Count > 0 && !BareGrafikkMotor(app.Motorer))) lock (apper) apper[app.Rot] = app;
        });

        // Programmer som kjører nå
        var kjorer = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
            using (p) { var s = ProsessSti.Hent(p); if (s != null) kjorer.Add(s); }

        foreach (var app in apper.Values.OrderBy(a => a.Rot, StringComparer.OrdinalIgnoreCase))
        {
            // Modellfiler i nettleserens modellstruktur hører ikke til programmet som ligger i samme mappe (GitHub-exe ved siden av
            // en kopi av Chrome-modellene): de blir et eget funn, «Kopi av nettleserens AI-modeller»
            var kopier = app.Filer.Where(x => Nettlesermodell(x.Sti)).ToList();
            if (kopier.Count > 0 && kopier.Count < app.Filer.Count + app.MotorFiler.Count + app.AiPakker.Count)
            {
                var k = new AppAi { Rot = app.Rot, Beskyttet = app.Beskyttet, Kopi = true };
                k.Filer.AddRange(kopier);
                app.Filer.RemoveAll(x => Nettlesermodell(x.Sti));
                LeggTilLeverandorFunn(k, kjorer);
                if (app.Filer.Count == 0 && app.AiPakker.Count == 0 && (app.Motorer.Count == 0 || BareGrafikkMotor(app.Motorer))) continue;
            }
            else if (kopier.Count > 0 && kopier.Count == app.Filer.Count && app.MotorFiler.Count == 0 && app.AiPakker.Count == 0) app.Kopi = true;
            LeggTilLeverandorFunn(app, kjorer);
        }

        LeggTilFarlige(ff);
        // Modeller fra Hugging Face, LM Studio osv. og Python/Node med AI i AppData
        foreach (var (sti, lengde, m) in ff.Modeller.OrderByDescending(m => m.Lengde)) LeggTilModell(sti, lengde, m);
        foreach (var (sti, (pakkeliste, agent, sprak)) in ff.Miljoer)
        {
            var f = LeggTil($"{sprak}-prosjekt med AI: {Prosjektnavn(sti)}", "Skygge-AI (utvikling)", agent ? Risiko.Rod : Risiko.Gul,
                agent ? "Ukjent AI-agent: kode som kan handle på egen hånd med AI." : "Kode som bruker AI-biblioteker.",
                sprak, $"Mappe: {sti} ({string.Join(", ", pakkeliste)})");
            f.Bruk = $"Bruker {string.Join(", ", pakkeliste.Take(4))}{(pakkeliste.Count > 4 ? " …" : "")}.";
        }
    }

    private void LeverandorGaa(string mappe, int dybde, AppAi app, FilFunn ff, HashSet<string> hopp, Stopwatch frist)
    {
        if (hopp.Contains(mappe)) return;
        if (dybde < 0) { Tilgangslogg.TellMappe(mappe, Utfall.HoppetOver, detalj: "dybdegrensen for leverandørmapper er nådd"); return; }
        if (frist.Elapsed > Frist(40))
        {
            var brukt = Fullt ? "30 minutter" : "40 sekunder";
            Tilgangslogg.EnGang("appdata-40", "Mappe", mappe, Utfall.Tidsgrense, $"{brukt} brukt i AppData; resten ble ikke gått gjennom");
            Tilgangslogg.TellMappe(mappe, Utfall.Tidsgrense, detalj: $"{brukt} brukt i AppData");
            return;
        }
        var navn = Path.GetFileName(mappe);
        if (LeverandorHopp.Contains(navn) && (!Fullt || AntivirusMappe(navn))) { Tilgangslogg.TellMappe(mappe, Utfall.HoppetOver, detalj: AntivirusMappe(navn) ? "antivirusets egne filer, røres ikke" : "mappenavn som hoppes over av regel (buffer, logger, oppdateringer)"); return; }
        if (navn is "site-packages" or "dist-packages") { Miljo(mappe, PythonAi, "Python", ff); return; }
        if (navn == "node_modules") { Miljo(mappe, NodeAi, "Node", ff); return; }
        FileSystemInfo[] innhold;
        try { innhold = new DirectoryInfo(mappe).GetFileSystemInfos(); } catch (Exception e) { Tilgangslogg.Feil("Mappe", mappe, e); return; }
        long bytes = 0;
        foreach (var e in innhold) if (e is FileInfo fi) try { bytes += fi.Length; } catch { }
        Tilgangslogg.TellMappe(mappe, Utfall.Lest, innhold.LongCount(e => e is FileInfo), bytes);
        Interlocked.Increment(ref _mapperLest);
        foreach (var e in innhold)
        {
            FileAttributes a;
            try { a = e.Attributes; } catch { continue; }
            if ((a & FileAttributes.ReparsePoint) != 0 || (a & Skyfil) != 0) continue;   // aldri last ned skyfiler (OneDrive)
            if (e is DirectoryInfo d) { LeverandorGaa(d.FullName, dybde - 1, app, ff, hopp, frist); continue; }
            if (e is not FileInfo fil) continue;
            try { LeverandorFil(fil, innhold, app, ff); } catch { }
        }
    }

    private void LeverandorFil(FileInfo fil, FileSystemInfo[] naboer, AppAi app, FilFunn ff)
    {
        var ext = fil.Extension;
        if (fil.Name.Equals("app.asar", StringComparison.OrdinalIgnoreCase))
        {
            if (AsarPakker(fil.FullName) is { } asar) lock (app) { foreach (var p in asar.Pakker) app.AiPakker.Add(p); app.AsarFiler.Add(fil.FullName); }
            return;
        }
        if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var (m, motor) in Motorer)
                if (m.IsMatch(fil.Name)) lock (app) { app.Motorer.Add(motor); if (app.MotorFiler.Count < 20) app.MotorFiler.Add(fil.FullName); }
            return;
        }
        long lengde = fil.Length;
        if (lengde < 20 * 1024 * 1024 && !InnebygdeFormater.ContainsKey(ext)) SjekkLitenModell(fil, ff, lengde);
        if (lengde < 1024 * 1024) return;
        string? format = null;
        if (InnebygdeFormater.TryGetValue(ext, out var kjent)) format = kjent;
        // OpenVINO: modell.xml (beskrivelse) + modell.bin (vektene)
        else if (ext.Equals(".bin", StringComparison.OrdinalIgnoreCase)
                 && naboer.Any(n => n.Name.Equals(Path.GetFileNameWithoutExtension(fil.Name) + ".xml", StringComparison.OrdinalIgnoreCase))
                 && ErOpenVino(Path.Combine(fil.DirectoryName!, Path.GetFileNameWithoutExtension(fil.Name) + ".xml")))
            format = "OpenVINO";
        else if (lengde >= 20 * 1024 * 1024 && Fullt)
            format = ModellFormat.Gjenkjenn(fil.FullName)?.Format;
        else if (lengde >= 20 * 1024 * 1024 && ext.ToLowerInvariant() is not (".zip" or ".7z" or ".rar" or ".cab" or ".iso" or ".mp4" or ".mkv" or ".mov"
                     or ".exe" or ".msi" or ".msix" or ".appx" or ".vhdx" or ".pst" or ".ost" or ".jpg" or ".png" or ".pak" or ".dat" or ".db" or ".log" or ".edb" or ".etl"))
            format = ModellFormat.Gjenkjenn(fil.FullName)?.Format;
        if (format == null) return;

        // Egne modeller (GGUF, safetensors osv.) i brukerens mapper hører til "Lokal AI", ikke til en leverandør
        if (!app.Beskyttet && format is not ("ONNX" or "ONNX Runtime" or "TensorFlow Lite" or "LiteRT-LM" or "Qualcomm SNPE" or "TensorRT" or "ExecuTorch" or "Core ML" or "OpenVINO"))
        {
            var modell = ModellFormat.Gjenkjenn(fil.FullName);
            if (modell != null && lengde >= 100 * 1024 * 1024) { lock (ff) ff.Modeller.Add((fil.FullName, lengde, modell)); return; }
        }
        lock (app) app.Filer.Add((fil.FullName, lengde, format, fil.CreationTime, fil.LastWriteTime));
    }

    private static bool ErOpenVino(string xml)
    {
        try
        {
            using var s = new FileStream(xml, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            Tilgangslogg.Logg("Fil", xml, Utfall.Lest, "filhode (OpenVINO)");
            var buf = new byte[400];
            int n = s.Read(buf, 0, buf.Length);
            return System.Text.Encoding.UTF8.GetString(buf, 0, n).Contains("<net ");
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", xml, e); return false; }
    }

    private bool Nettlesermodell(string sti) =>
        sti.Split('\\', '/').Any(d => KjenteNettleserModeller.ContainsKey(d) || d.Equals("ProvenanceData", StringComparison.OrdinalIgnoreCase));

    private void LeggTilLeverandorFunn(AppAi app, HashSet<string> kjorer)
    {
        var rot = app.Rot;
        var mappenavn = Path.GetFileName(rot);
        var liten = rot.ToLowerInvariant().Replace('/', '\\');
        var frø = _regler.LeverandorAi.FirstOrDefault(l => l.Ord.Any(o => liten.Contains(o.ToLowerInvariant())));

        // Hvem står bak: 1) gyldig signatur, 2) pakkemanifest i en beskyttet mappe, 3) kjent mappe fra regelfila, 4) filinfo
        string? produkt = null, utgiver = null, kilde = null;
        string? exe = null;
        try
        {
            // Største exe, men ikke installasjons- og oppdateringsprogrammer: i Edge WebView2 er Installer\setup.exe
            // størst, og da het funnet «Microsoft Edge Installer» i stedet for WebView2
            exe = Plattform.Filer(rot, "*.exe", 3).Take(200)
                .OrderBy(f => Installasjonsprogram.IsMatch(f.FullName.Substring(rot.Length)) ? 1 : 0).ThenByDescending(f => f.Length)
                .Select(f => f.FullName).FirstOrDefault();
        }
        catch { }
        var signert = exe != null ? Signatur.Utgiver(exe) : null;
        if (signert == null) foreach (var m in app.MotorFiler.Take(3)) if ((signert = Signatur.Utgiver(m)) != null) break;
        if (signert != null) { utgiver = signert; kilde = "signatur"; }
        if (app.Beskyttet && Pakkeinfo(rot) is { } pk)
        {
            produkt ??= pk.Navn;
            if (utgiver == null && pk.Utgiver != null) { utgiver = pk.Utgiver; kilde = "Windows-pakke"; }
        }
        string? filUtgiver = null;
        if (exe != null)
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(exe);
                if (!string.IsNullOrWhiteSpace(vi.ProductName)) produkt ??= vi.ProductName.Trim();
                if (!string.IsNullOrWhiteSpace(vi.CompanyName)) filUtgiver = vi.CompanyName.Trim();
            }
            catch { }
        }
        if (frø != null) produkt = frø.Navn;
        produkt ??= Pakkenavn(mappenavn);
        if (utgiver == null && frø != null && app.Beskyttet) { utgiver = frø.Utgiver; kilde = "mappe beskyttet av Windows"; }
        utgiver ??= filUtgiver ?? frø?.Utgiver;
        kilde ??= utgiver == null ? null : "filinfo, ikke bekreftet med signatur";

        // Kjent utgiver bare når det er bekreftet (signatur eller beskyttet mappe)
        bool bekreftet = kilde is "signatur" or "Windows-pakke" or "mappe beskyttet av Windows";
        bool kjent = bekreftet && utgiver != null && KjenteLeverandorer.Any(k => utgiver.Inneholder(k));
        long storrelse = app.Filer.Sum(f => f.Lengde);
        bool stor = storrelse >= 500L * 1024 * 1024;
        var risiko = !kjent ? Risiko.Rod : stor ? Risiko.Gul : Risiko.Gronn;
        // Bare modellfiler i nettleserens egen modellstruktur: en kopi av Chrome/Edge sine modeller, ikke et ukjent program
        bool kopi = app.Kopi;
        if (kopi) { risiko = Risiko.Gul; produkt = "Kopi av nettleserens AI-modeller"; frø = null; utgiver = null; kilde = null; exe = null; }

        var regel = FinnRegel($"{produkt} {exe}");
        // Samme komponent skal bli én rad: kjente mapper får navnet fra regelfila uten utgiver, og ellers fjernes
        // versjonsnummer (WindowsAppRuntime.1.8 og .2) og utgiveren kortes til firmaet («Microsoft Windows» og
        // «Microsoft Corporation» er begge Microsoft). Hver kopi står fortsatt som egen mappe i detaljene.
        var firma = utgiver == null ? null : Firma(utgiver);
        var navn = regel?.Navn ?? frø?.Navn
                   ?? (firma != null && !UtenVersjon(produkt).Inneholder(firma) ? $"{UtenVersjon(produkt)} ({firma})" : UtenVersjon(produkt));
        var hva = frø?.Hva ?? (app.Filer.Count > 0 ? "AI-modeller som kjører lokalt i programmet"
            : app.Motorer.Count > 0 && !BareGrafikkMotor(app.Motorer) ? "AI-motor som kan kjøre AI-modeller lokalt" : "AI-biblioteker pakket inn i programmet");
        var hvorfor = kopi
            ? "Modellfiler med samme mappestruktur som Chrome/Edge sine innebygde AI-modeller, utenfor nettleserens egen mappe og uten noe program ved siden av. Hvem som la dem her, er ikke bekreftet."
            : kjent
            ? $"{Forkort(utgiver!)} har lagt AI inn i programmet: {hva}. Kom med programmet eller en oppdatering, uten at noen ble spurt."
            : "Ukjent program med egne AI-modeller eller AI-motor. Vi kan ikke bekrefte hvem som har laget det.";
        var f = regel != null ? FraRegel(regel, "Innebygd AI", null!)
            : LeggTil(navn, kopi ? LeverandorKategori + " (nettleser)" : LeverandorKategori, risiko, hvorfor, "Innebygd AI", null,
                enkelt: kopi ? "Kopi av nettleserens AI-modeller" : kjent ? $"AI lagt inn av {Forkort(utgiver!)}" : "Ukjent program med AI");
        f.Risiko = RisikoTekst.Hoyeste(f.Risiko, risiko);
        // Innebygde modellfiler er ikke AI brukeren kjører selv: programmet telles én gang, ikke hver fil
        f.LeggTilInnebygde(app.Filer.Count);

        // Når kom det på PC-en
        DateTime? lagtInn = null, oppdatert = null;
        foreach (var x in app.Filer) { if (lagtInn == null || x.Opprettet < lagtInn) lagtInn = x.Opprettet; if (oppdatert == null || x.Endret > oppdatert) oppdatert = x.Endret; }
        try { var dr = Directory.GetCreationTime(rot); if (lagtInn == null || dr < lagtInn) lagtInn = dr; } catch { }
        foreach (var mf in app.MotorFiler) try { var t = File.GetLastWriteTime(mf); if (oppdatert == null || t > oppdatert) oppdatert = t; } catch { }
        bool iGang = kjorer.Any(k => k.StartsWith(rot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        f.Tidspunkt(lagtInn, iGang ? DateTime.Now : oppdatert);

        // Flere kopier eller versjoner av samme komponent er slått sammen: teksten gjelder alle
        int kopier = f.Detaljer.Count(d => d.StartsWith("Mappe: ", StringComparison.Ordinal)) + 1;
        var deler = new List<string>();
        if (utgiver != null) deler.Add($"Fra {Firma(utgiver)}");
        if (f.Innebygde > 0) deler.Add($"{f.Innebygde} {(f.Innebygde == 1 ? "innebygd modellfil" : "innebygde modellfiler")}{(kopier == 1 ? $" ({Rapport.Storrelse(storrelse)})" : "")}");
        if (kopier > 1) deler.Add($"{kopier} mapper");
        if (app.Motorer.Count > 0) deler.Add($"AI-motor: {string.Join(", ", app.Motorer)}");
        if (app.AiPakker.Count > 0) deler.Add($"AI-biblioteker: {string.Join(", ", app.AiPakker.Take(4))}{(app.AiPakker.Count > 4 ? " …" : "")}");
        if (lagtInn != null) deler.Add($"lagt inn {Tid(lagtInn)}");
        f.Bruk = string.Join(", ", deler) + (iGang ? ". Kjører nå." : ".");
        if (iGang) f.Merk(Tilstand.KjorerNa);

        f.Detalj($"Mappe: {rot} · {hva}{(lagtInn != null ? $" · lagt inn {Tid(lagtInn)}" : "")}");
        if (kopi) f.Detalj("Modellfilene har samme navn og mappestruktur som Chrome/Edge sine; hvem som kopierte dem hit, står ikke i filene");
        else f.Detalj($"Utgiver: {utgiver ?? "ukjent"}{(kilde != null ? $" · {kilde}" : "")}");
        foreach (var x in app.Filer.OrderByDescending(x => x.Lengde).Take(40))
            f.Detalj($"Fil: {x.Sti} · {x.Format} · {Rapport.Storrelse(x.Lengde)} · lagt inn {Tid(x.Opprettet)}{(x.Endret.Date != x.Opprettet.Date ? $" · oppdatert {Tid(x.Endret)}" : "")}");
        if (app.Filer.Count > 40) f.Detalj($"Og {app.Filer.Count - 40} modellfiler til i {rot}");
        foreach (var m in app.MotorFiler.Take(8)) f.Detalj($"AI-motor: {m}");
        foreach (var a in app.AsarFiler.Take(4)) f.Detalj($"app.asar: {a} ({string.Join(", ", app.AiPakker)})");
        if (app.AiPakker.Any(p => NodeAi.TryGetValue(p, out var ag) && ag)) f.Advarsel("Programmet har med biblioteker for AI-agenter som kan handle på egen hånd.");
        if (frø != null && !frø.Bekreftet) f.Merknad("Navnet kommer fra en liste over kjente mapper som ikke er bekreftet på alle PC-er. Selve funnet er gjort på innholdet.");
        if (!bekreftet && utgiver != null) f.Advarsel($"Programmet sier at det er fra {Forkort(utgiver)}, men det er ikke bekreftet med en gyldig signatur.");
        foreach (var k in kjorer.Where(k => k.StartsWith(rot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))) HuskMappe(k, f);
    }

    /// <summary>Navn og utgiver fra AppxManifest.xml i en Windows-pakke (liten tekstfil).</summary>
    private static (string? Navn, string? Utgiver)? Pakkeinfo(string rot)
    {
        try
        {
            var fil = Path.Combine(rot, "AppxManifest.xml");
            if (!File.Exists(fil) || new FileInfo(fil).Length > 512 * 1024) return null;
            var t = Tilgangslogg.Prov("Fil", fil, () => File.ReadAllText(fil), "");
            string? Tag(string navn)
            {
                var m = Regex.Match(t, $"<{navn}>([^<]+)</{navn}>");
                return m.Success && !m.Groups[1].Value.StartsWith("ms-resource:") ? m.Groups[1].Value.Trim() : null;
            }
            return (Tag("DisplayName"), Tag("PublisherDisplayName"));
        }
        catch { return null; }
    }

    /// <summary>"Microsoft.Paint_11.2.0.0_x64__8wekyb3d8bbwe" → "Microsoft.Paint".</summary>
    private static string Pakkenavn(string mappe)
    {
        var i = mappe.IndexOf('_');
        return i > 0 ? mappe.Substring(0, i) : mappe;
    }

    /// <summary>"Microsoft.WindowsAppRuntime.1.8" → "Microsoft.WindowsAppRuntime", "Program v2.1" → "Program". "Microsoft 365" står.</summary>
    internal static string UtenVersjon(string navn)
    {
        var u = Regex.Replace(navn, @"(?:\.\d+(?:\.\d+)*|[\s_-]v?\d+(?:\.\d+)+)$", "", RegexOptions.IgnoreCase);
        return u.Length >= 3 ? u : navn;
    }

    /// <summary>Firmaet bak en utgiver: «Microsoft Windows» og «Microsoft Corporation» blir begge «Microsoft».</summary>
    internal static string Firma(string utgiver) =>
        KjenteLeverandorer.Where(k => Regex.IsMatch(utgiver, @"(?<![\p{L}\d])" + Regex.Escape(k) + @"(?![\p{L}\d])", RegexOptions.IgnoreCase))
            .OrderByDescending(k => k.Length).FirstOrDefault() ?? Forkort(utgiver);

    /// <summary>"Microsoft Corporation" → "Microsoft", "NVIDIA Corporation" → "NVIDIA".</summary>
    private static string Forkort(string utgiver) =>
        Regex.Replace(utgiver, @"[,\s]+(Corporation|Corp\.?|Inc\.?|Incorporated|LLC|Ltd\.?|Limited|GmbH|AG|AS|ASA|Co\.|Company|S\.A\.)\.?$", "", RegexOptions.IgnoreCase).Trim();
}
