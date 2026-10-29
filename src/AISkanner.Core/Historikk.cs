using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Spor Windows selv fører over programmer som har kjørt: Prefetch, BAM, Amcache, oppgavelageret og hendelsesloggene
/// (4688, Sysmon og DNS-loggen når de er slått på). Leses mens søket går, som administrator, bare lesing.
/// Ingenting lagres. Det som vises, er hvilket program, når, og regelen som slo til.
/// </summary>
public sealed partial class Skanner
{
    private void WindowsHistorikk()
    {
        if (!Plattform.ErWindows) return;
        foreach (var (navn, steg) in new (string, Action)[]
        {
            ("Prefetch", PrefetchHistorikk), ("BAM", Bam), ("Amcache", Amcache), ("Hendelseslogger", Hendelseslogger),
        })
        {
            try { steg(); }
            catch (Exception e) { Tilgangslogg.Logg("Sjekk", $"Windows-historikk: {navn}", Utfall.Feil, $"Sjekken stoppet: {Tilgangslogg.Beskriv(e)}"); }
        }
    }

    private static DateTime? Filtid(long ft) =>
        ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(ft).ToLocalTime() : null;

    // ---------- Prefetch ----------

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool GetVolumeInformation(string rot, StringBuilder? navn, int navnLengde, out uint serie, out uint maks, out uint flagg, StringBuilder? fs, int fsLengde);

    private static readonly Regex VolumIPrefetch = new(@"^\\VOLUME\{[0-9a-f]+-([0-9a-f]{8})\}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly ISet<string> PrefetchModeller = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".gguf", ".safetensors", ".llamafile", ".ggml" };

    /// <summary>
    /// C:\Windows\Prefetch: én fil per program som har kjørt, med de siste kjøretidene og filene programmet åpnet de første
    /// sekundene. Viser AI som er brukt før, også når den er avinstallert, og AI-biblioteker Python og Node har lastet.
    /// </summary>
    private void PrefetchHistorikk()
    {
        var mappe = Utvid(@"%SystemRoot%\Prefetch");
        string[] filer;
        try { filer = Directory.GetFiles(mappe, "*.pf"); }
        catch (Exception e) { Tilgangslogg.Feil("Mappe", mappe, e); return; }
        var volum = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in DriveInfo.GetDrives())
            try { if (GetVolumeInformation(d.Name, null, 0, out var s, out _, out _, null, 0)) volum[s.ToString("x8")] = d.Name.Substring(0, 2); } catch { }
        int lest = 0;
        foreach (var fil in filer)
        {
            var exe = Path.GetFileName(fil);
            int bindestrek = exe.LastIndexOf('-');
            if (bindestrek > 0) exe = exe.Substring(0, bindestrek);
            byte[]? data;
            try
            {
                using var fs = Admintilgang.AapneLes(fil);
                using var ms = new MemoryStream();
                fs.CopyTo(ms);
                data = AISkanner.Prefetch.Pakkut(ms.ToArray());
                lest++;
                Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil, detalj: "programnavn, kjøretider og filnavn programmet åpnet");
            }
            catch (Exception e) { Tilgangslogg.Feil("Fil", fil, e); continue; }
            if (data == null || data.Length < 0x100 || Encoding.ASCII.GetString(data, 4, 4) != "SCCA")
            {
                Tilgangslogg.Tell("Fil", Utfall.HoppetOver, sted: fil, detalj: "ukjent Prefetch-format");
                continue;
            }
            var kjort = AISkanner.Prefetch.Tolk(data)?.Tider ?? new List<DateTime>();
            var sist = kjort.Count > 0 ? kjort.Max() : File.GetLastWriteTime(fil);
            var forst = kjort.Count > 0 ? kjort.Min() : (DateTime?)null;

            // Filene programmet åpnet
            var referanser = new List<string>();
            foreach (var s in AISkanner.Prefetch.Filer(data))
            {
                var m = VolumIPrefetch.Match(s);
                referanser.Add(m.Success && volum.TryGetValue(m.Groups[1].Value, out var bokstav) ? bokstav + s.Substring(m.Length) : s);
            }
            var tid = $"sist kjørt {Nar(sist, "Prefetch i Windows")}{(kjort.Count > 1 ? $", {kjort.Count} av de siste kjøringene registrert" : "")}";
            var programfil = referanser.FirstOrDefault(r => r.EndsWith("\\" + exe, StringComparison.OrdinalIgnoreCase));

            var regel = FinnRegel(Path.GetFileNameWithoutExtension(exe)) ?? (programfil != null ? FinnRegel(programfil) : null);
            Funn? f = null;
            if (regel != null)
            {
                f = FraRegel(regel, "Kjørt før", $"Kjørt før: {programfil ?? exe} · {tid}");
                f.Bruk ??= "Brukt før.";
                f.Merk(Tilstand.BruktFor);
                f.Tidspunkt(forst, sist);
            }
            // Python og Node: AI-bibliotekene de lastet
            var navn = Path.GetFileNameWithoutExtension(exe);
            if (Kommandolinje.ErTolk(navn))
            {
                var bruker = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
                bool agent = false;
                foreach (var r in referanser)
                {
                    var m = Regex.Match(r, @"\\(?:site|dist)-packages\\([^\\]+)\\", RegexOptions.IgnoreCase);
                    if (m.Success && PythonAi.TryGetValue(m.Groups[1].Value, out var ag)) { bruker.Add(m.Groups[1].Value.ToLowerInvariant()); agent |= ag; }
                    m = Regex.Match(r, @"\\node_modules\\((?:@[^\\]+\\)?[^\\]+)\\", RegexOptions.IgnoreCase);
                    if (m.Success && NodeAi.TryGetValue(m.Groups[1].Value.Replace('\\', '/'), out ag)) { bruker.Add(m.Groups[1].Value.Replace('\\', '/').ToLowerInvariant()); agent |= ag; }
                }
                if (bruker.Count > 0)
                {
                    var sprak = navn.StartsWith("py", StringComparison.OrdinalIgnoreCase) ? "Python" : "Node";
                    var skript = referanser.Where(r => Skriptendelser.Contains(Path.GetExtension(r))
                        && r.IndexOf("-packages\\", StringComparison.OrdinalIgnoreCase) < 0 && r.IndexOf("\\node_modules\\", StringComparison.OrdinalIgnoreCase) < 0
                        && r.IndexOf("\\Lib\\", StringComparison.OrdinalIgnoreCase) < 0).Take(5).ToList();
                    var t = LeggTil($"{sprak} har kjørt AI-biblioteker", agent ? "Skygge-AI (agent)" : "Skygge-AI", Risiko.Rod,
                        $"{sprak} på PC-en har lastet AI-biblioteker. Windows har registrert det i Prefetch. Viser AI som er kjørt fra skript, også når skriptet er borte.",
                        "Kjørt før", $"{exe}: lastet {string.Join(", ", bruker)}{(skript.Count > 0 ? $" · skript: {string.Join(", ", skript)}" : "")} · {tid}",
                        enkelt: $"{sprak} med AI-biblioteker");
                    t.Bruk ??= "Brukt før.";
                    t.Merk(Tilstand.BruktFor); t.Sterkt();
                    t.Tidspunkt(forst, sist);
                }
            }
            // AI-modeller programmet åpnet
            var modeller = referanser.Where(r => PrefetchModeller.Contains(Path.GetExtension(r))).Take(5).ToList();
            if (modeller.Count > 0)
            {
                f ??= LeggTil($"Program som har lastet AI-modeller: {exe}", "Lokal AI", Risiko.Rod,
                    "Et program har åpnet AI-modellfiler. Windows har registrert det i Prefetch.", "Kjørt før", null, enkelt: "Program med AI-modeller");
                f.Bruk ??= "Brukt før.";
                f.Merk(Tilstand.BruktFor); f.Sterkt();
                f.Tidspunkt(forst, sist);
                f.Detalj($"{exe} åpnet {string.Join(", ", modeller)} · {tid}");
            }
            data = null;
        }
        Tilgangslogg.Logg("Mappe", mappe, lest > 0 ? Utfall.Lest : Utfall.Nektet,
            lest > 0 ? $"{lest} Prefetch-filer: programnavn, kjøretider og filnavn programmet åpnet" : "Prefetch krever administrator");
    }

    // ---------- BAM ----------

    /// <summary>Background Activity Moderator: siste gang hvert program kjørte, per bruker.</summary>
    private void Bam()
    {
        int lest = 0;
        foreach (var sti in new[] { @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", @"SYSTEM\CurrentControlSet\Services\bam\UserSettings" })
        {
            using var k = Tilgangslogg.Nokkel(Registry.LocalMachine, sti);
            if (k == null) continue;
            foreach (var sid in k.GetSubKeyNames())
            {
                using var bruker = k.OpenSubKey(sid);
                if (bruker == null) continue;
                foreach (var verdi in bruker.GetValueNames())
                {
                    lest++;
                    if (!verdi.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase) && verdi.IndexOf('_') < 0) continue;
                    var prog = verdi.StartsWith("\\Device\\", StringComparison.OrdinalIgnoreCase) ? Admintilgang.TilDos(verdi) : verdi;
                    var regel = FinnRegel(prog);
                    if (regel == null) continue;
                    DateTime? t = bruker.GetValue(verdi) is byte[] b && b.Length >= 8 ? Filtid(BitConverter.ToInt64(b, 0)) : null;
                    var f = FraRegel(regel, "Kjørt før", $"Kjørt før: {prog}{(t is { } n ? $" · sist {Nar(n, "BAM i Windows")}" : "")} · konto {Konto(sid)}");
                    f.Bruk ??= "Brukt før.";
                    f.Merk(Tilstand.BruktFor);
                    if (t != null) f.Tidspunkt(t, t);
                }
            }
            break;
        }
        if (lest > 0) Tilgangslogg.Logg("Register", @"HKLM\SYSTEM\CurrentControlSet\Services\bam", Utfall.Lest, $"{lest} programmer med siste kjøretid");
    }

    private static string Konto(string sid)
    {
        try { return new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value; }
        catch { return sid; }
    }

    // ---------- Amcache ----------

    /// <summary>
    /// Amcache.hve: Windows' liste over programfiler og programmer som har vært på PC-en, med sti, versjon, utgiver og SHA-1.
    /// Holdes låst av Windows, så den leses rett fra disken som administrator.
    /// </summary>
    private void Amcache()
    {
        var sti = Utvid(@"%SystemRoot%\appcompat\Programs\Amcache.hve");
        if (!File.Exists(sti)) { Tilgangslogg.Logg("Fil", sti, Utfall.IkkeFunnet); return; }
        byte[] bytes;
        try
        {
            using var fs = Admintilgang.AapneLes(sti);
            if (fs.Length > 512L * 1024 * 1024) { Tilgangslogg.Logg("Fil", sti, Utfall.HoppetOver, "større enn 512 MB"); return; }
            bytes = new byte[fs.Length];
            int lest = 0;
            while (lest < bytes.Length) { int r = fs.Read(bytes, lest, bytes.Length - lest); if (r <= 0) break; lest += r; }
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return; }
        int antall = LesAmcache(bytes);
        Tilgangslogg.Logg("Fil", sti, antall >= 0 ? Utfall.Lest : Utfall.Feil,
            antall >= 0 ? $"{antall} programfiler og programmer; transaksjonsloggene leses ikke, så de siste minuttene kan mangle" : "ukjent format");
    }

    internal List<Funn> FunnHittil() { lock (_funn) return _funn.Values.ToList(); }

    /// <summary>Leser Amcache-bytene. Returnerer antall oppføringer, eller -1 når fila ikke er en registerfil.</summary>
    internal int LesAmcache(byte[] bytes)
    {
        var hive = Hive.Fra(bytes);
        var rot = hive?.Rot;
        if (hive == null || rot == null) return -1;
        int antall = 0;
        var root = hive.Finn(rot, "Root") ?? rot;
        if (hive.Finn(root, "InventoryApplicationFile") is { } filer)
            foreach (var k in hive.Under(filer))
            {
                antall++;
                var v = hive.Verdier(k);
                v.TryGetValue("LowerCaseLongPath", out var sti);
                v.TryGetValue("Name", out var navn);
                v.TryGetValue("ProductName", out var produkt);
                var regel = FinnRegel($"{navn} {produkt} {sti}");
                if (regel == null) continue;
                var versjon = v.TryGetValue("Version", out var ver) && ver.Length > 0 ? ver : v.TryGetValue("BinFileVersion", out ver) ? ver : null;
                var sha = v.TryGetValue("FileId", out var id) && id.Length == 44 ? id.Substring(4) : null;
                var f = FraRegel(regel, "Windows' programhistorikk (Amcache)",
                    $"Amcache: {sti ?? navn}{(versjon != null ? $" · versjon {versjon}" : "")}{(v.TryGetValue("Publisher", out var utg) && utg.Length > 0 ? $" · {utg}" : "")}"
                    + $"{(sha != null ? $" · SHA-1 {sha}" : "")}{(k.Endret > DateTime.MinValue ? $" · registrert {Nar(k.Endret, "Amcache")}" : "")}");
                f.SettVersjon(versjon, "Amcache");
                f.Bruk ??= "Har vært på PC-en.";
            }
        if (hive.Finn(root, "InventoryApplication") is { } apper)
            foreach (var k in hive.Under(apper))
            {
                antall++;
                var v = hive.Verdier(k);
                v.TryGetValue("Name", out var navn);
                v.TryGetValue("RootDirPath", out var mappe);
                var regel = FinnRegel($"{navn} {mappe}");
                if (regel == null) continue;
                v.TryGetValue("Version", out var versjon);
                var f = FraRegel(regel, "Windows' programhistorikk (Amcache)",
                    $"Amcache: program {navn}{(string.IsNullOrEmpty(versjon) ? "" : $" {versjon}")}{(string.IsNullOrEmpty(mappe) ? "" : $" i {mappe}")}"
                    + $"{(v.TryGetValue("InstallDate", out var dato) && dato.Length > 0 ? $" · installert {dato}" : "")}");
                f.SettVersjon(versjon, "Amcache");
                f.Bruk ??= "Har vært på PC-en.";
            }
        return antall;
    }

    // ---------- Oppgavelageret ----------

    /// <summary>Siste kjøretid for en planlagt oppgave, fra oppgavelageret i registeret (TaskCache).</summary>
    private static DateTime? OppgaveSistKjort(string oppgave)
    {
        if (!Plattform.ErWindows) return null;
        try
        {
            const string rot = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
            using var tre = Registry.LocalMachine.OpenSubKey($@"{rot}\Tree\{oppgave}");
            if (tre?.GetValue("Id") is not string id) return null;
            using var t = Registry.LocalMachine.OpenSubKey($@"{rot}\Tasks\{id}");
            return t?.GetValue("DynamicInfo") is byte[] b && b.Length >= 20 ? Filtid(BitConverter.ToInt64(b, 12)) : null;
        }
        catch { return null; }
    }

    // ---------- Hendelseslogger ----------

    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr EvtQuery(IntPtr okt, string sti, string sporring, int flagg);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtNext(IntPtr resultat, int antall, [Out] IntPtr[] hendelser, int ventetid, int flagg, out int fikk);

    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool EvtRender(IntPtr kontekst, IntPtr hendelse, int flagg, int lengde, [Out] char[]? buffer, out int brukt, out int egenskaper);

    [DllImport("wevtapi.dll")]
    private static extern bool EvtClose(IntPtr h);

    private static readonly Regex HendelseData = new(@"<Data Name=['""](\w+)['""]>([^<]*)</Data>", RegexOptions.Compiled);
    private static readonly Regex HendelseTid = new(@"SystemTime=['""]([^'""]+)['""]", RegexOptions.Compiled);

    /// <summary>
    /// Leser hendelser fra én logg, nyeste først, i høyst <paramref name="frist"/>. Hver hendelse gis som feltene i den.
    /// Returnerer antall lest, eller null når loggen ikke finnes eller Windows nekter.
    /// </summary>
    private static int? Hendelser(string logg, string sporring, int maks, TimeSpan frist, Action<Dictionary<string, string>, DateTime> hver, out int feil)
    {
        feil = 0;
        var q = EvtQuery(IntPtr.Zero, logg, sporring, 0x1 | 0x200);
        if (q == IntPtr.Zero) { feil = Marshal.GetLastWin32Error(); return null; }
        int antall = 0;
        var klokke = System.Diagnostics.Stopwatch.StartNew();
        var h = new IntPtr[64];
        char[] buf = new char[16384];
        try
        {
            while (antall < maks && klokke.Elapsed < frist && EvtNext(q, h.Length, h, 1000, 0, out var fikk) && fikk > 0)
                for (int i = 0; i < fikk; i++)
                {
                    try
                    {
                        if (!EvtRender(IntPtr.Zero, h[i], 1, buf.Length * 2, buf, out var brukt, out _))
                        {
                            if (Marshal.GetLastWin32Error() != 122 || brukt <= 0) continue;
                            buf = new char[brukt / 2 + 1];
                            if (!EvtRender(IntPtr.Zero, h[i], 1, buf.Length * 2, buf, out brukt, out _)) continue;
                        }
                        var xml = new string(buf, 0, Math.Max(0, brukt / 2 - 1));
                        var felt = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        foreach (Match m in HendelseData.Matches(xml)) felt[m.Groups[1].Value] = WebUtility.HtmlDecode(m.Groups[2].Value);
                        var pid = Regex.Match(xml, @"<Execution ProcessID=['""](\d+)");
                        if (pid.Success) felt["_pid"] = pid.Groups[1].Value;
                        var tm = HendelseTid.Match(xml);
                        var tid = tm.Success && DateTime.TryParse(tm.Groups[1].Value, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t.ToLocalTime() : DateTime.MinValue;
                        antall++;
                        hver(felt, tid);
                    }
                    finally { EvtClose(h[i]); }
                }
        }
        finally { EvtClose(q); }
        return antall;
    }

    private static string? Felt(Dictionary<string, string> d, string navn) => d.TryGetValue(navn, out var v) ? v : null;

    private const string Siste30Dager = "TimeCreated[timediff(@SystemTime) <= 2592000000]";

    private void Hendelseslogger()
    {
        var frist = Fullt ? TimeSpan.FromSeconds(30) : TimeSpan.FromSeconds(6);
        int maks = Fullt ? 200000 : 30000;
        bool linjer = Kommandolinje.Tillatt(_regler, out _);

        // Programstarter: Security 4688 og Sysmon 1. Samme program telles én gang, med siste tid.
        var starter = new Dictionary<string, (string Exe, DateTime Sist, int Antall, string? Konto)>(StringComparer.OrdinalIgnoreCase);
        var tolket = new HashSet<string>(StringComparer.Ordinal);
        void Start(string? exe, string? linje, DateTime tid, string? konto, string kilde)
        {
            if (string.IsNullOrEmpty(exe)) return;
            var prosess = Path.GetFileNameWithoutExtension(exe);
            if (Kommandolinje.ErTolk(prosess))
            {
                // Tolkere: kommandolinjen vurderes i minnet (samme regler som for prosesser som kjører nå)
                if (linjer && !string.IsNullOrEmpty(linje) && tolket.Add(linje!)) Vurder(prosess, exe, 0, linje!, null, tid, kilde);
                return;
            }
            if (FinnRegel(exe) == null) return;
            starter[exe!] = starter.TryGetValue(exe!, out var s)
                ? (exe!, s.Sist > tid ? s.Sist : tid, s.Antall + 1, s.Konto ?? konto)
                : (exe!, tid, 1, konto);
            if (linjer && !string.IsNullOrEmpty(linje) && tolket.Add(linje!) && FinnRegel(exe) is { } r)
            {
                Funn? ai;
                lock (_funn) _funn.TryGetValue(r.Navn, out ai);
                Vurder(prosess, exe, 0, linje!, ai ?? FraRegel(r, "Kjørt før", $"Kjørt før: {exe}"), tid, kilde);
            }
        }
        Logglest("Security", $"*[System[(EventID=4688) and {Siste30Dager}]]", "hendelse 4688 (programstart)", maks, frist,
            (d, t) => Start(Felt(d, "NewProcessName"), Felt(d, "CommandLine"), t, Felt(d, "SubjectUserName"), "hendelse 4688 i Windows"));
        Logglest("Microsoft-Windows-Sysmon/Operational", $"*[System[(EventID=1 or EventID=22) and {Siste30Dager}]]", "Sysmon 1 og 22 (programstart og DNS)", maks, frist, (d, t) =>
        {
            if (d.ContainsKey("QueryName")) DnsHendelse(d["QueryName"], Felt(d, "Image"), t, "Sysmon");
            else Start(Felt(d, "Image"), Felt(d, "CommandLine"), t, Felt(d, "User"), "Sysmon i Windows");
        });
        Logglest("Microsoft-Windows-DNS-Client/Operational", $"*[System[(EventID=3008) and {Siste30Dager}]]", "DNS-loggen (oppslag)", maks, frist,
            (d, t) => DnsHendelse(Felt(d, "QueryName"), null, t, "DNS-loggen i Windows"));

        foreach (var (exe, sist, antall, konto) in starter.Values)
        {
            var r = FinnRegel(exe);
            if (r == null) continue;
            var f = FraRegel(r, "Kjørt før", $"Startet: {exe} · sist {Nar(sist, "hendelsesloggen i Windows")} · {antall} {(antall == 1 ? "gang" : "ganger")} siste 30 dager{(konto != null ? $" · konto {konto}" : "")}");
            f.Bruk ??= "Brukt før.";
            f.Merk(Tilstand.BruktFor);
            f.Tidspunkt(null, sist);
        }
    }

    private void Logglest(string logg, string sporring, string hva, int maks, TimeSpan frist, Action<Dictionary<string, string>, DateTime> hver)
    {
        var lest = Hendelser(logg, sporring, maks, frist, hver, out var feil);
        if (lest == null)
            Tilgangslogg.Logg("Hendelseslogg", logg, feil is 5 ? Utfall.Nektet : feil is 15007 or 2 ? Utfall.IkkeFunnet : Utfall.Feil,
                feil is 5 ? "krever administrator" : feil is 15007 or 2 ? "loggen finnes ikke på denne PC-en (ikke installert)" : $"Windows-feil {feil}");
        else
            Tilgangslogg.Logg("Hendelseslogg", logg, Utfall.Lest,
                lest == 0 ? $"{hva}: ingen hendelser siste 30 dager (loggen er av eller tom)" : $"{hva}: {lest} hendelser siste 30 dager{(lest >= maks ? $", de {maks} nyeste" : "")}; bare programnavn, tid og AI-navn brukes");
    }

    private readonly object _dnsLaas = new();

    private void DnsHendelse(string? navn, string? exe, DateTime tid, string kilde)
    {
        if (string.IsNullOrEmpty(navn) || Tjeneste(navn!.TrimEnd('.')) is not { } tj) return;
        navn = navn.TrimEnd('.');
        var prosess = exe == null ? null : Path.GetFileNameWithoutExtension(exe);
        lock (_dnsLaas)
        {
            if (prosess != null && !Nettleserprosesser.ContainsKey(prosess) && !string.Equals(Path.GetFileName(exe), "AISkanner.exe", StringComparison.OrdinalIgnoreCase))
            {
                var f = FunnForProsess(prosess, exe) ?? LeggTil($"Program som har kontaktet AI: {Path.GetFileName(exe)}", "Skygge-AI", Risiko.Rod,
                    "Et program som ikke er en nettleser, har slått opp navnet til en AI-tjeneste. Windows har registrert det.", "Kjørt før", null,
                    enkelt: "Program som har kontaktet AI");
                f.Detalj($"{exe} slo opp {navn} ({tj.Navn}) · {Nar(tid, kilde)}");
                f.Bruk ??= "Brukt før.";
                f.Merk(Tilstand.BruktFor);
                f.Tidspunkt(null, tid);
                return;
            }
            if (!_regler.AiTjenester.Contains(tj))
            {
                var f = LeggTil(tj.Navn, "Nettleser-AI (nettsted)", RisikoTekst.Fra(tj.Risiko), tj.Hvorfor, prosess != null ? Nettleserprosesser[prosess] : "Windows", null, enkelt: tj.Enkelt);
                f.Privat = true;
                f.Bruk ??= "Åpnet før.";
                f.Merk(Tilstand.BruktFor);
                f.Land ??= tj.Land;
                f.OpprinnelseLand ??= tj.Land;
                f.Detalj($"Slått opp: {navn} · {Nar(tid, kilde)}");
                f.Tidspunkt(null, tid);
            }
            else
            {
                var f = LeggTil("AI-tjenester kontaktet nylig", "Skygge-AI", RisikoTekst.Hoyeste(RisikoTekst.Fra(tj.Risiko), Risiko.Gul),
                    "Et program på PC-en har nylig snakket med AI-tjenester. Windows forteller ikke hvilket program, bare at navnet ble slått opp.",
                    "Windows", null, enkelt: "AI-tjenester kontaktet");
                f.Detalj($"Slått opp: {navn} ({tj.Navn}{(tj.Land != null ? ", " + IpLand.Navn(tj.Land) : "")}) · {Nar(tid, kilde)}");
                if (tj.Land != null && !f.SenderTil.Contains(tj.Land)) f.SenderTil.Add(tj.Land);
                f.Tidspunkt(null, tid);
            }
        }
    }
}
