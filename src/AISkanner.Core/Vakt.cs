using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Vakt: følger AI-agentene mens vinduet er åpent og ser etter angrep som pågår, sett utenfra.
/// Hva agentene starter (prosesser), hvilke hemmelighetsfiler de åpner, hvor de kobler seg til og hva som endres i oppsettet deres.
/// Kilder: Windows' egne hendelser (ETW Kernel-Process, Kernel-File, Kernel-Network, DNS-Client) som administrator,
/// ellers prosesslista hvert halve sekund og varsler om endrede filer. Bare lesing og bare i minnet: ingen prompt, ingen
/// innhold i filer eller pakker, ikke minnet til andre prosesser. Kommandolinjen til programmer agenten starter sammenlignes
/// med reglene og kastes; den vises aldri, bare regelen som slo til.
/// Regler: ATR (Agent Threat Rules), SigmaHQ og MITRE ATLAS, med kilde per regel.
/// </summary>
public sealed class Vakt : IDisposable
{
    public sealed record Hendelse(DateTime Tid, string Regel, string Kilde, string Agent, int AgentPid, string Program, int Pid, string? Hva, bool Rod);

    // ---------- Reglene ----------

    private const RegexOptions Ri = RegexOptions.IgnoreCase | RegexOptions.Compiled;

    /// <summary>Kommandoer agenten starter (verktøykallet sett utenfra). Navn, mønster, kilde.</summary>
    internal static readonly (string Navn, Regex Monster, string Kilde)[] Kommandoregler =
    {
        ("lager planlagt oppgave eller autostart", new(@"\bschtasks(\.exe)?\s+/create\b|\breg(\.exe)?\s+add\s+\S*\\(Run|RunOnce)\b|Register-ScheduledTask|New-ScheduledTask|\\Start Menu\\Programs\\Startup\\", Ri),
            "ATR-2026-00064 (tool_args) · ATLAS AML.T0142"),
        ("lager bruker eller svekker vernet", new(@"\bnet(\.exe)?\s+user\s+\S+\s+\S+\s+/add\b|\bnet(\.exe)?\s+localgroup\s+administrat\w*\s+\S+\s+/add|New-LocalUser|netsh(\.exe)?\s+(advfirewall|firewall)\s+\S*\s*(add|set|disable)|Set-MpPreference\s+[^\r\n]*-Disable|Add-MpPreference\s+[^\r\n]*-Exclusion", Ri),
            "ATR-2026-00064 (tool_args) · ATLAS AML.T0053"),
        ("skjult eller kodet PowerShell", new(@"\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\s-w(indowstyle)?\s+hidden\b|\biex\b[^\r\n]*(downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod)|(iwr|irm|invoke-webrequest|invoke-restmethod)[^|\r\n]*\|\s*iex\b", Ri),
            "SigmaHQ proc_creation_win_powershell_encoded_cmd · ATLAS AML.T0050"),
        ("laster ned med Windows-verktøy", new(@"\bcertutil(\.exe)?\s+[^\r\n]*-(urlcache|decode)\b|\bbitsadmin(\.exe)?\s+[^\r\n]*/transfer\b|\bmshta(\.exe)?\s+https?:|\brundll32(\.exe)?\s+[^\r\n]*javascript:|\bregsvr32(\.exe)?\s+[^\r\n]*/i:https?:", Ri),
            "SigmaHQ (LOLBAS: certutil, bitsadmin, mshta, regsvr32) · ATLAS AML.T0050"),
        ("henter Windows' passordlager", new(@"\breg(\.exe)?\s+save\s+hklm\\(sam|security|system)\b|\bvssadmin(\.exe)?\s+create\s+shadow|\bntdsutil\b|comsvcs(\.dll)?[^\r\n]*minidump|\bprocdump[^\r\n]*lsass|\bcmdkey(\.exe)?\s+/list", Ri),
            "SigmaHQ (credential dumping) · ATLAS AML.T0090"),
        ("sletter spor", new(@"\bwevtutil(\.exe)?\s+cl\b|Clear-EventLog|\bvssadmin(\.exe)?\s+delete\s+shadows|\bfsutil(\.exe)?\s+usn\s+deletejournal|\bwbadmin(\.exe)?\s+delete\s+catalog", Ri),
            "SigmaHQ (indicator removal) · ATLAS AML.T0138"),
        ("sletter alt i en mappe", new(@"\b(rd|rmdir)\s+/s\s+/q\s+[""']?([a-z]:\\?[""']?\s*$|%userprofile%|%homepath%|c:\\users\\[^\\\s]+\\?[""']?\s*$)|Remove-Item\s+[^\r\n]*(-Recurse[^\r\n]*-Force|-Force[^\r\n]*-Recurse)[^\r\n]*\s([a-z]:\\\*?|~|\$HOME|\$env:USERPROFILE)[""']?\s*$|\bformat(\.com)?\s+[a-z]:|\bcipher(\.exe)?\s+/w:", Ri),
            "ATR-2026-00716 · ATLAS AML.T0101"),
        ("sender filer ut", new(@"\bcurl(\.exe)?[^\r\n]*(\s-T\s|--upload-file|\s-F\s+\S*=@|--data-binary\s+@)|Invoke-(WebRequest|RestMethod)\s+[^\r\n]*-InFile\b|\brclone(\.exe)?\s+(copy|sync|move)\b", Ri),
            "ATR-2026-02261 · ATLAS AML.T0086"),
        ("kobler et skall til nettet", new(@"\bnc(at)?(\.exe)?\s+[^\r\n]*\s-e\s|Net\.Sockets\.TCPClient[^\r\n]*(GetStream|StreamReader)", Ri),
            "ATR-2026-02600 · ATLAS AML.T0072"),
    };

    private static readonly Regex RaIp = new(@"\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|certutil|bitsadmin|mshta)\b[^\r\n]*https?://(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}", Ri);

    /// <summary>Hemmelighetsfiler. Sti-bit (små bokstaver), navn, kilde, og programmer som har lov å åpne dem.</summary>
    internal static readonly (string[] Biter, string Navn, string Kilde, string[] Lov)[] Hemmeligheter =
    {
        (new[] { @"\.ssh\id_" }, "SSH-nøkkel", "ATLAS AML.T0055", new[] { "ssh", "ssh-agent", "ssh-add", "scp", "sftp", "git", "git-remote-https", "git-remote-ssh" }),
        (new[] { @"\.aws\credentials" }, "AWS-nøkler", "ATLAS AML.T0055", new[] { "aws" }),
        (new[] { @"\.kube\config" }, "Kubernetes-tilgang", "ATLAS AML.T0055", new[] { "kubectl", "helm", "k9s" }),
        (new[] { @"\.docker\config.json" }, "Docker-innlogging", "ATLAS AML.T0055", new[] { "docker", "docker-credential-desktop", "docker-credential-wincred" }),
        (new[] { @"\.git-credentials" }, "Git-passord", "ATLAS AML.T0055", new[] { "git", "git-credential-store", "git-credential-manager" }),
        (new[] { @"\microsoft\credentials\", @"\microsoft\protect\", @"\microsoft\vault\" }, "Windows' passordlager", "ATLAS AML.T0090", Array.Empty<string>()),
        (new[] { @"\windows\system32\config\sam", @"\windows\system32\config\security", @"\ntds\ntds.dit" }, "Windows' kontodatabase", "ATLAS AML.T0090", Array.Empty<string>()),
        (new[] { @"\login data", @"\network\cookies", @"\local state", @"\logins.json", @"\key4.db", @"\cookies.sqlite" }, "nettleserens passord eller innlogging", "ATLAS AML.T0113 · AML.T0055",
            new[] { "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "msedgewebview2", "comet" }),
        (new[] { @"\wallet.dat", @"\exodus\exodus.wallet", @"\electrum\wallets\", @"\ethereum\keystore\", @"nkbihfbeogaeaoehlefnkodbefgpgknn" }, "kryptolommebok", "ATR-2026-02261 · ATLAS AML.T0055", Array.Empty<string>()),
        (new[] { @"\.claude\.credentials.json", @"\.codex\auth.json", @"\.gemini\oauth_creds.json", @"\github cli\hosts.yml", @"\.config\gh\hosts.yml", @"\.hermes\auth.json" }, "innlogging for AI-agenter eller GitHub", "ATLAS AML.T0083 · AML.T0098",
            new[] { "gh", "git-credential-manager" }),
    };

    /// <summary>Uttakstjenester: brukes til å ta ut data og sjelden av vanlige verktøy.</summary>
    internal static readonly string[] Uttak =
    {
        "webhook.site", "pipedream.net", "requestbin.com", "requestbin.net", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "transfer.sh",
        "pastebin.com", "paste.ee", "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "burpcollaborator.net", "glot.io", "file.io", "0x0.st", "temp.sh",
    };

    /// <summary>Filer i agentoppsett som Vakt følger med på.</summary>
    internal static readonly string[] Oppsettfiler =
    {
        "settings.json", "settings.local.json", ".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json", "config.toml", "CLAUDE.md", "AGENTS.md", "GEMINI.md", "SKILL.md",
    };

    private static readonly HashSet<string> Skall = new(StringComparer.OrdinalIgnoreCase)
        { "powershell", "pwsh", "cmd", "curl", "wget", "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "nc", "ncat", "wscript", "cscript", "bash", "sh" };

    // ---------- Tilstand (bare i minnet) ----------

    private readonly Skanner _s;
    private readonly bool _linjer;
    private EtwOkt? _etw;
    private Timer? _poll;
    private readonly List<FileSystemWatcher> _fsw = new();
    private readonly object _las = new();
    private readonly Dictionary<int, (int Rot, string Agent)> _tre = new();
    private readonly Dictionary<int, (string Navn, string? Sti)> _prog = new();
    private readonly Dictionary<int, Queue<DateTime>> _starter = new();
    private readonly HashSet<int> _mangeVarslet = new();
    private readonly HashSet<IPAddress> _navngitt = new();
    private readonly Dictionary<string, (int Pid, DateTime Tid)> _sisteSkriving = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Hendelse> _hendelser = new();
    private readonly HashSet<string> _sett = new();
    private HashSet<int> _kjente = new();

    public string Status { get; private set; } = "ikke startet";
    public bool Etw => _etw != null;
    public DateTime Startet { get; } = DateTime.Now;
    /// <summary>Antall programstarter fra agentene som er sett.</summary>
    public long Starter;

    private static readonly Guid Prosess = new("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"), Fil = new("EDD08927-9CC4-4E65-B970-C2560FB5C289"),
        Nett = new("7DD42A49-5329-4832-8DFD-43D979153A88"), Dns = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    internal Vakt(Skanner s, bool linjer) { _s = s; _linjer = linjer; }

    /// <summary>Starter vakten. Som administrator med Windows' hendelser, ellers prosesslista hvert halve sekund.</summary>
    public static Vakt Start(Skanner s, bool linjer, IEnumerable<string> prosjektmapper)
    {
        var v = new Vakt(s, linjer);
        foreach (var (pid, (forelder, exe)) in Prosesstre.Liste()) v.NyProsess(pid, forelder, exe, null, logg: false);
        v._etw = EtwOkt.Start("AISkanner-Vakt", new[] { (Prosess, 0x10UL), (Fil, 0x80UL | 0x1000UL), (Nett, 0x10UL | 0x20UL), (Dns, ulong.MaxValue) },
            (k, id) => k == Prosess ? id == 1 : k == Fil ? id is 12 or 30 : k == Nett ? id is 12 or 28 : id == 3008, v.Ta, out var grunn);
        if (v._etw == null)
        {
            v._kjente = new HashSet<int>(Prosesstre.Liste().Keys);
            v._poll = new Timer(_ => v.Poll(), null, 500, 500);
        }
        v.Status = v._etw != null ? "Windows' hendelser i sanntid (prosesser, filer, nett, DNS)" : $"prosesslista hvert halve sekund; filer og nett {grunn}";
        Tilgangslogg.Logg("Vakt", "AI-agentenes prosesser, filer, nett og oppsett (live)", Utfall.Lest, v.Status + "; bare i minnet, aldri innhold");
        v.Folg(prosjektmapper);
        return v;
    }

    public List<Hendelse> Hendelser() { lock (_las) return _hendelser.ToList(); }
    public List<(int Pid, string Agent)> Agenter() { lock (_las) return _tre.Where(x => x.Key == x.Value.Rot).Select(x => (x.Key, x.Value.Agent)).ToList(); }

    // ---------- Hvem er en AI-agent ----------

    internal static bool ErAgent(Produkt p) => p.Kategori == "Skygge-AI (agent)" || p.Navn.Contains("skrivebordsapp");

    /// <summary>Agenten bak et program: produktregelen på sti, og for tolkere (node, python) på kommandolinjen.</summary>
    private string? Agent(int pid, string navn, string? sti)
    {
        if (_s.FinnRegel(sti ?? navn) is { } r && ErAgent(r)) return r.Navn;
        if (_linjer && Kommandolinje.ErTolk(navn) && Kommandolinje.Les(pid) is { } l && _s.FinnRegel(l) is { } r2 && ErAgent(r2)) return r2.Navn;
        return null;
    }

    internal void NyProsess(int pid, int forelder, string exe, DateTime? tid, bool logg = true)
    {
        if (pid <= 4 || Plattform.ErEgen(pid)) return;
        var navn = Kort(exe);
        var sti = exe.Contains('\\') ? exe : null;
        string? agent; int rot;
        lock (_las)
        {
            _prog[pid] = (navn, sti);
            if (_tre.TryGetValue(forelder, out var f)) { rot = f.Rot; agent = f.Agent; _tre[pid] = (rot, agent); }
            else { agent = null; rot = pid; }
        }
        if (agent == null)
        {
            if ((agent = Agent(pid, navn, sti)) != null) lock (_las) _tre[pid] = (pid, agent);
            return;
        }
        if (!logg) return;
        var naa = tid ?? DateTime.Now;
        Interlocked.Increment(ref Starter);
        // V2: løpsk agent
        lock (_las)
        {
            if (!_starter.TryGetValue(rot, out var q)) _starter[rot] = q = new Queue<DateTime>();
            q.Enqueue(naa);
            while (q.Count > 0 && naa - q.Peek() > TimeSpan.FromMinutes(1)) q.Dequeue();
            if (q.Count >= 150 && _mangeVarslet.Add(rot))
                Legg(new Hendelse(naa, "startet minst 150 programmer på ett minutt", "ATR excessive-autonomy · ATLAS AML.T0034", agent, rot, navn, pid, null, false));
        }
        // V1: hva agenten startet. Kommandolinjen leses nå, mens programmet kjører, sammenlignes og kastes.
        var linje = _linjer ? Kommandolinje.Les(pid) : null;
        if (linje == null) return;
        foreach (var (regel, m, kilde) in Kommandoregler)
            if (m.IsMatch(linje)) Legg(new Hendelse(naa, regel, kilde, agent, rot, sti ?? navn, pid, null, true));
        if (RaIp.Match(linje) is { Success: true } x && Offentlig(int.Parse(x.Groups[2].Value), int.Parse(x.Groups[3].Value)))
            Legg(new Hendelse(naa, "henter fra en IP-adresse uten navn", "ATR-2026-00220 · ATLAS AML.T0072", agent, rot, sti ?? navn, pid, null, true));
        if (Skanner.ErSkillsAdd(linje))
            Legg(new Hendelse(naa, "legger til ferdigheter (npx skills add)", "SigmaHQ proc_creation_win_node_new_agent_skills_installed · ATLAS AML.T0104", agent, rot, sti ?? navn, pid, null, false));
    }

    // Programnavn uten mappe og .exe (Windows-sti, også når kontrollen kjører utenfor Windows)
    private static string Kort(string sti) => Path.GetFileNameWithoutExtension(sti.Replace('\\', '/'));

    private static bool Offentlig(int a, int b) =>
        !(a is 0 or 10 or 127 or > 223 || (a == 169 && b == 254) || (a == 172 && b is >= 16 and <= 31) || (a == 192 && b == 168) || (a == 100 && b is >= 64 and <= 127));

    private (int Rot, string Agent)? I(int pid) { lock (_las) return _tre.TryGetValue(pid, out var t) ? t : null; }
    private string Navn(int pid) { lock (_las) return _prog.TryGetValue(pid, out var p) ? p.Sti ?? p.Navn : $"PID {pid}"; }

    private void Legg(Hendelse h)
    {
        lock (_las)
        {
            // Samme regel for samme program og samme mål telles én gang
            if (!_sett.Add($"{h.Regel}|{h.Program}|{h.Hva}|{h.AgentPid}") || _hendelser.Count >= 500) return;
            _hendelser.Add(h);
        }
    }

    // ---------- Windows' hendelser ----------

    /// <summary>Hendelser mottatt per kilde (prosess, fil, nett, DNS) og siste programbilde, for vakttesten.</summary>
    public readonly long[] Mottatt = new long[4];
    public string? SisteBilde;

    private void Ta(EtwOkt.Hendelse h)
    {
        Interlocked.Increment(ref Mottatt[h.Kilde == Prosess ? 0 : h.Kilde == Fil ? 1 : h.Kilde == Nett ? 2 : 3]);
        try
        {
            if (h.Kilde == Prosess) Prosesstart(h);
            else if (h.Kilde == Fil) Filapning(h);
            else if (h.Kilde == Nett) Tilkobling(h);
            else Dnsoppslag(h);
        }
        catch (Exception x) when (x is ArgumentException or IndexOutOfRangeException or FormatException) { }
    }

    // Kernel-Process 1: ProcessID, CreateTime, ParentProcessID, SessionID, (Flags fra versjon 1), ImageName
    internal void Prosesstart(EtwOkt.Hendelse h)
    {
        var d = h.Data;
        if (d.Length < 24) return;
        int pid = BitConverter.ToInt32(d, 0), forelder = BitConverter.ToInt32(d, 12);
        int o = h.Versjon >= 1 ? 24 : 20;
        var bilde = Admintilgang.TilDos(EtwOkt.Tekst(d, ref o));
        SisteBilde = bilde;
        NyProsess(pid, forelder, bilde, DateTime.Now);
    }

    // Kernel-File 12/30: Irp, FileObject (pekere), IssuingThreadId, CreateOptions, CreateAttributes, ShareAccess, FileName
    internal void Filapning(EtwOkt.Hendelse h)
    {
        int o = (h.Peker32 ? 8 : 16) + 16;
        if (h.Data.Length <= o) return;
        var t = I(h.Pid);
        string? navn = null;
        // V5: hvem som skrev i et agentoppsett (brukes når filvarselet kommer)
        var d = h.Data;
        var opsjoner = BitConverter.ToInt32(d, o - 12);
        int disposisjon = (opsjoner >> 24) & 0xFF;   // 0 supersede, 2 create, 3 open_if, 4 overwrite, 5 overwrite_if
        if (t == null && disposisjon is 1) return;
        navn = EtwOkt.Tekst(d, ref o);
        var liten = navn.ToLowerInvariant();
        if (disposisjon != 1 && Oppsettfiler.Any(f => liten.EndsWith("\\" + f.ToLowerInvariant())))
            lock (_las) _sisteSkriving[Admintilgang.TilDos(navn)] = (h.Pid, DateTime.Now);
        if (t is not { } a) return;
        // V4: agentens prosesstre åpner en hemmelighetsfil
        foreach (var (biter, hva, kilde, lov) in Hemmeligheter)
        {
            if (!biter.Any(b => liten.Contains(b))) continue;
            var prog = Navn(h.Pid);
            var kort = Kort(prog);
            if (lov.Contains(kort, StringComparer.OrdinalIgnoreCase)) return;
            // Agenten selv med sin egen innlogging er vanlig bruk
            if (hva.StartsWith("innlogging for AI") && h.Pid == a.Rot) return;
            Legg(new Hendelse(DateTime.Now, $"åpnet {hva}", kilde, a.Agent, a.Rot, prog, h.Pid, Admintilgang.TilDos(navn), true));
            return;
        }
    }

    // Kernel-Network 12/28 (TCP connect): samme oppsett som UDP 42/58 (PID, størrelse, til, fra, porter)
    internal void Tilkobling(EtwOkt.Hendelse h)
    {
        if (NettEtw.Tolk(h.Id == 12 ? 42 : 58, h.Data) is not { } k || I(k.Pid) is not { } a) return;
        var ip = k.A1;
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return;
        var b = ip.GetAddressBytes();
        if (b.Length == 4 && !Offentlig(b[0], b[1])) return;
        if (b.Length == 16 && (b[0] & 0xFE) == 0xFC || b.Length == 16 && b[0] == 0xFE) return;
        bool navngitt; lock (_las) navngitt = _navngitt.Contains(ip);
        var prog = Navn(k.Pid);
        // V3: et skall eller nedlastingsverktøy fra agenten kobler til en adresse uten navn
        if (!navngitt && Skall.Contains(Kort(prog)))
            Legg(new Hendelse(DateTime.Now, "kobler til en IP-adresse uten navn", "ATR-2026-00225 · ATLAS AML.T0072", a.Agent, a.Rot, prog, k.Pid, $"{ip}:{k.P1}", true));
    }

    // DNS-Client 3008: QueryName, QueryType, QueryOptions, QueryStatus, QueryResults
    internal void Dnsoppslag(EtwOkt.Hendelse h)
    {
        int o = 0;
        var navn = EtwOkt.Tekst(h.Data, ref o).TrimEnd('.').ToLowerInvariant();
        o += 4 + 8 + 4;
        var svar = o < h.Data.Length ? EtwOkt.Tekst(h.Data, ref o) : "";
        lock (_las)
            foreach (var del in svar.Split(';'))
            {
                var x = del.Trim();
                if (x.StartsWith("::ffff:")) x = x.Substring(7);
                if (IPAddress.TryParse(x, out var ip)) _navngitt.Add(ip);
            }
        if (I(h.Pid) is not { } a) return;
        var treff = Uttak.FirstOrDefault(u => navn == u || navn.EndsWith("." + u))
                    ?? _s.Regelsett.IocDomener.Select(i => i.Domene).FirstOrDefault(u => navn == u || navn.EndsWith("." + u));
        if (treff != null)
            Legg(new Hendelse(DateTime.Now, "slår opp en uttakstjeneste eller et kjent misbruksdomene", "ATR-2026-00135 · ATLAS AML.T0086", a.Agent, a.Rot, Navn(h.Pid), h.Pid, navn, true));
    }

    // ---------- Uten administrator: prosesslista hvert halve sekund ----------

    private int _iPoll;
    private void Poll()
    {
        if (Interlocked.Exchange(ref _iPoll, 1) == 1) return;
        try
        {
            var liste = Prosesstre.Liste();
            foreach (var (pid, (forelder, exe)) in liste)
                if (!_kjente.Contains(pid))
                {
                    string sti = exe;
                    try { using var p = Process.GetProcessById(pid); sti = ProsessSti.Hent(p) ?? exe; } catch { }
                    NyProsess(pid, forelder, sti, DateTime.Now);
                }
            _kjente = new HashSet<int>(liste.Keys);
        }
        catch { }
        finally { Volatile.Write(ref _iPoll, 0); }
    }

    // ---------- V5: endringer i agentoppsett ----------

    private readonly HashSet<string> _fulgt = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Følger med på agentoppsett i mappene (V5). Mapper som allerede følges, hoppes over.</summary>
    public void Folg(IEnumerable<string> prosjektmapper)
    {
        var hjem = Skanner.Utvid("%USERPROFILE%");
        var mapper = new[] { ".claude", ".codex", ".gemini", ".cursor", ".agents", ".warp", ".hermes", ".openclaw" }.Select(d => Path.Combine(hjem, d))
            .Append(Skanner.Utvid(@"%APPDATA%\Claude")).Append(Skanner.Utvid(@"%APPDATA%\Code\User")).Append(Path.Combine(hjem, "Downloads"))
            .Concat(prosjektmapper).Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var m in mapper)
            try
            {
                lock (_fsw) if (_fulgt.Count >= 40 || !_fulgt.Add(m)) continue;
                var w = new FileSystemWatcher(m) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite };
                w.Changed += (_, e) => Endret(e.FullPath);
                w.Created += (_, e) => Endret(e.FullPath);
                w.Renamed += (_, e) => Endret(e.FullPath);
                w.EnableRaisingEvents = true;
                lock (_fsw) _fsw.Add(w);
            }
            catch { }
    }

    private void Endret(string sti)
    {
        var fil = Path.GetFileName(sti);
        if (!Oppsettfiler.Contains(fil, StringComparer.OrdinalIgnoreCase)) return;
        int pid = 0;
        lock (_las) if (_sisteSkriving.TryGetValue(sti, out var s) && DateTime.Now - s.Tid < TimeSpan.FromSeconds(5)) pid = s.Pid;
        var t = pid > 0 ? I(pid) : null;
        var prog = pid > 0 ? Navn(pid) : "ukjent (krever administrator)";
        // Rødt når en AI-agent eller noe den startet skriver i et agentoppsett (ATR-2026-00200/00429), eller fila kom i Nedlastinger
        bool ned = sti.IndexOf(@"\Downloads\", StringComparison.OrdinalIgnoreCase) >= 0;
        bool agentSkrev = t != null;
        Legg(new Hendelse(DateTime.Now, ned ? "instruksjonsfil for AI-agenter kom i Nedlastinger" : agentSkrev ? "AI-agent endret agentoppsett" : "agentoppsett endret",
            "ATR-2026-00200 · ATR-2026-00429 · ATLAS AML.T0081", t?.Agent ?? "", t?.Rot ?? 0, prog, pid, sti, ned || agentSkrev && !Path.GetFileName(prog).StartsWith(t!.Value.Agent.Split(' ')[0], StringComparison.OrdinalIgnoreCase)));
    }

    public void Dispose()
    {
        _etw?.Dispose(); _etw = null;
        _poll?.Dispose(); _poll = null;
        foreach (var w in _fsw) try { w.Dispose(); } catch { }
        _fsw.Clear();
    }
}
