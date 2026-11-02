using System.Net;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>Resultatet av én sjekk, vist som «Sjekket» i Funn. Nivå: -1 ikke sjekket, 0 sjekket uten funn, 1 funn, 2 funn med fare.</summary>
/// <summary>Linjer: det sjekken bygger på (vises når knappen trykkes i Funn).</summary>
public sealed record Sjekkstatus(string Navn, string Tekst, int Niva, IReadOnlyList<string>? Linjer = null);

public sealed partial class Skanner
{
    public List<Sjekkstatus> Sjekker { get; private set; } = new();
    private readonly List<string> _lytterLinjer = new();
    private int _apneAiPorter, _lyttereLest;

    /// <summary>
    /// Lyttende porter som hører til AI-servere (Ollama 11434, LM Studio 1234 …). Blir detalj på funnet for programmet;
    /// åpen mot nettet (0.0.0.0 eller ::) blir advarsel. Bare lesing av Windows' porttabeller, ingenting kobles til.
    /// </summary>
    internal void LyttendeAiPorter()
    {
        lock (_lytterLinjer) { _lytterLinjer.Clear(); _apneAiPorter = 0; _lyttereLest = 0; }
        if (!Plattform.ErWindows || TestNett != null) return;
        var sett = new Dictionary<(int, int, bool), (List<string> Adr, bool Apen)>();
        foreach (var (l, udp) in TcpTabell.Hent().Select(l => (l, false)).Concat(TcpTabell.UdpLyttere().Select(l => (l, true))))
        {
            if (l.Pid <= 4 || Plattform.ErEgen(l.Pid)) continue;
            var k = (l.Pid, l.Port, udp);
            var adr = l.Adresse.Equals(IPAddress.Any) ? "0.0.0.0" : l.Adresse.Equals(IPAddress.IPv6Any) ? "::" : l.Adresse.ToString();
            if (!sett.TryGetValue(k, out var x)) sett[k] = x = (new List<string>(), false);
            if (!x.Adr.Contains(adr)) x.Adr.Add(adr);
            sett[k] = (x.Adr, x.Apen || NettProtokoll.Apen(l.Adresse));
        }
        _lyttereLest = sett.Count;
        foreach (var ((pid, port, udp), (adr, apen)) in sett)
        {
            string navn; string? sti;
            try { using var p = System.Diagnostics.Process.GetProcessById(pid); navn = p.ProcessName; sti = ProsessSti.Hent(p); } catch { continue; }
            if (Nettleserprosesser.ContainsKey(navn)) continue;
            var f = FunnForProsess(navn, sti);
            if (!NettProtokoll.VisLytter(port, udp, navn, f != null)) continue;
            var hva = udp ? NettProtokoll.Udp(port) : NettProtokoll.AiPorter.TryGetValue(port, out var ap) ? $"standardport for {ap.Hva}" : $"port {port}";
            var linje = $"Lytter på {(udp ? "UDP" : "TCP")} {string.Join(", ", adr)} port {port} ({hva}) · {sti ?? navn} (PID {pid}) · {(apen ? "åpen mot nettet: kan nås fra andre maskiner" : "bare denne PC-en")}";
            lock (_lytterLinjer) { _lytterLinjer.Add(linje); if (apen) _apneAiPorter++; }
            if (f == null) continue;
            f.Detalj(linje);
            f.Merk(Tilstand.KjorerNa);
            if (apen) f.Advarsel($"AI-serveren lytter på alle nettverkskort (port {port}) og kan nås fra andre maskiner på nettet.");
        }
        Tilgangslogg.Logg("Port", "lyttende porter for AI-servere (TCP og UDP)", Utfall.Lest, $"{_lytterLinjer.Count} AI-porter, {_apneAiPorter} åpne mot nettet");
    }

    /// <summary>Skjermkort og NPU-er Windows kjenner (driverklassene i registeret): navn, leverandør og driverversjon.</summary>
    private static IEnumerable<string> Brikker()
    {
        var l = new List<string>();
        foreach (var (klasse, hva) in new[] { ("{4d36e968-e325-11ce-bfc1-08002be10318}", "Skjermkort (GPU)"), ("{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}", "NPU (AI-brikke)") })
        {
            var sti = $@"SYSTEM\CurrentControlSet\Control\Class\{klasse}";
            try
            {
                using var rot = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(sti);
                int n = 0;
                foreach (var navn in rot?.GetSubKeyNames() ?? Array.Empty<string>())
                {
                    if (navn.Length != 4 || !navn.All(char.IsDigit)) continue;
                    using var k = rot!.OpenSubKey(navn);
                    if (k?.GetValue("DriverDesc") is not string desc) continue;
                    n++;
                    l.Add($"{hva}: {desc} · {k.GetValue("ProviderName")} · driver {k.GetValue("DriverVersion")}");
                }
                if (n == 0) l.Add($"{hva}: ingen funnet");
                Tilgangslogg.Logg("Register", @"HKLM\" + sti, n > 0 ? Utfall.Lest : Utfall.IkkeFunnet, $"{hva}: {n}");
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { l.Add($"{hva}: kunne ikke leses ({e.GetType().Name})"); }
        }
        return l;
    }

    /// <summary>Én linje per sjekk som ellers bare synes i rapporten eller Datagrunnlag: hva den fant, eller at den ikke fant noe.</summary>
    internal void LagSjekker()
    {
        if (!Plattform.ErWindows)
        {
            Sjekker = new[] { "BIOS (WPBT)", "SRUM", "UDP/QUIC", "Lyttende AI-porter", "Docker", "WSL", "GPU/NPU" }.Select(n => new Sjekkstatus(n, "bare Windows", -1)).ToList();
            return;
        }
        var l = new List<Sjekkstatus>();
        var funn = _funn.Values.ToList();
        var logg = Logg.Oppforinger.ToList();
        bool Lest(string mal) => logg.Any(t => t.Utfall == Utfall.Lest && t.Mal.IndexOf(mal, StringComparison.OrdinalIgnoreCase) >= 0);
        List<string> fl; lock (Fastvarelinjer) fl = Fastvarelinjer.ToList();

        // Hver knapp viser det sjekken bygger på: funnene, linjene fra Windows eller grunnen til at den ikke ble lest
        static List<string> Linjer(IEnumerable<string> x) => x.Distinct().Take(500).ToList();
        List<string> FraFunn(Func<Funn, bool> hvilke, Func<Funn, IEnumerable<string>> linjer) =>
            Linjer(funn.Where(hvilke).SelectMany(f => linjer(f).Select(d => $"{f.Navn}: {d}")));
        List<string> Logget(string mal) => Linjer(logg.Where(t => t.Mal.IndexOf(mal, StringComparison.OrdinalIgnoreCase) >= 0)
            .Select(t => $"{t.Utfall}: {t.Mal}{(t.Detalj != null ? " · " + t.Detalj : "")}"));

        var wpbt = fl.FirstOrDefault(x => x.StartsWith("Fastvare (BIOS)", StringComparison.Ordinal));
        var wl = wpbt == null ? null : new[] { wpbt };
        l.Add(wpbt == null ? new("BIOS (WPBT)", "ikke lest", -1)
            : wpbt.Contains("ingen WPBT") ? new("BIOS (WPBT)", "ingen program fra BIOS", 0, wl)
            : new("BIOS (WPBT)", wpbt.Contains("AI-regel traff:") ? "BIOS starter et AI-program" : "BIOS starter et program (ikke AI)", wpbt.Contains("AI-regel traff:") ? 2 : 1, wl));
        var tj = fl.FirstOrDefault(x => x.StartsWith("Tjenester og drivere endret", StringComparison.Ordinal));
        if (tj != null)
        {
            var n = Regex.Match(tj, @"siste 7 dager: (\d+)").Groups[1].Value;
            List<string> tl; lock (Fastvarelinjer) tl = new[] { tj }.Concat(EndredeTjenester.OrderByDescending(x => x)).ToList();
            l.Add(tj.Contains("AI-regel traff:") ? new("Tjenester endret 7 d", $"{n} endret, AI-regel traff", 1, tl)
                : new("Tjenester endret 7 d", n.Length > 0 ? $"{n} endret, ingen AI" : "ingen endret", 0, tl));
        }
        var sl = Linjer((SrumStatus != null ? new[] { SrumStatus } : Array.Empty<string>()).Concat(FraFunn(f => f.Detaljer.Any(d => d.StartsWith("SRUM", StringComparison.Ordinal)), f => f.Detaljer.Where(d => d.StartsWith("SRUM", StringComparison.Ordinal)))).Concat(Logget("SRUDB")));
        l.Add(SrumStatus == null ? new("SRUM", Nettverk.ErAdmin() ? "ikke lest" : "krever administrator", -1, sl)
            : SrumStatus.StartsWith("SRUM: kunne ikke leses", StringComparison.Ordinal) || SrumStatus.StartsWith("SRUM: feil", StringComparison.Ordinal)
                ? new("SRUM", SrumStatus.Substring(6, Math.Min(SrumStatus.Length - 6, 140)), -1, sl)
            : SrumRader <= 0 ? new("SRUM", "ingen timer kunne leses", -1, sl)
            : SrumAi > 0 ? new("SRUM", $"{SrumAi} AI-program med nettbruk", 1, sl) : new("SRUM", $"{SrumRader} timer lest, ingen AI", 0, sl));
        bool Udp(Mal m) => m.Protokoller.Any(p => p.StartsWith("UDP", StringComparison.Ordinal));
        var ul = FraFunn(f => f.Trafikk.Any(Udp), f => f.Trafikk.Where(Udp).Select(m => $"{m.Adresse}{(m.Tjeneste != null ? " (" + m.Tjeneste + ")" : "")} · {string.Join(", ", m.Protokoller)}"));
        int udp = funn.Count(f => f.Trafikk.Any(Udp));
        l.Add(!UdpLest ? new("UDP/QUIC", "krever administrator", -1) : udp > 0 ? new("UDP/QUIC", $"{udp} AI over UDP", 1, ul) : new("UDP/QUIC", "ingen AI over UDP", 0));
        List<string> ll; int lytt; lock (_lytterLinjer) { ll = _lytterLinjer.ToList(); lytt = ll.Count; }
        l.Add(_apneAiPorter > 0 ? new("Lyttende AI-porter", $"{_apneAiPorter} åpen mot nettet", 2, ll)
            : lytt > 0 ? new("Lyttende AI-porter", $"{lytt} bare på PC-en", 1, ll) : new("Lyttende AI-porter", "ingen", 0, new[] {
                $"Lest {_lyttereLest} lyttende porter (TCP og UDP) fra Windows' porttabeller. Ingen tilhører et AI-program, og ingen er en standardport for AI.",
                "Standardporter som sjekkes: " + string.Join(", ", NettProtokoll.AiPorter.Select(x => $"{x.Key} {x.Value.Hva}")),
                "Vanlige porter (3000, 5000, 8000, 8080, 8888) regnes bare som AI når programmet er et kjent AI-program eller en tolker (python, node …)." }));
        int docker = funn.Count(f => f.Hvor.Contains("Docker"));
        var dl = docker > 0 ? FraFunn(f => f.Hvor.Contains("Docker"), f => f.Detaljer.Take(3)) : Logget("docker_engine");
        l.Add(docker > 0 ? new("Docker", $"{docker} AI-bilde", 1, dl)
            : Lest("docker_engine") ? new("Docker", "sjekket, ingen AI", 0, dl)
            : logg.Any(t => t.Mal.Contains("docker_engine") && t.Utfall == Utfall.Nektet) ? new("Docker", "ingen tilgang", -1, dl) : new("Docker", "kjører ikke", 0, dl));
        bool IWsl(string d) => d.Contains(@"\\wsl.localhost\");
        int wsl = funn.Count(f => f.Detaljer.Any(IWsl));
        List<string> bl; lock (Blindsoner) bl = Blindsoner.Where(b => b.StartsWith("WSL", StringComparison.Ordinal)).ToList();
        var wl2 = Linjer(FraFunn(f => f.Detaljer.Any(IWsl), f => f.Detaljer.Where(IWsl)).Concat(bl).Concat(Logget(@"\\wsl.localhost")));
        l.Add(wsl > 0 ? new("WSL", $"{wsl} AI i Linux", 1, wl2) : bl.Count > 0 ? new("WSL", "installert, kjørte ikke", -1, wl2)
            : Lest(@"\\wsl.localhost") ? new("WSL", "sjekket, ingen AI", 0, wl2) : new("WSL", "ikke installert", 0, wl2));
        bool IGpu(string d) => d.Contains("bruker GPU/NPU");
        int gpu = funn.Count(f => f.Detaljer.Any(IGpu));
        var gl = Linjer(Brikker().Concat(FraFunn(f => f.Detaljer.Any(IGpu), f => f.Detaljer.Where(IGpu))).Concat(Logget("Ytelsestellere: GPU"))
            .Concat(_aiPid.IsEmpty ? new[] { "Ingen AI-prosess kjørte under søket, så GPU/NPU-bruk ble ikke målt. Bruken måles bare for prosesser som er funnet som AI." } : Array.Empty<string>()));
        l.Add(gpu > 0 ? new("GPU/NPU", $"{gpu} AI bruker GPU nå", 1, gl)
            : logg.Any(t => t.Mal.StartsWith("Ytelsestellere: GPU", StringComparison.Ordinal) && t.Utfall == Utfall.IkkeFunnet) ? new("GPU/NPU", "ingen GPU-tellere", -1, gl)
            : Lest("Ytelsestellere: GPU") ? new("GPU/NPU", "ingen AI bruker GPU nå", 0, gl)
            : _aiPid.IsEmpty ? new("GPU/NPU", "ingen AI-prosess kjørte", 0, gl) : new("GPU/NPU", "ikke målt", -1, gl));
        List<string> nl; lock (_nettsideLinjer) nl = _nettsideLinjer.ToList();
        l.Add(nl.Count > 0 ? new("AI i nettsider", $"{nl.Count} nettsted kjører AI-modell", 2, nl)
            : Lest("nettleserlagring") ? new("AI i nettsider", "ingen modeller i nettleserne", 0, Logget("nettleserlagring")) : new("AI i nettsider", "ikke lest", -1));
        Sjekker = l;
    }
}
