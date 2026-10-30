using System.Net;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>Resultatet av én sjekk, vist som «Sjekket» i Funn. Nivå: -1 ikke sjekket, 0 sjekket uten funn, 1 funn, 2 funn med fare.</summary>
public sealed record Sjekkstatus(string Navn, string Tekst, int Niva);

public sealed partial class Skanner
{
    public List<Sjekkstatus> Sjekker { get; private set; } = new();
    private readonly List<string> _lytterLinjer = new();
    private int _apneAiPorter;

    /// <summary>
    /// Lyttende porter som hører til AI-servere (Ollama 11434, LM Studio 1234 …). Blir detalj på funnet for programmet;
    /// åpen mot nettet (0.0.0.0 eller ::) blir advarsel. Bare lesing av Windows' porttabeller, ingenting kobles til.
    /// </summary>
    internal void LyttendeAiPorter()
    {
        lock (_lytterLinjer) { _lytterLinjer.Clear(); _apneAiPorter = 0; }
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

        var wpbt = fl.FirstOrDefault(x => x.StartsWith("Fastvare (BIOS)", StringComparison.Ordinal));
        l.Add(wpbt == null ? new("BIOS (WPBT)", Plattform.ErWindows ? "ikke lest" : "bare Windows", -1)
            : wpbt.Contains("ingen WPBT") ? new("BIOS (WPBT)", "ingen program fra BIOS", 0)
            : new("BIOS (WPBT)", wpbt.Contains("AI-regel traff:") ? "BIOS starter et AI-program" : "BIOS starter et program (ikke AI)", wpbt.Contains("AI-regel traff:") ? 2 : 1));
        var tj = fl.FirstOrDefault(x => x.StartsWith("Tjenester og drivere endret", StringComparison.Ordinal));
        if (tj != null)
        {
            var n = Regex.Match(tj, @"siste 7 dager: (\d+)").Groups[1].Value;
            l.Add(tj.Contains("AI-regel traff:") ? new("Tjenester endret 7 d", $"{n} endret, AI-regel traff", 1)
                : new("Tjenester endret 7 d", n.Length > 0 ? $"{n} endret, ingen AI" : "ingen endret", 0));
        }
        l.Add(SrumStatus == null ? new("SRUM", Nettverk.ErAdmin() ? "ikke lest" : "krever administrator", -1)
            : SrumRader <= 0 ? new("SRUM", "ingen timer kunne leses", -1)
            : SrumAi > 0 ? new("SRUM", $"{SrumAi} AI-program med nettbruk", 1) : new("SRUM", $"{SrumRader} timer lest, ingen AI", 0));
        int udp = funn.Count(f => f.Trafikk.Any(m => m.Protokoller.Any(p => p.StartsWith("UDP", StringComparison.Ordinal))));
        l.Add(!UdpLest ? new("UDP/QUIC", "krever administrator", -1) : udp > 0 ? new("UDP/QUIC", $"{udp} AI over UDP", 1) : new("UDP/QUIC", "ingen AI over UDP", 0));
        int lytt; lock (_lytterLinjer) lytt = _lytterLinjer.Count;
        l.Add(!Plattform.ErWindows ? new("Lyttende AI-porter", "bare Windows", -1)
            : _apneAiPorter > 0 ? new("Lyttende AI-porter", $"{_apneAiPorter} åpen mot nettet", 2)
            : lytt > 0 ? new("Lyttende AI-porter", $"{lytt} bare på PC-en", 1) : new("Lyttende AI-porter", "ingen", 0));
        int docker = funn.Count(f => f.Hvor.Contains("Docker"));
        l.Add(docker > 0 ? new("Docker", $"{docker} AI-bilde", 1)
            : Lest("docker_engine") ? new("Docker", "sjekket, ingen AI", 0)
            : logg.Any(t => t.Mal.Contains("docker_engine") && t.Utfall == Utfall.Nektet) ? new("Docker", "ingen tilgang", -1) : new("Docker", "kjører ikke", 0));
        int wsl = funn.Count(f => f.Detaljer.Any(d => d.Contains(@"\\wsl.localhost\")));
        bool wslAv; lock (Blindsoner) wslAv = Blindsoner.Any(b => b.StartsWith("WSL", StringComparison.Ordinal));
        l.Add(wsl > 0 ? new("WSL", $"{wsl} AI i Linux", 1) : wslAv ? new("WSL", "installert, kjørte ikke", -1)
            : Lest(@"\\wsl.localhost") ? new("WSL", "sjekket, ingen AI", 0) : new("WSL", "ikke installert", 0));
        int gpu = funn.Count(f => f.Detaljer.Any(d => d.Contains("bruker GPU/NPU")));
        l.Add(gpu > 0 ? new("GPU/NPU", $"{gpu} AI bruker GPU nå", 1)
            : logg.Any(t => t.Mal.StartsWith("Ytelsestellere: GPU", StringComparison.Ordinal) && t.Utfall == Utfall.IkkeFunnet) ? new("GPU/NPU", "ingen GPU-tellere", -1)
            : Lest("Ytelsestellere: GPU") ? new("GPU/NPU", "ingen AI bruker GPU nå", 0)
            : _aiPid.IsEmpty ? new("GPU/NPU", "ingen AI-prosess kjørte", 0) : new("GPU/NPU", "ikke målt", -1));
        Sjekker = l;
    }
}
