using System.Diagnostics;
using System.Net;

namespace AISkanner;

/// <summary>
/// «Nettverk»: hvilke programmer som snakker med AI-tjenester akkurat nå, sekund for sekund, mens vinduet er åpent.
/// Leser de samme tabellene som søket (TCP-tabellen og Windows' DNS-buffer). Ingen pakker fanges, ingen driver,
/// ingenting sendes ut, ingenting lagres. Datamengde krever administrator (EStats). UDP (QUIC, WebRTC, DNS) med adresse og
/// mengde kommer fra Windows' nettverkshendelser (NettEtw), også bare som administrator.
/// </summary>
public sealed class Nettverkvisning : IDisposable
{
    /// <summary>
    /// Én rad: et program og en AI-tjeneste. <paramref name="Uavklart"/>: et kjent AI-program med forbindelser der vi ikke
    /// kan avgjøre tjenesten (navnet er ikke i DNS-bufferen). Da er Tjeneste null og <paramref name="Ai"/> funnet programmet hører til.
    /// </summary>
    public sealed record Rad(string Program, string? Sti, int Pid, string? Tjeneste, string? Vert, string? Land, string? Cdn,
        string? EierLand, int Forbindelser, long? UtPerSek, long? InnPerSek, bool Kjent, string? Nettleser, string? Ai, bool Uavklart,
        IReadOnlyCollection<string> AlleLand, IReadOnlyList<string>? IpEiere = null, string Protokoll = "TCP");
    /// <summary>Et program med åpne UDP-porter (mulig QUIC/HTTP/3, som ikke synes her). Bare antall, ikke hvor.</summary>
    public sealed record Udp(string Program, int Porter, bool Nettleser);
    /// <summary>En lyttende port som hører til en AI-server. <paramref name="Apen"/>: lytter på alle nettverkskort, kan nås fra andre maskiner.</summary>
    public sealed record LytterRad(string Program, int Pid, int Port, bool ErUdp, string Adresse, bool Apen, string Hva, string? Ai);
    /// <summary>UDP-strømmer akkurat nå etter type (QUIC, STUN/TURN, DNS …): antall strømmer og programmer.</summary>
    public sealed record UdpType(string Hva, int Strommer, int Programmer, long Ut, long Inn);
    /// <summary>Én kilde Nettverk leser: utfall «lest», «kunne ikke leses: grunn» eller «aldri lest: grunn».</summary>
    public sealed record Kilde(string Navn, string Utfall, long? Antall, string Detalj);
    public sealed record Bilde(DateTime Tid, List<Rad> Rader, long? UtPerSek, long? InnPerSek, int AndreForbindelser, int AndreNettleser, List<Udp> UdpHint,
        List<LytterRad>? Lyttere = null, List<UdpType>? UdpTyper = null, List<string>? KryptertDns = null, List<Kilde>? Kilder = null);

    private readonly Skanner _skanner;
    private readonly Datamaling? _maling = Datamaling.Tom();
    private readonly Dictionary<IPAddress, List<string>> _dns = new();
    private readonly Dictionary<int, (string Navn, string? Sti)> _prosesser = new();
    private readonly HashSet<int> _ukjentPid = new();
    private readonly Dictionary<string, (long Ut, long Inn)> _forrige = new();
    private HashSet<(int, int)> _lyttere = new();
    private Dictionary<int, int> _udp = new();
    private List<TcpTabell.Lytter> _tcpL = new(), _udpL = new();
    private readonly NettEtw? _etw;
    private readonly string _etwGrunn = "";
    private readonly Dictionary<(int, IPAddress, int), (long Ut, long Inn)> _forrigeUdp = new();
    private Dictionary<int, (int Forelder, string Exe)> _liste = new();
    private readonly Dictionary<int, string?> _vertsprogram = new();
    private DateTime _sistDns = DateTime.MinValue, _sistLyttere = DateTime.MinValue, _forrigeTid = DateTime.Now;

    public bool MalerData => _maling != null;

    public Nettverkvisning(Skanner skanner)
    {
        _skanner = skanner;
        if (skanner.TestNett == null) _etw = NettEtw.Start(out _etwGrunn);
        Tilgangslogg.Logg("Nettverk", "UDP-trafikk (Windows' nettverkshendelser, Kernel-Network)", _etw != null ? Utfall.Lest : Plattform.ErWindows ? Utfall.Nektet : Utfall.IkkeFunnet,
            _etw != null ? "adresse, port og størrelse per UDP-datagram, bare i minnet, aldri innhold" : _etwGrunn);
        Tilgangslogg.Logg("Nettverk", "Nettverk (live)", Utfall.Lest,
            _maling != null ? "AI-forbindelser og datamengde per sekund, bare i minnet" : "AI-forbindelser per sekund (datamengde krever administrator), bare i minnet");
    }

    public Bilde Les()
    {
        var naa = DateTime.Now;
        List<Tilkobling> alle;
        var test = _skanner.TestNett?.Invoke();
        if (test != null)
        {
            alle = test.Tilkoblinger;
            foreach (var (ip, n) in test.Dns) _dns[ip] = n;
            foreach (var (pid, p) in test.Prosesser) _prosesser[pid] = p;
            _tcpL = test.Lyttere ?? new();
            _udpL = test.UdpLyttere ?? new();
            _lyttere = new HashSet<(int, int)>(_tcpL.Select(l => (l.Pid, l.Port)));
        }
        else
        {
            alle = Nettverk.Tilkoblinger(logg: false);
            if (naa - _sistDns > TimeSpan.FromSeconds(2))
            {
                // DNS-bufferen glemmer navn etter en stund; det vi har sett, beholdes mens vinduet er åpent
                foreach (var (ip, n) in Nettverk.DnsBuffer(out _, logg: false))
                {
                    if (!_dns.TryGetValue(ip, out var l)) _dns[ip] = l = new List<string>();
                    foreach (var x in n) if (!l.Contains(x)) l.Add(x);
                }
                _sistDns = naa;
            }
            if (naa - _sistLyttere > TimeSpan.FromSeconds(5))
            {
                _tcpL = TcpTabell.Hent();
                _udpL = TcpTabell.UdpLyttere();
                _lyttere = new HashSet<(int, int)>(_tcpL.Select(l => (l.Pid, l.Port)));
                _udp = TcpTabell.UdpPerProgram();
                _liste = Prosesstre.Liste();
                _sistLyttere = naa;
            }
        }

        // Tjeneste "" = kjent AI-program, men vi kan ikke avgjøre hvor forbindelsen går
        var grupper = new Dictionary<(int, string), List<(Tilkobling T, string? Vert, AiNettsted? Tj)>>();
        int andre = 0, andreNettleser = 0;
        var navngitt = new List<(Tilkobling T, string? Vert, AiNettsted? Tj)>();
        foreach (var t in alle)
        {
            if (t.Pid <= 4 || Plattform.ErEgen(t.Pid) || _lyttere.Contains((t.Pid, t.LokalPort))) continue;
            string? vert = null; AiNettsted? tj = null;
            if (_dns.TryGetValue(t.Fjern, out var navn))
                foreach (var n in navn) if (_skanner.Tjeneste(n) is { } x) { vert = n; tj = x; break; }
            if (tj == null && _skanner.Vert(t.Fjern) is { } v && _skanner.Tjeneste(v) is { } y) { vert = v; tj = y; }
            navngitt.Add((t, vert, tj));
        }
        // Programmer (ikke nettlesere) som snakker med en AI-tjeneste nå: alle forbindelsene deres vises
        var aiPid = new HashSet<int>(navngitt.Where(x => x.Tj != null).Select(x => x.T.Pid));
        foreach (var (t, vert0, tj) in navngitt)
        {
            var vert = vert0;
            if (tj == null)
            {
                var (prog, sti) = Prosess(t.Pid);
                bool nettleser = Skanner.Nettleserprosesser.ContainsKey(prog);
                if (nettleser || (!aiPid.Contains(t.Pid) && AiFor(t.Pid, prog, sti) == null))
                {
                    andre++;
                    if (nettleser) andreNettleser++;
                    continue;
                }
                vert = _dns.TryGetValue(t.Fjern, out var nv) && nv.Count > 0 ? nv[0] : null;
            }
            var k = (t.Pid, tj?.Navn ?? "");
            if (!grupper.TryGetValue(k, out var g)) grupper[k] = g = new();
            g.Add((t, vert, tj));
        }

        Dictionary<string, (long Ut, long Inn)>? bytes = null;
        if (_maling != null)
        {
            foreach (var g in grupper.Values) foreach (var x in g) _maling.Legg(x.T);
            bytes = _maling.Les();
        }
        var sek = Math.Max(0.2, (naa - _forrigeTid).TotalSeconds);
        _forrigeTid = naa;

        var rader = new List<Rad>();
        long sumUt = 0, sumInn = 0;
        foreach (var ((pid, _), g) in grupper)
        {
            long? ut = null, inn = null;
            if (bytes != null)
            {
                long du = 0, di = 0;
                foreach (var x in g)
                {
                    if (!bytes.TryGetValue(x.T.Nokkel, out var b)) continue;
                    var f = _forrige.TryGetValue(x.T.Nokkel, out var fx) ? fx : b;   // første avlesning teller ikke det som var sendt før
                    du += Math.Max(0, b.Ut - f.Ut); di += Math.Max(0, b.Inn - f.Inn);
                    _forrige[x.T.Nokkel] = b;
                }
                ut = (long)(du / sek); inn = (long)(di / sek);
                sumUt += ut.Value; sumInn += inn.Value;
            }
            rader.Add(LagRad(pid, g.Select(x => (x.T.Fjern, x.Vert, x.Tj)).ToList(), g.Count, ut, inn, "TCP"));
        }

        // UDP fra Windows' nettverkshendelser: QUIC (HTTP/3) til AI-tjenester, og alle UDP-strømmer telt etter type
        var udpTyper = new Dictionary<string, (int N, HashSet<int> Pid, long Ut, long Inn)>();
        var kryptert = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        int udpAktive = 0;
        if (_etw != null)
        {
            var udpGrupper = new Dictionary<(int, string), List<(IPAddress Ip, string? Vert, AiNettsted? Tj, long Ut, long Inn, string Hva)>>();
            foreach (var st in _etw.Strommer())
            {
                var k = (st.Pid, st.Ip, st.Port);
                var f = _forrigeUdp.TryGetValue(k, out var fx) ? fx : (0L, 0L);
                _forrigeUdp[k] = (st.Ut, st.Inn);
                if (naa - st.Sist > TimeSpan.FromSeconds(10) || st.Pid <= 4 || Plattform.ErEgen(st.Pid)) continue;
                udpAktive++;
                long ut = (long)(Math.Max(0, st.Ut - f.Item1) / sek), inn = (long)(Math.Max(0, st.Inn - f.Item2) / sek);
                var hva = NettProtokoll.KryptertDns(st.Ip, st.Port, false) ?? NettProtokoll.Udp(st.Port);
                var t = udpTyper.TryGetValue(hva, out var tx) ? tx : (0, new HashSet<int>(), 0L, 0L);
                t.Item2.Add(st.Pid);
                udpTyper[hva] = (t.Item1 + 1, t.Item2, t.Item3 + ut, t.Item4 + inn);
                var (prog, sti) = Prosess(st.Pid);
                if (NettProtokoll.KryptertDns(st.Ip, st.Port, false) is { } kd) kryptert.Add($"{prog}: {kd}");
                string? vert = null; AiNettsted? tj = null;
                if (_dns.TryGetValue(st.Ip, out var navn))
                    foreach (var n in navn) if (_skanner.Tjeneste(n) is { } x) { vert = n; tj = x; break; }
                if (tj == null)
                {
                    if (Skanner.Nettleserprosesser.ContainsKey(prog) || AiFor(st.Pid, prog, sti) == null) continue;
                    vert = _dns.TryGetValue(st.Ip, out var nv) && nv.Count > 0 ? nv[0] : null;
                }
                var gk = (st.Pid, tj?.Navn ?? "");
                if (!udpGrupper.TryGetValue(gk, out var g)) udpGrupper[gk] = g = new();
                g.Add((st.Ip, vert, tj, ut, inn, hva));
            }
            foreach (var ((pid, _), g) in udpGrupper)
            {
                long ut = g.Sum(x => x.Ut), inn = g.Sum(x => x.Inn);
                if (bytes != null) { sumUt += ut; sumInn += inn; }
                rader.Add(LagRad(pid, g.Select(x => (x.Ip, x.Vert, x.Tj)).ToList(), g.Count, ut, inn, "UDP · " + string.Join(", ", g.Select(x => x.Hva).Distinct())));
            }
        }
        foreach (var t in alle)
            if (NettProtokoll.KryptertDns(t.Fjern, t.FjernPort, true) is { } kd && t.Pid > 4 && !Plattform.ErEgen(t.Pid)) kryptert.Add($"{Prosess(t.Pid).Navn}: {kd}");
        rader = rader.OrderBy(r => r.Kjent).ThenBy(r => r.Uavklart).ThenByDescending(r => r.UtPerSek ?? 0).ThenByDescending(r => r.Forbindelser).ToList();

        // UDP-porter hos nettlesere og AI-programmer: kan være QUIC (HTTP/3), som ikke synes i TCP-tabellen
        var udp = new Dictionary<string, (int Porter, bool Nettleser)>(StringComparer.OrdinalIgnoreCase);
        foreach (var (pid, n) in _udp)
        {
            if (pid <= 4 || Plattform.ErEgen(pid)) continue;
            var (prog, sti) = Prosess(pid);
            bool nettleser = Skanner.Nettleserprosesser.TryGetValue(prog, out var nl);
            if (!nettleser && AiFor(pid, prog, sti) == null) continue;
            var navn = nettleser ? nl! : prog;
            udp[navn] = (udp.TryGetValue(navn, out var x) ? x.Porter + n : n, nettleser);
        }
        var udpHint = udp.Select(x => new Udp(x.Key, x.Value.Porter, x.Value.Nettleser)).OrderByDescending(x => x.Porter).ToList();

        // Lyttende porter som hører til AI-servere. Samme program og port på IPv4 og IPv6 blir én rad.
        var lyttere = new Dictionary<(int, int, bool), LytterRad>();
        foreach (var (l, erUdp) in _tcpL.Select(l => (l, false)).Concat(_udpL.Select(l => (l, true))))
        {
            if (l.Pid <= 4 || Plattform.ErEgen(l.Pid)) continue;
            var (prog, sti) = Prosess(l.Pid);
            if (Skanner.Nettleserprosesser.ContainsKey(prog)) continue;
            var funn = AiFor(l.Pid, prog, sti);
            if (!NettProtokoll.VisLytter(l.Port, erUdp, prog, funn != null)) continue;
            var hva = erUdp ? NettProtokoll.Udp(l.Port) : NettProtokoll.AiPorter.TryGetValue(l.Port, out var ap) ? $"standardport for {ap.Hva}" : $"port {l.Port}";
            var adr = l.Adresse.Equals(IPAddress.Any) ? "0.0.0.0" : l.Adresse.Equals(IPAddress.IPv6Any) ? "::" : l.Adresse.ToString();
            var k = (l.Pid, l.Port, erUdp);
            lyttere[k] = lyttere.TryGetValue(k, out var x)
                ? x with { Adresse = x.Adresse.Contains(adr) ? x.Adresse : $"{x.Adresse}, {adr}", Apen = x.Apen || NettProtokoll.Apen(l.Adresse) }
                : new LytterRad(prog, l.Pid, l.Port, erUdp, adr, NettProtokoll.Apen(l.Adresse), hva, funn == null ? null : Oversikt.Navn(funn));
        }

        var kilder = new List<Kilde>
        {
            new("TCP-tabellen (IPv4 og IPv6)", "lest", alle.Count, "forbindelser ut nå, med program (PID) og adresse"),
            new("Lyttende TCP-porter", "lest", _tcpL.Count, "porter programmer venter på tilkoblinger på, med adresse"),
            new("UDP-tabellen", "lest", _udpL.Count, "åpne UDP-porter per program; Windows lagrer ikke hvor UDP sendes"),
            _etw != null
                ? new("UDP-trafikk (Windows' nettverkshendelser)", "lest", udpAktive, $"strømmer siste 10 s med adresse, port og mengde; {_etw.Hendelser} UDP-hendelser lest, aldri innhold")
                : new("UDP-trafikk (Windows' nettverkshendelser)", "kunne ikke leses: " + (_etwGrunn.Length > 0 ? _etwGrunn : "ikke startet"), null, "uten dette vises bare lokale UDP-porter, ikke hvor det sendes"),
            new("DNS-bufferen", "lest", _dns.Count, "navn → IP, gir navn til adressene"),
            _maling != null ? new("Datamengde TCP (EStats)", "lest", null, "byte sendt og mottatt per forbindelse")
                : new("Datamengde TCP (EStats)", "kunne ikke leses: krever administrator", null, "antall forbindelser vises i stedet"),
            new("Navnet i krypteringen (TLS SNI)", "aldri lest: krever pakkefangst, som programmet aldri gjør", null, "navnene kommer fra DNS-bufferen"),
            new("Innholdet i trafikken", "aldri lest: personvern", null, "ingen TLS-inspeksjon, ingen pakker fanges"),
        };
        return new Bilde(naa, rader, bytes != null ? sumUt : null, bytes != null ? sumInn : null, andre, andreNettleser, udpHint,
            lyttere.Values.OrderByDescending(l => l.Apen).ThenBy(l => l.Port).ToList(),
            udpTyper.Select(x => new UdpType(x.Key, x.Value.N, x.Value.Pid.Count, x.Value.Ut, x.Value.Inn)).OrderByDescending(x => x.Strommer).ToList(),
            kryptert.ToList(), kilder);
    }

    private Rad LagRad(int pid, List<(IPAddress Ip, string? Vert, AiNettsted? Tj)> g, int n, long? ut, long? inn, string protokoll)
    {
        var (prog, sti) = Prosess(pid);
        // Land og CDN per adresse. Går forbindelsene til flere land, vises ikke ett av dem som om det var alle.
        var steder = g.Select(x => x.Ip).Distinct().Select(ip =>
        {
            var c = IpLand.Cdn(ip, _dns.TryGetValue(ip, out var dn) ? dn : null);
            return (Cdn: c, Land: c != null ? null : IpLand.Finn(ip));
        }).Distinct().ToList();
        var (cdn, land) = steder.Count == 1 ? steder[0] : (null, null);
        var alleLand = steder.Where(x => x.Land != null).Select(x => x.Land!).Distinct().ToList();
        var nettleser = Skanner.Nettleserprosesser.TryGetValue(prog, out var nl) ? nl : null;
        if (nettleser == "WebView2" && Vertsprogram(pid) is { } vp) nettleser = $"WebView2 i {vp}";
        var funn = nettleser == null ? AiFor(pid, prog, sti) : null;
        // Et ukjent AI-spor er ikke «kjent» selv om programmet hører til et funn
        bool kjent = nettleser != null || (funn != null && funn.Gruppe != "spor");
        var forste = g[0];
        bool uavklart = forste.Tj == null;
        var vertene = g.Select(x => x.Vert).Where(v => v != null).Distinct().ToList();
        return new Rad(prog, sti, pid, forste.Tj?.Navn, uavklart ? (vertene.Count == 1 ? vertene[0] : null) : forste.Vert, land, cdn, forste.Tj?.Land,
            n, ut, inn, kjent, nettleser, funn == null ? null : Oversikt.Navn(funn), uavklart, alleLand,
            // IP-adressene med eier (ASN) fra offentlige rutetabeller i programmet (OSINT, ikke målt)
            g.Select(x => x.Ip).Distinct().Take(6).Select(ip => IpEier.Finn(ip) is { } e ? $"{ip} · {e}" : ip.ToString()).ToList(), protokoll);
    }

    // Regelsøket per program gjøres én gang mens visningen er åpen, ikke for hver forbindelse hvert sekund
    private readonly Dictionary<int, Funn?> _ai = new();
    private Funn? AiFor(int pid, string prog, string? sti) => _ai.TryGetValue(pid, out var f) ? f : _ai[pid] = _skanner.FunnForProsess(prog, sti);

    /// <summary>Programmet en WebView2-prosess viser nettsider for (Teams, Outlook, Widgets …): første forelder som ikke er WebView2.</summary>
    private string? Vertsprogram(int pid)
    {
        if (_vertsprogram.TryGetValue(pid, out var v)) return v;
        if (_liste.Count == 0) _liste = Prosesstre.Liste();
        string? svar = null;
        var sett = new HashSet<int>();
        for (int p = pid; _liste.TryGetValue(p, out var x) && sett.Add(p) && x.Forelder > 4; p = x.Forelder)
        {
            if (!_liste.TryGetValue(x.Forelder, out var f)) break;
            if (Path.GetFileNameWithoutExtension(f.Exe).Equals("msedgewebview2", StringComparison.OrdinalIgnoreCase)) continue;
            var (navn, sti) = Prosess(x.Forelder);
            svar = navn;
            try { if (sti != null && FileVersionInfo.GetVersionInfo(sti).ProductName is { } pn && pn.Trim().Length > 0) svar = pn.Trim(); } catch { }
            break;
        }
        return _vertsprogram[pid] = svar;
    }

    private (string Navn, string? Sti) Prosess(int pid)
    {
        if (_prosesser.TryGetValue(pid, out var p)) return p;
        if (_ukjentPid.Contains(pid)) return ("ukjent program", null);
        try { using var pr = Process.GetProcessById(pid); return _prosesser[pid] = (pr.ProcessName, ProsessSti.Hent(pr)); }
        catch { _ukjentPid.Add(pid); return ("ukjent program", null); }
    }

    public void Dispose() { _maling?.Dispose(); _etw?.Dispose(); }
}
