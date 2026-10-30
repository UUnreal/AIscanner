using System.Diagnostics;
using System.Net;

namespace AISkanner;

/// <summary>
/// «Nettverk»: hvilke programmer som snakker med AI-tjenester akkurat nå, sekund for sekund, mens vinduet er åpent.
/// Leser de samme tabellene som søket (TCP-tabellen og Windows' DNS-buffer). Ingen pakker fanges, ingen driver,
/// ingenting sendes ut, ingenting lagres. Datamengde krever administrator (EStats). Bare TCP: UDP og QUIC (HTTP/3) vises ikke.
/// </summary>
public sealed class Nettverkvisning : IDisposable
{
    /// <summary>
    /// Én rad: et program og en AI-tjeneste. <paramref name="Uavklart"/>: et kjent AI-program med forbindelser der vi ikke
    /// kan avgjøre tjenesten (navnet er ikke i DNS-bufferen). Da er Tjeneste null og <paramref name="Ai"/> funnet programmet hører til.
    /// </summary>
    public sealed record Rad(string Program, string? Sti, int Pid, string? Tjeneste, string? Vert, string? Land, string? Cdn,
        string? EierLand, int Forbindelser, long? UtPerSek, long? InnPerSek, bool Kjent, string? Nettleser, string? Ai, bool Uavklart,
        IReadOnlyCollection<string> AlleLand, IReadOnlyList<string>? IpEiere = null);
    /// <summary>Et program med åpne UDP-porter (mulig QUIC/HTTP/3, som ikke synes her). Bare antall, ikke hvor.</summary>
    public sealed record Udp(string Program, int Porter, bool Nettleser);
    public sealed record Bilde(DateTime Tid, List<Rad> Rader, long? UtPerSek, long? InnPerSek, int AndreForbindelser, int AndreNettleser, List<Udp> UdpHint);

    private readonly Skanner _skanner;
    private readonly Datamaling? _maling = Datamaling.Tom();
    private readonly Dictionary<IPAddress, List<string>> _dns = new();
    private readonly Dictionary<int, (string Navn, string? Sti)> _prosesser = new();
    private readonly HashSet<int> _ukjentPid = new();
    private readonly Dictionary<string, (long Ut, long Inn)> _forrige = new();
    private HashSet<(int, int)> _lyttere = new();
    private Dictionary<int, int> _udp = new();
    private Dictionary<int, (int Forelder, string Exe)> _liste = new();
    private readonly Dictionary<int, string?> _vertsprogram = new();
    private DateTime _sistDns = DateTime.MinValue, _sistLyttere = DateTime.MinValue, _forrigeTid = DateTime.Now;

    public bool MalerData => _maling != null;

    public Nettverkvisning(Skanner skanner)
    {
        _skanner = skanner;
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
            _lyttere = new HashSet<(int, int)>((test.Lyttere ?? new()).Select(l => (l.Pid, l.Port)));
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
                _lyttere = new HashSet<(int, int)>(TcpTabell.Hent().Select(l => (l.Pid, l.Port)));
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
            var (prog, sti) = Prosess(pid);
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
            // Land og CDN per adresse. Går forbindelsene til flere land, vises ikke ett av dem som om det var alle.
            var steder = g.Select(x => x.T.Fjern).Distinct().Select(ip =>
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
            rader.Add(new Rad(prog, sti, pid, forste.Tj?.Navn, uavklart ? (vertene.Count == 1 ? vertene[0] : null) : forste.Vert, land, cdn, forste.Tj?.Land,
                g.Count, ut, inn, kjent, nettleser, funn == null ? null : Oversikt.Navn(funn), uavklart, alleLand,
                // IP-adressene med eier (ASN) fra offentlige rutetabeller i programmet (OSINT, ikke målt)
                g.Select(x => x.T.Fjern).Distinct().Take(6).Select(ip => IpEier.Finn(ip) is { } e ? $"{ip} · {e}" : ip.ToString()).ToList()));
        }
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
        return new Bilde(naa, rader, bytes != null ? sumUt : null, bytes != null ? sumInn : null, andre, andreNettleser, udpHint);
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

    public void Dispose() => _maling?.Dispose();
}
