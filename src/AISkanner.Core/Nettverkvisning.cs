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
    public sealed record Rad(string Program, string? Sti, int Pid, string Tjeneste, string? Vert, string? Land, string? Cdn,
        string? EierLand, int Forbindelser, long? UtPerSek, long? InnPerSek, bool Kjent, string? Nettleser);
    public sealed record Bilde(DateTime Tid, List<Rad> Rader, long? UtPerSek, long? InnPerSek, int AndreForbindelser);

    private readonly Skanner _skanner;
    private readonly Datamaling? _maling = Datamaling.Tom();
    private readonly Dictionary<IPAddress, List<string>> _dns = new();
    private readonly Dictionary<int, (string Navn, string? Sti)> _prosesser = new();
    private readonly HashSet<int> _ukjentPid = new();
    private readonly Dictionary<string, (long Ut, long Inn)> _forrige = new();
    private HashSet<(int, int)> _lyttere = new();
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
                _sistLyttere = naa;
            }
        }

        var grupper = new Dictionary<(int, string), List<(Tilkobling T, string? Vert, AiNettsted Tj)>>();
        int andre = 0;
        foreach (var t in alle)
        {
            if (t.Pid <= 4 || t.Pid == Plattform.EgenPid || _lyttere.Contains((t.Pid, t.LokalPort))) continue;
            string? vert = null; AiNettsted? tj = null;
            if (_dns.TryGetValue(t.Fjern, out var navn))
                foreach (var n in navn) if (_skanner.Tjeneste(n) is { } x) { vert = n; tj = x; break; }
            if (tj == null && _skanner.Vert(t.Fjern) is { } v && _skanner.Tjeneste(v) is { } y) { vert = v; tj = y; }
            if (tj == null) { andre++; continue; }
            var k = (t.Pid, tj.Navn);
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
            var forste = g[0];
            var cdn = IpLand.Cdn(forste.T.Fjern, _dns.TryGetValue(forste.T.Fjern, out var dn) ? dn : null);
            var nettleser = Skanner.Nettleserprosesser.TryGetValue(prog, out var nl) ? nl : null;
            bool kjent = nettleser != null || _skanner.FunnForProsess(prog, sti) != null;
            rader.Add(new Rad(prog, sti, pid, forste.Tj.Navn, forste.Vert, cdn != null ? null : IpLand.Finn(forste.T.Fjern), cdn, forste.Tj.Land,
                g.Count, ut, inn, kjent, nettleser));
        }
        rader = rader.OrderBy(r => r.Kjent).ThenByDescending(r => r.UtPerSek ?? 0).ThenByDescending(r => r.Forbindelser).ToList();
        return new Bilde(naa, rader, bytes != null ? sumUt : null, bytes != null ? sumInn : null, andre);
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
