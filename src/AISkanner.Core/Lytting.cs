using System.Diagnostics;
using System.Net;

namespace AISkanner;

/// <summary>
/// Lyttevindu: leser TCP-tabellen hvert 250. ms og DNS-bufferen hvert 2. sekund mens søket går,
/// så korte forbindelser (et API-kall på to sekunder) også blir sett. Ingen pakker fanges, ingenting sendes ut,
/// ingenting lagres. Alt ligger i minnet til søket er ferdig. Bare TCP: UDP og QUIC (HTTP/3) vises ikke.
/// </summary>
internal sealed class Lyttevindu : IDisposable
{
    private readonly Dictionary<string, (Tilkobling T, DateTime Forst, DateTime Sist)> _sett = new();
    private readonly Dictionary<string, Tilkobling> _lokale = new();
    private readonly Dictionary<IPAddress, List<string>> _dns = new();
    private readonly HashSet<string> _dnsNavn = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, (string Navn, string? Sti)> _prosesser = new();
    private readonly HashSet<int> _ukjentPid = new();
    private readonly Dictionary<string, (long Ut, long Inn)> _bytes = new();
    private readonly Datamaling? _maling;
    private readonly CancellationTokenSource _stopp = new();
    private readonly Stopwatch _klokke = Stopwatch.StartNew();
    private readonly Task _lop;
    public int Avlesninger { get; private set; }
    public double Sekunder => _klokke.Elapsed.TotalSeconds;

    private Lyttevindu(Datamaling? maling)
    {
        _maling = maling;
        _lop = Task.Run(Lop);
    }

    public static Lyttevindu Start(Datamaling? maling) => new(maling);

    private async Task Lop()
    {
        var sistDns = TimeSpan.FromSeconds(-10);
        var sistBytes = TimeSpan.Zero;
        while (!_stopp.IsCancellationRequested)
        {
            try
            {
                Les();
                if (_klokke.Elapsed - sistDns >= TimeSpan.FromSeconds(2)) { LesDns(); sistDns = _klokke.Elapsed; }
                if (_maling != null && _klokke.Elapsed - sistBytes >= TimeSpan.FromSeconds(1)) { LesBytes(); sistBytes = _klokke.Elapsed; }
            }
            catch (Exception e) { Debug.WriteLine($"Lyttevindu: {e.Message}"); }
            try { await Task.Delay(250, _stopp.Token).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
        }
    }

    private void Les()
    {
        var naa = DateTime.Now;
        var alle = Nettverk.Alle(logg: false);
        var liste = Nettverk.Ute(alle);
        lock (_sett)
        {
            Avlesninger++;
            foreach (var t in Nettverk.LokaleAiKlienter(alle))
            {
                _lokale[t.Nokkel] = t;
                if (t.Pid > 4 && !Plattform.ErEgen(t.Pid) && !_prosesser.ContainsKey(t.Pid) && !_ukjentPid.Contains(t.Pid))
                {
                    try { using var p = Process.GetProcessById(t.Pid); _prosesser[t.Pid] = (p.ProcessName, ProsessSti.Hent(p)); }
                    catch { _ukjentPid.Add(t.Pid); }
                }
            }
            foreach (var t in liste)
            {
                if (_sett.TryGetValue(t.Nokkel, out var x)) _sett[t.Nokkel] = (x.T, x.Forst, naa);
                else
                {
                    _sett[t.Nokkel] = (t, naa, naa);
                    _maling?.Legg(t);
                }
                // Prosessen slås opp første gang, mens den ennå kjører
                if (t.Pid > 4 && !Plattform.ErEgen(t.Pid) && !_prosesser.ContainsKey(t.Pid) && !_ukjentPid.Contains(t.Pid))
                {
                    try { using var p = Process.GetProcessById(t.Pid); _prosesser[t.Pid] = (p.ProcessName, ProsessSti.Hent(p)); }
                    catch { _ukjentPid.Add(t.Pid); }
                }
            }
        }
    }

    private void LesDns()
    {
        var kart = Nettverk.DnsBuffer(out var navn, logg: false);
        lock (_sett)
        {
            foreach (var n in navn) _dnsNavn.Add(n);
            foreach (var (ip, liste) in kart)
            {
                if (!_dns.TryGetValue(ip, out var l)) _dns[ip] = l = new List<string>();
                foreach (var n in liste) if (!l.Contains(n)) l.Add(n);
            }
        }
    }

    // EStats-tellerne er borte når forbindelsen lukkes, så siste avlesning tas vare på
    private void LesBytes()
    {
        var b = _maling!.Les();
        lock (_sett)
            foreach (var (k, v) in b)
                _bytes[k] = _bytes.TryGetValue(k, out var x) ? (Math.Max(x.Ut, v.Ut), Math.Max(x.Inn, v.Inn)) : v;
    }

    /// <summary>Alt sett så langt, uten å stoppe lyttingen (resultatet vises før lyttevinduet er ferdig).</summary>
    public NettBilde Bilde()
    {
        try { Les(); LesDns(); if (_maling != null) LesBytes(); } catch { }
        return Lag(logg: false);
    }

    /// <summary>Stopper lyttingen og gir alt som ble sett i vinduet som ett nettbilde.</summary>
    public NettBilde Stopp()
    {
        _stopp.Cancel();
        try { _lop.Wait(2000); } catch { }
        try { Les(); LesDns(); if (_maling != null) LesBytes(); } catch { }
        return Lag(logg: true);
    }

    private NettBilde Lag(bool logg)
    {
        lock (_sett)
        {
            var nb = new NettBilde
            {
                Tilkoblinger = _sett.Values.Select(x => x.T).ToList(),
                Lokale = _lokale.Values.ToList(),
                Dns = _dns.ToDictionary(x => x.Key, x => x.Value.ToList()),
                DnsNavn = _dnsNavn.ToList(),
                Prosesser = new Dictionary<int, (string, string?)>(_prosesser),
                Bytes = _maling != null ? new Dictionary<string, (long, long)>(_bytes) : null,
                Sekunder = _maling?.Sekunder ?? 0,
                Tider = _sett.ToDictionary(x => x.Key, x => (x.Value.Forst, x.Value.Sist)),
                LytteSekunder = Sekunder,
                Avlesninger = Avlesninger,
            };
            if (logg) Tilgangslogg.Logg("Nettverk", "TCP-tabellen (GetExtendedTcpTable), lyttevindu", Utfall.Lest,
                $"{Avlesninger} avlesninger på {Sekunder:0} sekunder, {_sett.Count} forbindelser sett");
            if (logg) Tilgangslogg.Logg("Nettverk", "DNS-bufferen (bare navn Windows allerede har slått opp), lyttevindu", Utfall.Lest,
                $"{_dnsNavn.Count} navn; bare AI-navn brukes, resten forkastes");
            return nb;
        }
    }

    public void Dispose() { _stopp.Cancel(); _stopp.Dispose(); }
}

/// <summary>
/// «Følg med»: datamengden til ett funn, sekund for sekund, mens vinduet er åpent. Bare i minnet. Lukkes vinduet
/// eller tas haken bort, er alt borte. Datamengde krever administrator (EStats); uten vises bare antall forbindelser.
/// Bare TCP: UDP og QUIC (HTTP/3) telles ikke.
/// </summary>
public sealed class Folger : IDisposable
{
    public sealed record Punkt(DateTime Tid, long? UtPerSek, long? InnPerSek, int Forbindelser, List<string> Mottakere);

    private readonly Skanner _skanner;
    private readonly Funn _funn;
    private readonly Datamaling? _maling = Datamaling.Tom();
    private readonly Dictionary<string, (long Ut, long Inn)> _forrige = new();
    private HashSet<int> _pider = new();
    private HashSet<string>? _ipFilter;
    private DateTime _sistePidSjekk = DateTime.MinValue, _forrigeTid = DateTime.Now;

    public bool MalerData => _maling != null;

    public Folger(Skanner skanner, Funn funn)
    {
        _skanner = skanner;
        _funn = funn;
        Tilgangslogg.Logg("Nettverk", $"Følg med: {funn.Navn}", Utfall.Lest, _maling != null ? "datamengde per sekund, bare i minnet" : "antall forbindelser (datamengde krever administrator)");
    }

    public Punkt Les()
    {
        var naa = DateTime.Now;
        if (naa - _sistePidSjekk > TimeSpan.FromSeconds(5))
        {
            (_pider, _ipFilter) = _skanner.ProsesserFor(_funn);
            _sistePidSjekk = naa;
        }
        var mine = Nettverk.Tilkoblinger(logg: false)
            .Where(t => _pider.Contains(t.Pid) && (_ipFilter == null || _ipFilter.Contains(t.Fjern.ToString()))).ToList();
        long? ut = null, inn = null;
        if (_maling != null)
        {
            foreach (var t in mine) _maling.Legg(t);
            var bytes = _maling.Les();
            var sek = Math.Max(0.2, (naa - _forrigeTid).TotalSeconds);
            long du = 0, di = 0;
            foreach (var t in mine)
            {
                if (!bytes.TryGetValue(t.Nokkel, out var b)) continue;
                var f = _forrige.TryGetValue(t.Nokkel, out var x) ? x : (0, 0);
                du += Math.Max(0, b.Ut - f.Ut);
                di += Math.Max(0, b.Inn - f.Inn);
                _forrige[t.Nokkel] = b;
            }
            ut = (long)(du / sek);
            inn = (long)(di / sek);
        }
        _forrigeTid = naa;
        var mottakere = mine.Select(t => _skanner.Vert(t.Fjern) ?? t.Fjern.ToString()).Distinct().Take(6).ToList();
        return new Punkt(naa, ut, inn, mine.Count, mottakere);
    }

    public void Dispose() => _maling?.Dispose();
}
