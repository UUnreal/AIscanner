using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

namespace AISkanner;

/// <summary>Øyeblikksbilde av nettverket: hvem som er koblet til hva akkurat nå.</summary>
internal sealed class NettBilde
{
    public List<Tilkobling> Tilkoblinger = new();
    /// <summary>Programmer på PC-en koblet til en lokal AI-server (127.0.0.1:11434 osv.).</summary>
    public List<Tilkobling> Lokale = new();
    public Dictionary<IPAddress, List<string>> Dns = new();
    public List<string> DnsNavn = new();
    public Dictionary<int, (string Navn, string? Sti)> Prosesser = new();
    public List<Kortlivet> Kortlivede = new();
    /// <summary>Målte byte per forbindelse, eller null når vi ikke kjører som administrator.</summary>
    public Dictionary<string, (long Ut, long Inn)>? Bytes;
    public double Sekunder;
    /// <summary>Første og siste gang hver forbindelse ble sett i lyttevinduet.</summary>
    public Dictionary<string, (DateTime Forst, DateTime Sist)> Tider = new();
    public double LytteSekunder;
    public int Avlesninger;
    /// <summary>Lyttende porter. Null: leses fra Windows når de trengs.</summary>
    public List<TcpTabell.Lytter>? Lyttere;

    public static NettBilde Hent(Datamaling? maling)
    {
        var alle = Nettverk.Alle();
        var nb = new NettBilde { Tilkoblinger = Nettverk.Ute(alle), Lokale = Nettverk.LokaleAiKlienter(alle) };
        nb.Dns = Nettverk.DnsBuffer(out nb.DnsNavn);
        foreach (var pid in nb.Tilkoblinger.Concat(nb.Lokale).Select(t => t.Pid).Distinct())
        {
            if (pid <= 4 || Plattform.ErEgen(pid)) continue;
            try { using var p = Process.GetProcessById(pid); nb.Prosesser[pid] = (p.ProcessName, ProsessSti.Hent(p)); } catch { }
        }
        if (maling != null)
        {
            nb.Bytes = maling.Les();
            nb.Sekunder = maling.Sekunder;
        }
        return nb;
    }
}

/// <summary>
/// Hvor AI-programmene sender data. Alt bygger på det Windows faktisk viser nå:
/// åpne forbindelser per program, navn fra DNS-bufferen og land fra innebygd IP-tabell. Ingenting sendes ut.
/// Nettleserne vises bare med forbindelser til kjente AI-tjenester, aldri annen surfing.
/// </summary>
public sealed partial class Skanner
{
    /// <summary>Mappen et AI-program kjører fra, så alle prosessene til programmet kan knyttes til funnet.</summary>
    private readonly ConcurrentDictionary<string, Funn> _mappeFunn = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Om datamengde ble målt i siste søk (krever administrator), og hvor lenge.</summary>
    public bool DataMalt { get; private set; }
    public double MaleSekunder { get; private set; }

    /// <summary>Hvor lenge lyttevinduet varer (sekunder, maks 60). 0 = ett øyeblikksbilde til slutt, som før 2.17.</summary>
    public int LytteSekunder { get; set; } = 20;

    /// <summary>Hvor lenge det faktisk ble lyttet i siste søk.</summary>
    public double LyttetSekunder { get; private set; }

    /// <summary>Programmene (PID) som hørte til hvert funn i siste søk. Brukes av «Følg med».</summary>
    private readonly ConcurrentDictionary<Funn, HashSet<int>> _funnPid = new();

    /// <summary>Kun for testing: erstatter det ekte nettverksbildet.</summary>
    internal Func<NettBilde>? TestNett { get; set; }

    internal static readonly Dictionary<string, string> Nettleserprosesser = new(StringComparer.OrdinalIgnoreCase)
    {
        ["chrome"] = "Chrome", ["msedge"] = "Edge", ["firefox"] = "Firefox", ["brave"] = "Brave", ["opera"] = "Opera",
        ["vivaldi"] = "Vivaldi", ["arc"] = "Arc", ["waterfox"] = "Waterfox", ["librewolf"] = "LibreWolf", ["iexplore"] = "Internet Explorer",
        // Nettleserdelen andre programmer (Teams, Outlook, Widgets) viser nettsider i. Forbindelsene er programmets, ikke WebView2-ens
        ["msedgewebview2"] = "WebView2",
    };

    private void HuskMappe(string? exe, Funn f)
    {
        var mappe = string.IsNullOrEmpty(exe) ? null : Path.GetDirectoryName(exe);
        if (!string.IsNullOrEmpty(mappe) && !ErSystemmappe(mappe!)) _mappeFunn.TryAdd(mappe!, f);
    }

    internal AiNettsted? Tjeneste(string vert) =>
        _regler.AiTjenester.FirstOrDefault(t => t.Treffer(vert)) ?? FinnNettsted(vert);

    private Task<Dictionary<IPAddress, List<string>>>? _aiIp;
    /// <summary>Windows' DNS-buffer var fylt av en eldre AI-skanners egne oppslag, og ble ikke brukt som bevis.</summary>
    public bool DnsBufferForurenset { get; private set; }
    private HashSet<string>? _nettleserVerter;

    private void Trafikk(NettBilde nb)
    {
        DataMalt = nb.Bytes != null;
        MaleSekunder = nb.Sekunder;

        // Egne oppslag av AI-adressene, og AI-tjenestene nettleserne har i nettverkslageret sitt
        Dictionary<IPAddress, List<string>>? egne = null;
        try { if (_aiIp != null && _aiIp.Wait(TimeSpan.FromSeconds(5))) egne = _aiIp.Result; } catch { }
        if (egne != null) _nettleserVerter ??= AiAdresser.NettleserVerter(ChromiumRotter(), v => Tjeneste(v) != null);
        var viaIp = new HashSet<Tilkobling>();

        (string? Vert, AiNettsted? Tj) Navn(IPAddress ip)
        {
            if (nb.Dns.TryGetValue(ip, out var navn) && navn.Count > 0)
            {
                foreach (var n in navn)
                    if (Tjeneste(n) is { } t) return (n, t);
                return (navn[0], null);
            }
            // Ikke i Windows' DNS-buffer: kjent igjen på IP-adressen, men bare tjenester nettleseren selv har brukt nylig
            var nokkel = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
            if (egne != null && _nettleserVerter != null && egne.TryGetValue(nokkel, out var verter))
                foreach (var v in verter)
                    if (_nettleserVerter.Contains(v) && Tjeneste(v) is { } t) return (v, t);
            return (null, null);
        }

        // Forbindelser inn til en port programmet selv lytter på er klienter, ikke steder det sender til
        var lyttere = nb.Lyttere ??= TcpTabell.Hent();
        var lytterSett = new HashSet<(int, int)>(lyttere.Select(l => (l.Pid, l.Port)));
        bool Inn(Tilkobling t) => lytterSett.Contains((t.Pid, t.LokalPort));
        _funnPid.Clear();

        var oppslag = new Dictionary<Tilkobling, (string? Vert, AiNettsted? Tj)>();
        foreach (var t in nb.Tilkoblinger)
        {
            oppslag[t] = Navn(t.Fjern);
            if (oppslag[t].Tj != null && !(nb.Dns.TryGetValue(t.Fjern, out var dn) && dn.Count > 0)) viaIp.Add(t);
        }
        _vertForIp.Clear();
        foreach (var (t, v) in oppslag) if (v.Tj != null && v.Vert != null) _vertForIp[t.Fjern.ToString()] = v.Vert;
        // Programmer vi ikke kjente som AI, men som snakker med en AI-tjeneste. Da vises alt programmet er koblet til.
        var skjulte = new Dictionary<int, Funn>();
        foreach (var t in nb.Tilkoblinger)
        {
            if (Inn(t) || viaIp.Contains(t) || skjulte.ContainsKey(t.Pid) || oppslag[t].Tj is not { } tj || !nb.Prosesser.TryGetValue(t.Pid, out var p)) continue;
            if (t.Pid <= 4 || Plattform.ErEgen(t.Pid) || Nettleserprosesser.ContainsKey(p.Navn) || _pidFunn.ContainsKey(t.Pid) || FunnForProsess(p.Navn, p.Sti) != null) continue;
            skjulte[t.Pid] = SkjultAi(t.Pid, p.Navn, p.Sti, tj);
        }

        var mal = new Dictionary<Funn, Dictionary<string, Mal>>();
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in nb.Tilkoblinger)
        {
            if (t.Pid <= 4 || Plattform.ErEgen(t.Pid) || Inn(t) || !nb.Prosesser.TryGetValue(t.Pid, out var p)) continue;
            var (vert, tj) = oppslag[t];
            Funn? f;
            if (Nettleserprosesser.TryGetValue(p.Navn, out var nettleser))
            {
                if (tj == null) continue;   // annen surfing angår ikke oss
                f = LeggTil(tj.Navn, "Nettleser-AI (nettsted)", RisikoTekst.Fra(tj.Risiko), tj.Hvorfor, nettleser, null, enkelt: tj.Enkelt);
                f.Privat = true;
                if (viaIp.Contains(t))
                    f.Detalj($"Kjent igjen på IP-adressen: {t.Fjern} er {vert} nå, og {nettleser} har {vert} i nettverkslageret sitt (nettleseren slår opp navn selv, så Windows' DNS-buffer har det ikke)");
                var apen = $"Åpen i {nettleser} nå.";
                if (f.Bruk == null) f.Bruk = apen;
                else if (!f.Bruk.Contains(apen)) f.Bruk = f.Bruk.TrimEnd('.') + ". " + apen;   // trafikken kan leses to ganger (lytting i bakgrunnen)
                f.Merk(Tilstand.KjorerNa); f.Sterkt();
            }
            else
            {
                f = skjulte.TryGetValue(t.Pid, out var sk) ? sk : _pidFunn.TryGetValue(t.Pid, out var pf) ? pf : FunnForProsess(p.Navn, p.Sti);
                if (f == null) continue;
                // IP-treff uten navn gjelder bare nettlesere: andre programmer kan dele adressen med en annen tjeneste
                if (viaIp.Contains(t)) { vert = null; tj = null; }
            }
            if (vert != null) sett.Add(vert);
            _funnPid.GetOrAdd(f, _ => new HashSet<int>()).Add(t.Pid);

            var adresse = vert ?? t.Fjern.ToString();
            if (!mal.TryGetValue(f, out var liste)) mal[f] = liste = new Dictionary<string, Mal>(StringComparer.OrdinalIgnoreCase);
            var cdn = IpLand.Cdn(t.Fjern, nb.Dns.TryGetValue(t.Fjern, out var dnsNavn) ? dnsNavn : null);
            var land = cdn != null ? "CDN" : IpLand.Finn(t.Fjern);
            if (!liste.TryGetValue(adresse, out var m))
                liste[adresse] = m = new Mal { Adresse = adresse, Tjeneste = tj?.Navn, Land = land, Cdn = cdn, EierLand = tj?.Land };
            m.Antall++;
            var ip = t.Fjern.ToString();
            if (m.Ip.Count < 8 && !m.Ip.Any(x => x.Ip == ip)) m.Ip.Add(new IpSted(ip, land, cdn));
            var kilde = t.Lokal.ToString();
            if (m.KildeIp.Count < 4 && !m.KildeIp.Contains(kilde)) m.KildeIp.Add(kilde);
            var fil = p.Sti ?? p.Navn;
            if (m.Prosesser.Count < 4 && !m.Prosesser.Any(x => x.Pid == t.Pid)) m.Prosesser.Add(new Prosessfil(t.Pid, fil));
            if (nb.Tider.TryGetValue(t.Nokkel, out var tt))
            {
                if (m.Forst == null || tt.Forst < m.Forst) m.Forst = tt.Forst;
                if (m.Sist == null || tt.Sist > m.Sist) m.Sist = tt.Sist;
            }
            if (nb.Bytes != null && nb.Bytes.TryGetValue(t.Nokkel, out var b))
            {
                m.Ut = (m.Ut ?? 0) + b.Ut;
                m.Inn = (m.Inn ?? 0) + b.Inn;
            }
        }

        var farlige = new HashSet<string>(_regler.HoyrisikoLand, StringComparer.OrdinalIgnoreCase);
        foreach (var (f, liste) in mal)
        {
            lock (f)
            {
                f.Trafikk.Clear();
                f.Trafikk.AddRange(liste.Values.OrderByDescending(x => x.Ut ?? 0).ThenByDescending(x => x.Tjeneste != null).ThenByDescending(x => x.Antall).Take(15));
            }
            if (f.Bruk == null) f.Bruk = "Koblet til nettet nå.";
            f.Merk(Tilstand.KjorerNa); f.Sterkt();
            f.Tidspunkt(null, DateTime.Now);
            foreach (var m in liste.Values)
            {
                var land = m.EierLand != null && farlige.Contains(m.EierLand) ? m.EierLand : m.Land;
                if (land == null || !farlige.Contains(land)) continue;
                f.Risiko = Risiko.Rod;
                f.Advarsel(m.EierLand == land && m.Land != land
                    ? $"Sender data til et selskap i {IpLand.Navn(land)} ({m.Adresse})."
                    : $"Sender data til {IpLand.Navn(land)} ({m.Adresse}).");
            }
        }

        // Navn Windows nylig har slått opp. Viser AI som er brukt selv om forbindelsen er lukket, også i privat nettlesing.
        var nylig = new Dictionary<AiNettsted, SortedSet<string>>();
        // Vern mot falske spor: AI-skanner før 2.30.0 slo selv opp alle kjente AI-adresser via Windows, og de ligger
        // i bufferen til de går ut (opptil timer). Står de fleste navnene på lista i bufferen samtidig, er det
        // skannerens egne oppslag, ikke bruk. Da brukes ikke bufferen som bevis i dette søket.
        var kjente = new HashSet<string>(_regler.AiTjenester.Concat(_regler.AiNettsteder).SelectMany(t => t.Domener).Select(d => d.Trim('.').ToLowerInvariant()));
        int iBuffer = nb.DnsNavn.Count(n => kjente.Contains(n.Trim('.').ToLowerInvariant()));
        if (kjente.Count > 0 && iBuffer >= Math.Max(30, kjente.Count / 2))
        {
            DnsBufferForurenset = true;
            lock (Blindsoner) Blindsoner.Add("Windows' DNS-buffer ble ikke brukt: den er full av oppslag fra en eldre AI-skanner. Kjør «ipconfig /flushdns» som administrator og søk igjen.");
            Tilgangslogg.Logg("Nettverk", "Windows' DNS-buffer", Utfall.HoppetOver,
                $"brukes ikke som bevis: {iBuffer} av {kjente.Count} kjente AI-navn står i bufferen samtidig, som etter oppslag fra en eldre AI-skanner. Kjør «ipconfig /flushdns» og søk igjen.");
            return;
        }
        foreach (var n in nb.DnsNavn)
        {
            if (sett.Contains(n) || Tjeneste(n) is not { } tj) continue;
            if (!nylig.TryGetValue(tj, out var s)) nylig[tj] = s = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            s.Add(n);
        }
        // Bufferen sier bare at navnet er slått opp, ikke av hvem og ikke at noe ble sendt. Derfor «Bare slått opp»,
        // svakt spor, IP-en navnet pekte på, og at programmet er ukjent. Bruk kommer bare fra historikk eller tilkobling.
        var ipFor = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (ip, navn) in nb.Dns)
            foreach (var n in navn)
            {
                if (!ipFor.TryGetValue(n, out var l)) ipFor[n] = l = new List<string>();
                if (l.Count < 3) l.Add($"{ip}{(IpLand.Finn(ip) is { } k ? $" ({IpLand.Navn(k)})" : "")}");
            }
        string Bevis(string v) =>
            $"Windows' DNS-buffer: {v}{(ipFor.TryGetValue(v, out var ip) ? $" → {string.Join(", ", ip)}" : "")} · programmet som slo opp er ukjent (Windows lagrer det ikke) · ingen tilkobling sett under søket";
        var api = new List<(AiNettsted Tj, SortedSet<string> Verter)>();
        foreach (var (tj, verter) in nylig)
        {
            if (!_regler.AiTjenester.Contains(tj))
            {
                // Et AI-nettsted: legg til på nettstedsfunnet
                var f = LeggTil(tj.Navn, "Nettleser-AI (nettsted)", RisikoTekst.Fra(tj.Risiko), tj.Hvorfor, "Windows", null, enkelt: tj.Enkelt);
                f.Privat = true;
                f.Merk(Tilstand.SlattOpp);
                f.Svakt();
                f.Land ??= tj.Land;
                f.OpprinnelseLand ??= tj.Land;
                foreach (var v in verter) f.Detalj(Bevis(v));
            }
            else api.Add((tj, verter));
        }
        if (api.Count > 0)
        {
            bool fraLand = api.Any(a => a.Tj.Land != null && farlige.Contains(a.Tj.Land));
            var risiko = api.Select(a => RisikoTekst.Fra(a.Tj.Risiko)).Aggregate(Risiko.Gronn, RisikoTekst.Hoyeste);
            var f = LeggTil(AiTjenesterSlattOpp, "Skygge-AI", fraLand ? Risiko.Rod : RisikoTekst.Hoyeste(risiko, Risiko.Gul),
                AiTjenesterHvorfor, "Windows", null, enkelt: "AI-tjenester slått opp");
            f.Bruk = $"{string.Join(", ", api.Select(a => a.Tj.Navn).Distinct().Take(4))}.";
            f.Merk(Tilstand.SlattOpp);
            f.Svakt();
            foreach (var (tj, verter) in api)
                foreach (var v in verter) f.Detalj($"{Bevis(v)} · {tj.Navn}{(tj.Land != null ? ", " + IpLand.Navn(tj.Land) : "")}");
            if (fraLand) f.Advarsel("Minst én av tjenestene hører hjemme i et land der dataene ikke bør havne.");
            foreach (var (tj, _) in api) if (tj.Land != null && !f.SenderTil.Contains(tj.Land)) f.SenderTil.Add(tj.Land);
        }
    }

    internal const string AiTjenesterSlattOpp = "AI-tjenester slått opp på PC-en";
    internal const string AiTjenesterHvorfor = "Et program på PC-en har slått opp navnet til AI-tjenester. Et oppslag er ikke bruk: Windows lagrer ikke hvilket program som spurte eller om noe ble sendt.";

    internal Funn? FunnForProsess(string navn, string? sti)
    {
        var mappe = string.IsNullOrEmpty(sti) ? null : Path.GetDirectoryName(sti);
        if (mappe != null && _mappeFunn.TryGetValue(mappe, out var f)) return f;
        var regel = FinnRegel($"{navn} {sti}");
        if (regel == null) return null;
        lock (_funn) return _funn.TryGetValue(regel.Navn, out f) ? f : null;
    }

    /// <summary>Et program vi ikke visste var AI, men som snakker med en AI-tjeneste.</summary>
    private Funn SkjultAi(int pid, string prosess, string? sti, AiNettsted tj)
    {
        string produkt = prosess, utgiver = "";
        if (sti != null)
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(sti);
                if (!string.IsNullOrWhiteSpace(vi.ProductName)) produkt = vi.ProductName.Trim();
                utgiver = vi.CompanyName ?? "";
            }
            catch { }
        }
        bool kjent = KjenteUtgivere.Any(u => utgiver.Inneholder(u));
        bool fraNedlasting = sti != null && ErRisikabelPlass(sti);
        if (!kjent || fraNedlasting)
        {
            // Ukjent program mot en AI-tjeneste: et ukjent AI-spor, alltid rødt
            var u = Spor($"Ukjent program snakker med AI: {produkt}",
                $"Et program uten kjent utgiver har forbindelse til {tj.Navn}. Vi vet ikke hva det er eller hva det sender.", null);
            u.Detalj($"Program som kjører: {sti ?? prosess} (PID {pid}) · utgiver: {(string.IsNullOrWhiteSpace(utgiver) ? "ukjent" : utgiver.Trim())}");
            if (fraNedlasting) u.Advarsel("Kjører fra en nedlastings- eller midlertidig mappe, ikke fra en vanlig installasjon.");
            else u.Advarsel($"Ukjent program med forbindelse til {tj.Navn}.");
            HuskMappe(sti, u);
            return u;
        }
        var risiko = RisikoTekst.Fra(tj.Risiko);
        var f = LeggTil(produkt, "Skygge-AI", risiko,
            $"Programmet snakker med {tj.Navn} i bakgrunnen. Det kan sende innhold fra PC-en til en AI-tjeneste.",
            "Snakker med AI", null, enkelt: "Program som bruker AI i det stille");
        f.Detalj($"Program som kjører: {sti ?? prosess} (PID {pid})");
        HuskMappe(sti, f);
        return f;
    }

    /// <summary>Porter som nesten bare brukes av lokale AI-servere. Andre porter teller bare når programmet er kjent AI.</summary>
    private static readonly HashSet<int> AiPorter = new() { 11434, 1234, 4891, 1337 };

    /// <summary>
    /// Noen på en annen maskin bruker en lokal AI-server på denne PC-en: en etablert forbindelse inn til porten
    /// serveren lytter på, fra en adresse som ikke er PC-en selv. Ukjent AI-spor, alltid rødt.
    /// </summary>
    private void InnTilAiServer(NettBilde nb)
    {
        var lyttere = nb.Lyttere ?? TcpTabell.Hent();
        var porter = lyttere.ToLookup(l => (l.Pid, l.Port));
        var grupper = nb.Tilkoblinger
            .Where(t => t.Pid > 4 && !Plattform.ErEgen(t.Pid) && porter.Contains((t.Pid, t.LokalPort)) && !IPAddress.IsLoopback(t.Fjern))
            .GroupBy(t => (t.Pid, t.LokalPort));
        foreach (var g in grupper)
        {
            if (!nb.Prosesser.TryGetValue(g.Key.Pid, out var p)) continue;
            var ai = FunnForProsess(p.Navn, p.Sti);
            if (ai == null && !AiPorter.Contains(g.Key.LokalPort)) continue;
            var navn = ai != null ? Oversikt.Navn(ai) : p.Navn;
            var f = Spor($"AI-server brukt fra annen maskin: {navn}",
                $"En annen maskin er koblet til {navn} på port {g.Key.LokalPort} på denne PC-en. Vi vet ikke hvem det er eller hva den bruker AI-en til.", null);
            f.Advarsel($"Andre maskiner bruker {navn} på denne PC-en nå.");
            DateTime? forst = null, sist = null;
            foreach (var k in g.GroupBy(t => t.Fjern.ToString()).Take(20))
            {
                DateTime? a = null, b = null;
                foreach (var t in k)
                    if (nb.Tider.TryGetValue(t.Nokkel, out var tt))
                    {
                        if (a == null || tt.Forst < a) a = tt.Forst;
                        if (b == null || tt.Sist > b) b = tt.Sist;
                    }
                if (a < forst || forst == null) forst = a;
                if (b > sist || sist == null) sist = b;
                var land = IpLand.Navn(IpLand.Finn(k.First().Fjern));
                long? bytes = nb.Bytes == null ? null : k.Sum(t => nb.Bytes.TryGetValue(t.Nokkel, out var x) ? x.Ut + x.Inn : 0);
                f.ErstattDetalj($"Klient {k.Key}{(land != null ? $" ({land})" : "")} · port {g.Key.LokalPort} · ", $"Klient {k.Key}{(land != null ? $" ({land})" : "")} · port {g.Key.LokalPort} · {k.Count()} forbindelse{(k.Count() == 1 ? "" : "r")}"
                    + (bytes != null ? $" · {Rapport.Storrelse(bytes.Value)}" : "")
                    + (a != null ? $" · sett {a:HH:mm:ss}–{b:HH:mm:ss}" : " · sett nå"));
            }
            f.Detalj($"Program: {p.Sti ?? p.Navn} (PID {g.Key.Pid})");
            f.Tidspunkt(forst ?? DateTime.Now, sist ?? DateTime.Now);
            f.Bruk = $"{g.Select(t => t.Fjern).Distinct().Count()} klient(er) koblet til nå.";
            f.Merk(Tilstand.KjorerNa); f.Sterkt();
            _funnPid.GetOrAdd(f, _ => new HashSet<int>()).Add(g.Key.Pid);
        }

        // Program på PC-en som ikke er kjent AI, men bruker den lokale AI-serveren (PromptLock-mønsteret)
        var serverPid = new HashSet<int>(lyttere.Where(l => Nettverk.AiServerPorter.Contains(l.Port)).Select(l => l.Pid));
        foreach (var g in nb.Lokale.Where(t => t.Pid > 4 && !Plattform.ErEgen(t.Pid) && !serverPid.Contains(t.Pid)).GroupBy(t => t.Pid))
        {
            if (!nb.Prosesser.TryGetValue(g.Key, out var p) || FunnForProsess(p.Navn, p.Sti) != null) continue;
            var portene = string.Join(", ", g.Select(t => t.FjernPort).Distinct());
            var f = Spor($"Ukjent program bruker lokal AI-server: {p.Navn}",
                $"Et program som ikke er kjent som AI-app, er koblet til den lokale AI-serveren (port {portene}). Vi vet ikke hva det bruker modellen til.", null);
            f.Advarsel("Ukjent program bruker den lokale AI-modellen.");
            f.ErstattDetalj($"Program som kjører: {p.Sti ?? p.Navn} (PID {g.Key}) · port ", $"Program som kjører: {p.Sti ?? p.Navn} (PID {g.Key}) · port {portene} · {g.Count()} forbindelse{(g.Count() == 1 ? "" : "r")}");
            f.Tidspunkt(DateTime.Now, DateTime.Now);
            _funnPid.GetOrAdd(f, _ => new HashSet<int>()).Add(g.Key);
        }

        // Domener kjent fra AI-misbruk i DNS-bufferen
        var ioc = _regler.IocDomener.Where(d => nb.DnsNavn.Any(n => n.Equals(d.Domene, StringComparison.OrdinalIgnoreCase) || n.EndsWith("." + d.Domene, StringComparison.OrdinalIgnoreCase))).ToList();
        if (ioc.Count > 0)
        {
            var f = Spor("Domener kjent fra AI-misbruk slått opp",
                "Windows har nylig slått opp et domene som er kjent fra angrep der AI-verktøy eller falske AI-tjenester ble brukt. Vi vet ikke hvilket program som gjorde det.", null);
            f.Advarsel("Domene kjent fra AI-misbruk er slått opp på denne PC-en nylig.");
            foreach (var d in ioc) f.Detalj($"Windows har nylig slått opp: {d.Domene}{(d.Kilde != null ? " · " + d.Kilde : "")}");
            f.Tidspunkt(DateTime.Now, DateTime.Now);
        }
    }

    private readonly ConcurrentDictionary<string, string> _vertForIp = new();

    /// <summary>Navnet en IP-adresse hadde i DNS-bufferen under søket, ellers null.</summary>
    internal string? Vert(IPAddress ip) => _vertForIp.TryGetValue(ip.ToString(), out var v) ? v : null;

    /// <summary>
    /// Programmene som hører til et funn nå: de som hadde forbindelser i søket, og de som kjører fra samme mappe eller
    /// treffer samme regel. For AI-nettsteder er det nettleseren, men bare forbindelser til tjenestens adresser telles.
    /// </summary>
    internal (HashSet<int> Pider, HashSet<string>? IpFilter) ProsesserFor(Funn f)
    {
        var pider = _funnPid.TryGetValue(f, out var kjente) ? new HashSet<int>(kjente) : new HashSet<int>();
        HashSet<string>? filter = null;
        if (f.Kategori.Contains("(nettsted)"))
        {
            filter = new HashSet<string>(f.Trafikk.SelectMany(m => m.Ip.Select(i => i.Ip)));
            foreach (var p in Process.GetProcesses())
                using (p)
                    if (Nettleserprosesser.ContainsKey(p.ProcessName)) pider.Add(p.Id);
            return (pider, filter);
        }
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (p.Id <= 4 || Plattform.ErEgen(p.Id) || pider.Contains(p.Id)) continue;
                string? sti = null;
                try { sti = ProsessSti.Hent(p); } catch { }
                if (FunnForProsess(p.ProcessName, sti) == f) pider.Add(p.Id);
            }
        }
        return (pider, filter);
    }

    /// <summary>Kan «Følg med» vise noe for funnet: et program som kjørte eller hadde forbindelser under søket.</summary>
    public bool KanFolges(Funn f) =>
        _funnPid.ContainsKey(f) || f.Trafikk.Count > 0 || (f.Gruppe != "spor" && !f.Kategori.StartsWith("Nettleser-AI", StringComparison.Ordinal) && _mappeFunn.Values.Contains(f));
}
