using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

namespace AISkanner;

/// <summary>Øyeblikksbilde av nettverket: hvem som er koblet til hva akkurat nå.</summary>
internal sealed class NettBilde
{
    public List<Tilkobling> Tilkoblinger = new();
    public Dictionary<IPAddress, List<string>> Dns = new();
    public List<string> DnsNavn = new();
    public Dictionary<int, (string Navn, string? Sti)> Prosesser = new();
    /// <summary>Målte byte per forbindelse, eller null når vi ikke kjører som administrator.</summary>
    public Dictionary<string, (long Ut, long Inn)>? Bytes;
    public double Sekunder;

    public static NettBilde Hent(Datamaling? maling)
    {
        var nb = new NettBilde { Tilkoblinger = Nettverk.Tilkoblinger() };
        nb.Dns = Nettverk.DnsBuffer(out nb.DnsNavn);
        foreach (var pid in nb.Tilkoblinger.Select(t => t.Pid).Distinct())
        {
            if (pid <= 4 || pid == Plattform.EgenPid) continue;
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

    /// <summary>Kun for testing: erstatter det ekte nettverksbildet.</summary>
    internal Func<NettBilde>? TestNett { get; set; }

    private static readonly Dictionary<string, string> Nettleserprosesser = new(StringComparer.OrdinalIgnoreCase)
    {
        ["chrome"] = "Chrome", ["msedge"] = "Edge", ["firefox"] = "Firefox", ["brave"] = "Brave", ["opera"] = "Opera",
        ["vivaldi"] = "Vivaldi", ["arc"] = "Arc", ["waterfox"] = "Waterfox", ["librewolf"] = "LibreWolf", ["iexplore"] = "Internet Explorer",
    };

    private void HuskMappe(string? exe, Funn f)
    {
        var mappe = string.IsNullOrEmpty(exe) ? null : Path.GetDirectoryName(exe);
        if (!string.IsNullOrEmpty(mappe) && !ErSystemmappe(mappe!)) _mappeFunn.TryAdd(mappe!, f);
    }

    private AiNettsted? Tjeneste(string vert) =>
        _regler.AiTjenester.FirstOrDefault(t => t.Treffer(vert)) ?? FinnNettsted(vert);

    private void Trafikk(NettBilde nb)
    {
        DataMalt = nb.Bytes != null;
        MaleSekunder = nb.Sekunder;

        (string? Vert, AiNettsted? Tj) Navn(IPAddress ip)
        {
            if (!nb.Dns.TryGetValue(ip, out var navn) || navn.Count == 0) return (null, null);
            foreach (var n in navn)
                if (Tjeneste(n) is { } t) return (n, t);
            return (navn[0], null);
        }

        var oppslag = new Dictionary<Tilkobling, (string? Vert, AiNettsted? Tj)>();
        foreach (var t in nb.Tilkoblinger) oppslag[t] = Navn(t.Fjern);
        // Programmer vi ikke kjente som AI, men som snakker med en AI-tjeneste. Da vises alt programmet er koblet til.
        var skjulte = new Dictionary<int, Funn>();
        foreach (var t in nb.Tilkoblinger)
        {
            if (skjulte.ContainsKey(t.Pid) || oppslag[t].Tj is not { } tj || !nb.Prosesser.TryGetValue(t.Pid, out var p)) continue;
            if (t.Pid <= 4 || t.Pid == Plattform.EgenPid || Nettleserprosesser.ContainsKey(p.Navn) || FunnForProsess(p.Navn, p.Sti) != null) continue;
            skjulte[t.Pid] = SkjultAi(t.Pid, p.Navn, p.Sti, tj);
        }

        var mal = new Dictionary<Funn, Dictionary<string, Mal>>();
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in nb.Tilkoblinger)
        {
            if (t.Pid <= 4 || t.Pid == Plattform.EgenPid || !nb.Prosesser.TryGetValue(t.Pid, out var p)) continue;
            var (vert, tj) = oppslag[t];
            Funn? f;
            if (Nettleserprosesser.TryGetValue(p.Navn, out var nettleser))
            {
                if (tj == null) continue;   // annen surfing angår ikke oss
                f = LeggTil(tj.Navn, "Nettleser-AI (nettsted)", RisikoTekst.Fra(tj.Risiko), tj.Hvorfor, nettleser, null, enkelt: tj.Enkelt, rad: tj.Rad);
                f.Privat = true;
                f.Bruk = f.Bruk == null ? $"Åpen i {nettleser} nå." : f.Bruk.TrimEnd('.') + $". Åpen i {nettleser} nå.";
            }
            else
            {
                f = skjulte.TryGetValue(t.Pid, out var sk) ? sk : FunnForProsess(p.Navn, p.Sti);
                if (f == null) continue;
            }
            if (vert != null) sett.Add(vert);

            var adresse = vert ?? t.Fjern.ToString();
            if (!mal.TryGetValue(f, out var liste)) mal[f] = liste = new Dictionary<string, Mal>(StringComparer.OrdinalIgnoreCase);
            if (!liste.TryGetValue(adresse, out var m))
                liste[adresse] = m = new Mal { Adresse = adresse, Tjeneste = tj?.Navn, Land = IpLand.Finn(t.Fjern), EierLand = tj?.Land };
            m.Antall++;
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
        foreach (var n in nb.DnsNavn)
        {
            if (sett.Contains(n) || Tjeneste(n) is not { } tj) continue;
            if (!nylig.TryGetValue(tj, out var s)) nylig[tj] = s = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            s.Add(n);
        }
        var api = new List<(AiNettsted Tj, SortedSet<string> Verter)>();
        foreach (var (tj, verter) in nylig)
        {
            if (!_regler.AiTjenester.Contains(tj))
            {
                // Et AI-nettsted: legg til på nettstedsfunnet
                var f = LeggTil(tj.Navn, "Nettleser-AI (nettsted)", RisikoTekst.Fra(tj.Risiko), tj.Hvorfor, "Windows", null, enkelt: tj.Enkelt, rad: tj.Rad);
                f.Privat = true;
                f.Bruk ??= "Åpnet nylig.";
                foreach (var v in verter) f.Detalj($"Windows har nylig slått opp: {v}");
            }
            else api.Add((tj, verter));
        }
        if (api.Count > 0)
        {
            bool fraLand = api.Any(a => a.Tj.Land != null && farlige.Contains(a.Tj.Land));
            var risiko = api.Select(a => RisikoTekst.Fra(a.Tj.Risiko)).Aggregate(Risiko.Gronn, RisikoTekst.Hoyeste);
            var f = LeggTil("AI-tjenester kontaktet nylig", "Skygge-AI", fraLand ? Risiko.Rod : RisikoTekst.Hoyeste(risiko, Risiko.Gul),
                "Et program på PC-en har nylig snakket med AI-tjenester. Windows forteller ikke hvilket program, bare at navnet ble slått opp.",
                "Windows", null, enkelt: "AI-tjenester kontaktet", rad: "Søk igjen mens programmene er åpne for å se hvem som sender.");
            f.Bruk = $"{string.Join(", ", api.Select(a => a.Tj.Navn).Distinct().Take(4))}.";
            foreach (var (tj, verter) in api)
                foreach (var v in verter) f.Detalj($"Windows har nylig slått opp: {v} ({tj.Navn}{(tj.Land != null ? ", " + IpLand.Navn(tj.Land) : "")})");
            if (fraLand) f.Advarsel("Minst én av tjenestene hører hjemme i et land der dataene ikke bør havne.");
        }
    }

    private Funn? FunnForProsess(string navn, string? sti)
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
        var risiko = kjent && !fraNedlasting ? RisikoTekst.Fra(tj.Risiko) : Risiko.Rod;
        var f = LeggTil(produkt, "Skygge-AI", risiko,
            $"Programmet snakker med {tj.Navn} i bakgrunnen. Det kan sende innhold fra PC-en til en AI-tjeneste.",
            "Snakker med AI", null, enkelt: "Program som bruker AI i det stille",
            rad: kjent ? "Sjekk at bruken er godkjent." : "Finn ut hva programmet er og hva det sender. Avinstaller det hvis ingen vet.");
        f.Detalj($"Program som kjører: {sti ?? prosess} (PID {pid})");
        if (fraNedlasting) f.Advarsel("Kjører fra en nedlastings- eller midlertidig mappe, ikke fra en vanlig installasjon.");
        return f;
    }
}
