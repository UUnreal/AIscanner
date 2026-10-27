using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Kartet i Datagrunnlag: alle steder søket rørte (disk, register, nettverk) som et tre, med antall, størrelse,
/// utfall og funn per sted. Bygges mens søket går, ligger bare i minnet og forsvinner med søket. Kommer aldri i
/// rapporten eller revisjonsloggen. Bare stier og navn, aldri innhold.
/// </summary>
public sealed class Kart
{
    public const string Disk = "Disk", Register = "Registeret", Nett = "Nettverk", Annet = "Annet";
    private const int MaksBarn = 150, MaksNoder = 25000;

    private sealed class Sted
    {
        public long Filer, Bytes;
        public readonly int[] Utfall = new int[Enum.GetValues(typeof(Utfall)).Length];
        public readonly HashSet<string> Sjekker = new();
        public readonly List<string> Detaljer = new();
        public DateTime Tid = DateTime.Now;
    }

    private readonly ConcurrentDictionary<string, Sted> _steder = new(StringComparer.OrdinalIgnoreCase);

    private static readonly Regex DiskSti = new(@"^(?:[A-Za-z]:\\|\\\\|/)", RegexOptions.Compiled);
    private static readonly Regex RegSti = new(@"^(?:HKCU|HKLM|HKU|HKCR|HKEY_[A-Z_]+)\\", RegexOptions.Compiled);
    private static readonly Regex DiskIFunn = new(@"(?:[A-Za-z]:\\|\\\\)[^:*?""<>|()·]+[^:*?""<>|()·\s]", RegexOptions.Compiled);
    private static readonly Regex UnixIFunn = new(@"(?<![\w/:])/[^:*?""<>|()·\s]+", RegexOptions.Compiled);   // bare for testing på Linux
    private static readonly Regex RegIFunn = new(@"(?:HKCU|HKLM|HKU|HKCR|HKEY_[A-Z_]+)\\[^·:«»]+[^·:«»\s]", RegexOptions.Compiled);

    /// <summary>Gjør om det loggen kaller «mål» til en plass i treet: Disk\C:\…, Registeret\HKCU\…, Nettverk\…, Annet\…</summary>
    public static string Plass(string hva, string mal)
    {
        mal = mal.Trim();
        if (DiskSti.IsMatch(mal)) return Disk + "\\" + mal.Replace('/', '\\').TrimEnd('\\');
        if (hva == "Register" || RegSti.IsMatch(mal)) return Register + "\\" + mal.TrimEnd('\\');
        if (hva is "Nettverk" or "Port") return Nett + "\\" + mal.Replace('\\', '/');
        return Annet + "\\" + hva + "\\" + mal.Replace('\\', '/');
    }

    public void Legg(string plass, string sjekk, Utfall utfall, string? detalj = null, long filer = 0, long bytes = 0)
    {
        var s = _steder.GetOrAdd(plass, _ => new Sted());
        lock (s)
        {
            s.Utfall[(int)utfall]++;
            s.Filer += filer;
            s.Bytes += bytes;
            if (s.Sjekker.Count < 8) s.Sjekker.Add(sjekk);
            if (detalj != null && s.Detaljer.Count < 3 && !s.Detaljer.Contains(detalj)) s.Detaljer.Add(detalj);
        }
    }

    /// <summary>Hvert sted per utfall (opptil <paramref name="maks"/> per utfall), så tallene i Datagrunnlag kan åpnes som lister.</summary>
    public IEnumerable<(string Rot, string Sti, Utfall Utfall, int Antall, string Sjekk, string? Detalj, string Plass)> Steder(int maks)
    {
        var tatt = new int[Enum.GetValues(typeof(Utfall)).Length];
        foreach (var (plass, s) in _steder.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase))
        {
            int i = plass.IndexOf('\\');
            var rot = i < 0 ? plass : plass.Substring(0, i);
            var sti = i < 0 ? "" : plass.Substring(i + 1);
            if (rot == Annet && sti.IndexOf('\\') is var j && j > 0) { rot = sti.Substring(0, j); sti = sti.Substring(j + 1); }
            lock (s)
                for (int u = 0; u < s.Utfall.Length; u++)
                    if (s.Utfall[u] > 0 && tatt[u]++ < maks)
                        yield return (rot, sti, (Utfall)u, s.Utfall[u], s.Sjekker.FirstOrDefault() ?? "", s.Detaljer.FirstOrDefault(), plass);
        }
    }

    /// <summary>Stiene og registernøklene et funn peker på, slik at funnet kan merkes på kartet.</summary>
    public static IEnumerable<string> StederFor(Funn f)
    {
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var disk = Path.DirectorySeparatorChar == '/' ? UnixIFunn : DiskIFunn;
        foreach (var t in f.Detaljer.Concat(f.Hvor))
        {
            foreach (Match m in disk.Matches(t))
            {
                var p = Disk + "\\" + m.Value.Replace('/', '\\').TrimEnd('\\');
                if (sett.Add(p)) yield return p;
            }
            foreach (Match m in RegIFunn.Matches(t)) if (sett.Add(Register + "\\" + m.Value.TrimEnd('\\'))) yield return Register + "\\" + m.Value.TrimEnd('\\');
        }
    }

    private sealed class Node
    {
        public string Navn = "", Sti = "";
        public Sted? Eget;
        public readonly Dictionary<string, Node> Barn = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<int> Funn = new();
        public long Antall, Bytes;
        public int Risiko = -1;   // høyeste risiko blant funn her eller under: 0 lav, 1 middels, 2 høy
        public readonly int[] Utfall = new int[Enum.GetValues(typeof(Utfall)).Length];
    }

    /// <summary>Treet som sendes til vinduet. Lange kjeder med én undermappe slås sammen, store mapper kuttes til de største.</summary>
    public object Tre(IReadOnlyList<Funn>? funn, Func<string?, string> t)
    {
        var rot = new Node { Navn = "PC-en" };
        Node Finn(string plass)
        {
            var n = rot;
            var sti = "";
            foreach (var del in plass.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                sti = sti.Length == 0 ? del : sti + "\\" + del;
                if (!n.Barn.TryGetValue(del, out var b)) n.Barn[del] = b = new Node { Navn = del, Sti = sti };
                n = b;
            }
            return n;
        }
        foreach (var (plass, s) in _steder) Finn(plass).Eget = s;
        if (funn != null)
            for (int i = 0; i < funn.Count; i++)
                foreach (var p in StederFor(funn[i]))
                {
                    var n = Finn(p);
                    if (!n.Funn.Contains(i)) n.Funn.Add(i);
                }

        int Risikotall(Risiko r) => r switch { Risiko.Rod => 2, Risiko.Gul => 1, _ => 0 };
        void Summer(Node n)
        {
            foreach (var b in n.Barn.Values)
            {
                Summer(b);
                n.Antall += b.Antall; n.Bytes += b.Bytes; n.Risiko = Math.Max(n.Risiko, b.Risiko);
                for (int i = 0; i < n.Utfall.Length; i++) n.Utfall[i] += b.Utfall[i];
            }
            if (n.Eget is { } e)
            {
                lock (e)
                {
                    n.Antall += e.Filer + e.Utfall.Sum();
                    n.Bytes += e.Bytes;
                    for (int i = 0; i < n.Utfall.Length; i++) n.Utfall[i] += e.Utfall[i];
                }
            }
            foreach (var i in n.Funn) n.Risiko = Math.Max(n.Risiko, Risikotall(funn![i].Risiko));
            if (n.Funn.Count > 0 && n.Antall == 0) n.Antall = 1;
        }
        Summer(rot);

        var navn = Enum.GetValues(typeof(Utfall)).Cast<Utfall>().Select(u => u.ToString().ToLowerInvariant()).ToArray();
        int noder = 0;
        object Ut(Node n, string visNavn, int dybde)
        {
            noder++;
            // C:\ → Users → navn → AppData: én kjede uten egne data vises som ett trinn
            var kjede = n;
            while (kjede.Barn.Count == 1 && kjede.Eget == null && kjede.Funn.Count == 0 && dybde > 1)
            {
                kjede = kjede.Barn.Values.First();
                visNavn += "\\" + kjede.Navn;
            }
            n = kjede;
            var barn = n.Barn.Values.OrderByDescending(b => b.Antall).ThenByDescending(b => b.Bytes).ToList();
            var vis = noder < MaksNoder ? barn.Take(MaksBarn).ToList() : new List<Node>();
            var resten = barn.Skip(vis.Count).ToList();
            var c = vis.Select(b => Ut(b, b.Navn, dybde + 1)).ToList();
            if (resten.Count > 0)
                c.Add(new { n = resten.Count.ToString(), a = resten.Sum(b => b.Antall), b = resten.Sum(b => b.Bytes), r = resten.Max(b => b.Risiko), rest = true,
                    u = Utfallene(resten.Aggregate(new int[navn.Length], (sum, b) => { for (int i = 0; i < sum.Length; i++) sum[i] += b.Utfall[i]; return sum; }), navn) });
            var e = n.Eget;
            return new
            {
                n = visNavn,
                s = n.Sti.Length == 0 ? null : n.Sti,
                a = n.Antall,
                b = n.Bytes,
                r = n.Risiko,
                u = Utfallene(n.Utfall, navn),
                f = n.Funn.Count > 0 ? n.Funn : null,
                k = e == null ? null : e.Sjekker.Select(t).ToList(),
                d = e == null || e.Detaljer.Count == 0 ? null : e.Detaljer.Select(t).ToList(),
                fi = e?.Filer > 0 ? e.Filer : (long?)null,
                c = c.Count > 0 ? c : null,
            };
        }
        return Ut(rot, "PC-en", 0);
    }

    private static Dictionary<string, int>? Utfallene(int[] u, string[] navn)
    {
        Dictionary<string, int>? d = null;
        for (int i = 0; i < u.Length; i++) if (u[i] > 0) (d ??= new())[navn[i]] = u[i];
        return d;
    }
}
