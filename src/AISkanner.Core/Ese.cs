using System.Text;

namespace AISkanner;

/// <summary>
/// Minimal leser for ESE-databaser (Extensible Storage Engine), nok til å lese tabeller med faste kolonner og korte
/// tagged-kolonner, som SRUM (System32\sru\SRUDB.dat). Bare lesing, rett fra strømmen, ingenting skrives eller kopieres.
/// Format: libesedb-dokumentasjonen (Joachim Metz), «Extensible Storage Engine (ESE) Database File (EDB) format».
/// </summary>
internal sealed class EseFil
{
    private readonly Stream _s;
    public int Side { get; }
    private readonly bool _stor;
    private readonly int _hode;
    public int SiderLest { get; private set; }
    private readonly Dictionary<string, Tabell> _tabeller = new(StringComparer.OrdinalIgnoreCase);

    public sealed class Kolonne { public int Id; public int Type; public int Storrelse; public string Navn = ""; }
    public sealed class Tabell { public int ObjId; public uint Rot; public string Navn = ""; public Dictionary<int, Kolonne> Kolonner = new(); }

    public EseFil(Stream s)
    {
        _s = s;
        var h = new byte[668];
        s.Position = 0;
        if (Les(h, 0, h.Length) < h.Length || BitConverter.ToUInt32(h, 4) != 0x89ABCDEF) throw new InvalidDataException("ikke en ESE-database");
        Side = (int)BitConverter.ToUInt32(h, 236);
        if (Side is not (2048 or 4096 or 8192 or 16384 or 32768)) throw new InvalidDataException($"ukjent sidestørrelse {Side}");
        _stor = Side >= 16384;
        _hode = _stor ? 80 : 40;
        LesKatalog();
    }

    private int Les(byte[] b, int off, int n)
    {
        int lest = 0;
        while (lest < n) { int r = _s.Read(b, off + lest, n - lest); if (r <= 0) break; lest += r; }
        return lest;
    }

    private byte[]? LesSide(uint nr)
    {
        var b = new byte[Side];
        long pos = (long)(nr + 1) * Side;
        if (pos + Side > _s.Length) return null;
        _s.Position = pos;
        if (Les(b, 0, Side) < Side) return null;
        SiderLest++;
        return b;
    }

    private static ushort U16(byte[] b, int o) => o >= 0 && o + 2 <= b.Length ? BitConverter.ToUInt16(b, o) : (ushort)0;
    public int Feil { get; private set; }

    /// <summary>Verdiene på en side (tag 1 og utover): start, lengde og flagg.</summary>
    private IEnumerable<(int Start, int Lengde, int Flagg)> Tagger(byte[] p)
    {
        int antall = U16(p, 34);
        for (int i = 1; i < antall; i++)
        {
            int pos = Side - 4 * (i + 1);
            if (pos < _hode) yield break;
            ushort a = U16(p, pos), b = U16(p, pos + 2);
            int lengde, start, flagg;
            if (_stor) { lengde = a & 0x7FFF; start = _hode + (b & 0x7FFF); flagg = start + 1 < Side ? U16(p, start) >> 13 : 0; }
            else { lengde = a & 0x1FFF; start = _hode + (b & 0x1FFF); flagg = b >> 13; }
            if (lengde <= 0 || start + lengde > Side) continue;
            yield return (start, lengde, flagg);
        }
    }

    /// <summary>Hva rotsiden til en tabell inneholder: flagg, eier og antall verdier. Viser hvorfor en tabell gir 0 poster.</summary>
    public string RotInfo(Tabell t)
    {
        var p = LesSide(t.Rot);
        if (p == null) return $"rotside {t.Rot} ligger utenfor fila ({_s.Length / Side} sider)";
        uint flagg = BitConverter.ToUInt32(p, 36);
        int eier = BitConverter.ToInt32(p, 24), tagger = U16(p, 34);
        var tom = eier == 0 && flagg == 0;
        return $"rotside {t.Rot}: flagg 0x{flagg:X}, eier {eier} (tabell {t.ObjId}), {tagger} verdier{(tom ? ", siden er tom i fila (ikke skrevet fra Windows' logg ennå)" : eier != t.ObjId ? ", siden tilhører en annen tabell" : "")}";
    }

    /// <summary>Alle poster i et B-tre (bladsidene), som (side, start, lengde) for postdataene.</summary>
    public IEnumerable<(byte[] Side, int Start, int Lengde)> Poster(uint rot, Func<bool>? stopp = null)
    {
        var stabel = new Stack<uint>();
        var sett = new HashSet<uint>();
        stabel.Push(rot);
        while (stabel.Count > 0)
        {
            if (stopp?.Invoke() == true) yield break;
            var nr = stabel.Pop();
            if (!sett.Add(nr) || sett.Count > 2_000_000) continue;
            var p = LesSide(nr);
            if (p == null) continue;
            uint flagg = BitConverter.ToUInt32(p, 36);
            bool blad = (flagg & 0x2) != 0, forelder = (flagg & 0x4) != 0;
            if ((flagg & 0x20) != 0 || (flagg & 0x40) != 0 || (flagg & 0x80) != 0) continue; // plass-, indeks- og LV-trær
            var barn = new List<uint>();
            var poster = new List<(byte[], int, int)>();
            try
            {
                foreach (var (start, lengde, tf) in Tagger(p))
                {
                    int o = start, slutt = start + lengde;
                    if ((tf & 0x4) != 0) o += 2; // felles nøkkel
                    if (o + 2 > slutt) continue;
                    int lokal = U16(p, o) & 0x1FFF;
                    o += 2 + lokal;
                    if (o > slutt) continue;
                    if (forelder && !blad) { if (slutt - 4 >= o) barn.Add(BitConverter.ToUInt32(p, slutt - 4)); }
                    else if (blad && (tf & 0x2) == 0) poster.Add((p, o, slutt - o));
                }
            }
            catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException) { Feil++; }
            foreach (var x in poster) yield return x;
            for (int i = barn.Count - 1; i >= 0; i--) stabel.Push(barn[i]);
        }
    }

    /// <summary>En post delt i faste, variable og tagged kolonner.</summary>
    public sealed class Post
    {
        private readonly byte[] _p; private readonly int _start, _lengde;
        private readonly Dictionary<int, Kolonne> _k;
        private readonly bool _stor;
        public Post(byte[] p, int start, int lengde, Dictionary<int, Kolonne> k, bool stor) { _p = p; _start = start; _lengde = lengde; _k = k; _stor = stor; }

        private int SisteFast => _start + 4 <= _p.Length ? _p[_start] : 0;
        private int SisteVariabel => _start + 4 <= _p.Length ? _p[_start + 1] : 0;
        private int VarStart => U16(_p, _start + 2);

        public (int Start, int Lengde)? Fast(int id)
        {
            if (id > SisteFast) return null;
            int o = _start + 4;
            for (int i = 1; i < id; i++) o += _k.TryGetValue(i, out var c) ? Storrelse(c) : 0;
            if (!_k.TryGetValue(id, out var k)) return null;
            int n = Storrelse(k);
            // Nullbiter etter de faste dataene: satt bit = tom verdi
            // Nullbitene står rett før de variable dataene
            int bitmap = _start + VarStart - (SisteFast + 7) / 8;
            int nr = id - 1;
            if (bitmap >= 0 && bitmap + nr / 8 < Math.Min(_p.Length, _start + _lengde) && (_p[bitmap + nr / 8] & (1 << (nr % 8))) != 0) return null;
            return o + n <= _start + _lengde ? (o, n) : null;
        }

        public (int Start, int Lengde)? Variabel(int id)
        {
            if (id < 128 || id > SisteVariabel) return null;
            int antall = SisteVariabel - 127, tabell = _start + VarStart, data = tabell + 2 * antall;
            int forrige = 0;
            for (int i = 128; i <= id; i++)
            {
                int v = U16(_p, tabell + 2 * (i - 128));
                int slutt = v & 0x7FFF;
                if (i == id) return (v & 0x8000) != 0 || slutt < forrige ? null : (data + forrige, slutt - forrige);
                if ((v & 0x8000) == 0) forrige = slutt;
            }
            return null;
        }

        /// <summary>Tagged kolonne (id 256+): verdien og flaggene (0x02 komprimert, 0x04 lagret som lang verdi).</summary>
        public (int Start, int Lengde, int Flagg)? Tagget(int id)
        {
            int antall = SisteVariabel >= 128 ? SisteVariabel - 127 : 0, tabell = _start + VarStart;
            int varSlutt = 0;
            for (int i = 0; i < antall; i++) { int v = U16(_p, tabell + 2 * i); if ((v & 0x8000) == 0) varSlutt = v & 0x7FFF; }
            int t = tabell + 2 * antall + varSlutt, slutt = _start + _lengde;
            if (t + 4 > slutt) return null;
            int forste = U16(_p, t + 2) & (_stor ? 0x7FFF : 0x3FFF);
            int n = forste / 4;
            for (int i = 0; i < n && t + 4 * i + 4 <= slutt; i++)
            {
                int kol = U16(_p, t + 4 * i), raa = U16(_p, t + 4 * i + 2);
                if (kol != id) continue;
                int fra = raa & (_stor ? 0x7FFF : 0x3FFF);
                int til = i + 1 < n ? U16(_p, t + 4 * (i + 1) + 2) & (_stor ? 0x7FFF : 0x3FFF) : slutt - t;
                if (fra > til || t + til > slutt) return null;
                bool harFlagg = _stor || (raa & 0x4000) != 0;
                int flagg = harFlagg && til > fra && t + fra < _p.Length ? _p[t + fra] : 0;
                return harFlagg ? (t + fra + 1, til - fra - 1, flagg) : (t + fra, til - fra, 0);
            }
            return null;
        }

        public long? Tall(int id)
        {
            if (Fast(id) is not { } v) return null;
            if (v.Start < 0 || v.Start + v.Lengde > _p.Length) return null;
            return v.Lengde switch { 1 => _p[v.Start], 2 => BitConverter.ToInt16(_p, v.Start), 4 => BitConverter.ToInt32(_p, v.Start), 8 => BitConverter.ToInt64(_p, v.Start), _ => null };
        }

        public DateTime? Tid(int id)
        {
            if (Fast(id) is not { Lengde: 8 } v || v.Start < 0 || v.Start + 8 > _p.Length) return null;
            var d = BitConverter.ToDouble(_p, v.Start);
            if (d is > 30000 and < 80000) return DateTime.FromOADate(d);
            // Noen kolonner lagrer tiden som FILETIME (100 ns siden 1601)
            var ft = BitConverter.ToInt64(_p, v.Start);
            return ft is > 125911584000000000 and < 157469184000000000 ? DateTime.FromFileTimeUtc(ft).ToLocalTime() : null;
        }

        public string? Tekst(int id)
        {
            var v = Variabel(id);
            if (v == null || v.Value.Start < 0 || v.Value.Lengde < 0 || v.Value.Start + v.Value.Lengde > _p.Length) return null;
            return Encoding.ASCII.GetString(_p, v.Value.Start, v.Value.Lengde).TrimEnd('\0');
        }

        /// <summary>Binær verdi fra en tagged kolonne. Komprimert 7-bit blir pakket ut; lange verdier og Xpress leses ikke.</summary>
        public byte[]? Binar(int id, out bool hoppetOver)
        {
            hoppetOver = false;
            if (Tagget(id) is not { } v) return null;
            if ((v.Flagg & 0x04) != 0) { hoppetOver = true; return null; }
            if (v.Start < 0 || v.Lengde < 0 || v.Start + v.Lengde > _p.Length) return null;
            var b = new byte[v.Lengde];
            Array.Copy(_p, v.Start, b, 0, v.Lengde);
            if ((v.Flagg & 0x02) == 0 || b.Length == 0) return b;
            int type = b[0] >> 3;
            if (type is 1 or 2) return SjuBit(b, type == 2);
            hoppetOver = true;
            return null;
        }

        private static byte[] SjuBit(byte[] b, bool unicode)
        {
            var ut = new List<byte>();
            int bits = 0, buf = 0;
            for (int i = 1; i < b.Length; i++)
            {
                buf |= b[i] << bits; bits += 8;
                while (bits >= 7) { ut.Add((byte)(buf & 0x7F)); if (unicode) ut.Add(0); buf >>= 7; bits -= 7; }
            }
            return ut.ToArray();
        }
    }

    private static int Storrelse(Kolonne k) => k.Type switch
    {
        1 or 2 => 1, 3 or 17 => 2, 4 or 6 or 14 => 4, 5 or 7 or 8 or 15 => 8, 16 => 16, _ => k.Storrelse,
    };

    public Post Tolk((byte[] Side, int Start, int Lengde) r, Tabell t) => new(r.Side, r.Start, r.Lengde, t.Kolonner, _stor);

    public Tabell? Finn(string navn) => _tabeller.TryGetValue(navn, out var t) ? t : null;
    public IEnumerable<Tabell> Tabeller => _tabeller.Values;

    private void LesKatalog()
    {
        // MSysObjects: rot på side 4. Faste kolonner: 1 ObjidTable, 2 Type, 3 Id, 4 ColtypOrPgnoFDP, 5 SpaceUsage. Navn er variabel 128.
        var kat = new Dictionary<int, Kolonne>
        {
            [1] = new() { Id = 1, Type = 4 }, [2] = new() { Id = 2, Type = 3 }, [3] = new() { Id = 3, Type = 4 },
            [4] = new() { Id = 4, Type = 4 }, [5] = new() { Id = 5, Type = 4 }, [6] = new() { Id = 6, Type = 4 },
            [7] = new() { Id = 7, Type = 4 }, [8] = new() { Id = 8, Type = 1 }, [9] = new() { Id = 9, Type = 3 },
            [10] = new() { Id = 10, Type = 4 }, [11] = new() { Id = 11, Type = 17 }, [12] = new() { Id = 12, Type = 17 },
        };
        var perId = new Dictionary<int, Tabell>();
        var kolonner = new List<(int Tabell, Kolonne K)>();
        foreach (var r in Poster(4))
        {
          try
          {
            var p = new Post(r.Side, r.Start, r.Lengde, kat, _stor);
            var type = p.Tall(2);
            var navn = p.Tekst(128);
            if (navn == null) continue;
            if (type == 1 && p.Tall(3) is { } id && p.Tall(4) is { } rot)
                perId[(int)id] = _tabeller[navn] = new Tabell { ObjId = (int)id, Rot = (uint)rot, Navn = navn };
            else if (type == 2 && p.Tall(1) is { } tab && p.Tall(3) is { } kid && p.Tall(4) is { } kt)
                kolonner.Add(((int)tab, new Kolonne { Id = (int)kid, Type = (int)kt, Storrelse = (int)(p.Tall(5) ?? 0), Navn = navn }));
          }
          catch (ArgumentException) { Feil++; }
          catch (IndexOutOfRangeException) { Feil++; }
        }
        foreach (var (tab, k) in kolonner) if (perId.TryGetValue(tab, out var t)) t.Kolonner[k.Id] = k;
    }

    public int? KolonneId(Tabell t, string navn) => t.Kolonner.Values.FirstOrDefault(k => k.Navn.Equals(navn, StringComparison.OrdinalIgnoreCase))?.Id;
}
