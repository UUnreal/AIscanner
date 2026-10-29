using System.Text;

namespace AISkanner;

/// <summary>
/// Leser en registerfil (regf) direkte fra bytene, uten å laste den inn i Windows' register. Brukes for Amcache.hve,
/// som Windows holder låst. Bare lesing, og bare i minnet. Transaksjonsloggene (.LOG1/.LOG2) tas ikke med, så de siste
/// minuttenes endringer kan mangle.
/// </summary>
internal sealed class Hive
{
    private readonly byte[] _b;
    private const int Bin = 4096;

    private Hive(byte[] b) { _b = b; }

    public static Hive? Fra(byte[] b)
    {
        if (b.Length < Bin + 32 || Encoding.ASCII.GetString(b, 0, 4) != "regf") return null;
        return new Hive(b);
    }

    public Nokkel? Rot => Nk(BitConverter.ToInt32(_b, 0x24));

    public sealed class Nokkel
    {
        internal int Celle;
        public string Navn = "";
        public DateTime Endret;
        internal int AntallUnder, UnderListe, AntallVerdier, VerdiListe;
    }

    private int Pos(int celle) => Bin + celle;

    private bool Gyldig(int celle, int lengde) => celle >= 0 && Pos(celle) + 4 + lengde <= _b.Length;

    private Nokkel? Nk(int celle)
    {
        if (!Gyldig(celle, 0x4C)) return null;
        int p = Pos(celle) + 4;
        if (_b[p] != (byte)'n' || _b[p + 1] != (byte)'k') return null;
        int flagg = BitConverter.ToUInt16(_b, p + 2);
        int navnLengde = BitConverter.ToUInt16(_b, p + 0x48);
        if (p + 0x4C + navnLengde > _b.Length) return null;
        var navn = (flagg & 0x20) != 0 ? Encoding.GetEncoding(28591).GetString(_b, p + 0x4C, navnLengde) : Encoding.Unicode.GetString(_b, p + 0x4C, navnLengde);
        long ft = BitConverter.ToInt64(_b, p + 4);
        return new Nokkel
        {
            Celle = celle, Navn = navn,
            Endret = ft > 0 && ft < DateTime.MaxValue.ToFileTimeUtc() ? DateTime.FromFileTimeUtc(ft).ToLocalTime() : DateTime.MinValue,
            AntallUnder = BitConverter.ToInt32(_b, p + 0x14), UnderListe = BitConverter.ToInt32(_b, p + 0x1C),
            AntallVerdier = BitConverter.ToInt32(_b, p + 0x24), VerdiListe = BitConverter.ToInt32(_b, p + 0x28),
        };
    }

    public IEnumerable<Nokkel> Under(Nokkel k)
    {
        if (k.AntallUnder <= 0) yield break;
        foreach (var c in Liste(k.UnderListe, 0))
            if (Nk(c) is { } n) yield return n;
    }

    private IEnumerable<int> Liste(int celle, int dybde)
    {
        if (dybde > 4 || !Gyldig(celle, 4)) yield break;
        int p = Pos(celle) + 4;
        var sig = Encoding.ASCII.GetString(_b, p, 2);
        int antall = BitConverter.ToUInt16(_b, p + 2);
        int steg = sig is "lf" or "lh" ? 8 : 4;
        if (sig is not ("lf" or "lh" or "li" or "ri") || p + 4 + antall * steg > _b.Length) yield break;
        for (int i = 0; i < antall; i++)
        {
            int c = BitConverter.ToInt32(_b, p + 4 + i * steg);
            if (sig == "ri") foreach (var x in Liste(c, dybde + 1)) yield return x;
            else yield return c;
        }
    }

    public Nokkel? Finn(Nokkel k, string sti)
    {
        Nokkel? n = k;
        foreach (var del in sti.Split('\\'))
        {
            n = Under(n!).FirstOrDefault(x => x.Navn.Equals(del, StringComparison.OrdinalIgnoreCase));
            if (n == null) return null;
        }
        return n;
    }

    /// <summary>Tekstverdiene (REG_SZ og REG_EXPAND_SZ) i en nøkkel, og tallverdier som tekst. Store verdier (db) hoppes over.</summary>
    public Dictionary<string, string> Verdier(Nokkel k)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (k.AntallVerdier <= 0 || k.AntallVerdier > 4096 || !Gyldig(k.VerdiListe, k.AntallVerdier * 4)) return d;
        int lp = Pos(k.VerdiListe) + 4;
        for (int i = 0; i < k.AntallVerdier; i++)
        {
            int c = BitConverter.ToInt32(_b, lp + i * 4);
            if (!Gyldig(c, 0x14)) continue;
            int p = Pos(c) + 4;
            if (_b[p] != (byte)'v' || _b[p + 1] != (byte)'k') continue;
            int navnLengde = BitConverter.ToUInt16(_b, p + 2);
            uint lengde = BitConverter.ToUInt32(_b, p + 4);
            int data = BitConverter.ToInt32(_b, p + 8);
            int type = BitConverter.ToInt32(_b, p + 0xC);
            int flagg = BitConverter.ToUInt16(_b, p + 0x10);
            if (p + 0x14 + navnLengde > _b.Length) continue;
            var navn = (flagg & 1) != 0 ? Encoding.GetEncoding(28591).GetString(_b, p + 0x14, navnLengde) : Encoding.Unicode.GetString(_b, p + 0x14, navnLengde);
            bool inne = (lengde & 0x80000000) != 0;
            int len = (int)(lengde & 0x7FFFFFFF);
            byte[] bytes;
            if (inne) { bytes = BitConverter.GetBytes(data).Take(Math.Min(4, len)).ToArray(); }
            else
            {
                if (len > 16344 || !Gyldig(data, len)) continue;
                bytes = new byte[len];
                Buffer.BlockCopy(_b, Pos(data) + 4, bytes, 0, len);
            }
            d[navn] = type switch
            {
                1 or 2 => Encoding.Unicode.GetString(bytes).TrimEnd('\0'),
                4 when bytes.Length >= 4 => BitConverter.ToUInt32(bytes, 0).ToString(),
                11 when bytes.Length >= 8 => BitConverter.ToUInt64(bytes, 0).ToString(),
                _ => "",
            };
        }
        return d;
    }
}
