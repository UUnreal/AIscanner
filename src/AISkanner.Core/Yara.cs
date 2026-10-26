using System.Globalization;
using System.Reflection;
using System.Text;

namespace AISkanner;

/// <summary>
/// Leser og kjører YARA-regler (en del av språket) uten libyara. Reglene ligger i en åpen tekstfil (ai-modeller.yar)
/// som også kan kjøres med vanlig yara.exe. Støtter:
///   strenger: "tekst" (nocase, wide, ascii) og hex { 4D 5A ?? 00 }
///   betingelser: and, or, not, ( ), $a, #a, $a at N, $a in (A..B), any/all/N of them, any of ($a*),
///   filesize, uint8/16/32(N), uint16be/uint32be(N), ==, !=, &lt;, &lt;=, &gt;, &gt;=, true, false, tall med KB/MB.
/// Leser bare starten (og slutten) av filen, aldri hele modellen. Kjører ingenting.
/// </summary>
public sealed class YaraRegler
{
    public sealed class Regel
    {
        public string Navn = "";
        public readonly List<string> Tagger = new();
        public readonly Dictionary<string, string> Meta = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<(string Id, byte?[] Monster, bool Nocase)> Strenger = new();
        public readonly List<string> Betingelse = new();
        public string Beskrivelse => Meta.TryGetValue("beskrivelse", out var b) ? b : Navn;
        public Risiko? Risiko => Meta.TryGetValue("risiko", out var r) ? r switch { "rod" => AISkanner.Risiko.Rod, "gul" => AISkanner.Risiko.Gul, "gronn" => AISkanner.Risiko.Gronn, _ => null } : null;
        public bool Ondsinnet => Tagger.Contains("ondsinnet");
    }

    public List<Regel> Regler { get; } = new();
    public string Kilde { get; private set; } = "innebygd";

    /// <summary>ai-modeller.yar ved siden av programmet hvis den finnes (så bedriften kan legge til egne regler), ellers de innebygde.</summary>
    public static YaraRegler Last(string? sti = null)
    {
        sti ??= Path.Combine(AppContext.BaseDirectory, "ai-modeller.yar");
        if (File.Exists(sti)) { var y = Les(File.ReadAllText(sti)); y.Kilde = sti; return y; }
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.ai-modeller.yar")
                      ?? throw new InvalidOperationException("Mangler innebygde YARA-regler.");
        using var r = new StreamReader(s, Encoding.UTF8);
        return Les(r.ReadToEnd());
    }

    // ---------- lesing av regelfila ----------

    public static YaraRegler Les(string tekst)
    {
        var y = new YaraRegler();
        var t = Tokens(tekst);
        int i = 0;
        string Neste() => i < t.Count ? t[i++] : throw new FormatException("Uventet slutt på YARA-fila.");
        while (i < t.Count)
        {
            var ord = Neste();
            if (ord is "private" or "global") continue;
            if (ord == "import" || ord == "include") { Neste(); continue; }
            if (ord != "rule") throw new FormatException($"Forventet 'rule', fant '{ord}'.");
            var r = new Regel { Navn = Neste() };
            if (t[i] == ":") { i++; while (t[i] != "{") r.Tagger.Add(Neste()); }
            if (Neste() != "{") throw new FormatException($"Mangler {{ i regel {r.Navn}.");
            string del = "";
            while (true)
            {
                var x = Neste();
                if (x == "}" && del != "strings-hex") break;
                if (x is "meta:" or "strings:" or "condition:") { del = x; continue; }
                if (del == "meta:")
                {
                    if (Neste() != "=") throw new FormatException($"Feil i meta i {r.Navn}.");
                    var v = Neste();
                    r.Meta[x] = v.StartsWith("\"") ? Uttrykk(v) : v;
                }
                else if (del == "strings:")
                {
                    if (Neste() != "=") throw new FormatException($"Feil i strings i {r.Navn}.");
                    var v = Neste();
                    bool nocase = false, wide = false, ascii = false;
                    while (i < t.Count && t[i] is "nocase" or "wide" or "ascii" or "fullword")
                    {
                        var m = Neste();
                        nocase |= m == "nocase"; wide |= m == "wide"; ascii |= m == "ascii";
                    }
                    if (v.StartsWith("{")) r.Strenger.Add((x, Hex(v), false));
                    else
                    {
                        var b = Bytes(v);
                        if (!wide || ascii) r.Strenger.Add((x, b.Select(c => (byte?)c).ToArray(), nocase));
                        if (wide) r.Strenger.Add((x, b.SelectMany(c => new byte?[] { c, 0 }).ToArray(), nocase));
                    }
                }
                else if (del == "condition:") r.Betingelse.Add(x);
            }
            y.Regler.Add(r);
        }
        return y;
    }

    private static List<string> Tokens(string s)
    {
        var t = new List<string>();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '/' && i + 1 < s.Length && s[i + 1] == '/') { while (i < s.Length && s[i] != '\n') i++; continue; }
            if (c == '/' && i + 1 < s.Length && s[i + 1] == '*') { int e = s.IndexOf("*/", i + 2, StringComparison.Ordinal); i = e < 0 ? s.Length : e + 2; continue; }
            if (c == '"')
            {
                int j = i + 1;
                while (j < s.Length && s[j] != '"') j += s[j] == '\\' ? 2 : 1;
                t.Add(s.Substring(i, j - i + 1)); i = j + 1; continue;
            }
            if (c == '{' && t.Count > 0 && t[t.Count - 1] == "=")
            {
                int e = s.IndexOf('}', i);
                t.Add(s.Substring(i, e - i + 1)); i = e + 1; continue;
            }
            if ("{}()=,:<>!".IndexOf(c) >= 0 || (c == '.' && i + 1 < s.Length && s[i + 1] == '.'))
            {
                var to = i + 1 < s.Length ? s.Substring(i, 2) : "";
                if (to is "==" or "!=" or "<=" or ">=" or "..") { t.Add(to); i += 2; continue; }
                if (c == ':' && t.Count > 0 && t[t.Count - 1] is "meta" or "strings" or "condition") { t[t.Count - 1] += ":"; i++; continue; }
                t.Add(c.ToString()); i++; continue;
            }
            int k = i;
            while (k < s.Length && !char.IsWhiteSpace(s[k]) && "{}()=,:<>!\"".IndexOf(s[k]) < 0 && !(s[k] == '.' && k + 1 < s.Length && s[k + 1] == '.')) k++;
            t.Add(s.Substring(i, k - i)); i = k;
        }
        return t;
    }

    private static string Uttrykk(string sitat)
    {
        var sb = new StringBuilder();
        for (int i = 1; i < sitat.Length - 1; i++)
        {
            char c = sitat[i];
            if (c != '\\') { sb.Append(c); continue; }
            char n = sitat[++i];
            switch (n)
            {
                case 'n': sb.Append('\n'); break;
                case 't': sb.Append('\t'); break;
                case 'r': sb.Append('\r'); break;
                case 'x': sb.Append((char)Convert.ToByte(sitat.Substring(i + 1, 2), 16)); i += 2; break;
                default: sb.Append(n); break;
            }
        }
        return sb.ToString();
    }

    /// <summary>"tekst" med \n, \xHH osv. til bytes (\xHH blir nøyaktig én byte).</summary>
    private static byte[] Bytes(string sitat)
    {
        var ut = new List<byte>();
        for (int i = 1; i < sitat.Length - 1; i++)
        {
            char c = sitat[i];
            if (c != '\\') { ut.AddRange(Encoding.UTF8.GetBytes(c.ToString())); continue; }
            char n = sitat[++i];
            switch (n)
            {
                case 'n': ut.Add(10); break;
                case 't': ut.Add(9); break;
                case 'r': ut.Add(13); break;
                case 'x': ut.Add(Convert.ToByte(sitat.Substring(i + 1, 2), 16)); i += 2; break;
                default: ut.Add((byte)n); break;
            }
        }
        return ut.ToArray();
    }

    private static byte?[] Hex(string blokk)
    {
        var deler = blokk.Trim('{', '}').Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var ut = new List<byte?>();
        foreach (var d in deler.SelectMany(d => Enumerable.Range(0, d.Length / 2).Select(k => d.Substring(k * 2, 2))))
            ut.Add(d == "??" ? null : Convert.ToByte(d, 16));
        return ut.ToArray();
    }

    // ---------- kjøring ----------

    /// <summary>Kjører reglene på starten og slutten av en fil. Returnerer reglene som slo til.</summary>
    public List<Regel> Sjekk(string fil, int hode = 8 << 20, int hale = 1 << 20, bool bareOndsinnede = false)
    {
        try
        {
            using var fs = new FileStream(fil, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            long lengde = fs.Length;
            var a = new byte[(int)Math.Min(lengde, hode)];
            fs.LesAlt(a);
            byte[]? b = null;
            if (lengde > a.Length + 0 && hale > 0)
            {
                long fra = Math.Max(a.Length, lengde - hale);
                b = new byte[(int)(lengde - fra)];
                fs.Position = fra;
                fs.LesAlt(b);
            }
            return Sjekk(a, b, lengde, bareOndsinnede);
        }
        catch { return new List<Regel>(); }
    }

    public List<Regel> Sjekk(byte[] hode, byte[]? hale, long filstorrelse, bool bareOndsinnede = false)
    {
        var treff = new List<Regel>();
        foreach (var r in Regler)
        {
            if (bareOndsinnede && !r.Ondsinnet) continue;
            var funnet = new Dictionary<string, List<long>>();
            foreach (var (id, m, nocase) in r.Strenger)
            {
                if (!funnet.TryGetValue(id, out var l)) funnet[id] = l = new List<long>();
                Finn(hode, m, nocase, 0, l);
                if (hale != null) Finn(hale, m, nocase, filstorrelse - hale.Length, l);
            }
            try
            {
                var e = new Evaluering(r, funnet, hode, filstorrelse);
                if (e.Kjor()) treff.Add(r);
            }
            catch { }
        }
        return treff;
    }

    private static void Finn(byte[] data, byte?[] m, bool nocase, long start, List<long> ut)
    {
        if (m.Length == 0 || m.Length > data.Length) return;
        // Hopp rett til steder der første faste byte stemmer
        int k = Array.FindIndex(m, x => x != null);
        if (k < 0) return;
        byte f = m[k]!.Value;
        var kandidater = nocase && Lav(f) != Stor(f) ? new[] { Lav(f), Stor(f) } : new[] { f };
        foreach (var kand in kandidater)
        {
            int i = Array.IndexOf(data, kand, k);
            while (i >= 0 && ut.Count < 100)
            {
                int s0 = i - k;
                if (s0 + m.Length > data.Length) break;
                int j = 0;
                for (; j < m.Length; j++)
                {
                    if (m[j] is not { } b) continue;
                    byte d = data[s0 + j];
                    if (d != b && !(nocase && Lav(d) == Lav(b))) break;
                }
                if (j == m.Length) ut.Add(start + s0);
                i = i + 1 < data.Length ? Array.IndexOf(data, kand, i + 1) : -1;
            }
        }
    }

    private static byte Stor(byte b) => b is >= (byte)'a' and <= (byte)'z' ? (byte)(b - 32) : b;
    private static byte Lav(byte b) => b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;

    private sealed class Evaluering
    {
        private readonly Regel _r;
        private readonly Dictionary<string, List<long>> _f;
        private readonly byte[] _hode;
        private readonly long _storrelse;
        private readonly List<string> _t;
        private int _i;

        public Evaluering(Regel r, Dictionary<string, List<long>> f, byte[] hode, long storrelse)
        { _r = r; _f = f; _hode = hode; _storrelse = storrelse; _t = r.Betingelse; }

        public bool Kjor() { _i = 0; var v = Eller(); return v != 0; }

        private string? Se => _i < _t.Count ? _t[_i] : null;
        private string Ta() => _t[_i++];

        private long Eller() { var v = Og(); while (Se == "or") { Ta(); var h = Og(); v = (v != 0 || h != 0) ? 1 : 0; } return v; }
        private long Og() { var v = Ikke(); while (Se == "and") { Ta(); var h = Ikke(); v = (v != 0 && h != 0) ? 1 : 0; } return v; }
        private long Ikke() { if (Se == "not") { Ta(); return Ikke() == 0 ? 1 : 0; } return Sammenlign(); }

        private long Sammenlign()
        {
            var v = Ledd();
            if (Se is "==" or "!=" or "<" or "<=" or ">" or ">=")
            {
                var op = Ta(); var h = Ledd();
                return op switch { "==" => v == h, "!=" => v != h, "<" => v < h, "<=" => v <= h, ">" => v > h, _ => v >= h } ? 1 : 0;
            }
            return v;
        }

        private long Ledd()
        {
            var x = Ta();
            if (x == "(") { var v = Eller(); Ta(); return v; }
            if (x == "true") return 1;
            if (x == "false") return 0;
            if (x == "filesize") return _storrelse;
            if (x.StartsWith("uint"))
            {
                Ta(); var p = Eller(); Ta();
                int n = x.StartsWith("uint8") ? 1 : x.StartsWith("uint16") ? 2 : 4;
                if (p < 0 || p + n > _hode.Length) return -1;
                long v = 0;
                bool be = x.EndsWith("be");
                for (int k = 0; k < n; k++) v |= (long)_hode[p + k] << (8 * (be ? n - 1 - k : k));
                return v;
            }
            if (x is "any" or "all" || (char.IsDigit(x[0]) && Se == "of"))
            {
                Ta(); // of
                var sett = new List<string>();
                if (Se == "them") { Ta(); sett.AddRange(_f.Keys); }
                else
                {
                    Ta(); // (
                    while (true)
                    {
                        var s = Ta();
                        if (s == ")") break;
                        if (s == ",") continue;
                        sett.AddRange(s.EndsWith("*") ? _f.Keys.Where(k => k.StartsWith(s.TrimEnd('*'))) : new[] { s });
                    }
                }
                int treff = sett.Count(s => _f.TryGetValue(s, out var l) && l.Count > 0);
                return (x == "any" ? treff > 0 : x == "all" ? treff == sett.Count : treff >= Tall(x)) ? 1 : 0;
            }
            if (x.StartsWith("#")) return _f.TryGetValue("$" + x.Substring(1), out var c) ? c.Count : 0;
            if (x.StartsWith("$"))
            {
                var l = _f.TryGetValue(x, out var f) ? f : new List<long>();
                if (Se == "at") { Ta(); var p = Ledd(); return l.Contains(p) ? 1 : 0; }
                if (Se == "in") { Ta(); Ta(); var fra = Eller(); Ta(); var til = Eller(); Ta(); return l.Any(o => o >= fra && o <= til) ? 1 : 0; }
                return l.Count > 0 ? 1 : 0;
            }
            return Tall(x);
        }

        private static long Tall(string s)
        {
            long gang = 1;
            if (s.EndsWith("KB")) { gang = 1024; s = s.Substring(0, s.Length - 2); }
            else if (s.EndsWith("MB")) { gang = 1024 * 1024; s = s.Substring(0, s.Length - 2); }
            return (s.StartsWith("0x") ? long.Parse(s.Substring(2), NumberStyles.HexNumber) : long.Parse(s, CultureInfo.InvariantCulture)) * gang;
        }
    }
}
