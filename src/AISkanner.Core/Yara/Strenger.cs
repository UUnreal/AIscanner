using System.Text;
using System.Text.RegularExpressions;

namespace AISkanner.YaraMotor;

/// <summary>Et område av filen som er lest inn (starten eller slutten).</summary>
internal sealed class Bit
{
    public readonly byte[] Data;
    public readonly long Start;
    private string? _tekst;
    public Bit(byte[] data, long start) { Data = data; Start = start; }

    public bool HarTekst => _tekst != null;
    /// <summary>Mange treff i samme bit: da lønner det seg å lage hele teksten én gang.</summary>
    public int Vinduer;

    /// <summary>Et lite utsnitt som tekst, for å sjekke ett treff uten å gjøre hele filen om til tekst.</summary>
    public string Vindu(int fra, int lengde)
    {
        var c = new char[lengde];
        for (int i = 0; i < lengde; i++) c[i] = (char)Data[fra + i];
        return new string(c);
    }

    /// <summary>Bytene som tekst (én byte = ett tegn), for regex.</summary>
    public string Tekst
    {
        get
        {
            if (_tekst != null) return _tekst;
            var c = new char[Data.Length];
            for (int i = 0; i < c.Length; i++) c[i] = (char)Data[i];
            return _tekst = new string(c);
        }
    }
}

/// <summary>En streng i en regel ($a = ...). Kan ha flere varianter (ascii, wide, xor-nøkler, base64).</summary>
internal sealed class Streng
{
    public string Id = "";
    public bool Privat;
    public readonly List<Matcher> Matchere = new();
    public int Nr;
    /// <summary>
    /// Hex med lange eller ubegrensede hopp ({ 50 4B 03 04 [-] 50 4B 01 02 }) deles i biter som søkes hver for seg
    /// og settes sammen etterpå, som i YARA. Da slipper vi å lete gjennom resten av filen etter hvert treff.
    /// </summary>
    public List<(Streng Del, int Min, int Maks)>? Kjede;
}

/// <summary>
/// Én måte strengen kan se ut i filen. Atom = noen faste bytes som må finnes; de søkes etter for alle strenger samtidig.
/// Bare der et atom finnes, sjekkes hele strengen. Strenger uten atom søkes for seg (tregere, sjeldent).
/// </summary>
internal sealed class Matcher
{
    public Streng Eier = null!;
    public byte[]? Atom;            // med små bokstaver (filen sammenlignes også med små bokstaver)
    public int MinFor, MaksFor;     // hvor langt atomet kan stå fra starten av treffet
    public byte[]? Bokstavelig;     // vanlige tekst- og hex-strenger uten jokertegn
    public bool Nocase;
    public Regex? Forankret;        // \G(...) for kontroll der atomet er funnet
    public Regex? Fri;              // for strenger uten atom
    public bool Helord, Bred;
    /// <summary>YARA sin RE_SCAN_LIMIT.</summary>
    public const int Skannegrense = 4096;
    public int MaksLengde = Skannegrense;

    /// <summary>Lengden på treffet som starter på posisjon s, eller -1.</summary>
    public int Sjekk(Bit b, int s)
    {
        if (s < 0) return -1;
        int lengde;
        if (Bokstavelig != null)
        {
            var d = b.Data;
            if (s + Bokstavelig.Length > d.Length) return -1;
            for (int j = 0; j < Bokstavelig.Length; j++)
            {
                byte x = d[s + j], y = Bokstavelig[j];
                if (x != y && !(Nocase && Fold[x] == Fold[y])) return -1;
            }
            lengde = Bokstavelig.Length;
        }
        else
        {
            if (s > b.Data.Length) return -1;
            Match m;
            if (b.HarTekst || ++b.Vinduer > 64) m = Forankret!.Match(b.Tekst, s);
            else
            {
                // Som i YARA ser et treff høyst 4096 bytes fremover. Én byte bakover så ^ og \b blir riktige.
                int fra = System.Math.Max(0, s - 1);
                int l = System.Math.Min(b.Data.Length - fra, s - fra + MaksLengde);
                var v = b.Vindu(fra, l);
                m = Forankret!.Match(v, s - fra);
                if (m.Success) m = m.Index == s - fra ? m : Match.Empty;
                if (!m.Success) return -1;
                lengde = m.Length;
                return Helord && !ErHelord(b.Data, s, lengde, Bred) ? -1 : lengde;
            }
            if (!m.Success || m.Index != s) return -1;
            lengde = m.Length;
        }
        return Helord && !ErHelord(b.Data, s, lengde, Bred) ? -1 : lengde;
    }

    public IEnumerable<(int Start, int Lengde)> SokAlt(Bit b)
    {
        int pos = 0, antall = 0;
        var t = b.Tekst;
        while (pos <= t.Length && antall < Strengsok.MaksTreff)
        {
            var m = Fri!.Match(t, pos);
            if (!m.Success) yield break;
            if (!Helord || ErHelord(b.Data, m.Index, m.Length, Bred)) { antall++; yield return (m.Index, m.Length); }
            pos = m.Index + 1;
        }
    }

    private static bool ErHelord(byte[] d, int s, int l, bool bred)
    {
        static bool Alnum(byte c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        int steg = bred ? 2 : 1;
        if (s - steg >= 0 && Alnum(d[s - steg])) return false;
        if (s + l < d.Length && Alnum(d[s + l])) return false;
        return true;
    }

    public static readonly byte[] Fold = Enumerable.Range(0, 256).Select(i => (byte)(i >= 'A' && i <= 'Z' ? i + 32 : i)).ToArray();
}

/// <summary>Lager matchere fra strengdefinisjoner i regelfila.</summary>
internal static class Strengbygger
{
    private const int MaksAtom = 8;

    public static void Tekst(Streng s, byte[] b, HashSet<string> mod, (int Fra, int Til)? xor, string? alfabet)
    {
        bool wide = mod.Contains("wide"), ascii = mod.Contains("ascii") || !wide;
        bool nocase = mod.Contains("nocase"), helord = mod.Contains("fullword");
        if (mod.Contains("base64") || mod.Contains("base64wide"))
        {
            foreach (var v in Base64Varianter(b, alfabet))
            {
                if (mod.Contains("base64")) Legg(s, v, false, false, false);
                if (mod.Contains("base64wide")) Legg(s, Bred(v), false, false, false);
            }
            return;
        }
        var varianter = new List<(byte[] B, bool Bred)>();
        if (ascii) varianter.Add((b, false));
        if (wide) varianter.Add((Bred(b), true));
        foreach (var (v, bred) in varianter)
        {
            if (xor is { } x)
                for (int k = x.Fra; k <= x.Til; k++) Legg(s, v.Select(c => (byte)(c ^ k)).ToArray(), false, helord, bred);
            else Legg(s, v, nocase, helord, bred);
        }
    }

    private static void Legg(Streng s, byte[] b, bool nocase, bool helord, bool bred)
    {
        var m = new Matcher { Eier = s, Bokstavelig = b, Nocase = nocase, Helord = helord, Bred = bred };
        var (fra, lengde) = BesteVindu(b.Select(x => (byte?)x).ToArray());
        m.Atom = b.Skip(fra).Take(lengde).Select(x => Matcher.Fold[x]).ToArray();
        m.MinFor = m.MaksFor = fra;
        s.Matchere.Add(m);
    }

    private static byte[] Bred(byte[] b) => b.SelectMany(c => new[] { c, (byte)0 }).ToArray();

    /// <summary>Som YARA: tre kodinger (strengen kan starte på hver av de tre posisjonene i en base64-gruppe), uten tegnene som avhenger av nabobytes.</summary>
    private static IEnumerable<byte[]> Base64Varianter(byte[] b, string? alfabet)
    {
        const string Standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int skift = 0; skift < 3; skift++)
        {
            var data = new byte[skift + b.Length];
            Array.Copy(b, 0, data, skift, b.Length);
            var kode = Convert.ToBase64String(data);
            if (alfabet != null) kode = new string(kode.Select(c => c == '=' ? '=' : alfabet[Standard.IndexOf(c)]).ToArray());
            int foran = skift == 0 ? 0 : skift == 1 ? 2 : 3;
            int rest = data.Length % 3;
            int bak = rest == 0 ? 0 : rest == 1 ? 3 : 2;
            if (kode.Length - foran - bak <= 0) continue;
            yield return Encoding.ASCII.GetBytes(kode.Substring(foran, kode.Length - foran - bak));
        }
    }

    // ---------- hex ----------

    private abstract class Del { public int Min, Maks; }
    private sealed class Byte : Del { public byte Verdi, Maske; public bool Ikke; public Byte() { Min = Maks = 1; } }
    private sealed class Hopp : Del { }
    private sealed class Alt : Del { public List<List<Del>> Grener = new(); }

    public static void Hex(Streng s, string tekst, HashSet<string> mod)
    {
        int i = 0;
        var deler = HexSekvens(tekst.Replace("\r", " ").Replace("\n", " ").Replace("\t", " "), ref i, false);
        bool helord = mod.Contains("fullword");
        // Lange hopp på toppnivå: del opp i en kjede
        if (!helord && deler.Any(d => d is Hopp h && (h.Maks < 0 || h.Maks - h.Min > Kjedegrense)))
        {
            s.Kjede = new List<(Streng, int, int)>();
            var bit = new List<Del>();
            int min = 0, maks = 0;
            foreach (var d in deler.Append(null))
            {
                if (d is Hopp h && (h.Maks < 0 || h.Maks - h.Min > Kjedegrense) || d == null)
                {
                    if (bit.Count > 0)
                    {
                        var del = new Streng { Id = s.Id + "#" + s.Kjede.Count, Privat = true };
                        HexSekvensMatcher(del, bit, false);
                        s.Kjede.Add((del, min, maks));
                        bit = new List<Del>();
                    }
                    if (d is Hopp hh) { min = hh.Min; maks = hh.Maks; }
                    continue;
                }
                bit.Add(d);
            }
            return;
        }
        HexSekvensMatcher(s, deler, helord);
    }

    /// <summary>YARA deler hex-strenger ved hopp større enn dette.</summary>
    private const int Kjedegrense = 200;

    private static void HexSekvensMatcher(Streng s, List<Del> deler, bool helord)
    {
        // Bare faste bytes: vanlig bokstavelig søk
        if (deler.All(d => d is Byte { Maske: 0xFF, Ikke: false }))
        {
            Legg(s, deler.Cast<Byte>().Select(d => d.Verdi).ToArray(), false, helord, false);
            return;
        }
        var m = new Matcher { Eier = s, Helord = helord };
        if (deler.All(d => d.Maks >= 0)) m.MaksLengde = System.Math.Min(Matcher.Skannegrense, deler.Sum(d => d.Maks) + 1);
        var re = new StringBuilder();
        foreach (var d in deler) Regexdel(d, re);
        Ferdig(m, re.ToString(), RegexOptions.Singleline, Atom(deler));
        s.Matchere.Add(m);
    }

    private static List<Del> HexSekvens(string t, ref int i, bool iAlt)
    {
        var ut = new List<Del>();
        while (i < t.Length)
        {
            char c = t[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (iAlt && (c == '|' || c == ')')) break;
            if (c == '(')
            {
                i++;
                var alt = new Alt();
                while (true)
                {
                    alt.Grener.Add(HexSekvens(t, ref i, true));
                    if (i >= t.Length) throw new FormatException("Hex-alternativ uten ).");
                    if (t[i++] == ')') break;
                }
                alt.Min = alt.Grener.Min(g => g.Sum(d => d.Min));
                alt.Maks = alt.Grener.Max(g => g.Any(d => d.Maks < 0) ? -1 : g.Sum(d => d.Maks));
                if (alt.Grener.Any(g => g.Any(d => d.Maks < 0))) alt.Maks = -1;
                ut.Add(alt);
                continue;
            }
            if (c == '[')
            {
                int e = t.IndexOf(']', i);
                var innhold = t.Substring(i + 1, e - i - 1).Trim();
                i = e + 1;
                var h = new Hopp();
                if (innhold == "-") { h.Min = 0; h.Maks = -1; }
                else if (innhold.Contains("-"))
                {
                    var p = innhold.Split('-');
                    h.Min = p[0].Trim().Length == 0 ? 0 : int.Parse(p[0].Trim());
                    h.Maks = p[1].Trim().Length == 0 ? -1 : int.Parse(p[1].Trim());
                }
                else h.Min = h.Maks = int.Parse(innhold);
                ut.Add(h);
                continue;
            }
            bool ikke = false;
            if (c == '~') { ikke = true; i++; while (char.IsWhiteSpace(t[i])) i++; }
            if (i + 1 >= t.Length) throw new FormatException($"Ugyldig hex: {t}");
            char a = t[i], b = t[i + 1];
            i += 2;
            int Nib(char x) => x == '?' ? 0 : Convert.ToInt32(x.ToString(), 16);
            byte maske = (byte)((a == '?' ? 0 : 0xF0) | (b == '?' ? 0 : 0x0F));
            ut.Add(new Byte { Verdi = (byte)((Nib(a) << 4) | Nib(b)), Maske = maske, Ikke = ikke });
        }
        return ut;
    }

    private static void Regexdel(Del d, StringBuilder re)
    {
        switch (d)
        {
            case Byte b when b.Maske == 0xFF && !b.Ikke: re.Append($"\\x{b.Verdi:X2}"); break;
            case Byte b when b.Maske == 0 && !b.Ikke: re.Append('.'); break;
            case Byte b:
                re.Append('[');
                for (int v = 0; v < 256; v++)
                    if (((v & b.Maske) == b.Verdi) != b.Ikke) re.Append($"\\x{v:X2}");
                re.Append(']');
                break;
            case Hopp h: re.Append(h.Maks < 0 ? $".{{{h.Min},}}?" : $".{{{h.Min},{h.Maks}}}?"); break;
            case Alt a:
                re.Append("(?:");
                for (int k = 0; k < a.Grener.Count; k++)
                {
                    if (k > 0) re.Append('|');
                    foreach (var x in a.Grener[k]) Regexdel(x, re);
                }
                re.Append(')');
                break;
        }
    }

    /// <summary>Lengste rekke faste bytes før første ubegrensede hopp, og hvor langt fra starten den kan stå.</summary>
    private static (byte[] Atom, int Min, int Maks)? Atom(List<Del> deler)
    {
        (byte[], int, int)? beste = null;
        int bestePoeng = 0;
        int min = 0, maks = 0;
        int k = 0;
        while (k < deler.Count)
        {
            if (deler[k] is Byte { Maske: 0xFF, Ikke: false })
            {
                int start = k;
                var rekke = new List<byte?>();
                while (k < deler.Count && deler[k] is Byte { Maske: 0xFF, Ikke: false } bb) { rekke.Add(bb.Verdi); k++; }
                var (fra, lengde) = BesteVindu(rekke.ToArray());
                int poeng = Kvalitet(rekke.Skip(fra).Take(lengde).Select(x => x!.Value).ToArray());
                if (poeng > bestePoeng)
                {
                    bestePoeng = poeng;
                    beste = (rekke.Skip(fra).Take(lengde).Select(x => Matcher.Fold[x!.Value]).ToArray(), min + fra, maks + fra);
                }
                min += rekke.Count; maks += rekke.Count;
                continue;
            }
            var d = deler[k++];
            if (d.Maks < 0) break;   // ubegrenset hopp: atom må stå før
            min += d.Min; maks += d.Maks;
            if (maks - min > 4096) break;
        }
        return beste;
    }

    // ---------- regex ----------

    public static void Regex(Streng s, string monster, string flagg, HashSet<string> mod)
    {
        var valg = RegexOptions.CultureInvariant;
        if (flagg.Contains('i') || mod.Contains("nocase")) valg |= RegexOptions.IgnoreCase;
        if (flagg.Contains('s')) valg |= RegexOptions.Singleline;
        var prefiks = Prefiks(monster);
        bool bred = mod.Contains("wide"), ascii = !bred || mod.Contains("ascii");
        if (ascii)
        {
            var m = new Matcher { Eier = s, Helord = mod.Contains("fullword") };
            Ferdig(m, monster, valg, prefiks.Length > 0 ? (prefiks.Select(c => Matcher.Fold[c]).ToArray(), 0, 0) : null);
            s.Matchere.Add(m);
        }
        if (bred)
        {
            var m = new Matcher { Eier = s, Helord = mod.Contains("fullword"), Bred = true };
            var bp = prefiks.SelectMany(c => new[] { Matcher.Fold[c], (byte)0 }).Take(MaksAtom).ToArray();
            Ferdig(m, Bredt(monster), valg, bp.Length >= 2 ? (bp, 0, 0) : null);
            s.Matchere.Add(m);
        }
    }

    /// <summary>Wide-regex: hvert tegn i mønsteret følges av en nullbyte (UTF-16LE), som i YARA.</summary>
    private static string Bredt(string re)
    {
        var ut = new StringBuilder();
        void Tegn(string atom) => ut.Append("(?:").Append(atom).Append(@"\x00)");
        for (int i = 0; i < re.Length; i++)
        {
            char c = re[i];
            switch (c)
            {
                case '\\':
                    if (i + 1 >= re.Length) { ut.Append(c); break; }
                    char n = re[i + 1];
                    if (n is 'b' or 'B') { ut.Append(c).Append(n); i++; break; }
                    int l = n == 'x' ? 4 : 2;
                    Tegn(re.Substring(i, Math.Min(l, re.Length - i)));
                    i += l - 1;
                    break;
                case '[':
                    int j = i + 1;
                    if (j < re.Length && re[j] == '^') j++;
                    if (j < re.Length && re[j] == ']') j++;
                    while (j < re.Length && re[j] != ']') { if (re[j] == '\\') j++; j++; }
                    Tegn(re.Substring(i, Math.Min(j + 1, re.Length) - i));
                    i = j;
                    break;
                case '.':
                    Tegn(".");
                    break;
                case '{':
                    int e = re.IndexOf('}', i);
                    if (e < 0) { Tegn(@"\{"); break; }
                    ut.Append(re, i, e - i + 1); i = e;
                    break;
                case '(': case ')': case '|': case '^': case '$': case '*': case '+': case '?':
                    ut.Append(c);
                    break;
                default:
                    Tegn(System.Text.RegularExpressions.Regex.Escape(c.ToString()));
                    break;
            }
        }
        return ut.ToString();
    }

    /// <summary>Faste tegn i starten av et regex, f.eks. "eval\(" i /eval\(.{0,40}\)/. Tomt hvis regexet har | på toppnivå.</summary>
    private static byte[] Prefiks(string re)
    {
        int dybde = 0;
        for (int k = 0; k < re.Length; k++)
        {
            if (re[k] == '\\') { k++; continue; }
            if (re[k] == '[') { while (k < re.Length && re[k] != ']') { if (re[k] == '\\') k++; k++; } continue; }
            if (re[k] == '(') dybde++;
            else if (re[k] == ')') dybde--;
            else if (re[k] == '|' && dybde == 0) return Array.Empty<byte>();
        }
        var ut = new List<byte>();
        int i = 0;
        while (i < re.Length && ut.Count < MaksAtom + 1)
        {
            char c = re[i];
            if (".[](){}*+?|^$".IndexOf(c) >= 0) break;
            if (c == '\\')
            {
                if (i + 1 >= re.Length) break;
                char n = re[i + 1];
                if (n == 'x' && i + 3 < re.Length) { ut.Add(Convert.ToByte(re.Substring(i + 2, 2), 16)); i += 4; continue; }
                if (n == 'n') { ut.Add(10); i += 2; continue; }
                if (n == 't') { ut.Add(9); i += 2; continue; }
                if (n == 'r') { ut.Add(13); i += 2; continue; }
                if (char.IsLetterOrDigit(n)) break;   // \d, \w, \s, \b osv.
                ut.Add((byte)n); i += 2; continue;
            }
            if (c > 127) break;
            ut.Add((byte)c); i++;
        }
        // Et kvantor rett etter gjør siste tegn valgfritt
        if (i < re.Length && "*?{".IndexOf(re[i]) >= 0 && ut.Count > 0) ut.RemoveAt(ut.Count - 1);
        if (ut.Count > MaksAtom) ut.RemoveRange(MaksAtom, ut.Count - MaksAtom);
        return ut.Count >= 2 ? ut.ToArray() : Array.Empty<byte>();
    }

    private static void Ferdig(Matcher m, string re, RegexOptions valg, (byte[] Atom, int Min, int Maks)? atom)
    {
        // YARA-regex er laget for bytes: \x80-\xFF skal være én byte, og ingen kulturregler
        m.Forankret = new Regex(@"\G(?:" + re + ")", valg);
        if (atom is { } a && a.Atom.Length > 0) { m.Atom = a.Atom; m.MinFor = a.Min; m.MaksFor = a.Maks; }
        else m.Fri = new Regex(re, valg);
    }

    // ---------- atomvalg ----------

    private static (int Fra, int Lengde) BesteVindu(byte?[] b)
    {
        int lengde = Math.Min(MaksAtom, b.Length);
        int beste = 0, bestePoeng = -1;
        for (int fra = 0; fra + lengde <= b.Length; fra++)
        {
            int p = Kvalitet(b.Skip(fra).Take(lengde).Select(x => x ?? 0).ToArray());
            if (p > bestePoeng) { bestePoeng = p; beste = fra; }
        }
        return (beste, lengde);
    }

    /// <summary>Atomer med vanlige bytes (00, FF, mellomrom) gir mange falske treff; ulike bytes er best.</summary>
    private static int Kvalitet(byte[] b)
    {
        int p = 0;
        foreach (var x in b) p += x is 0x00 or 0xFF or 0x20 or 0xCC or 0x90 ? 1 : 3;
        return p + b.Distinct().Count() * 2;
    }
}

/// <summary>
/// Søker etter alle strengene i alle regler i én gjennomgang av dataene (Aho-Corasick på atomene),
/// og sjekker bare hele strengen der et atom er funnet.
/// </summary>
internal sealed class Strengsok
{
    public const int MaksTreff = 1000;
    private readonly int[][] _neste;
    private readonly List<int>[] _ut;
    private readonly List<Matcher> _atomer = new();
    private readonly List<Matcher> _frie = new();
    public readonly int AntallStrenger;
    private readonly List<Streng> _kjeder;

    public Strengsok(IEnumerable<Streng> strenger)
    {
        var alle = strenger.ToList();
        AntallStrenger = alle.Count;
        _kjeder = alle.Where(s => s.Kjede != null).ToList();
        alle.AddRange(_kjeder.SelectMany(s => s.Kjede!.Select(k => k.Del)));
        foreach (var s in alle)
            foreach (var m in s.Matchere)
                (m.Atom is { Length: > 0 } ? _atomer : _frie).Add(m);

        // Trie
        var neste = new List<int[]> { Ny() };
        var ut = new List<List<int>> { new() };
        for (int k = 0; k < _atomer.Count; k++)
        {
            int node = 0;
            foreach (var b in _atomer[k].Atom!)
            {
                if (neste[node][b] < 0) { neste[node][b] = neste.Count; neste.Add(Ny()); ut.Add(new List<int>()); }
                node = neste[node][b];
            }
            ut[node].Add(k);
        }
        // Feilkoblinger, og gjør om til en ferdig tabell (DFA)
        var feil = new int[neste.Count];
        var ko = new Queue<int>();
        for (int b = 0; b < 256; b++)
        {
            if (neste[0][b] < 0) neste[0][b] = 0;
            else { feil[neste[0][b]] = 0; ko.Enqueue(neste[0][b]); }
        }
        while (ko.Count > 0)
        {
            int n = ko.Dequeue();
            ut[n].AddRange(ut[feil[n]]);
            for (int b = 0; b < 256; b++)
            {
                int v = neste[n][b];
                if (v < 0) neste[n][b] = neste[feil[n]][b];
                else { feil[v] = neste[feil[n]][b]; ko.Enqueue(v); }
            }
        }
        _neste = neste.ToArray();
        _ut = ut.ToArray();
        static int[] Ny() { var a = new int[256]; for (int i = 0; i < 256; i++) a[i] = -1; return a; }
    }

    /// <summary>Alle treff, per streng: startposisjon i filen og lengde.</summary>
    public Dictionary<Streng, SortedDictionary<long, int>> Sok(IEnumerable<Bit> biter)
    {
        var treff = new Dictionary<Streng, SortedDictionary<long, int>>();
        void Legg(Streng s, long pos, int lengde)
        {
            if (!treff.TryGetValue(s, out var d)) treff[s] = d = new SortedDictionary<long, int>();
            if (d.Count < MaksTreff && !d.ContainsKey(pos)) d[pos] = lengde;
        }
        var fold = Matcher.Fold;
        foreach (var bit in biter)
        {
            var data = bit.Data;
            int tilstand = 0;
            for (int i = 0; i < data.Length; i++)
            {
                tilstand = _neste[tilstand][fold[data[i]]];
                var liste = _ut[tilstand];
                if (liste.Count == 0) continue;
                foreach (var k in liste)
                {
                    var m = _atomer[k];
                    // Strenger med fullt antall treff trenger ikke flere kontroller
                    if (treff.TryGetValue(m.Eier, out var fulle) && fulle.Count >= MaksTreff) continue;
                    int atomStart = i - m.Atom!.Length + 1;
                    for (int s = atomStart - m.MaksFor; s <= atomStart - m.MinFor; s++)
                    {
                        int l = m.Sjekk(bit, s);
                        if (l >= 0) Legg(m.Eier, bit.Start + s, l);
                    }
                }
            }
            foreach (var m in _frie)
                foreach (var (s, l) in m.SokAlt(bit)) Legg(m.Eier, bit.Start + s, l);
        }
        // Sett sammen kjedene: første bit, så hver neste bit innenfor hoppet
        foreach (var s in _kjeder)
        {
            var deltreff = s.Kjede!.Select(k => treff.TryGetValue(k.Del, out var t) ? t : null).ToList();
            if (deltreff.Any(b => b == null)) continue;
            foreach (var (start, l0) in deltreff[0]!)
            {
                long slutt = start + l0;
                bool ok = true;
                for (int i = 1; i < deltreff.Count && ok; i++)
                {
                    var (_, min, maks) = s.Kjede![i];
                    ok = false;
                    foreach (var (q, lq) in deltreff[i]!)
                    {
                        if (q < slutt + min) continue;
                        if (maks >= 0 && q > slutt + maks) break;
                        slutt = q + lq; ok = true; break;
                    }
                }
                if (ok) Legg(s, start, (int)(slutt - start));
            }
        }
        return treff;
    }
}
