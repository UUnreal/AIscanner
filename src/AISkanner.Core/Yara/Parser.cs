using System.Text.RegularExpressions;
using Regel = AISkanner.YaraRegler.Regel;
using Uttrykk = System.Func<AISkanner.YaraMotor.Kontekst, object?>;

namespace AISkanner.YaraMotor;

/// <summary>
/// Leser regelfila og gjør hver betingelse om til en ferdig funksjon (lukning), så kjøringen per fil blir rask.
/// Støtter YARA 4-syntaksen: and/or/not/defined, sammenligninger, contains/icontains/startswith/endswith/iequals/matches,
/// regning og bitoperasjoner, $a at/in, #a (in), @a[i], !a[i], any/all/none/N/N% of them/(...) (at/in), for ... of, for ... in,
/// regelreferanser og regelsett, int8–uint32be, filesize, entrypoint og modulene pe, math, hash, time, string og console.
/// </summary>
internal sealed class Parser
{
    private static readonly HashSet<string> KjenteModuler = new() { "pe", "math", "hash", "time", "string", "console", "dotnet", "elf", "macho", "magic", "cuckoo" };
    private static readonly HashSet<string> Modifikatorer = new() { "nocase", "wide", "ascii", "fullword", "private", "xor", "base64", "base64wide" };

    private readonly List<Token> _t;
    private int _i;
    private readonly List<Regel> _regler = new();
    private Regel _regel = null!;
    private Dictionary<string, Streng> _strenger = new();
    private readonly List<HashSet<string>> _variabler = new();
    private int _forOf;
    private int _anonym;

    private Parser(string tekst) { _t = Leksikon.Les(tekst); }

    public static List<Regel> Les(string tekst) => new Parser(tekst).Fil();

    // ---------- hjelpere ----------

    private Token Se => _t[_i];
    private Token Neste => _t[Math.Min(_i + 1, _t.Count - 1)];
    private Token Ta() => _t[_i++];
    private bool Er(string s) => Se.Type is T.Ord or T.Tegn && Se.Tekst == s;
    private Exception Feil(string melding) => new FormatException($"YARA, linje {Se.Linje}{(_regel != null ? $" (regel {_regel.Navn})" : "")}: {melding}");
    private void Forvent(string s) { if (!Er(s)) throw Feil($"forventet '{s}', fant {Se}"); _i++; }
    private string Ord() { if (Se.Type != T.Ord) throw Feil($"forventet et navn, fant {Se}"); return Ta().Tekst; }

    // ---------- fil og regler ----------

    private List<Regel> Fil()
    {
        while (Se.Type != T.Slutt)
        {
            if (Er("import")) { Ta(); if (Se.Type != T.Tekst) throw Feil("import mangler modulnavn"); Ta(); continue; }
            if (Er("include")) throw Feil("include støttes ikke. Legg alle reglene i én fil.");
            bool privat = false, global = false;
            while (Er("private") || Er("global")) { if (Ta().Tekst == "private") privat = true; else global = true; }
            Forvent("rule");
            _regel = new Regel { Navn = Ord(), Privat = privat, Global = global };
            if (_regler.Any(r => r.Navn == _regel.Navn)) throw Feil($"regelen {_regel.Navn} finnes fra før");
            _strenger = new Dictionary<string, Streng>();
            _anonym = 0;
            if (Er(":")) { Ta(); while (Se.Type == T.Ord) _regel.Tagger.Add(Ta().Tekst); }
            Forvent("{");
            if (Er("meta")) { Ta(); Forvent(":"); Meta(); }
            if (Er("strings")) { Ta(); Forvent(":"); Strenger(); }
            Forvent("condition"); Forvent(":");
            _regel.Betingelse = Eller();
            Forvent("}");
            _regel.StrengListe.AddRange(_strenger.Values);
            _regler.Add(_regel);
        }
        return _regler;
    }

    private void Meta()
    {
        while (Se.Type == T.Ord && Neste.Type == T.Tegn && Neste.Tekst == "=")
        {
            var navn = Ta().Tekst; Ta();
            bool minus = false;
            if (Er("-")) { Ta(); minus = true; }
            var v = Ta();
            _regel.Meta[navn] = v.Type switch
            {
                T.Tekst => v.Tekst,
                T.Heltall => ((minus ? -1 : 1) * v.Heltall).ToString(),
                T.Desimal => v.Tekst,
                T.Ord when v.Tekst is "true" or "false" => v.Tekst,
                _ => throw Feil($"ugyldig verdi i meta: {v}"),
            };
        }
    }

    private void Strenger()
    {
        while (Se.Type == T.Ord && Se.Tekst.StartsWith("$"))
        {
            var id = Ta().Tekst;
            if (id == "$") id = "$\u0001" + _anonym++;
            if (_strenger.ContainsKey(id)) throw Feil($"strengen {id} finnes fra før");
            Forvent("=");
            var verdi = Ta();
            var mod = new HashSet<string>();
            (int, int)? xor = null;
            string? alfabet = null;
            while (Se.Type == T.Ord && Modifikatorer.Contains(Se.Tekst))
            {
                var m = Ta().Tekst;
                mod.Add(m);
                if (m == "xor")
                {
                    xor = (0, 255);
                    if (Er("("))
                    {
                        Ta();
                        int fra = (int)Ta().Heltall, til = fra;
                        if (Er("-")) { Ta(); til = (int)Ta().Heltall; }
                        Forvent(")");
                        xor = (fra, til);
                    }
                }
                else if (m is "base64" or "base64wide" && Er("("))
                {
                    Ta(); alfabet = Ta().Tekst; Forvent(")");
                    if (alfabet.Length != 64) throw Feil("base64-alfabet må ha 64 tegn");
                }
            }
            var s = new Streng { Id = id, Privat = mod.Contains("private") };
            switch (verdi.Type)
            {
                case T.Tekst: Strengbygger.Tekst(s, verdi.Bytes!, mod, xor, alfabet); break;
                case T.Hex: Strengbygger.Hex(s, verdi.Tekst, mod); break;
                case T.Regex: Strengbygger.Regex(s, verdi.Tekst, verdi.RegexFlagg, mod); break;
                default: throw Feil($"ugyldig streng {id}: {verdi}");
            }
            _strenger[id] = s;
        }
    }

    // ---------- uttrykk ----------

    private Uttrykk Eller()
    {
        var v = Og();
        while (Er("or")) { Ta(); var a = v; var b = Og(); v = k => V.Sann(a(k)) || V.Sann(b(k)); }
        return v;
    }

    private Uttrykk Og()
    {
        var v = Ikke();
        while (Er("and")) { Ta(); var a = v; var b = Ikke(); v = k => V.Sann(a(k)) && V.Sann(b(k)); }
        return v;
    }

    private Uttrykk Ikke()
    {
        if (Er("not")) { Ta(); var x = Ikke(); return k => x(k) is { } v ? !V.Sann(v) : null; }
        if (Er("defined")) { Ta(); var x = Ikke(); return k => x(k) != null; }
        return Relasjon();
    }

    private Uttrykk Relasjon()
    {
        var a = BitEller();
        while (true)
        {
            var op = Se.Tekst;
            if (Se.Type == T.Tegn && op is "==" or "!=" or "<" or "<=" or ">" or ">=")
            {
                Ta(); var x = a; var b = BitEller();
                a = k => V.Sammenlign(x(k), b(k), op);
            }
            else if (Se.Type == T.Ord && op is "contains" or "icontains" or "startswith" or "istartswith" or "endswith" or "iendswith" or "iequals")
            {
                Ta(); var x = a; var b = BitEller();
                a = k => V.Tekstsjekk(x(k), b(k), op);
            }
            else if (Se.Type == T.Ord && op == "matches")
            {
                Ta();
                if (Se.Type != T.Regex) throw Feil("matches må følges av et regex");
                var r = Ta();
                var re = new Regex(r.Tekst, (r.RegexFlagg.Contains('i') ? RegexOptions.IgnoreCase : 0) | (r.RegexFlagg.Contains('s') ? RegexOptions.Singleline : 0) | RegexOptions.CultureInvariant);
                var x = a;
                a = k => x(k) is string s ? re.IsMatch(s) : null;
            }
            else return a;
        }
    }

    private Uttrykk BitEller() => Binar(BitXor, "|");
    private Uttrykk BitXor() => Binar(BitOg, "^");
    private Uttrykk BitOg() => Binar(Skift, "&");
    private Uttrykk Skift() => Binar(Pluss, "<<", ">>");
    private Uttrykk Pluss() => Binar(Gange, "+", "-");
    private Uttrykk Gange() => Binar(Unar, "*", "\\", "%");

    private Uttrykk Binar(Func<Uttrykk> under, params string[] ops)
    {
        var v = under();
        while (Se.Type == T.Tegn && ops.Contains(Se.Tekst))
        {
            // "50% of them" er en kvantor, ikke modulo
            if (Se.Tekst == "%" && Neste.Type == T.Ord && Neste.Tekst == "of") return v;
            var op = Ta().Tekst; var a = v; var b = under();
            v = k => V.Regn(a(k), b(k), op);
        }
        return v;
    }

    private Uttrykk Unar()
    {
        if (Er("-")) { Ta(); var x = Unar(); return k => V.Regn(0L, x(k), "-"); }
        if (Er("~")) { Ta(); var x = Unar(); return k => x(k) is long l ? ~l : null; }
        return Primar();
    }

    private Uttrykk Primar()
    {
        var t = Se;
        if (Er("(")) { Ta(); var e = Eller(); Forvent(")"); return Etterledd(e); }
        if (t.Type == T.Heltall)
        {
            Ta();
            long n = t.Heltall;
            if (Er("of")) return Av(Kvantor.Antall(_ => n));
            if (Er("%") && Neste.Type == T.Ord && Neste.Tekst == "of") { Ta(); return Av(Kvantor.Prosent(_ => n)); }
            return _ => n;
        }
        if (t.Type == T.Desimal) { Ta(); double d = t.Desimal; return _ => d; }
        if (t.Type == T.Tekst) { Ta(); var s = Moduler.Latin1(t.Bytes!); return _ => s; }
        if (t.Type == T.Regex) throw Feil("regex kan bare brukes etter matches eller i strings");
        if (t.Type != T.Ord) throw Feil($"uventet {t}");
        switch (t.Tekst)
        {
            case "true": Ta(); return _ => true;
            case "false": Ta(); return _ => false;
            case "filesize": Ta(); return k => k.Filstorrelse;
            case "entrypoint": Ta(); return k => k.Modul("pe") is Struktur pe ? pe["entry_point"] : null;
            case "any": Ta(); return Av(Kvantor.Noen);
            case "all": Ta(); return Av(Kvantor.Alle);
            case "none": Ta(); return Av(Kvantor.Ingen);
            case "for": Ta(); return For();
            case "them": throw Feil("'them' må stå etter of");
        }
        var navn = t.Tekst;
        if (navn[0] is '$' or '#' or '@' or '!') return Strengreferanse();
        if (Regex.IsMatch(navn, @"^u?int(8|16|32)(be)?$") && Neste.Type == T.Tegn && Neste.Tekst == "(")
        {
            Ta(); Ta();
            var pos = Eller(); Forvent(")");
            int n = navn.Contains("8") ? 1 : navn.Contains("16") ? 2 : 4;
            bool be = navn.EndsWith("be"), fortegn = !navn.StartsWith("u");
            return k =>
            {
                if (pos(k) is not long p) return null;
                var b = k.Les(p, n);
                if (b == null) return null;
                long v = 0;
                for (int i = 0; i < n; i++) v |= (long)b[i] << (8 * (be ? n - 1 - i : i));
                if (fortegn && (v & (1L << (8 * n - 1))) != 0) v -= 1L << (8 * n);
                return v;
            };
        }
        Ta();
        // Variabel i en løkke, modul eller regel
        for (int i = _variabler.Count - 1; i >= 0; i--)
            if (_variabler[i].Contains(navn)) return Etterledd(k => k.Variabler.TryGetValue(navn, out var v) ? v : null);
        if (KjenteModuler.Contains(navn)) return Etterledd(k => k.Modul(navn));
        var regel = _regler.FirstOrDefault(r => r.Navn == navn);
        if (regel != null) return k => k.KjorRegel(regel);
        throw Feil($"ukjent navn '{navn}'");
    }

    /// <summary>.felt, [indeks] og (argumenter) etter et navn.</summary>
    private Uttrykk Etterledd(Uttrykk v)
    {
        while (true)
        {
            if (Er("."))
            {
                Ta(); var felt = Ord(); var x = v;
                v = k => x(k) is Struktur s ? s[felt] : null;
            }
            else if (Er("["))
            {
                Ta(); var indeks = Eller(); Forvent("]"); var x = v;
                v = k =>
                {
                    var o = x(k); var i = indeks(k);
                    if (o is List<object?> l && i is long n) return n >= 0 && n < l.Count ? l[(int)n] : null;
                    if (o is Dictionary<string, object?> d && i is string key) return d.TryGetValue(key, out var r) ? r : null;
                    return null;
                };
            }
            else if (Er("("))
            {
                Ta();
                var arg = new List<Uttrykk>();
                while (!Er(")"))
                {
                    if (Se.Type == T.Regex) { var r = Ta(); var re = new Regex(r.Tekst, r.RegexFlagg.Contains('i') ? RegexOptions.IgnoreCase : 0); arg.Add(_ => re); }
                    else arg.Add(Eller());
                    if (Er(",")) Ta();
                }
                Ta();
                var x = v;
                v = k => x(k) is Funksjon f ? f(k, arg.Select(a => a(k)).ToArray()) : null;
            }
            else return v;
        }
    }

    // ---------- strenger i betingelsen ----------

    private Uttrykk Strengreferanse()
    {
        var navn = Ta().Tekst;
        char type = navn[0];
        var id = "$" + navn.Substring(1);
        Func<Kontekst, Streng?> streng;
        if (id == "$")
        {
            if (_forOf == 0) throw Feil($"'{navn}' uten navn kan bare brukes i for ... of");
            streng = k => k.Anonym;
        }
        else
        {
            if (!_strenger.TryGetValue(id, out var s)) throw Feil($"ukjent streng {id}");
            streng = _ => s;
        }
        switch (type)
        {
            case '$':
                if (Er("at")) { Ta(); var pos = Pluss(); return k => pos(k) is long p ? k.TreffFor(streng(k)!)?.ContainsKey(p) == true : null; }
                if (Er("in")) { var (lo, hi) = Omrade(); return k => lo(k) is long a && hi(k) is long b ? k.TreffFor(streng(k)!)?.Keys.Any(o => o >= a && o <= b) == true : null; }
                return k => k.TreffFor(streng(k)!)?.Count > 0;
            case '#':
                if (Er("in")) { var (lo, hi) = Omrade(); return k => lo(k) is long a && hi(k) is long b ? (long)(k.TreffFor(streng(k)!)?.Keys.Count(o => o >= a && o <= b) ?? 0) : null; }
                return k => (long)(k.TreffFor(streng(k)!)?.Count ?? 0);
            default:
                Uttrykk nr = _ => 1L;
                if (Er("[")) { Ta(); nr = Eller(); Forvent("]"); }
                bool lengde = type == '!';
                return k =>
                {
                    var t = k.TreffFor(streng(k)!);
                    if (t == null || nr(k) is not long n || n < 1 || n > t.Count) return null;
                    var e = t.ElementAt((int)n - 1);
                    return lengde ? e.Value : e.Key;
                };
        }
    }

    private (Uttrykk Lo, Uttrykk Hi) Omrade()
    {
        Forvent("in"); Forvent("(");
        var lo = Eller(); Forvent(".."); var hi = Eller();
        Forvent(")");
        return (lo, hi);
    }

    // ---------- of og for ----------

    private sealed class Kvantor
    {
        public Func<int, int, Kontekst, bool?> Oppfylt = null!;
        public static readonly Kvantor Noen = new() { Oppfylt = (n, _, _) => n > 0 };
        public static readonly Kvantor Alle = new() { Oppfylt = (n, tot, _) => n == tot };
        public static readonly Kvantor Ingen = new() { Oppfylt = (n, _, _) => n == 0 };
        public static Kvantor Antall(Uttrykk x) => new() { Oppfylt = (n, _, k) => x(k) is long m ? n >= m : null };
        public static Kvantor Prosent(Uttrykk x) => new() { Oppfylt = (n, tot, k) => x(k) is long p ? n * 100L >= p * tot : null };
    }

    private Kvantor LesKvantor()
    {
        if (Er("any")) { Ta(); return Kvantor.Noen; }
        if (Er("all")) { Ta(); return Kvantor.Alle; }
        if (Er("none")) { Ta(); return Kvantor.Ingen; }
        var x = Pluss();
        if (Er("%")) { Ta(); return Kvantor.Prosent(x); }
        return Kvantor.Antall(x);
    }

    /// <summary>Settet etter of: them, ($a, $b*) eller (regel1, regel*).</summary>
    private (List<Streng>? Strenger, List<Regel>? Regler) Sett()
    {
        if (Er("them")) { Ta(); return (_strenger.Values.ToList(), null); }
        Forvent("(");
        var strenger = new List<Streng>();
        var regler = new List<Regel>();
        while (!Er(")"))
        {
            var n = Ord();
            if (n.StartsWith("$"))
            {
                if (n.EndsWith("*")) strenger.AddRange(_strenger.Where(s => s.Key.StartsWith(n.TrimEnd('*'))).Select(s => s.Value));
                else if (_strenger.TryGetValue(n, out var s)) strenger.Add(s);
                else throw Feil($"ukjent streng {n}");
            }
            else if (n.EndsWith("*")) regler.AddRange(_regler.Where(r => r.Navn.StartsWith(n.TrimEnd('*'))));
            else regler.Add(_regler.FirstOrDefault(r => r.Navn == n) ?? throw Feil($"ukjent regel {n}"));
            if (Er(",")) Ta();
        }
        Ta();
        if (strenger.Count > 0 && regler.Count > 0) throw Feil("et sett kan ikke blande strenger og regler");
        return regler.Count > 0 ? (null, regler) : (strenger, null);
    }

    private Uttrykk Av(Kvantor q)
    {
        Forvent("of");
        var (strenger, regler) = Sett();
        if (regler != null) return k => q.Oppfylt(regler.Count(r => k.KjorRegel(r)), regler.Count, k);
        var liste = strenger!;
        if (Er("at"))
        {
            Ta(); var pos = Pluss();
            return k => pos(k) is long p ? q.Oppfylt(liste.Count(s => k.TreffFor(s)?.ContainsKey(p) == true), liste.Count, k) : null;
        }
        if (Er("in"))
        {
            var (lo, hi) = Omrade();
            return k => lo(k) is long a && hi(k) is long b ? q.Oppfylt(liste.Count(s => k.TreffFor(s)?.Keys.Any(o => o >= a && o <= b) == true), liste.Count, k) : null;
        }
        return k => q.Oppfylt(liste.Count(s => k.TreffFor(s)?.Count > 0), liste.Count, k);
    }

    private Uttrykk For()
    {
        var q = LesKvantor();
        if (Er("of"))
        {
            Ta();
            var (strenger, regler) = Sett();
            if (regler != null) throw Feil("for ... of virker bare på strenger");
            Forvent(":"); Forvent("(");
            _forOf++;
            var kropp = Eller();
            _forOf--;
            Forvent(")");
            var liste = strenger!;
            return k =>
            {
                var gammel = k.Anonym;
                int n = 0;
                foreach (var s in liste) { k.Anonym = s; if (V.Sann(kropp(k))) n++; }
                k.Anonym = gammel;
                return q.Oppfylt(n, liste.Count, k);
            };
        }
        // for any i in (1..#a) : ( ... ),  for all s in pe.sections : ( ... ),  for any k, v in ordbok : ( ... )
        var navn = new List<string> { Ord() };
        while (Er(",")) { Ta(); navn.Add(Ord()); }
        Forvent("in");
        Func<Kontekst, IEnumerable<object?[]>?> verdier;
        if (Er("("))
        {
            Ta();
            var forste = Eller();
            if (Er(".."))
            {
                Ta(); var siste = Eller(); Forvent(")");
                verdier = k => forste(k) is long a && siste(k) is long b ? Omr(a, b) : null;
            }
            else
            {
                var liste = new List<Uttrykk> { forste };
                while (Er(",")) { Ta(); liste.Add(Eller()); }
                Forvent(")");
                verdier = k => liste.Select(x => new[] { x(k) });
            }
        }
        else
        {
            var kilde = Primar();
            verdier = k => kilde(k) switch
            {
                List<object?> l => l.Select(x => new[] { x }),
                Dictionary<string, object?> d => d.Select(x => new object?[] { x.Key, x.Value }),
                _ => null,
            };
        }
        Forvent(":"); Forvent("(");
        _variabler.Add(new HashSet<string>(navn));
        var b = Eller();
        _variabler.RemoveAt(_variabler.Count - 1);
        Forvent(")");
        return k =>
        {
            var alle = verdier(k);
            if (alle == null) return null;
            var gamle = navn.Select(n => k.Variabler.TryGetValue(n, out var g) ? g : null).ToArray();
            int treff = 0, totalt = 0;
            foreach (var v in alle)
            {
                for (int i = 0; i < navn.Count; i++) k.Variabler[navn[i]] = i < v.Length ? v[i] : null;
                totalt++;
                if (V.Sann(b(k))) treff++;
                if (totalt > 1_000_000) break;
            }
            for (int i = 0; i < navn.Count; i++) k.Variabler[navn[i]] = gamle[i];
            return q.Oppfylt(treff, totalt, k);
        };
        static IEnumerable<object?[]> Omr(long a, long b) { for (long i = a; i <= b && i - a < 1_000_000; i++) yield return new object?[] { i }; }
    }
}

/// <summary>Regning og sammenligning med YARAs regler: udefinert (null) smitter, og gjør betingelsen usann.</summary>
internal static class V
{
    public static bool Sann(object? o) => o switch
    {
        null => false,
        bool b => b,
        long l => l != 0,
        double d => d != 0,
        string s => s.Length > 0,
        _ => true,
    };

    private static object? Tall(object? o) => o is bool b ? (b ? 1L : 0L) : o;

    public static object? Sammenlign(object? a, object? b, string op)
    {
        a = Tall(a); b = Tall(b);
        if (a == null || b == null) return null;
        int c;
        if (a is string x && b is string y) c = string.CompareOrdinal(x, y);
        else if (a is long l1 && b is long l2) c = l1.CompareTo(l2);
        else if ((a is long or double) && (b is long or double)) c = Convert.ToDouble(a).CompareTo(Convert.ToDouble(b));
        else return null;
        return op switch { "==" => c == 0, "!=" => c != 0, "<" => c < 0, "<=" => c <= 0, ">" => c > 0, _ => c >= 0 };
    }

    public static object? Tekstsjekk(object? a, object? b, string op)
    {
        if (a is not string x || b is not string y) return null;
        var sml = op.StartsWith("i") ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return op switch
        {
            "contains" or "icontains" => x.IndexOf(y, sml) >= 0,
            "startswith" or "istartswith" => x.StartsWith(y, sml),
            "endswith" or "iendswith" => x.EndsWith(y, sml),
            _ => string.Equals(x, y, sml),
        };
    }

    public static object? Regn(object? a, object? b, string op)
    {
        a = Tall(a); b = Tall(b);
        if (a == null || b == null) return null;
        if (a is long x && b is long y)
        {
            switch (op)
            {
                case "+": return x + y;
                case "-": return x - y;
                case "*": return x * y;
                case "\\": return y == 0 ? null : x / y;
                case "%": return y == 0 ? null : x % y;
                case "&": return x & y;
                case "|": return x | y;
                case "^": return x ^ y;
                case "<<": return y >= 64 ? 0L : x << (int)y;
                case ">>": return y >= 64 ? 0L : x >> (int)y;
            }
        }
        if ((a is long or double) && (b is long or double))
        {
            double p = Convert.ToDouble(a), q = Convert.ToDouble(b);
            return op switch { "+" => p + q, "-" => p - q, "*" => p * q, "\\" => q == 0 ? null : p / q, _ => null };
        }
        return null;
    }
}
