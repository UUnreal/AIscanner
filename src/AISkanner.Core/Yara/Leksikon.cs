using System.Globalization;
using System.Text;

namespace AISkanner.YaraMotor;

internal enum T { Ord, Tekst, Hex, Regex, Heltall, Desimal, Tegn, Slutt }

/// <summary>Ett ord i regelfila.</summary>
internal sealed class Token
{
    public T Type;
    public string Tekst = "";
    /// <summary>Bytes for tekststrenger (etter \x.. osv.).</summary>
    public byte[]? Bytes;
    public long Heltall;
    public double Desimal;
    /// <summary>Flagg etter et regex (i, s).</summary>
    public string RegexFlagg = "";
    public int Linje;
    public override string ToString() => Type == T.Slutt ? "slutten av fila" : $"'{Tekst}'";
}

/// <summary>Deler YARA-tekst opp i ord, tall, strenger, hex og regex.</summary>
internal static class Leksikon
{
    public static List<Token> Les(string s)
    {
        var ut = new List<Token>();
        int i = 0, linje = 1;
        bool ForrigeEr(string x) => ut.Count > 0 && ut[ut.Count - 1].Type == T.Tegn && ut[ut.Count - 1].Tekst == x;
        while (i < s.Length)
        {
            char c = s[i];
            if (c == '\n') { linje++; i++; continue; }
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '/' && i + 1 < s.Length && s[i + 1] == '/') { while (i < s.Length && s[i] != '\n') i++; continue; }
            if (c == '/' && i + 1 < s.Length && s[i + 1] == '*')
            {
                int e = s.IndexOf("*/", i + 2, StringComparison.Ordinal);
                int slutt = e < 0 ? s.Length : e + 2;
                for (int k = i; k < slutt; k++) if (s[k] == '\n') linje++;
                i = slutt; continue;
            }
            var t = new Token { Linje = linje };
            if (c == '"')
            {
                var b = new List<byte>();
                int j = i + 1;
                while (j < s.Length && s[j] != '"')
                {
                    if (s[j] == '\\' && j + 1 < s.Length)
                    {
                        char n = s[j + 1];
                        switch (n)
                        {
                            case 'n': b.Add(10); j += 2; break;
                            case 't': b.Add(9); j += 2; break;
                            case 'r': b.Add(13); j += 2; break;
                            case 'x': b.Add(Convert.ToByte(s.Substring(j + 2, 2), 16)); j += 4; break;
                            default: b.AddRange(Encoding.UTF8.GetBytes(n.ToString())); j += 2; break;
                        }
                        continue;
                    }
                    if (s[j] == '\n') throw new FormatException($"Linje {linje}: tekst uten avsluttende \".");
                    b.AddRange(Encoding.UTF8.GetBytes(s[j].ToString()));
                    j++;
                }
                t.Type = T.Tekst; t.Bytes = b.ToArray(); t.Tekst = Encoding.UTF8.GetString(t.Bytes);
                ut.Add(t); i = j + 1; continue;
            }
            if (c == '{' && ForrigeEr("="))
            {
                int e = s.IndexOf('}', i);
                if (e < 0) throw new FormatException($"Linje {linje}: hex-streng uten }}.");
                var innhold = s.Substring(i + 1, e - i - 1);
                // Kommentarer inni hex
                innhold = System.Text.RegularExpressions.Regex.Replace(innhold, @"//[^\n]*|/\*.*?\*/", " ", System.Text.RegularExpressions.RegexOptions.Singleline);
                for (int k = i; k < e; k++) if (s[k] == '\n') linje++;
                t.Type = T.Hex; t.Tekst = innhold;
                ut.Add(t); i = e + 1; continue;
            }
            if (c == '/')
            {
                // Regex: /.../is
                var sb = new StringBuilder();
                int j = i + 1;
                while (j < s.Length && s[j] != '/')
                {
                    if (s[j] == '\\' && j + 1 < s.Length) { sb.Append(s[j]).Append(s[j + 1]); j += 2; continue; }
                    if (s[j] == '\n') throw new FormatException($"Linje {linje}: regex uten avsluttende /.");
                    sb.Append(s[j]); j++;
                }
                j++;
                int f = j;
                while (j < s.Length && (s[j] == 'i' || s[j] == 's')) j++;
                t.Type = T.Regex; t.Tekst = sb.ToString(); t.RegexFlagg = s.Substring(f, j - f);
                ut.Add(t); i = j; continue;
            }
            if (char.IsDigit(c))
            {
                int j = i;
                if (c == '0' && i + 1 < s.Length && (s[i + 1] == 'x' || s[i + 1] == 'X'))
                {
                    j = i + 2;
                    while (j < s.Length && Uri.IsHexDigit(s[j])) j++;
                    t.Type = T.Heltall; t.Heltall = long.Parse(s.Substring(i + 2, j - i - 2), NumberStyles.HexNumber);
                }
                else if (c == '0' && i + 1 < s.Length && s[i + 1] == 'o')
                {
                    j = i + 2;
                    while (j < s.Length && s[j] >= '0' && s[j] <= '7') j++;
                    t.Type = T.Heltall; t.Heltall = Convert.ToInt64(s.Substring(i + 2, j - i - 2), 8);
                }
                else
                {
                    while (j < s.Length && char.IsDigit(s[j])) j++;
                    if (j + 1 < s.Length && s[j] == '.' && char.IsDigit(s[j + 1]))
                    {
                        j++;
                        while (j < s.Length && char.IsDigit(s[j])) j++;
                        t.Type = T.Desimal; t.Desimal = double.Parse(s.Substring(i, j - i), CultureInfo.InvariantCulture);
                    }
                    else { t.Type = T.Heltall; t.Heltall = long.Parse(s.Substring(i, j - i), CultureInfo.InvariantCulture); }
                }
                if (t.Type == T.Heltall && j + 1 < s.Length && s[j + 1] == 'B' && (s[j] == 'K' || s[j] == 'M'))
                {
                    t.Heltall *= s[j] == 'K' ? 1024 : 1024 * 1024;
                    j += 2;
                }
                t.Tekst = s.Substring(i, j - i);
                ut.Add(t); i = j; continue;
            }
            if (char.IsLetter(c) || c == '_' || ((c is '$' or '#' or '@' or '!') && Navnetegn(s, i + 1, c)))
            {
                int j = i + 1;
                while (j < s.Length && (char.IsLetterOrDigit(s[j]) || s[j] == '_')) j++;
                if (j < s.Length && s[j] == '*' && c == '$') j++;
                else if (j < s.Length && s[j] == '*' && char.IsLetter(c) && FørSettSlutt(s, j + 1)) j++;   // regelnavn med * i "any of (regel*)"
                t.Type = T.Ord; t.Tekst = s.Substring(i, j - i);
                ut.Add(t); i = j; continue;
            }
            // Tegn
            var to = i + 1 < s.Length ? s.Substring(i, 2) : "";
            if (to is "==" or "!=" or "<=" or ">=" or "<<" or ">>" or "..")
            {
                t.Type = T.Tegn; t.Tekst = to; ut.Add(t); i += 2; continue;
            }
            t.Type = T.Tegn; t.Tekst = c.ToString(); ut.Add(t); i++;
        }
        ut.Add(new Token { Type = T.Slutt, Linje = linje });
        return ut;
    }

    private static bool FørSettSlutt(string s, int i)
    {
        while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        return i < s.Length && (s[i] == ',' || s[i] == ')');
    }

    /// <summary>$a, $, $*, #a, #, @a, @, !a, ! (det siste bare i for-løkker, ellers er ! en del av !=).</summary>
    private static bool Navnetegn(string s, int i, char forste)
    {
        if (forste == '$') return true;
        if (i >= s.Length) return forste != '!';
        char n = s[i];
        if (forste == '!') return char.IsLetter(n) || n == '_' || n == '[';
        return true;
    }
}
