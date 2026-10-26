using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Oversetter tekstene skanneren lager til engelsk, i vinduet og i rapporten. Ordlista ligger i engelsk.txt.
/// Lengste tekst vinner, og alt byttes i én runde, så engelsk tekst blir ikke oversatt på nytt.
/// Stier og nettadresser røres ikke. Det som mangler i lista, står igjen på norsk.
/// </summary>
public static class Engelsk
{
    private sealed class Ordliste
    {
        public readonly List<(Regex Monster, string Til)> Monstre = new();
        public readonly Dictionary<string, string> Fraser = new(StringComparer.Ordinal);
        public Regex? Alle;
    }

    private static readonly Lazy<Ordliste> Liste = new(Last);
    private static readonly Regex Setninger = new(@"(?<=[.!?])\s+(?=[A-ZÆØÅ«])", RegexOptions.Compiled);
    // Forkortelser med punktum må byttes før domene-vernet under, ellers ser de ut som domener
    private static readonly (string Fra, string Til)[] Forkortelser = { ("f.eks.", "e.g."), ("m.fl.", "et al."), ("bl.a.", "among others"), ("o.l.", "etc.") };
    private static readonly TimeSpan Grense = TimeSpan.FromSeconds(1);

    // Windows-stier (til neste " · " eller slutten), nettadresser og ord med punktum (domener, filnavn)
    private static readonly Regex Beskyttet = new(
        @"[A-Za-z]:\\.*?(?=\s·\s|\s\(|$)|\bHK(?:LM|CU|CR|U)\\.*?(?=\s·\s|\s\(|$)|\\\\[^\s]+|https?://\S+|\b[\w-]+(?:\.[\w-]+)*\.[A-Za-z][\w-]+\b", RegexOptions.Compiled, Grense);

    private static Ordliste Last()
    {
        var o = new Ordliste();
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.engelsk.txt");
            if (s == null) return o;
            using var r = new StreamReader(s, Encoding.UTF8);
            string? linje;
            while ((linje = r.ReadLine()) != null)
            {
                if (linje.Length == 0 || linje[0] == '#') continue;
                int i = linje.LastIndexOf('|');
                if (i <= 0) continue;
                var (fra, til) = (linje.Substring(0, i), linje.Substring(i + 1));
                if (fra[0] != '~') foreach (var (f, t) in Forkortelser) fra = fra.Replace(f, t);
                if (fra[0] == '~') { o.Monstre.Add((new Regex(fra.Substring(1), RegexOptions.CultureInvariant, Grense), til)); continue; }
                o.Fraser[fra] = til;
                // Skanneren viser ofte bare første setning(er). Hver setning legges også inn alene, og de første setningene samlet.
                var a = Setninger.Split(fra);
                var b = Setninger.Split(til);
                if (a.Length > 1 && a.Length == b.Length)
                    for (int n = 0; n < a.Length; n++)
                    {
                        if (!o.Fraser.ContainsKey(a[n])) o.Fraser[a[n]] = b[n];
                        var forste = string.Join(" ", a.Take(n + 1));
                        if (!o.Fraser.ContainsKey(forste)) o.Fraser[forste] = string.Join(" ", b.Take(n + 1));
                    }
            }
            // Én regex med alle frasene, lengste først. Bare hele ord: "lag" skal ikke treffe i "Lambda-lag".
            var alt = string.Join("|", o.Fraser.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape));
            if (alt.Length > 0) o.Alle = new Regex(@"(?<![\p{L}\d-])(?:" + alt + @")(?![\p{L}\d-])", RegexOptions.CultureInvariant, Grense);
        }
        catch { }
        return o;
    }

    public static string? Til(string? tekst)
    {
        if (string.IsNullOrEmpty(tekst)) return tekst;
        try
        {
            var o = Liste.Value;
            foreach (var (fra, til) in Forkortelser) tekst = tekst!.Replace(fra, til);
            var sb = new StringBuilder(tekst!.Length + 16);
            int pos = 0;
            foreach (Match b in Beskyttet.Matches(tekst))
            {
                sb.Append(Oversett(o, tekst.Substring(pos, b.Index - pos)));
                sb.Append(b.Value);
                pos = b.Index + b.Length;
            }
            sb.Append(Oversett(o, tekst.Substring(pos)));
            return sb.ToString();
        }
        catch { return tekst; }
    }

    public static List<string> Til(IEnumerable<string> tekster) => tekster.Select(t => Til(t)!).ToList();

    /// <summary>Oversetter alle tekstverdier i et JSON-dokument. Nøklene røres ikke.</summary>
    public static string Json(string json)
    {
        var rot = System.Text.Json.Nodes.JsonNode.Parse(json);
        void Gaa(System.Text.Json.Nodes.JsonNode? n)
        {
            if (n is System.Text.Json.Nodes.JsonObject obj)
                foreach (var k in obj.Select(x => x.Key).ToList())
                {
                    if (obj[k] is System.Text.Json.Nodes.JsonValue v && v.TryGetValue<string>(out var s)) obj[k] = Til(s);
                    else Gaa(obj[k]);
                }
            else if (n is System.Text.Json.Nodes.JsonArray arr)
                for (int i = 0; i < arr.Count; i++)
                {
                    if (arr[i] is System.Text.Json.Nodes.JsonValue v && v.TryGetValue<string>(out var s)) arr[i] = Til(s);
                    else Gaa(arr[i]);
                }
        }
        Gaa(rot);
        return rot?.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }) ?? json;
    }

    private static string Oversett(Ordliste o, string s)
    {
        if (s.Length == 0) return s;
        foreach (var (m, til) in o.Monstre) s = m.Replace(s, til);
        return o.Alle == null ? s : o.Alle.Replace(s, x => o.Fraser.TryGetValue(x.Value, out var t) ? t : x.Value);
    }
}
