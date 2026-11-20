using System.Text.Json;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Avhengighetsfiler i prosjekter (requirements*.txt, pyproject.toml, Pipfile, poetry.lock, uv.lock, environment.yml,
/// package.json, .csproj, packages.lock.json, packages.config). Bare pakkenavn leses og sammenlignes med pakkelistene i regler.json. Kommentarer, versjoner, adresser
/// og alt annet i fila leses ikke videre, vises ikke og lagres ikke. Store filer hoppes over.
/// </summary>
public sealed partial class Skanner
{
    private static readonly Regex AvhNavn = new(@"^[A-Za-z0-9@][A-Za-z0-9_.\-/]*", RegexOptions.Compiled);
    private static readonly Regex Nokkel = new(@"^([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*=\s*([^\[]|$)", RegexOptions.Compiled);
    private static readonly Regex Sitert = new(@"[""']([A-Za-z0-9][A-Za-z0-9_.\-]*)", RegexOptions.Compiled);

    /// <summary>Språket fila hører til, eller null når navnet ikke er en avhengighetsfil.</summary>
    internal static string? Avhengighetsfil(string navn)
    {
        var n = navn.ToLowerInvariant();
        if (n == "package.json") return "Node";
        if (n.EndsWith(".csproj") || n.EndsWith(".fsproj") || n.EndsWith(".vbproj") || n is "packages.lock.json" or "directory.packages.props" or "packages.config") return ".NET";
        if (n.StartsWith("requirements") && n.EndsWith(".txt") || n is "pyproject.toml" or "pipfile" or "poetry.lock" or "uv.lock" or "environment.yml" or "environment.yaml") return "Python";
        return null;
    }

    /// <summary>Pakkenavnene i fila. Ingenting annet tas med.</summary>
    internal static IEnumerable<string> AvhengighetNavn(string navn, string tekst)
    {
        var n = navn.ToLowerInvariant();
        if (n == "package.json")
        {
            var ut = new List<string>();
            try
            {
                using var d = JsonDocument.Parse(tekst);
                if (d.RootElement.ValueKind != JsonValueKind.Object) return ut;
                foreach (var del in new[] { "dependencies", "devDependencies", "optionalDependencies", "peerDependencies" })
                    if (d.RootElement.TryGetProperty(del, out var a) && a.ValueKind == JsonValueKind.Object)
                        ut.AddRange(a.EnumerateObject().Select(p => p.Name));
            }
            catch (JsonException) { }
            return ut;
        }
        if (Avhengighetsfil(n) == ".NET")
        {
            // <PackageReference Include="X"/>, <PackageVersion Include="X"/>, <package id="X"/> og «"X": { "type": …» i packages.lock.json
            var ut = new List<string>();
            foreach (Match m in NugetNavn.Matches(tekst)) ut.Add(m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value);
            return ut;
        }
        return Linjer(n, tekst);
    }
    private static readonly Regex NugetNavn = new(@"<(?:PackageReference|PackageVersion|package)\s[^>]*?\b(?:Include|Update|id)\s*=\s*""([A-Za-z0-9_.\-]{1,100})""|""([A-Za-z0-9_.\-]{1,100})""\s*:\s*\{\s*""type""", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static IEnumerable<string> Linjer(string n, string tekst)
    {
        string seksjon = "";
        bool iListe = false;
        foreach (var r in tekst.Split('\n').Take(50000))
        {
            var h = r.IndexOf('#');
            var l = (h >= 0 ? r.Substring(0, h) : r).Trim();
            if (l.Length == 0) continue;
            if (n.StartsWith("requirements"))
            {
                if (!l.StartsWith("-") && AvhNavn.Match(l) is { Success: true } m) yield return m.Value;
                continue;
            }
            if (n.StartsWith("environment."))
            {
                if (l.StartsWith("- ") && AvhNavn.Match(l.Substring(2).Trim()) is { Success: true } m && m.Value != "pip") yield return m.Value;
                continue;
            }
            if (l.StartsWith("[")) { seksjon = l.ToLowerInvariant(); iListe = false; continue; }
            if (n.EndsWith(".lock"))
            {
                if (seksjon == "[[package]]" && l.StartsWith("name") && Sitert.Match(l) is { Success: true } m) yield return m.Groups[1].Value;
                continue;
            }
            // pyproject.toml og Pipfile
            bool avh = seksjon.Contains("dependenc") || seksjon is "[packages]" or "[dev-packages]";
            if (avh && Nokkel.Match(l) is { Success: true } k) { if (k.Groups[1].Value != "python") yield return k.Groups[1].Value; continue; }
            if (seksjon == "[project]" && l.StartsWith("dependencies")) iListe = true;
            if (avh || iListe) foreach (Match s in Sitert.Matches(l)) yield return s.Groups[1].Value;
            if (iListe && l.Contains("]")) iListe = false;
        }
    }

    /// <summary>Leser en avhengighetsfil og husker AI-pakkene i den. Bare navn som står i pakkelistene, tas med.</summary>
    private static void SjekkAvhengighetsfil(FileInfo fil, string sprak, FilFunn ff)
    {
        long lengde;
        try { lengde = fil.Length; } catch { return; }
        var grense = fil.Name.EndsWith(".lock", StringComparison.OrdinalIgnoreCase) ? 4L << 20 : 1L << 20;
        if (lengde > grense) { Tilgangslogg.Tell("Fil", Utfall.HoppetOver, sted: fil.FullName, detalj: "avhengighetsfil større enn grensen"); return; }
        string tekst;
        try { tekst = File.ReadAllText(fil.FullName); } catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); return; }
        Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName, detalj: "avhengighetsfil: bare pakkenavn");
        var (pakker, agent) = AiPakker(AvhengighetNavn(fil.Name, tekst), sprak == "Node" ? NodeAi : sprak == ".NET" ? DotnetAi : PythonAi, sprak == "Python");
        if (pakker.Count == 0 || pakker.All(p => p is "ai" or "agents")) return;
        lock (ff) ff.Avhengigheter.Add((fil.FullName, fil.DirectoryName ?? "", pakker, agent, sprak));
    }

    /// <summary>Navnene som står i pakkelista. Python-navn sammenlignes uten forskjell på store/små bokstaver, «-», «_» og «.».</summary>
    internal static (SortedSet<string> Pakker, bool Agent) AiPakker(IEnumerable<string> navn, Dictionary<string, bool> kjente, bool python)
    {
        static string N(string s) => s.ToLowerInvariant().Replace('-', '_').Replace('.', '_');
        var oppslag = python ? kjente.GroupBy(k => N(k.Key)).ToDictionary(g => g.Key, g => g.First()) : null;
        var pakker = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        bool agent = false;
        foreach (var x in navn)
        {
            KeyValuePair<string, bool> k;
            if (oppslag != null) { if (!oppslag.TryGetValue(N(x), out k)) continue; }
            else if (kjente.TryGetValue(x, out var a)) k = new(x, a); else continue;
            pakker.Add(k.Key);
            agent |= k.Value;
        }
        return (pakker, agent);
    }
}
