using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Kommandolinjen til en prosess, lest fra Windows (ProcessCommandLineInformation). Prosessminnet leses ikke.
/// Brukes bare for tolkere (python, node, powershell …) og programmer som allerede er AI-funn, og bare i minnet:
/// den sammenlignes med reglene og kastes. Det som vises, er regelen som slo til og skriptfila, aldri argumentene.
/// IT kan slå det av (regler.json «lesKommandolinjer»: false, eller HKLM\SOFTWARE\Policies\AISkanner LesKommandolinjer = 0).
/// </summary>
internal static class Kommandolinje
{
    /// <summary>Tolkere som kjører skript. Navnet på prosessen, uten .exe.</summary>
    public static readonly ISet<string> Tolkere = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "python", "pythonw", "python3", "py", "pyw", "node", "bun", "deno", "powershell", "pwsh", "java", "javaw", "uv", "uvx", "wscript", "cscript",
    };

    public static bool ErTolk(string prosess) =>
        Tolkere.Contains(prosess) || System.Text.RegularExpressions.Regex.IsMatch(prosess, @"^pythonw?3(\.?\d+)?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr prosess, int klasse, IntPtr buffer, int lengde, out int svar);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint tilgang, bool arv, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    private const int ProcessCommandLineInformation = 60;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    /// <summary>Kommandolinjen, eller null når Windows nekter (andre kontoer uten admin, beskyttede prosesser).</summary>
    public static string? Les(int pid)
    {
        if (!Plattform.ErWindows) return null;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            NtQueryInformationProcess(h, ProcessCommandLineInformation, IntPtr.Zero, 0, out var lengde);
            if (lengde <= 0 || lengde > 1 << 20) return null;
            var buf = Marshal.AllocHGlobal(lengde);
            try
            {
                if (NtQueryInformationProcess(h, ProcessCommandLineInformation, buf, lengde, out _) != 0) return null;
                // UNICODE_STRING { ushort Length; ushort MaximumLength; PWSTR Buffer } – bufferen ligger rett etter
                int bytes = (ushort)Marshal.ReadInt16(buf);
                var peker = Marshal.ReadIntPtr(buf, IntPtr.Size);
                return bytes == 0 || peker == IntPtr.Zero ? "" : Marshal.PtrToStringUni(peker, bytes / 2);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }

    /// <summary>Om IT har slått av lesing av kommandolinjer. Grunnen logges i datagrunnlaget.</summary>
    public static bool Tillatt(Regelsett regler, out string grunn)
    {
        if (regler.LesKommandolinjer == false) { grunn = $"slått av av IT i {regler.Kilde} (lesKommandolinjer: false)"; return false; }
        if (Plattform.ErWindows)
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\AISkanner");
                if (k?.GetValue("LesKommandolinjer") is int v && v == 0) { grunn = @"slått av av IT (HKLM\SOFTWARE\Policies\AISkanner LesKommandolinjer = 0)"; return false; }
            }
            catch { }
        grunn = "";
        return true;
    }

    /// <summary>Deler en Windows-kommandolinje i argumenter, etter samme regler som CommandLineToArgvW.</summary>
    public static List<string> Del(string linje)
    {
        var liste = new List<string>();
        var sb = new StringBuilder();
        bool i = false, har = false;
        for (int n = 0; n < linje.Length; n++)
        {
            char c = linje[n];
            if (c == '\\')
            {
                // 2n skråstreker + " gir n skråstreker og bytter anførsel; 2n+1 gir n og et vanlig "
                int s = 0;
                while (n < linje.Length && linje[n] == '\\') { s++; n++; }
                if (n < linje.Length && linje[n] == '"') { sb.Append('\\', s / 2); if (s % 2 == 1) sb.Append('"'); else i = !i; }
                else { sb.Append('\\', s); n--; }
                har = true;
                continue;
            }
            if (c == '"') { i = !i; har = true; continue; }
            if (!i && char.IsWhiteSpace(c)) { if (har) { liste.Add(sb.ToString()); sb.Clear(); har = false; } continue; }
            sb.Append(c); har = true;
        }
        if (har) liste.Add(sb.ToString());
        return liste;
    }

    /// <summary>Hva tolken kjører. Ingen argumenter tas med ut, bare skript, modul, pakke og kode skrevet på linjen.</summary>
    public sealed class Tolket
    {
        public string? Skript;
        public string? Modul;
        public string? Pakke;
        public string? Kode;
        public bool Kodet;
        public List<string> Flagg = new();
        public string? Modellfil;
        public string Sprak = "";
    }

    private static readonly ISet<string> Modellendelser = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".gguf", ".safetensors", ".ggml", ".llamafile", ".bin", ".pt", ".pth", ".ckpt", ".onnx", ".mlmodel",
    };

    public static Tolket Les(string prosess, IReadOnlyList<string> a)
    {
        var t = new Tolket();
        var p = prosess.ToLowerInvariant();
        bool python = p.StartsWith("py"), ps = p is "powershell" or "pwsh", java = p.StartsWith("java"), uv = p.StartsWith("uv");
        t.Sprak = p is "wscript" or "cscript" ? "Windows Script" : python ? "Python" : ps ? "PowerShell" : java ? "Java" : uv ? "Python" : p == "deno" ? "Deno" : p == "bun" ? "Bun" : p == "node" ? "Node" : "";
        int n = 1;
        if (python)
            for (; n < a.Count; n++)
            {
                var x = a[n];
                if (x == "-m" && n + 1 < a.Count) { t.Modul = a[++n]; n++; break; }
                if (x == "-c" && n + 1 < a.Count) { t.Kode = a[++n]; n++; break; }
                if (x is "-W" or "-X" or "-Q") { n++; continue; }
                if (x.StartsWith("-")) continue;
                t.Skript = x; n++; break;
            }
        else if (ps)
            for (; n < a.Count; n++)
            {
                var x = a[n].ToLowerInvariant();
                if (x.Length > 1 && x[0] == '/') x = "-" + x.Substring(1);
                if (Forkortet(x, "-file", 2) && !Forkortet(x, "-executionpolicy", 2) && n + 1 < a.Count) { t.Skript = a[++n]; n++; break; }
                if ((x is "-e" or "-ec" || Forkortet(x, "-encodedcommand", 3)) && !Forkortet(x, "-executionpolicy", 3) && n + 1 < a.Count)
                {
                    try { t.Kode = Encoding.Unicode.GetString(Convert.FromBase64String(a[++n])); } catch { t.Kode = ""; }
                    t.Kodet = true; n++; break;
                }
                if (Forkortet(x, "-command", 2)) { t.Kode = string.Join(" ", a.Skip(n + 1)); n = a.Count; break; }
                if (x is "-ep" || Forkortet(x, "-executionpolicy", 3) || Forkortet(x, "-windowstyle", 2) || Forkortet(x, "-version", 2) || Forkortet(x, "-configurationname", 4)
                    || Forkortet(x, "-inputformat", 2) || Forkortet(x, "-outputformat", 2) || Forkortet(x, "-workingdirectory", 2) || Forkortet(x, "-psconsolefile", 2) || x == "-wd") { n++; continue; }
                if (x.StartsWith("-")) continue;
                // pwsh: første ord uten flagg er en skriptfil; Windows PowerShell: kode
                if (p == "pwsh") t.Skript = a[n]; else t.Kode = string.Join(" ", a.Skip(n));
                n = a.Count; break;
            }
        else if (java)
            for (; n < a.Count; n++)
            {
                var x = a[n];
                if (x == "-jar" && n + 1 < a.Count) { t.Skript = a[++n]; n++; break; }
                if (x is "-cp" or "-classpath" or "--class-path" or "-p" or "--module-path") { if (n + 1 < a.Count) t.Pakke = a[++n]; continue; }
                if (x.StartsWith("-")) continue;
                t.Modul = x; n++; break;
            }
        else if (uv)
        {
            if (p == "uv" && n < a.Count && a[n] == "tool") n++;
            if (n < a.Count && a[n] is "run" or "x" or "tool") n++;
            for (; n < a.Count; n++)
            {
                var x = a[n];
                if (x is "--from" or "--with" or "--python" or "-p" or "--index-url" or "--index") { n++; continue; }
                if (x.StartsWith("-")) continue;
                if (x.EndsWith(".py", StringComparison.OrdinalIgnoreCase)) t.Skript = x; else t.Pakke = x;
                n++; break;
            }
        }
        else
            for (; n < a.Count; n++)
            {
                var x = a[n];
                if (n == 1 && p is "bun" or "deno" && x is "run" or "x" or "exec" or "serve") continue;
                if (x is "-e" or "--eval" or "-p" or "--print" && n + 1 < a.Count) { t.Kode = a[++n]; n++; break; }
                if (x is "-r" or "--require" or "--import" or "--loader" or "--experimental-loader" or "--env-file") { n++; continue; }
                if (x.StartsWith("//")) continue;   // wscript og cscript: //B, //Nologo
                if (x.StartsWith("-")) continue;
                if (p == "bun" && n == 1 && !x.Contains('.') && !x.Contains('\\') && !x.Contains('/')) { t.Pakke = x; n++; break; }
                t.Skript = x; n++;
                // npx og npm exec: node npx-cli.js pakke
                var fil = x.Substring(x.LastIndexOfAny(new[] { '\\', '/' }) + 1).ToLowerInvariant();
                if (fil is "npx-cli.js" or "npm-cli.js")
                {
                    for (; n < a.Count; n++)
                    {
                        var y = a[n];
                        if (fil == "npm-cli.js" && y is "exec" or "x") continue;
                        if (y is "-p" or "--package") { t.Pakke ??= n + 1 < a.Count ? a[n + 1] : null; n++; continue; }
                        if (y.StartsWith("-")) continue;
                        t.Pakke ??= y; n++; break;
                    }
                    // Det er pakken som kjøres, ikke npx selv
                    if (t.Pakke != null) t.Skript = null;
                }
                break;
            }
        // Flagg som sier noe om risiko, for resten av linjen
        for (int k = 1; k < a.Count; k++)
        {
            var x = a[k].ToLowerInvariant();
            var verdi = x.Contains('=') ? x.Substring(x.IndexOf('=') + 1) : k + 1 < a.Count ? a[k + 1].ToLowerInvariant() : "";
            var navn = x.Contains('=') ? x.Substring(0, x.IndexOf('=')) : x;
            if (navn is "--host" or "--bind" or "--listen-host" or "--server-name" or "--ip" && verdi is "0.0.0.0" or "::" or "*" or "[::]")
                Legg(t, $"Åpen mot nettverket ({navn} {verdi})");
            else if (navn == "--listen" && (verdi.Length == 0 || verdi.StartsWith("-") || verdi.StartsWith("0.0.0.0") || !x.Contains('=')))
                Legg(t, "Åpen mot nettverket (--listen)");
            else if (navn is "--share" or "--public")
                Legg(t, $"Deler en offentlig lenke på nettet ({navn})");
            else if (navn is "--dangerously-skip-permissions" or "--dangerously-bypass-approvals-and-sandbox" or "--yolo" or "--full-auto"
                     or "--allow-all-tools" or "--auto-approve" or "--approval-mode" && (navn != "--approval-mode" || verdi is "yolo" or "full-auto"))
                Legg(t, $"Agent som kjører kommandoer uten å spørre ({navn})");
            else if (navn is "--trust-remote-code" or "--trust_remote_code")
                Legg(t, $"Kjører kode som følger med modellen ({navn})");
            else if (navn is "-m" or "--model" or "--model-path" or "--model_path" or "--ckpt" or "--checkpoint" && verdi.Length > 0
                     && Modellendelser.Contains(Path.GetExtension(verdi.Trim('"'))))
                t.Modellfil ??= (x.Contains('=') ? a[k].Substring(a[k].IndexOf('=') + 1) : a[k + 1]).Trim('"');
        }
        return t;
    }

    /// <summary>Filnavnet i en Windows-sti, også når kontrollen kjører på Linux.</summary>
    public static string Filnavn(string sti) => sti.Substring(sti.LastIndexOfAny(new[] { '\\', '/' }) + 1);

    private static void Legg(Tolket t, string f) { if (!t.Flagg.Contains(f)) t.Flagg.Add(f); }

    private static bool Forkortet(string x, string hel, int minst) => x.Length >= minst && hel.StartsWith(x, StringComparison.Ordinal);
}
