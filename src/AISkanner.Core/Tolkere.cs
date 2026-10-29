using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Skript som kjører i en tolk (python, node, powershell …). Programmet heter python.exe, så navnet sier ingenting:
/// det er skriptet som er AI-en. Kommandolinjen leses fra Windows, sammenlignes med reglene i minnet og kastes.
/// Det som vises, er regelen som slo til, skriptfila og hva skriptet bruker. Argumentene vises aldri.
/// </summary>
public sealed partial class Skanner
{
    /// <summary>Prosesser (PID) som er knyttet til et funn gjennom kommandolinjen. Brukes for trafikken.</summary>
    private readonly ConcurrentDictionary<int, Funn> _pidFunn = new();

    /// <summary>AI-program funnet i prosesslista, per PID, så kommandolinjen deres også kan leses.</summary>
    private readonly ConcurrentDictionary<int, (Funn Funn, string Navn, string? Sti)> _aiPid = new();

    private static readonly Regex PythonImport = new(@"^[ \t]*(?:from|import)[ \t]+([A-Za-z_]\w*)", RegexOptions.Multiline | RegexOptions.Compiled);
    private static readonly Regex NodeImport = new(@"(?:require\(\s*|import\s*\(\s*|\bfrom\s+|^\s*import\s+)['""]((?:@[\w.\-]+/)?[\w.\-]+)", RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly ISet<string> Skriptendelser = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".mts", ".tsx", ".ps1", ".psm1",
    };

    private void Kommandolinjer()
    {
        if (!Plattform.ErWindows) return;
        if (!Kommandolinje.Tillatt(_regler, out var grunn))
        {
            Tilgangslogg.Logg("Kommandolinje", "Kommandolinjene til tolkere og AI-programmer", Utfall.Blokkert, grunn);
            return;
        }
        int lest = 0, nektet = 0;
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                if (Plattform.ErEgen(p.Id)) continue;
                bool tolk = Kommandolinje.ErTolk(p.ProcessName);
                _aiPid.TryGetValue(p.Id, out var ai);
                if (!tolk && ai.Funn == null) continue;
                var linje = Kommandolinje.Les(p.Id);
                if (linje == null) { nektet++; continue; }
                lest++;
                Vurder(p.ProcessName, ai.Sti ?? ProsessSti.Hent(p), p.Id, linje, ai.Funn, null);
                linje = null;
            }
        }
        Tilgangslogg.Logg("Kommandolinje", "Kommandolinjene til tolkere og AI-programmer", lest > 0 || nektet == 0 ? Utfall.Lest : Utfall.Nektet,
            $"{lest} lest{(nektet > 0 ? $", {nektet} nektet av Windows" : "")}; sammenlignet med reglene i minnet og kastet; bare regeltreff og skriptfila vises, aldri argumentene");
    }

    /// <summary>
    /// Vurderer én kommandolinje. <paramref name="nar"/> er satt når linjen kommer fra en hendelseslogg (kjørt før),
    /// ellers kjører prosessen nå. Brukes også av kontrollen med laget tekst.
    /// </summary>
    internal Funn? Vurder(string prosess, string? exe, int pid, string linje, Funn? ai, DateTime? nar, string kilde = "")
    {
        var arg = Kommandolinje.Del(linje);
        if (arg.Count == 0) return null;
        var navn = Path.GetFileNameWithoutExtension(prosess);
        var t = Kommandolinje.Les(navn, arg);
        bool tolk = Kommandolinje.ErTolk(navn);
        string tid = nar is { } n ? $" · {Nar(n, kilde)}" : "";

        Funn? f = ai;
        if (tolk)
        {
            var bruker = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            var verter = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            bool agent = false, nokkel = false;
            Produkt? regel = null;

            // Modul (python -m vllm.entrypoints…), pakke (npx, uvx), hovedklasse (java)
            foreach (var x in new[] { t.Modul, TolkPakke(t.Pakke) })
            {
                if (string.IsNullOrEmpty(x)) continue;
                var topp = x!.Split('.')[0];
                if (PythonAi.TryGetValue(topp, out var ag) || NodeAi.TryGetValue(x, out ag)) { bruker.Add(x == topp || NodeAi.ContainsKey(x) ? x : topp); agent |= ag; }
                regel ??= FinnRegel(x.Replace('_', '-')) ?? FinnRegel(x);
            }
            if (t.Skript != null) regel ??= FinnRegel(t.Skript);

            // Innholdet i skriptfila og kode skrevet rett på linjen
            if (t.Skript != null && Skriptendelser.Contains(Path.GetExtension(t.Skript)) && Path.IsPathRooted(t.Skript))
                if (LesSkript(t.Skript) is { } tekst) Innhold(tekst, bruker, verter, ref agent, ref nokkel);
            if (!string.IsNullOrEmpty(t.Kode)) Innhold(t.Kode!, bruker, verter, ref agent, ref nokkel);
            t.Kode = null;

            var hva = t.Skript != null ? $"kjører {t.Skript}" : t.Modul != null ? $"kjører modulen {t.Modul}" : t.Pakke != null ? $"kjører pakken {TolkPakke(t.Pakke)}" : "kjører kode skrevet på kommandolinjen (vises ikke)";
            var detalj = $"{(nar == null ? "Kjører nå" : "Kjørt før")}: {navn}{(pid > 0 ? $" (PID {pid})" : "")} {hva}"
                + (bruker.Count > 0 ? $" · bruker {string.Join(", ", bruker)}" : "")
                + (verter.Count > 0 ? $" · snakker med {string.Join(", ", verter)}" : "")
                + (nokkel ? " · har en API-nøkkel i seg (vises ikke)" : "") + tid;

            if (t.Kodet && (bruker.Count > 0 || verter.Count > 0 || regel != null))
            {
                f = Spor("PowerShell med gjemt AI-kode",
                    "PowerShell kjører kode som er gjort om til base64 på kommandolinjen, så den ikke kan leses direkte. Koden bruker AI.", detalj);
                f.Advarsel("Koden er gjemt som base64 på kommandolinjen.");
            }
            else if (regel != null)
                f = FraRegel(regel, nar == null ? "Kjører nå" : "Kjørt før", detalj);
            else if (bruker.Count > 0 || verter.Count > 0)
            {
                var hvem = t.Skript != null ? Kommandolinje.Filnavn(t.Skript) : t.Modul ?? TolkPakke(t.Pakke) ?? "kode på kommandolinjen";
                f = LeggTil($"{t.Sprak}-skript med AI: {hvem}", agent ? "Skygge-AI (agent)" : "Skygge-AI", Risiko.Rod,
                    "Et skript bruker AI. Kjent igjen på skriptfila og på hva tolken ble startet med; argumentene vises ikke.",
                    nar == null ? "Kjører nå" : "Kjørt før", detalj, enkelt: $"{t.Sprak}-skript med AI");
            }
            if (f != null && nokkel) f.Advarsel("Skriptet har en API-nøkkel skrevet rett i seg.");
            if (f != null && f != ai) { if (t.Skript != null && Path.IsPathRooted(t.Skript)) HuskMappe(t.Skript, f); }
        }
        if (f == null) return null;

        if (nar == null) { f.Bruk ??= "Kjører nå."; f.Tidspunkt(null, DateTime.Now); if (pid > 0) _pidFunn[pid] = f; }
        else { f.Bruk ??= "Brukt før."; f.Tidspunkt(nar, nar); }
        if (t.Modellfil != null) f.Detalj($"Modellfil lastet: {t.Modellfil}{tid}");
        if (t.Flagg.Count > 0)
        {
            f.Detalj($"Startet med: {string.Join(" · ", t.Flagg)}{tid}");
            foreach (var x in t.Flagg) f.Advarsel(x + ".");
            f.Risiko = Risiko.Rod;
        }
        return f;
    }

    private static string? TolkPakke(string? pakke)
    {
        if (string.IsNullOrEmpty(pakke)) return null;
        var p = pakke!;
        int at = p.IndexOf('@', 1);
        if (at > 0) p = p.Substring(0, at);
        foreach (var skille in new[] { "==", ">=", "<=", "~=", "[" }) { int i = p.IndexOf(skille, StringComparison.Ordinal); if (i > 0) p = p.Substring(0, i); }
        return p;
    }

    private static string? LesSkript(string sti)
    {
        try
        {
            var fi = new FileInfo(sti);
            if (!fi.Exists) { Tilgangslogg.Tell("Fil", Utfall.IkkeFunnet, sted: sti); return null; }
            if (fi.Length > 2 * 1024 * 1024) { Tilgangslogg.Tell("Fil", Utfall.HoppetOver, sted: sti, detalj: "skript større enn 2 MB"); return null; }
            using var fs = Admintilgang.AapneLes(sti);
            using var r = new StreamReader(fs);
            var tekst = r.ReadToEnd();
            Tilgangslogg.Tell("Fil", Utfall.Lest, sted: sti, detalj: "skriptfil en tolk kjører");
            return tekst;
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", sti, e); return null; }
    }

    private void Innhold(string tekst, SortedSet<string> bruker, SortedSet<string> verter, ref bool agent, ref bool nokkel)
    {
        foreach (Match m in PythonImport.Matches(tekst))
            if (PythonAi.TryGetValue(m.Groups[1].Value, out var ag)) { bruker.Add(m.Groups[1].Value); agent |= ag; }
        foreach (Match m in NodeImport.Matches(tekst))
            if (NodeAi.TryGetValue(m.Groups[1].Value, out var ag)) { bruker.Add(m.Groups[1].Value); agent |= ag; }
        foreach (var tj in _regler.AiTjenester)
            foreach (var d in tj.Domener)
                if (tekst.IndexOf(d, StringComparison.OrdinalIgnoreCase) >= 0) verter.Add(d);
        foreach (var v in AiApiVerter)
            if (tekst.IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0) verter.Add(v == ":11434" ? "Ollama (port 11434)" : v);
        nokkel |= NokkelMonster.IsMatch(tekst);
    }
}
