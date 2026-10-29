using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace AISkanner;

/// <summary>
/// Hvem som kjører et AI-program, og hvordan: konto, om det kjører som administrator, hvem som startet det, og SHA-256
/// av programfila. Leser bare prosessens tilgangsbillett (konto og nivå) og programfila, aldri prosessminnet.
/// </summary>
public sealed partial class Skanner
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint tilgang, bool arv, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr prosess, uint tilgang, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int klasse, IntPtr info, int lengde, out int svar);

    private const int TokenUser = 1, TokenElevation = 20;

    private readonly ConcurrentDictionary<string, string?> _sha = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Kontoen prosessen kjører som, og om den kjører som administrator. Null når Windows nekter.</summary>
    internal static (string? Konto, bool? Admin) Konto(int pid)
    {
        if (!Plattform.ErWindows) return (null, null);
        var h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return (null, null);
        try
        {
            if (!OpenProcessToken(h, 0x8, out var token)) return (null, null);
            try
            {
                string? konto = null;
                bool? admin = null;
                var buf = Marshal.AllocHGlobal(256);
                try
                {
                    if (GetTokenInformation(token, TokenUser, buf, 256, out _))
                    {
                        var sid = new SecurityIdentifier(Marshal.ReadIntPtr(buf));
                        try { konto = sid.Translate(typeof(NTAccount)).Value; } catch { konto = sid.Value; }
                    }
                    if (GetTokenInformation(token, TokenElevation, buf, 4, out _)) admin = Marshal.ReadInt32(buf) != 0;
                }
                finally { Marshal.FreeHGlobal(buf); }
                return (konto, admin);
            }
            finally { CloseHandle(token); }
        }
        catch { return (null, null); }
        finally { CloseHandle(h); }
    }

    /// <summary>SHA-256 av programfila, en gang per sti. Filer over 512 MB hashes ikke.</summary>
    internal string? Sha256(string? sti)
    {
        if (string.IsNullOrEmpty(sti)) return null;
        return _sha.GetOrAdd(sti!, s =>
        {
            try
            {
                var fi = new FileInfo(s);
                if (!fi.Exists || fi.Length > 512L * 1024 * 1024) return null;
                using var fs = Admintilgang.AapneLes(s, 1 << 16, FileOptions.SequentialScan);
                using var sha = SHA256.Create();
                return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "");
            }
            catch { return null; }
        });
    }

    /// <summary>Konto, nivå, forelder og SHA-256 for en prosess som er et AI-funn.</summary>
    private void HvemOgHvordan(Funn f, int pid, string? sti, Dictionary<int, (int Forelder, string Exe)> tre)
    {
        var (konto, admin) = Konto(pid);
        string? forelder = null;
        if (tre.TryGetValue(pid, out var meg) && meg.Forelder > 4 && tre.TryGetValue(meg.Forelder, out var far))
        {
            // Er PID-en brukt på nytt av en prosess som startet etter barnet, er den ekte forelderen borte
            var (barn, mor) = (Prosesstre.Startet(pid), Prosesstre.Startet(meg.Forelder));
            if (barn == null || mor == null || mor <= barn) forelder = Path.GetFileName(far.Exe);
        }
        var sha = Sha256(sti);
        var deler = new List<string>();
        if (konto != null) deler.Add($"kjører som {konto}{(admin == true ? " (som administrator)" : "")}");
        if (forelder != null) deler.Add($"startet av {forelder}");
        if (sha != null) deler.Add($"SHA-256 {sha}");
        if (deler.Count > 0) f.Detalj($"PID {pid}: {string.Join(" · ", deler)}");
        if (admin == true) f.Merknad("Kjører som administrator.");
    }

    /// <summary>
    /// AI-agenter som kjører kommandoer nå: prosesser (skall, tolkere, verktøy) som en AI-agent har startet, i hele kjeden.
    /// Bare programnavnet vises, aldri kommandoen.
    /// </summary>
    private void AgentBarn(Dictionary<int, (int Forelder, string Exe)> tre)
    {
        var agenter = _aiPid.Where(x => x.Value.Funn.Kategori.IndexOf("agent", StringComparison.OrdinalIgnoreCase) >= 0
                                        || x.Value.Funn.Kategori.StartsWith("Skygge-AI (utvikling)", StringComparison.Ordinal)).ToDictionary(x => x.Key, x => x.Value);
        if (agenter.Count == 0) return;
        var egne = Prosesstre.Egne(tre);
        foreach (var (pid, (_, exe)) in tre)
        {
            if (agenter.ContainsKey(pid) || egne.Contains(pid)) continue;
            var sett = new HashSet<int> { pid };
            var barnStart = Prosesstre.Startet(pid);
            for (int p = tre[pid].Forelder, ledd = 0; p > 4 && ledd < 8 && sett.Add(p) && tre.TryGetValue(p, out var x); p = x.Forelder, ledd++)
            {
                var start = Prosesstre.Startet(p);
                if (start != null && barnStart != null && start > barnStart) break;
                if (agenter.TryGetValue(p, out var agent))
                {
                    // Agentens egne hjelpeprosesser (samme program) er ikke kommandoer
                    if (string.Equals(Path.GetFileName(exe), Path.GetFileName(agent.Sti ?? agent.Navn + ".exe"), StringComparison.OrdinalIgnoreCase)) break;
                    agent.Funn.Detalj($"Kjører nå, startet av {agent.Navn} (PID {p}): {Path.GetFileName(exe)} (PID {pid}){(ledd > 0 ? $", {ledd + 1} ledd ned" : "")}");
                    agent.Funn.Merk(Tilstand.KjorerNa);
                    agent.Funn.Sterkt();
                    break;
                }
                barnStart = start;
            }
        }
    }
}
