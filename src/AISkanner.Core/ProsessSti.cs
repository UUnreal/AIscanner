using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace AISkanner;

/// <summary>
/// Henter filstien til en prosess med minst mulig tilgang (PROCESS_QUERY_LIMITED_INFORMATION).
/// Leser aldri minnet til andre prosesser, og rører aldri systemprosesser som lsass.
/// Process.MainModule ble fjernet fordi den åpner prosesser med minnelesing (PROCESS_VM_READ),
/// som sikkerhetsverktøy med rette tolker som forsøk på å stjele passord.
/// </summary>
public static class ProsessSti
{
    private static readonly HashSet<string> Urorlige = new(StringComparer.OrdinalIgnoreCase)
    {
        "Idle", "System", "Registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "LsaIso",
        "MsMpEng", "MsSense", "SenseIR", "SenseNdr", "SenseCncProxy", "NisSrv", "MpDefenderCoreService",
        "SecurityHealthService", "MemCompression", "fontdrvhost", "dwm",
    };

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint tilgang, bool arv, int pid);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr prosess, uint flagg, StringBuilder sti, ref uint lengde);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    public static string? Hent(Process p)
    {
        if (!Plattform.ErWindows) return null;
        if (p.Id <= 4 || Urorlige.Contains(p.ProcessName)) { Tilgangslogg.Tell("Prosess", Utfall.HoppetOver, sted: $"{p.ProcessName} ({p.Id})", detalj: p.Id <= 4 ? "systemprosess i Windows (ikke AI)" : "beskyttet Windows-prosess etter navn (ikke AI), røres ikke"); return null; }
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.Id);
        if (h == IntPtr.Zero)
        {
            var kode = Marshal.GetLastWin32Error();
            Tilgangslogg.Tell("Prosess", kode == 5 ? Utfall.Nektet : Utfall.Feil, sted: $"{p.ProcessName} ({p.Id})", detalj: kode == 5 ? "Windows nektet (kjører som administrator eller beskyttet)" : $"Windows-feil {kode}");
            return null;
        }
        Tilgangslogg.Tell("Prosess", Utfall.Lest, sted: $"{p.ProcessName} ({p.Id})");
        try
        {
            var sb = new StringBuilder(1024);
            uint lengde = (uint)sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref lengde) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }
}
