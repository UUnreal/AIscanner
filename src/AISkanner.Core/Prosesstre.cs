using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AISkanner;

/// <summary>
/// Hvem som startet en prosess, og hva den er: sti, utgiver, signatur, starttid. Leser prosesslista Windows gir alle
/// (Toolhelp) og åpner prosesser bare med minst mulig tilgang (PROCESS_QUERY_LIMITED_INFORMATION).
/// Leser aldri kommandolinjer, aldri minnet til andre prosesser, og rører aldri systemprosesser som lsass.
/// </summary>
public static class Prosesstre
{
    public sealed record Ledd(int Pid, string Navn, string? Sti, DateTime? Startet, bool Egen);
    public sealed record Info(int Pid, string Navn, string? Sti, DateTime? Startet, string? Produkt, string? Beskrivelse,
        string? Selskap, string? Signert, bool Egen, List<Ledd> StartetAv, bool KjedenBrutt);

    private const uint TH32CS_SNAPPROCESS = 0x2, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flagg, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32FirstW(IntPtr h, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern bool Process32NextW(IntPtr h, ref PROCESSENTRY32W e);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint tilgang, bool arv, int pid);
    [DllImport("kernel32.dll")] private static extern bool GetProcessTimes(IntPtr h, out long start, out long slutt, out long kjerne, out long bruker);

    /// <summary>Alle prosesser: pid → (foreldre-pid, exe-navn). Tom utenfor Windows.</summary>
    public static Dictionary<int, (int Forelder, string Exe)> Liste()
    {
        var svar = new Dictionary<int, (int, string)>();
        if (!Plattform.ErWindows) return svar;
        var h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (h == IntPtr.Zero || h == new IntPtr(-1)) return svar;
        try
        {
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(h, ref e)) return svar;
            do svar[(int)e.th32ProcessID] = ((int)e.th32ParentProcessID, e.szExeFile ?? "");
            while (Process32NextW(h, ref e));
        }
        finally { CloseHandle(h); }
        return svar;
    }

    /// <summary>AI-skanneren selv og alt den har startet (nettleserdelen WebView2). Tas aldri med som funn.</summary>
    public static HashSet<int> Egne(Dictionary<int, (int Forelder, string Exe)>? liste = null)
    {
        var egne = new HashSet<int> { Plattform.EgenPid };
        liste ??= Liste();
        var egenStart = Startet(Plattform.EgenPid);
        bool lagt;
        do
        {
            lagt = false;
            foreach (var (pid, (forelder, _)) in liste)
                // Barn startes etter forelderen; et gjenbrukt PID fra før skanneren startet er ikke vårt
                if (!egne.Contains(pid) && egne.Contains(forelder) && (egenStart == null || Startet(pid) is not { } s || s >= egenStart))
                {
                    egne.Add(pid);
                    lagt = true;
                }
        } while (lagt);
        return egne;
    }

    /// <summary>Når prosessen startet, eller null hvis Windows ikke sier det.</summary>
    public static DateTime? Startet(int pid)
    {
        if (!Plattform.ErWindows || pid <= 4) return null;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try { return GetProcessTimes(h, out var start, out _, out _, out _) && start > 0 ? DateTime.FromFileTime(start) : null; }
        finally { CloseHandle(h); }
    }

    private static string? Sti(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return ProsessSti.Hent(p); }
        catch { return null; }
    }

    /// <summary>Alt vi kan si om én prosess og hvem som startet den, opptil seks ledd opp.</summary>
    public static Info? Om(int pid)
    {
        var liste = Liste();
        if (!liste.TryGetValue(pid, out var meg)) return null;
        var egne = Egne(liste);
        var navn = Path.GetFileNameWithoutExtension(meg.Exe);
        var sti = Sti(pid);
        var startet = Startet(pid);
        string? produkt = null, beskrivelse = null, selskap = null, signert = null;
        if (sti != null)
        {
            try
            {
                var vi = FileVersionInfo.GetVersionInfo(sti);
                produkt = Tom(vi.ProductName); beskrivelse = Tom(vi.FileDescription); selskap = Tom(vi.CompanyName);
            }
            catch { }
            signert = Signatur.Utgiver(sti);
        }

        var kjede = new List<Ledd>();
        bool brutt = false;
        var barnStart = startet;
        var sett = new HashSet<int> { pid };
        for (int forelder = meg.Forelder; kjede.Count < 6; )
        {
            if (forelder <= 4 || !sett.Add(forelder)) break;
            if (!liste.TryGetValue(forelder, out var f)) { brutt = true; break; }   // forelderen er avsluttet
            var fStart = Startet(forelder);
            // Er PID-en brukt på nytt av en prosess som startet etter barnet, er den ekte forelderen borte
            if (fStart != null && barnStart != null && fStart > barnStart) { brutt = true; break; }
            kjede.Add(new Ledd(forelder, Path.GetFileNameWithoutExtension(f.Exe), Sti(forelder), fStart, egne.Contains(forelder)));
            barnStart = fStart;
            forelder = f.Forelder;
        }
        return new Info(pid, navn, sti, startet, produkt, beskrivelse, selskap, signert, egne.Contains(pid), kjede, brutt);
    }

    private static string? Tom(string? s) => string.IsNullOrWhiteSpace(s) ? null : s!.Trim();
}
