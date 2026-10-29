using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AISkanner;

/// <summary>
/// Som administrator bruker søket rettighetene administratoren allerede har, bare til lesing:
/// SeBackupPrivilege (samme rett som sikkerhetskopiprogrammer bruker) gjør at mapper og filer som er låst for
/// alle andre kan listes og filhodet leses. Ingenting endres, ingen rettigheter på filer eller mapper røres.
/// Prosesser som Windows nekter å åpne, får stien fra Windows' egen prosessliste, uten å åpne prosessen.
/// </summary>
public static class Admintilgang
{
    /// <summary>Retten til å lese alt for sikkerhetskopi er slått på for dette søket.</summary>
    public static bool Aktiv { get; private set; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { public uint Lav; public int Hoy; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenRett { public uint Antall; public Luid Luid; public uint Egenskaper; }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr prosess, uint tilgang, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? system, string navn, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool alleAv, ref TokenRett ny, int lengde, IntPtr forrige, IntPtr forrigeLengde);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string sti, uint tilgang, uint deling, IntPtr sikkerhet, uint opprett, uint flagg, IntPtr mal);

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8, SE_PRIVILEGE_ENABLED = 0x2;
    private const uint GENERIC_READ = 0x80000000, OPEN_EXISTING = 3, FILE_FLAG_BACKUP_SEMANTICS = 0x02000000, FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

    /// <summary>Slår på lesing for sikkerhetskopi når programmet kjører som administrator, og logger det i datagrunnlaget for hvert søk.</summary>
    public static void SlaPa()
    {
        if (!Plattform.ErWindows || !Nettverk.ErAdmin()) return;
        if (!Aktiv) try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token)) return;
            try
            {
                if (!LookupPrivilegeValue(null, "SeBackupPrivilege", out var luid)) return;
                var rett = new TokenRett { Antall = 1, Luid = luid, Egenskaper = SE_PRIVILEGE_ENABLED };
                // AdjustTokenPrivileges svarer «ok» også når retten mangler; feilkode 1300 betyr at den ikke ble gitt
                Aktiv = AdjustTokenPrivileges(token, false, ref rett, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
            }
            finally { CloseHandle(token); }
        }
        catch { Aktiv = false; }
        Tilgangslogg.Logg("Rettighet", "SeBackupPrivilege", Aktiv ? Utfall.Lest : Utfall.Nektet,
            Aktiv ? "administratorens lesing for sikkerhetskopi er på: låste mapper og filer kan leses, ingenting endres"
                  : "Windows ga ikke retten til lesing for sikkerhetskopi; låste mapper blir stående som nektet");
    }

    /// <summary>
    /// Åpner en fil bare for lesing. Hvis Windows nekter og søket kjører som administrator, åpnes den på nytt
    /// med lesing for sikkerhetskopi. Filen endres aldri, og tidsstemplene røres ikke.
    /// </summary>
    public static FileStream AapneLes(string sti, int buffer = 4096, FileOptions valg = FileOptions.None)
    {
        // Skjult datastrøm (fil.txt:navn): .NET Framework godtar ikke kolon i stien, så den åpnes direkte
        if (sti.IndexOf(':', 2) > 0)
        {
            var hs = CreateFile(sti, GENERIC_READ, 7, IntPtr.Zero, OPEN_EXISTING, Aktiv ? FILE_FLAG_BACKUP_SEMANTICS : 0, IntPtr.Zero);
            if (hs.IsInvalid) { var kode = Marshal.GetLastWin32Error(); hs.Dispose(); throw new IOException($"Windows-feil {kode}", kode); }
            return new FileStream(hs, FileAccess.Read, buffer);
        }
        try { return new FileStream(sti, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, buffer, valg); }
        catch (UnauthorizedAccessException) when (Aktiv)
        {
            uint flagg = FILE_FLAG_BACKUP_SEMANTICS | ((valg & FileOptions.SequentialScan) != 0 ? FILE_FLAG_SEQUENTIAL_SCAN : 0);
            var h = CreateFile(sti, GENERIC_READ, 7, IntPtr.Zero, OPEN_EXISTING, flagg, IntPtr.Zero);
            if (h.IsInvalid) { h.Dispose(); throw; }
            Tilgangslogg.Tell("Fil", Utfall.Lest, sted: sti, detalj: "lest med administratorens lesing for sikkerhetskopi (fila var låst for vanlig lesing)");
            return new FileStream(h, FileAccess.Read, buffer);
        }
    }

    // ---------- Skjulte datastrømmer (ADS) ----------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StromData { public long Lengde; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string Navn; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr FindFirstStreamW(string sti, int niva, out StromData data, uint flagg);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool FindNextStreamW(IntPtr h, out StromData data);

    [DllImport("kernel32.dll")]
    private static extern bool FindClose(IntPtr h);

    /// <summary>
    /// Navngitte datastrømmer i en fil (fil.txt:skjult). Utforsker viser dem ikke, og fila ser like stor ut som før.
    /// Bare navn og størrelse leses her. Hovedstrømmen (::$DATA) tas ikke med.
    /// </summary>
    public static List<(string Navn, long Lengde)> Strommer(string sti)
    {
        var liste = new List<(string, long)>();
        if (!Plattform.ErWindows) return liste;
        var h = FindFirstStreamW(sti, 0, out var d, 0);
        if (h == new IntPtr(-1)) return liste;
        try
        {
            do
            {
                // Navnet er «:navn:$DATA»
                if (d.Navn != "::$DATA" && d.Navn.EndsWith(":$DATA")) liste.Add((d.Navn.Substring(1, d.Navn.Length - 7), d.Lengde));
            } while (FindNextStreamW(h, out d));
        }
        finally { FindClose(h); }
        return liste;
    }

    // ---------- Prosesser Windows nekter å åpne ----------

    [StructLayout(LayoutKind.Sequential)]
    private struct ProsessIdInfo { public IntPtr Pid; public ushort Lengde; public ushort Maks; public IntPtr Buffer; }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int klasse, ref ProsessIdInfo info, int lengde, out int svar);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string enhet, StringBuilder mal, int lengde);

    private const int SystemProcessIdInformation = 88;
    private static Dictionary<string, string>? _enheter;

    /// <summary>
    /// Programfila til en prosess, fra Windows' egen prosessliste (SystemProcessIdInformation). Prosessen åpnes ikke,
    /// så dette virker også for prosesser som er beskyttet eller eies av andre kontoer. Leser bare stien.
    /// </summary>
    public static string? ProsessBilde(int pid)
    {
        if (!Plattform.ErWindows) return null;
        const int maks = 32 * 1024;
        var buf = Marshal.AllocHGlobal(maks);
        try
        {
            var info = new ProsessIdInfo { Pid = (IntPtr)pid, Lengde = 0, Maks = maks - 2, Buffer = buf };
            if (NtQuerySystemInformation(SystemProcessIdInformation, ref info, Marshal.SizeOf<ProsessIdInfo>(), out _) != 0 || info.Lengde == 0) return null;
            return TilDos(Marshal.PtrToStringUni(buf, info.Lengde / 2));
        }
        catch { return null; }
        finally { Marshal.FreeHGlobal(buf); }
    }

    /// <summary>\Device\HarddiskVolume3\Program Files\x.exe → C:\Program Files\x.exe</summary>
    private static string TilDos(string sti)
    {
        var enheter = _enheter;
        if (enheter == null)
        {
            enheter = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in DriveInfo.GetDrives())
            {
                var bokstav = d.Name.TrimEnd('\\');
                var sb = new StringBuilder(512);
                try { if (QueryDosDevice(bokstav, sb, sb.Capacity) != 0) enheter[sb.ToString()] = bokstav; } catch { }
            }
            _enheter = enheter;
        }
        foreach (var (enhet, bokstav) in enheter)
            if (sti.StartsWith(enhet + "\\", StringComparison.OrdinalIgnoreCase)) return bokstav + sti.Substring(enhet.Length);
        return sti;
    }
}
