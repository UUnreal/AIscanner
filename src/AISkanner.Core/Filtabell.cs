using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AISkanner;

/// <summary>
/// Fullt søk som administrator: Windows' filtabell (MFT) på en NTFS-disk gås gjennom én gang, post for post via NTFS, bare for å finne
/// hvilke filer som har en skjult datastrøm (ADS) på minst 50 MB. Bare de filene får strømmene sjekket med vanlig oppslag,
/// i stedet for at hver eneste fil på disken åpnes. Samme filer blir sjekket, med samme regler.
/// Bare lesing. Navn, mapper og størrelsen på strømmer tolkes; innholdet i små filer som ligger i selve tabellen tolkes aldri.
/// Går noe galt, eller ser noe uvanlig ut, brukes oppslaget per fil som før.
/// </summary>
internal static class Filtabell
{
    internal const long MinStrom = 50L * 1024 * 1024;
    private static readonly Dictionary<string, Lazy<HashSet<string>?>> Disker = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Glemmer tabellene fra forrige søk.</summary>
    internal static void Nullstill() { lock (Disker) Disker.Clear(); }

    /// <summary>Filene på samme disk som <paramref name="sti"/> som har en skjult datastrøm på minst 50 MB, eller null når tabellen ikke kan brukes.</summary>
    internal static HashSet<string>? StoreStrommer(string sti)
    {
        string? rot;
        try { rot = Path.GetPathRoot(sti); } catch { return null; }
        if (rot is not { Length: 3 } || rot[1] != ':') return null;
        Lazy<HashSet<string>?> l;
        lock (Disker) if (!Disker.TryGetValue(rot, out l!)) Disker[rot] = l = new(() => Les(rot));
        return l.Value;
    }

    /// <summary>
    /// Må strømmene til denne fila sjekkes? Ja når filtabellen ikke kan brukes, når fila har en stor strøm, og når stien har
    /// et kort 8.3-navn (RUNNER~1), som filtabellen ikke kan sammenlignes med.
    /// </summary>
    internal static bool MaaSjekkes(string sti) => StoreStrommer(sti) is not { } store || store.Contains(sti) || sti.IndexOf('~') >= 0;

    private static HashSet<string>? Les(string rot)
    {
        if (!Plattform.ErWindows || !Nettverk.ErAdmin()) return null;
        var mal = rot + "$MFT";
        try
        {
            var di = new DriveInfo(rot);
            if (di.DriveType is not (DriveType.Fixed or DriveType.Removable) || di.DriveFormat != "NTFS") return null;
            using var h = CreateFile(@"\\.\" + rot.Substring(0, 2), GENERIC_READ, 7, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h.IsInvalid) return Nei(mal, $"disken kunne ikke åpnes (Windows-feil {Marshal.GetLastWin32Error()})");
            var vd = new byte[96];
            if (!DeviceIoControl(h, FSCTL_GET_NTFS_VOLUME_DATA, null, 0, vd, vd.Length, out _, IntPtr.Zero))
                return Nei(mal, $"NTFS-data mangler (Windows-feil {Marshal.GetLastWin32Error()})");
            int str = BitConverter.ToInt32(vd, 48);
            long poster = BitConverter.ToInt64(vd, 56) / Math.Max(1, str);
            if (str < 1024 || str % 512 != 0 || poster <= 0) return Nei(mal, "uvanlige NTFS-verdier");

            // Hver post hentes gjennom NTFS (FSCTL_GET_NTFS_FILE_RECORD), så også endringer som ikke er skrevet til disken ennå er med
            var inn = new byte[8];
            var ut = new byte[12 + str];
            bool? Hent(long n)
            {
                BitConverter.GetBytes(n).CopyTo(inn, 0);
                if (!DeviceIoControl(h, FSCTL_GET_NTFS_FILE_RECORD, inn, 8, ut, ut.Length, out var lest, IntPtr.Zero)) return null;
                // Er posten ikke i bruk, gir Windows nærmeste post under som er i bruk
                return lest >= 12 + str && (BitConverter.ToInt64(ut, 0) & 0xFFFFFFFFFFFF) == n && BitConverter.ToInt32(ut, 8) == str;
            }
            var treff = new HashSet<long>();
            for (long n = 0; n < poster; n++)
            {
                var i = Hent(n);
                if (i == null) return Nei(mal, $"post {n} kunne ikke leses (Windows-feil {Marshal.GetLastWin32Error()})");
                if (i == false) continue;
                var s = StorStrom(ut, 12, str, n, out var eier);
                if (s == null) return Nei(mal, $"post {n} i tabellen så ødelagt ut");
                if (s == true) treff.Add(eier);
            }

            // Stiene til filene med store strømmer: navnet og mappene oppover hentes post for post (bare disse)
            var mapper = new Dictionary<long, string?> { [5] = rot.TrimEnd('\\') };
            List<(long Forelder, string Navn)>? Navn(long n) => Hent(n) == true && Fiks(ut, 12, str) ? Filnavn(ut, 12, str) : null;
            string? Mappe(long n, int dybde)
            {
                if (mapper.TryGetValue(n, out var kjent)) return kjent;
                string? sti = null;
                if (dybde < 256 && Navn(n) is { Count: > 0 } navn && Mappe(navn[0].Forelder, dybde + 1) is { } over) sti = over + "\\" + navn[0].Navn;
                return mapper[n] = sti;
            }
            var stier = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in treff)
            {
                if (Navn(t) is not { Count: > 0 } navn) return Nei(mal, "navnet på en fil med skjult datastrøm ble ikke funnet");
                foreach (var (forelder, navnet) in navn)
                {
                    if (Mappe(forelder, 0) is not { } over) return Nei(mal, "mappa til en fil med skjult datastrøm ble ikke funnet");
                    stier.Add(over + "\\" + navnet);
                }
            }
            Tilgangslogg.Logg("Fil", mal, Utfall.Lest,
                $"filtabellen lest som administrator ({poster} poster): bare navn og størrelse på skjulte datastrømmer, så bare filer med strøm på minst 50 MB åpnes");
            return stier;
        }
        catch (Exception e) { return Nei(mal, Tilgangslogg.Beskriv(e)); }
    }

    private static HashSet<string>? Nei(string mal, string grunn)
    {
        Tilgangslogg.Logg("Fil", mal, Utfall.HoppetOver, $"filtabellen ble ikke brukt ({grunn}); skjulte datastrømmer sjekkes fil for fil");
        return null;
    }

    /// <summary>Retter opp de to siste bytene i hver 512-del (NTFS' kontroll mot halvskrevne poster). Usant hvis bare noen av delene stemmer.</summary>
    private static bool Fiks(byte[] b, int s, int str)
    {
        if (b[s] != 'F' || b[s + 1] != 'I' || b[s + 2] != 'L' || b[s + 3] != 'E') return false;
        int usa = BitConverter.ToUInt16(b, s + 4), n = BitConverter.ToUInt16(b, s + 6);
        if (n < 2 || n - 1 > str / 512 || usa + 2 * n > str) return false;
        // Fra NTFS kan posten allerede være rettet: da står ikke kontrollverdien i endene, og posten brukes som den er
        int rettet = 0;
        for (int i = 1; i < n; i++)
        {
            int e = s + i * 512 - 2;
            if (b[e] != b[s + usa] || b[e + 1] != b[s + usa + 1]) continue;
            b[e] = b[s + usa + 2 * i]; b[e + 1] = b[s + usa + 2 * i + 1];
            rettet++;
        }
        return rettet == 0 || rettet == n - 1;
    }

    /// <summary>Ja hvis posten (eller filen den hører til) har en navngitt datastrøm på minst 50 MB. Null hvis posten er ødelagt.</summary>
    private static bool? StorStrom(byte[] b, int s, int str, long nr, out long eier)
    {
        eier = nr;
        if (b[s] != 'F' || b[s + 1] != 'I' || b[s + 2] != 'L' || b[s + 3] != 'E') return false;   // ubrukt plass
        if ((BitConverter.ToUInt16(b, s + 0x16) & 1) == 0) return false;                          // slettet post
        if (!Fiks(b, s, str)) return null;
        long basis = (long)(BitConverter.ToUInt64(b, s + 0x20) & 0xFFFFFFFFFFFF);
        if (basis != 0) eier = basis;
        for (int a = s + BitConverter.ToUInt16(b, s + 0x14); a + 16 <= s + str;)
        {
            uint type = BitConverter.ToUInt32(b, a);
            if (type == 0xFFFFFFFF) return false;
            int len = BitConverter.ToInt32(b, a + 4);
            if (len < 16 || a + len > s + str) return null;
            if (type == 0x80 && b[a + 9] > 0)
            {
                long lengde = b[a + 8] == 0 ? BitConverter.ToUInt32(b, a + 0x10)
                    : BitConverter.ToInt64(b, a + 0x10) == 0 && len >= 0x40 ? BitConverter.ToInt64(b, a + 0x30) : 0;
                if (lengde >= MinStrom) return true;
            }
            a += len;
        }
        return null;
    }

    /// <summary>Navnene (unntatt korte 8.3-navn) og mappa de ligger i.</summary>
    private static List<(long, string)> Filnavn(byte[] b, int s, int str)
    {
        var liste = new List<(long, string)>();
        for (int a = s + BitConverter.ToUInt16(b, s + 0x14); a + 16 <= s + str;)
        {
            uint type = BitConverter.ToUInt32(b, a);
            int len = BitConverter.ToInt32(b, a + 4);
            if (type == 0xFFFFFFFF || len < 16 || a + len > s + str) break;
            if (type == 0x30 && b[a + 8] == 0)
            {
                int v = a + BitConverter.ToUInt16(b, a + 0x14);
                if (v + 0x42 <= a + len && b[v + 0x41] != 2 && v + 0x42 + 2 * b[v + 0x40] <= a + len)
                    liste.Add(((long)(BitConverter.ToUInt64(b, v) & 0xFFFFFFFFFFFF), Encoding.Unicode.GetString(b, v + 0x42, 2 * b[v + 0x40])));
            }
            a += len;
        }
        return liste;
    }

    /// <summary>Bare for kontrollen: lager en skjult datastrøm med gitt start og lengde (.NET Framework godtar ikke kolon i stier).</summary>
    internal static void LagStrom(string sti, byte[] start, long lengde)
    {
        using var h = CreateFile(sti, GENERIC_WRITE, 0, IntPtr.Zero, CREATE_ALWAYS, 0, IntPtr.Zero);
        if (h.IsInvalid) throw new IOException($"Windows-feil {Marshal.GetLastWin32Error()}");
        using var fs = new FileStream(h, FileAccess.Write, 4096);
        fs.Write(start, 0, start.Length);
        fs.SetLength(lengde);
    }

    private const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000, OPEN_EXISTING = 3, CREATE_ALWAYS = 2, FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064, FSCTL_GET_NTFS_FILE_RECORD = 0x00090068;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string sti, uint tilgang, uint deling, IntPtr sikkerhet, uint opprett, uint flagg, IntPtr mal);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle h, uint kode, byte[]? inn, int innLengde, byte[] ut, int utLengde, out int lest, IntPtr ov);

}
