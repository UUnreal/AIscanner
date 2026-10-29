using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AISkanner;

/// <summary>
/// Leser en fil som Windows holder låst (feil 32/33, f.eks. WebCacheV01.dat), rett fra disken. Bare som administrator,
/// bare lesing. Fila åpnes bare for å lese hvor den ligger på disken (FILE_READ_ATTRIBUTES, som ikke kolliderer med
/// låsen), og så leses de samme klyngene fra disken (\\.\C:). Ingenting skrives, ingen skyggekopi lages.
/// Komprimerte og krypterte filer, og små filer som ligger inne i MFT, kan ikke leses slik.
/// </summary>
internal sealed class Raafil : Stream
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Utstrekning { public long NesteVcn; public long Lcn; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string sti, uint tilgang, uint deling, IntPtr sikkerhet, uint opprett, uint flagg, IntPtr mal);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle h, uint kode, ref long inn, int innLengde, byte[] ut, int utLengde, out int lest, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileSizeEx(SafeFileHandle h, out long storrelse);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetDiskFreeSpace(string rot, out uint sektorerPerKlynge, out uint bytePerSektor, out uint ledige, out uint totalt);

    private const uint FILE_READ_ATTRIBUTES = 0x80, GENERIC_READ = 0x80000000, OPEN_EXISTING = 3, FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073;
    private const int ERROR_MORE_DATA = 234;

    private readonly FileStream _disk;
    private readonly long _lengde, _klynge;
    private readonly List<(long StartVcn, long NesteVcn, long Lcn)> _biter;
    private long _pos;

    private Raafil(FileStream disk, long lengde, long klynge, List<(long, long, long)> biter)
    {
        _disk = disk; _lengde = lengde; _klynge = klynge; _biter = biter;
    }

    /// <summary>Åpner den låste fila rått fra disken, eller null hvis det ikke går.</summary>
    public static Stream? Apne(string sti)
    {
        if (!Plattform.ErWindows || !Admintilgang.Aktiv) return null;
        try
        {
            var a = File.GetAttributes(sti);
            if ((a & (FileAttributes.Compressed | FileAttributes.Encrypted | FileAttributes.SparseFile)) != 0) return null;
            var rot = Path.GetPathRoot(Path.GetFullPath(sti));
            if (rot == null || rot.Length != 3 || rot[1] != ':') return null;
            if (!GetDiskFreeSpace(rot, out var spk, out var bps, out _, out _)) return null;
            long klynge = (long)spk * bps;

            long lengde;
            var biter = new List<(long, long, long)>();
            using (var h = CreateFile(sti, FILE_READ_ATTRIBUTES, 7, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero))
            {
                if (h.IsInvalid || !GetFileSizeEx(h, out lengde)) return null;
                long vcn = 0;
                var ut = new byte[64 * 1024];
                while (true)
                {
                    bool ok = DeviceIoControl(h, FSCTL_GET_RETRIEVAL_POINTERS, ref vcn, 8, ut, ut.Length, out _, IntPtr.Zero);
                    int feil = ok ? 0 : Marshal.GetLastWin32Error();
                    if (!ok && feil != ERROR_MORE_DATA) return null;
                    int antall = BitConverter.ToInt32(ut, 0);
                    long start = BitConverter.ToInt64(ut, 8);
                    for (int i = 0; i < antall; i++)
                    {
                        long neste = BitConverter.ToInt64(ut, 16 + i * 16);
                        long lcn = BitConverter.ToInt64(ut, 24 + i * 16);
                        biter.Add((start, neste, lcn));
                        start = neste;
                    }
                    if (ok || antall == 0) break;
                    vcn = start;
                }
            }
            if (biter.Count == 0) return null;
            var disk = new FileStream(CreateFile($@"\\.\{rot.Substring(0, 2)}", GENERIC_READ, 3, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero), FileAccess.Read, 1);
            return new Raafil(disk, lengde, klynge, biter);
        }
        catch { return null; }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_pos >= _lengde || count <= 0) return 0;
        count = (int)Math.Min(count, _lengde - _pos);
        long vcn = _pos / _klynge;
        var bit = _biter.FirstOrDefault(b => vcn >= b.StartVcn && vcn < b.NesteVcn);
        if (bit.NesteVcn == 0) return 0;
        int iKlynge = (int)(_pos % _klynge);
        long igjenIBit = (bit.NesteVcn - vcn) * _klynge - iKlynge;
        int n = (int)Math.Min(count, igjenIBit);
        if (bit.Lcn < 0) Array.Clear(buffer, offset, n);   // tomt område i fila
        else
        {
            // Disken leses i hele klynger (må stå på sektorgrense)
            long fra = (bit.Lcn + (vcn - bit.StartVcn)) * _klynge;
            int klynger = (int)((iKlynge + n + _klynge - 1) / _klynge);
            var tmp = new byte[klynger * _klynge];
            _disk.Position = fra;
            int lest = 0;
            while (lest < tmp.Length) { int r = _disk.Read(tmp, lest, tmp.Length - lest); if (r <= 0) break; lest += r; }
            n = Math.Min(n, Math.Max(0, lest - iKlynge));
            Buffer.BlockCopy(tmp, iKlynge, buffer, offset, n);
        }
        _pos += n;
        return n;
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _lengde;
    public override long Position { get => _pos; set => _pos = Math.Max(0, value); }
    public override long Seek(long offset, SeekOrigin origin) => _pos = Math.Max(0, origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => _pos + offset, _ => _lengde + offset });
    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) _disk.Dispose(); base.Dispose(disposing); }
}
