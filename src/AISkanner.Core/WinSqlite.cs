using System.Runtime.InteropServices;
using System.Text;

namespace AISkanner;

/// <summary>
/// Minimal, skrivebeskyttet SQLite-leser som bruker winsqlite3.dll, som følger med Windows 10 og 11.
/// Da slipper vi å ta med en egen SQLite-motor (sparer flere MB).
/// </summary>
internal sealed class WinSqlite : IDisposable
{
    private const string Dll = "winsqlite3";
    private const int SQLITE_OK = 0, SQLITE_ROW = 100, SQLITE_NULL = 5;
    private const int SQLITE_OPEN_READONLY = 0x1, SQLITE_OPEN_URI = 0x40;

    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_open_v2(byte[] filnavn, out IntPtr db, int flagg, IntPtr vfs);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_close_v2(IntPtr db);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int lengde, out IntPtr stmt, IntPtr hale);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_bind_int64(IntPtr stmt, int nr, long verdi);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_step(IntPtr stmt);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_column_type(IntPtr stmt, int kol);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern long sqlite3_column_int64(IntPtr stmt, int kol);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern IntPtr sqlite3_column_text(IntPtr stmt, int kol);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_column_bytes(IntPtr stmt, int kol);
    [DllImport(Dll, CallingConvention = CallingConvention.Winapi)] private static extern int sqlite3_finalize(IntPtr stmt);

#if NET
    // Bare for testing på Linux: bruk systemets libsqlite3 i stedet for winsqlite3
    static WinSqlite()
    {
        if (!OperatingSystem.IsWindows())
            NativeLibrary.SetDllImportResolver(typeof(WinSqlite).Assembly, (navn, asm, sti) =>
                navn == Dll && NativeLibrary.TryLoad("libsqlite3.so.0", out var h) ? h : IntPtr.Zero);
    }
#endif

    private IntPtr _db;

    /// <summary>Åpner fila direkte, skrivebeskyttet og uten låser (immutable). Fila kopieres aldri.</summary>
    public WinSqlite(string sti)
    {
        var uri = new Uri(sti).AbsoluteUri + "?immutable=1";
        if (sqlite3_open_v2(Utf8(uri), out _db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, IntPtr.Zero) != SQLITE_OK)
        {
            Dispose();
            throw new IOException("Kunne ikke åpne databasen.");
        }
    }

    public interface IRad
    {
        bool ErTom(int kol);
        long Tall(int kol);
        string? Tekst(int kol);
    }

    private sealed class Rad : IRad
    {
        public IntPtr Stmt;
        public bool ErTom(int kol) => sqlite3_column_type(Stmt, kol) == SQLITE_NULL;
        public long Tall(int kol) => sqlite3_column_int64(Stmt, kol);
        public string? Tekst(int kol)
        {
            var p = sqlite3_column_text(Stmt, kol);
            if (p == IntPtr.Zero) return null;
            var b = new byte[sqlite3_column_bytes(Stmt, kol)];
            Marshal.Copy(p, b, 0, b.Length);
            return Encoding.UTF8.GetString(b);
        }
    }

    public void Les(string sql, long parameter, Action<IRad> hverRad)
    {
        if (sqlite3_prepare_v2(_db, Utf8(sql), -1, out var stmt, IntPtr.Zero) != SQLITE_OK) throw new IOException("Ugyldig spørring.");
        try
        {
            sqlite3_bind_int64(stmt, 1, parameter);
            var rad = new Rad { Stmt = stmt };
            while (sqlite3_step(stmt) == SQLITE_ROW) hverRad(rad);
        }
        finally { sqlite3_finalize(stmt); }
    }

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s + "\0");

    public void Dispose()
    {
        if (_db != IntPtr.Zero) sqlite3_close_v2(_db);
        _db = IntPtr.Zero;
    }
}
