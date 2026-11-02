using System.Runtime.InteropServices;

namespace AISkanner;

/// <summary>
/// Én sanntidsøkt mot Windows' egne hendelseskilder (ETW). Bare lesing: ingen fil, ingen driver, ingenting lagres.
/// Krever administrator. Brukes av Nettverk (UDP) og Vakt (prosesser, filer, nett og DNS for AI-agenter).
/// </summary>
internal sealed class EtwOkt : IDisposable
{
    /// <summary>Én hendelse slik den kommer fra Windows. Data er innholdet (maks 4 kB), kopiert ut av bufferen.</summary>
    internal readonly struct Hendelse
    {
        public readonly Guid Kilde; public readonly int Id, Versjon, Pid; public readonly bool Peker32; public readonly byte[] Data;
        public Hendelse(Guid kilde, int id, int versjon, int pid, bool peker32, byte[] data) { Kilde = kilde; Id = id; Versjon = versjon; Pid = pid; Peker32 = peker32; Data = data; }
    }

    private readonly string _navn;
    private readonly EventRecordCallback _tilbake;
    private readonly Action<Hendelse> _mottak;
    private readonly Func<Guid, int, bool> _vil;
    private ulong _okt, _spor;
    private Thread? _trad;

    private EtwOkt(string navn, Func<Guid, int, bool> vil, Action<Hendelse> mottak) { _navn = navn; _vil = vil; _mottak = mottak; _tilbake = Ta; }

    /// <summary>Starter økten med kildene (GUID, nøkkelord). <paramref name="vil"/> velger hendelsene før innholdet kopieres.</summary>
    public static EtwOkt? Start(string navn, (Guid Kilde, ulong Ord)[] kilder, Func<Guid, int, bool> vil, Action<Hendelse> mottak, out string grunn)
    {
        grunn = "";
        if (!Plattform.ErWindows) { grunn = "bare på Windows"; return null; }
        if (!Nettverk.ErAdmin()) { grunn = "krever administrator (Windows gir bare administrator tilgang til hendelseskildene)"; return null; }
        var e = new EtwOkt(navn, vil, mottak);
        try
        {
            var feil = e.Apne(kilder);
            if (feil != 0) { grunn = $"Windows-feil {feil} da hendelsesøkten skulle startes"; e.Dispose(); return null; }
        }
        catch (Exception x) when (x is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
        {
            grunn = x.GetType().Name; e.Dispose(); return null;
        }
        return e;
    }

    // EVENT_RECORD: EventHeader (Flags 4, ProcessId 12, ProviderId 24, Id 40, Version 42), UserDataLength 86, UserData 96
    private void Ta(IntPtr rec)
    {
        try
        {
            var kilde = new Guid(Enumerable.Range(0, 16).Select(i => Marshal.ReadByte(rec, 24 + i)).ToArray());
            int id = (ushort)Marshal.ReadInt16(rec, 40);
            if (!_vil(kilde, id)) return;
            int lengde = (ushort)Marshal.ReadInt16(rec, 86);
            var data = Marshal.ReadIntPtr(rec, 96);
            if (lengde <= 0 || lengde > 4096 || data == IntPtr.Zero) return;
            var b = new byte[lengde];
            Marshal.Copy(data, b, 0, lengde);
            _mottak(new Hendelse(kilde, id, Marshal.ReadByte(rec, 42), Marshal.ReadInt32(rec, 12), (Marshal.ReadInt16(rec, 4) & 0x20) != 0, b));
        }
        catch (Exception x) when (x is AccessViolationException or ArgumentException) { }
    }

    private int Apne((Guid Kilde, ulong Ord)[] kilder)
    {
        var props = Egenskaper();
        try
        {
            int r = StartTraceW(out _okt, _navn, props);
            if (r == 183)   // en gammel økt med samme navn (programmet ble stoppet brått): stopp den og start på nytt
            {
                ControlTraceW(0, _navn, props, 1);
                Marshal.FreeHGlobal(props);
                props = Egenskaper();
                r = StartTraceW(out _okt, _navn, props);
            }
            if (r != 0) return r;
        }
        finally { Marshal.FreeHGlobal(props); }
        foreach (var (kilde, ord) in kilder)
        {
            var g = kilde;
            int e = EnableTraceEx2(_okt, ref g, 1, 4, ord, 0, 0, IntPtr.Zero);
            if (e != 0) { Stopp(); return e; }
        }
        var logg = new EVENT_TRACE_LOGFILE { LoggerName = _navn, ProcessTraceMode = 0x100 | 0x10000000, EventRecordCallback = _tilbake };
        _spor = OpenTraceW(ref logg);
        if (_spor == ulong.MaxValue) { var f = Marshal.GetLastWin32Error(); Stopp(); return f == 0 ? -1 : f; }
        _trad = new Thread(() => { try { ProcessTrace(new[] { _spor }, 1, IntPtr.Zero, IntPtr.Zero); } catch { } }) { IsBackground = true, Name = _navn };
        _trad.Start();
        return 0;
    }

    // EVENT_TRACE_PROPERTIES (120 byte på x64) med navnet på økten etter
    private IntPtr Egenskaper()
    {
        const int hode = 120;
        int str = hode + (_navn.Length + 1) * 2 + 1024 * 2;
        var p = Marshal.AllocHGlobal(str);
        for (int i = 0; i < str; i++) Marshal.WriteByte(p, i, 0);
        Marshal.WriteInt32(p, 0, str);              // Wnode.BufferSize
        Marshal.WriteInt32(p, 40, 1);               // Wnode.ClientContext: QPC
        Marshal.WriteInt32(p, 44, 0x00020000);      // Wnode.Flags: WNODE_FLAG_TRACED_GUID
        Marshal.WriteInt32(p, 48, 64);              // BufferSize (kB)
        Marshal.WriteInt32(p, 64, 0x100);           // LogFileMode: EVENT_TRACE_REAL_TIME_MODE
        Marshal.WriteInt32(p, 68, 1);               // FlushTimer: 1 s
        Marshal.WriteInt32(p, 116, hode);           // LoggerNameOffset
        return p;
    }

    private void Stopp()
    {
        if (_okt == 0) return;
        var props = Egenskaper();
        try { ControlTraceW(_okt, null, props, 1); } finally { Marshal.FreeHGlobal(props); }
        _okt = 0;
    }

    public void Dispose()
    {
        Stopp();
        if (_spor != 0 && _spor != ulong.MaxValue) { CloseTrace(_spor); _spor = 0; }
    }

    // ---------- Lesing av innholdet ----------

    /// <summary>Nullterminert UTF-16-tekst fra <paramref name="o"/>; o flyttes forbi den.</summary>
    internal static string Tekst(byte[] d, ref int o)
    {
        int start = o;
        while (o + 1 < d.Length && (d[o] != 0 || d[o + 1] != 0)) o += 2;
        var s = System.Text.Encoding.Unicode.GetString(d, start, Math.Max(0, o - start));
        o += 2;
        return s;
    }

    private delegate void EventRecordCallback(IntPtr rec);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EVENT_TRACE_LOGFILE
    {
        public string? LogFileName;
        public string? LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 88)] public byte[] CurrentEvent;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 280)] public byte[] LogfileHeader;
        public IntPtr BufferCallback;
        public uint BufferSize, Filled, EventsLost;
        public EventRecordCallback EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] private static extern int StartTraceW(out ulong okt, string navn, IntPtr egenskaper);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] private static extern int ControlTraceW(ulong okt, string? navn, IntPtr egenskaper, uint kode);
    [DllImport("advapi32.dll")] private static extern int EnableTraceEx2(ulong okt, ref Guid kilde, uint kode, byte niva, ulong noen, ulong alle, uint frist, IntPtr param);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern ulong OpenTraceW(ref EVENT_TRACE_LOGFILE logg);
    [DllImport("advapi32.dll")] private static extern int ProcessTrace(ulong[] spor, uint antall, IntPtr start, IntPtr slutt);
    [DllImport("advapi32.dll")] private static extern int CloseTrace(ulong spor);
}
