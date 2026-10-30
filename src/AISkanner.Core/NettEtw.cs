using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace AISkanner;

/// <summary>
/// UDP-trafikk per program (QUIC/HTTP/3, WebRTC/STUN, DNS, DoT/DoQ) fra Windows' egen hendelseskilde
/// Microsoft-Windows-Kernel-Network, lest i sanntid mens Nettverk er åpent. UDP-tabellen sier bare hvilken lokal port et
/// program har; her kommer også adressen og porten det sendes til, og hvor mye. Bare adresser, porter og størrelser:
/// innholdet i pakkene finnes ikke i hendelsene og leses aldri. Ingen fil, ingen driver, ingenting sendes ut.
/// Krever administrator. Økten stoppes når visningen lukkes.
/// </summary>
public sealed class NettEtw : IDisposable
{
    public sealed class Strom
    {
        public int Pid; public IPAddress Ip = IPAddress.None; public int Port;
        public long Ut, Inn, Datagram; public DateTime Forst, Sist;
    }

    private const string Navn = "AISkanner-Nettverk";
    private static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private const ulong IPv4 = 0x10, IPv6 = 0x20;

    private readonly Dictionary<(int, IPAddress, int), Strom> _strommer = new();
    private readonly HashSet<IPAddress> _egne;
    private readonly EventRecordCallback _tilbake;
    private ulong _okt, _spor;
    private Thread? _trad;
    public string Status { get; private set; }
    public long Hendelser;
    public bool Virker { get; private set; }

    private NettEtw()
    {
        _tilbake = Hendelse;
        _egne = EgneAdresser();
        Status = "ikke startet";
    }

    /// <summary>Starter lesingen. Uten administrator: null og en grunn.</summary>
    public static NettEtw? Start(out string grunn)
    {
        grunn = "";
        if (!Plattform.ErWindows) { grunn = "bare på Windows"; return null; }
        if (!Nettverk.ErAdmin()) { grunn = "krever administrator (Windows gir bare administrator tilgang til nettverkshendelsene)"; return null; }
        var e = new NettEtw();
        try
        {
            var feil = e.Apne();
            if (feil != 0) { grunn = $"Windows-feil {feil} da hendelsesøkten skulle startes"; e.Dispose(); return null; }
        }
        catch (Exception x) when (x is DllNotFoundException or EntryPointNotFoundException or MarshalDirectiveException)
        {
            grunn = x.GetType().Name; e.Dispose(); return null;
        }
        e.Virker = true;
        e.Status = "lest i sanntid";
        return e;
    }

    /// <summary>Kopi av strømmene så langt (bare i minnet).</summary>
    public List<Strom> Strommer()
    {
        lock (_strommer) return _strommer.Values.Select(s => new Strom { Pid = s.Pid, Ip = s.Ip, Port = s.Port, Ut = s.Ut, Inn = s.Inn, Datagram = s.Datagram, Forst = s.Forst, Sist = s.Sist }).ToList();
    }

    /// <summary>Tolker innholdet i én UDP-hendelse: PID, størrelse, to adresser og to porter (portene i nettverksrekkefølge).</summary>
    internal static (int Pid, int Storrelse, IPAddress A1, IPAddress A2, int P1, int P2, bool Sendt)? Tolk(int id, byte[] d)
    {
        static int Port(byte[] b, int o) => (b[o] << 8) | b[o + 1];
        if (id is 42 or 43 && d.Length >= 20)
        {
            byte[] a = new byte[4], b = new byte[4];
            Array.Copy(d, 8, a, 0, 4); Array.Copy(d, 12, b, 0, 4);
            return (BitConverter.ToInt32(d, 0), BitConverter.ToInt32(d, 4), new IPAddress(a), new IPAddress(b), Port(d, 16), Port(d, 18), id == 42);
        }
        if (id is 58 or 59 && d.Length >= 44)
        {
            byte[] a = new byte[16], b = new byte[16];
            Array.Copy(d, 8, a, 0, 16); Array.Copy(d, 24, b, 0, 16);
            return (BitConverter.ToInt32(d, 0), BitConverter.ToInt32(d, 4), new IPAddress(a), new IPAddress(b), Port(d, 40), Port(d, 42), id == 58);
        }
        return null;
    }

    /// <summary>Legger én hendelse til. Motparten er adressen som ikke er PC-ens egen. Trafikk bare på PC-en (loopback) telles ikke.</summary>
    internal void Legg(int id, byte[] d, DateTime tid)
    {
        if (Tolk(id, d) is not { } h) return;
        bool egen1 = _egne.Contains(h.A1) || IPAddress.IsLoopback(h.A1), egen2 = _egne.Contains(h.A2) || IPAddress.IsLoopback(h.A2);
        if (egen1 && egen2) return;
        var (ip, port) = egen1 ? (h.A2, h.P2) : (h.A1, h.P1);
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return;
        lock (_strommer)
        {
            var k = (h.Pid, ip, port);
            if (!_strommer.TryGetValue(k, out var s))
            {
                if (_strommer.Count >= 20000) return;
                _strommer[k] = s = new Strom { Pid = h.Pid, Ip = ip, Port = port, Forst = tid };
            }
            if (h.Sendt) s.Ut += Math.Max(0, h.Storrelse); else s.Inn += Math.Max(0, h.Storrelse);
            s.Datagram++;
            s.Sist = tid;
        }
    }

    internal static NettEtw ForTest(params IPAddress[] egne) { var e = new NettEtw(); foreach (var a in egne) e._egne.Add(a); return e; }

    private static HashSet<IPAddress> EgneAdresser()
    {
        var s = new HashSet<IPAddress>();
        try
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var a in n.GetIPProperties().UnicastAddresses) s.Add(a.Address);
        }
        catch (NetworkInformationException) { }
        return s;
    }

    private void Hendelse(IntPtr rec)
    {
        try
        {
            int id = (ushort)Marshal.ReadInt16(rec, 40);
            if (id is not (42 or 43 or 58 or 59)) return;
            Interlocked.Increment(ref Hendelser);
            int lengde = (ushort)Marshal.ReadInt16(rec, 86);
            var data = Marshal.ReadIntPtr(rec, 96);
            if (lengde <= 0 || lengde > 256 || data == IntPtr.Zero) return;
            var b = new byte[lengde];
            Marshal.Copy(data, b, 0, lengde);
            Legg(id, b, DateTime.Now);
        }
        catch (Exception x) when (x is AccessViolationException or ArgumentException) { }
    }

    // ---------- ETW ----------
    private int Apne()
    {
        var props = Egenskaper(out var str);
        try
        {
            int r = StartTraceW(out _okt, Navn, props);
            if (r == 183)   // en gammel økt med samme navn (programmet ble stoppet brått): stopp den og start på nytt
            {
                ControlTraceW(0, Navn, props, 1);
                Marshal.FreeHGlobal(props);
                props = Egenskaper(out str);
                r = StartTraceW(out _okt, Navn, props);
            }
            if (r != 0) return r;
        }
        finally { Marshal.FreeHGlobal(props); }
        var g = KernelNetwork;
        int e = EnableTraceEx2(_okt, ref g, 1, 4, IPv4 | IPv6, 0, 0, IntPtr.Zero);
        if (e != 0) { Stopp(); return e; }
        var logg = new EVENT_TRACE_LOGFILE { LoggerName = Navn, ProcessTraceMode = 0x100 | 0x10000000, EventRecordCallback = _tilbake };
        _spor = OpenTraceW(ref logg);
        if (_spor == ulong.MaxValue) { var f = Marshal.GetLastWin32Error(); Stopp(); return f == 0 ? -1 : f; }
        _trad = new Thread(() => { try { ProcessTrace(new[] { _spor }, 1, IntPtr.Zero, IntPtr.Zero); } catch { } }) { IsBackground = true, Name = Navn };
        _trad.Start();
        return 0;
    }

    // EVENT_TRACE_PROPERTIES (120 byte på x64) med navnet på økten etter
    private static IntPtr Egenskaper(out int str)
    {
        const int hode = 120;
        str = hode + (Navn.Length + 1) * 2 + 1024 * 2;
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
        var props = Egenskaper(out _);
        try { ControlTraceW(_okt, null, props, 1); } finally { Marshal.FreeHGlobal(props); }
        _okt = 0;
    }

    public void Dispose()
    {
        Stopp();
        if (_spor != 0 && _spor != ulong.MaxValue) { CloseTrace(_spor); _spor = 0; }
        Virker = false;
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
