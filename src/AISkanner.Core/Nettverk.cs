using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace AISkanner;

/// <summary>En åpen TCP-forbindelse fra et program på PC-en til en maskin på nettet.</summary>
public sealed record Tilkobling(int Pid, IPAddress Lokal, int LokalPort, IPAddress Fjern, int FjernPort)
{
    internal uint[]? Rad4;      // MIB_TCPROW, brukes til datamåling
    internal byte[]? Rad6;      // MIB_TCP6ROW
    public string Nokkel => $"{Lokal}:{LokalPort}-{Fjern}:{FjernPort}";
}

/// <summary>
/// Leser nettverksbildet direkte fra Windows, uten admin og uten å sende noe:
/// åpne forbindelser per program (iphlpapi) og navnene PC-en nylig har slått opp (DNS-bufferen, samme kilde som ipconfig /displaydns).
/// </summary>
public static class Nettverk
{
    private const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_PID_CONNECTIONS = 4, ESTABLISHED = 5;

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr tabell, ref int storrelse, bool sorter, int ipVersjon, int klasse, uint reservert);

    /// <summary>Alle etablerte forbindelser til andre maskiner (ikke forbindelser innad på PC-en).</summary>
    public static List<Tilkobling> Tilkoblinger()
    {
        var liste = new List<Tilkobling>();
        if (!Plattform.ErWindows) return liste;
        Les(AF_INET, liste);
        Les(AF_INET6, liste);
        return liste.Where(t => !IPAddress.IsLoopback(t.Fjern) && !t.Fjern.Equals(IPAddress.Any) && !t.Fjern.Equals(IPAddress.IPv6Any)).ToList();
    }

    private static int Port(uint p) => (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));

    private static void Les(int familie, List<Tilkobling> liste)
    {
        int storrelse = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref storrelse, false, familie, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        if (storrelse <= 0) return;
        storrelse += 4096;   // tabellen kan vokse mellom de to kallene
        var buf = Marshal.AllocHGlobal(storrelse);
        try
        {
            if (GetExtendedTcpTable(buf, ref storrelse, false, familie, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != 0) return;
            int antall = Marshal.ReadInt32(buf);
            var rad = buf + 4;
            for (int i = 0; i < antall; i++)
            {
                if (familie == AF_INET)
                {
                    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid
                    var r = new uint[5];
                    for (int k = 0; k < 5; k++) r[k] = (uint)Marshal.ReadInt32(rad, k * 4);
                    int pid = Marshal.ReadInt32(rad, 20);
                    if (r[0] == ESTABLISHED)
                        liste.Add(new Tilkobling(pid, new IPAddress(r[1]), Port(r[2]), new IPAddress(r[3]), Port(r[4])) { Rad4 = r });
                    rad += 24;
                }
                else
                {
                    // MIB_TCP6ROW_OWNER_PID: localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid
                    var lokal = new byte[16];
                    var fjern = new byte[16];
                    Marshal.Copy(rad, lokal, 0, 16);
                    Marshal.Copy(rad + 24, fjern, 0, 16);
                    uint lokalScope = (uint)Marshal.ReadInt32(rad, 16), lokalPort = (uint)Marshal.ReadInt32(rad, 20);
                    uint fjernScope = (uint)Marshal.ReadInt32(rad, 40), fjernPort = (uint)Marshal.ReadInt32(rad, 44);
                    int state = Marshal.ReadInt32(rad, 48), pid = Marshal.ReadInt32(rad, 52);
                    if (state == ESTABLISHED)
                    {
                        // MIB_TCP6ROW (til datamåling): State, LocalAddr[16], LocalScopeId, LocalPort, RemoteAddr[16], RemoteScopeId, RemotePort
                        var r6 = new byte[52];
                        BitConverter.GetBytes(state).CopyTo(r6, 0);
                        lokal.CopyTo(r6, 4);
                        BitConverter.GetBytes(lokalScope).CopyTo(r6, 20);
                        BitConverter.GetBytes(lokalPort).CopyTo(r6, 24);
                        fjern.CopyTo(r6, 28);
                        BitConverter.GetBytes(fjernScope).CopyTo(r6, 44);
                        BitConverter.GetBytes(fjernPort).CopyTo(r6, 48);
                        var f = new IPAddress(fjern);
                        if (f.IsIPv4MappedToIPv6) f = f.MapToIPv4();
                        liste.Add(new Tilkobling(pid, new IPAddress(lokal), Port(lokalPort), f, Port(fjernPort)) { Rad6 = r6 });
                    }
                    rad += 56;
                }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // ---------- DNS-bufferen ----------

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable")]
    private static extern bool DnsGetCacheDataTable(out IntPtr tabell);

    [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode)]
    private static extern int DnsQuery(string navn, ushort type, uint valg, IntPtr ekstra, out IntPtr resultat, IntPtr reservert);

    [DllImport("dnsapi.dll")]
    private static extern void DnsRecordListFree(IntPtr liste, int type);

    private const ushort DNS_TYPE_A = 1, DNS_TYPE_AAAA = 28;
    private const uint DNS_QUERY_NO_WIRE_QUERY = 0x10;   // bare fra bufferen, aldri ut på nettet

    /// <summary>Navn PC-en nylig har slått opp, og hvilke navn hver IP-adresse hører til. Spør aldri en DNS-server.</summary>
    public static Dictionary<IPAddress, List<string>> DnsBuffer(out List<string> navn)
    {
        var kart = new Dictionary<IPAddress, List<string>>();
        navn = new List<string>();
        if (!Plattform.ErWindows) return kart;
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!DnsGetCacheDataTable(out var post)) return kart;
            // DNS_CACHE_ENTRY: pNext, pszName, wType, wDataLength, dwFlags
            while (post != IntPtr.Zero && sett.Count < 3000)
            {
                var n = Marshal.PtrToStringUni(Marshal.ReadIntPtr(post, IntPtr.Size));
                if (!string.IsNullOrEmpty(n)) sett.Add(n!.TrimEnd('.').ToLowerInvariant());
                post = Marshal.ReadIntPtr(post);
            }
        }
        catch { return kart; }

        // DNS_RECORD: pNext, pName, wType, wDataLength, Flags, dwTtl, dwReserved, Data
        int data = 2 * IntPtr.Size + 16;
        foreach (var n in sett)
        {
            navn.Add(n);
            foreach (var type in new[] { DNS_TYPE_A, DNS_TYPE_AAAA })
            {
                if (DnsQuery(n, type, DNS_QUERY_NO_WIRE_QUERY, IntPtr.Zero, out var liste, IntPtr.Zero) != 0 || liste == IntPtr.Zero) continue;
                try
                {
                    for (var r = liste; r != IntPtr.Zero; r = Marshal.ReadIntPtr(r))
                    {
                        var t = (ushort)Marshal.ReadInt16(r, 2 * IntPtr.Size);
                        IPAddress? ip = null;
                        if (t == DNS_TYPE_A) ip = new IPAddress((uint)Marshal.ReadInt32(r, data));
                        else if (t == DNS_TYPE_AAAA)
                        {
                            var b = new byte[16];
                            Marshal.Copy(r + data, b, 0, 16);
                            ip = new IPAddress(b);
                        }
                        // Flere navn kan dele samme adresse (f.eks. bak Cloudflare). Alle tas vare på.
                        if (ip == null) continue;
                        if (!kart.TryGetValue(ip, out var navnene)) kart[ip] = navnene = new List<string>();
                        if (!navnene.Contains(n)) navnene.Add(n);
                    }
                }
                finally { DnsRecordListFree(liste, 1); }
            }
        }
        return kart;
    }

    // ---------- Admin ----------

    public static bool ErAdmin()
    {
        if (!Plattform.ErWindows) return false;
        try { return SjekkAdmin(); } catch { return false; }
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static bool SjekkAdmin()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
}

/// <summary>
/// Måler hvor mye data hver forbindelse sender og mottar, med Windows' egne TCP-tellere (samme som Ressursovervåking).
/// Krever administrator. Måler bare fra tellerne slås på til de leses, og slår dem av igjen etterpå.
/// </summary>
public sealed class Datamaling : IDisposable
{
    private const int TcpConnectionEstatsData = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DataRod
    {
        public ulong DataBytesOut, DataSegsOut, DataBytesIn, DataSegsIn, SegsOut, SegsIn;
        public uint SoftErrors, SoftErrorReason, SndUna, SndNxt, SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

    [DllImport("iphlpapi.dll")] private static extern uint SetPerTcpConnectionEStats(uint[] rad, int type, byte[] rw, uint rwVer, uint rwSize, uint offset);
    [DllImport("iphlpapi.dll")] private static extern uint SetPerTcp6ConnectionEStats(byte[] rad, int type, byte[] rw, uint rwVer, uint rwSize, uint offset);
    [DllImport("iphlpapi.dll")] private static extern uint GetPerTcpConnectionEStats(uint[] rad, int type, IntPtr rw, uint rwVer, uint rwSize, IntPtr ros, uint rosVer, uint rosSize, out DataRod rod, uint rodVer, uint rodSize);
    [DllImport("iphlpapi.dll")] private static extern uint GetPerTcp6ConnectionEStats(byte[] rad, int type, IntPtr rw, uint rwVer, uint rwSize, IntPtr ros, uint rosVer, uint rosSize, out DataRod rod, uint rodVer, uint rodSize);

    private readonly List<Tilkobling> _pa = new();
    private readonly System.Diagnostics.Stopwatch _klokke = System.Diagnostics.Stopwatch.StartNew();

    public double Sekunder => _klokke.Elapsed.TotalSeconds;

    private Datamaling() { }

    /// <summary>Slår på tellerne for alle åpne forbindelser. Null hvis programmet ikke kjører som administrator.</summary>
    public static Datamaling? Start()
    {
        if (!Nettverk.ErAdmin()) return null;
        var m = new Datamaling();
        foreach (var t in Nettverk.Tilkoblinger())
            if (m.Sett(t, true)) m._pa.Add(t);
        return m;
    }

    private bool Sett(Tilkobling t, bool pa)
    {
        var rw = new byte[] { (byte)(pa ? 1 : 0) };
        try
        {
            if (t.Rad4 != null) return SetPerTcpConnectionEStats(t.Rad4, TcpConnectionEstatsData, rw, 0, 1, 0) == 0;
            if (t.Rad6 != null) return SetPerTcp6ConnectionEStats(t.Rad6, TcpConnectionEstatsData, rw, 0, 1, 0) == 0;
        }
        catch { }
        return false;
    }

    /// <summary>Byte sendt og mottatt siden målingen startet, per forbindelse som har vært målt hele tiden.</summary>
    public Dictionary<string, (long Ut, long Inn)> Les()
    {
        var svar = new Dictionary<string, (long, long)>();
        uint storrelse = (uint)Marshal.SizeOf<DataRod>();
        foreach (var t in _pa)
        {
            try
            {
                DataRod rod;
                uint feil = t.Rad4 != null
                    ? GetPerTcpConnectionEStats(t.Rad4, TcpConnectionEstatsData, IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0, out rod, 0, storrelse)
                    : GetPerTcp6ConnectionEStats(t.Rad6!, TcpConnectionEstatsData, IntPtr.Zero, 0, 0, IntPtr.Zero, 0, 0, out rod, 0, storrelse);
                if (feil == 0) svar[t.Nokkel] = ((long)rod.DataBytesOut, (long)rod.DataBytesIn);
            }
            catch { }
        }
        return svar;
    }

    /// <summary>Slår tellerne av igjen, så PC-en er som før.</summary>
    public void Dispose()
    {
        foreach (var t in _pa) Sett(t, false);
        _pa.Clear();
    }
}
