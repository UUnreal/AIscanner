using System.Net;
using System.Runtime.InteropServices;

namespace AISkanner;

/// <summary>Lyttende TCP-porter med eierprosess, hentet direkte fra Windows (iphlpapi). Krever ikke admin.</summary>
public static class TcpTabell
{
    public readonly record struct Lytter(IPAddress Adresse, int Port, int Pid);

    private const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_PID_LISTENER = 3;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr tabell, ref int storrelse, bool sorter, int ipVersjon, int klasse, uint reservert);

    public static List<Lytter> Hent()
    {
        var liste = new List<Lytter>();
        if (!Plattform.ErWindows) return liste;
        Les(AF_INET, liste);
        Les(AF_INET6, liste);
        Tilgangslogg.Logg("Port", "lyttende porter (GetExtendedTcpTable)", Utfall.Lest, $"{liste.Count} porter");
        return liste;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(IntPtr tabell, ref int storrelse, bool sorter, int ipVersjon, int klasse, uint reservert);
    private const int UDP_TABLE_OWNER_PID = 1;
    // Navneoppslag og oppdaging på nettet lokalt (DNS, NetBIOS, SSDP, mDNS, LLMNR), ikke trafikk ut
    private static readonly HashSet<int> LokaleUdp = new() { 53, 137, 138, 1900, 5353, 5355 };

    /// <summary>
    /// Åpne UDP-porter per program. Bare antall: UDP-tabellen sier ikke hvor det sendes. Brukes som hint om QUIC (HTTP/3),
    /// som går over UDP og derfor ikke synes i TCP-tabellen. Krever ikke admin.
    /// </summary>
    public static Dictionary<int, int> UdpPerProgram()
    {
        var svar = new Dictionary<int, int>();
        foreach (var l in UdpLyttere())
            if (!LokaleUdp.Contains(l.Port)) svar[l.Pid] = svar.TryGetValue(l.Pid, out var n) ? n + 1 : 1;
        return svar;
    }

    /// <summary>Alle åpne UDP-porter med adresse og eier. Bare lokal side: UDP-tabellen sier ikke hvor det sendes.</summary>
    public static List<Lytter> UdpLyttere()
    {
        var svar = new List<Lytter>();
        if (!Plattform.ErWindows) return svar;
        foreach (var familie in new[] { AF_INET, AF_INET6 })
        {
            int storrelse = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref storrelse, false, familie, UDP_TABLE_OWNER_PID, 0);
            if (storrelse <= 0) continue;
            storrelse += 4096;
            var buf = Marshal.AllocHGlobal(storrelse);
            try
            {
                if (GetExtendedUdpTable(buf, ref storrelse, false, familie, UDP_TABLE_OWNER_PID, 0) != 0) continue;
                int antall = Marshal.ReadInt32(buf);
                // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid (12 byte). MIB_UDP6ROW_OWNER_PID: localAddr[16], scope, localPort, pid (28 byte)
                int str = familie == AF_INET ? 12 : 28, portVed = familie == AF_INET ? 4 : 20, pidVed = familie == AF_INET ? 8 : 24;
                var rad = buf + 4;
                for (int i = 0; i < antall; i++, rad += str)
                {
                    IPAddress adr;
                    if (familie == AF_INET) adr = new IPAddress((uint)Marshal.ReadInt32(rad));
                    else { var b = new byte[16]; Marshal.Copy(rad, b, 0, 16); adr = new IPAddress(b); }
                    svar.Add(new Lytter(adr, Port((uint)Marshal.ReadInt32(rad, portVed)), Marshal.ReadInt32(rad, pidVed)));
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        return svar;
    }

    private static int Port(uint p) => (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));

    private static void Les(int familie, List<Lytter> liste)
    {
        int storrelse = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref storrelse, false, familie, TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (storrelse <= 0) return;
        var buf = Marshal.AllocHGlobal(storrelse);
        try
        {
            if (GetExtendedTcpTable(buf, ref storrelse, false, familie, TCP_TABLE_OWNER_PID_LISTENER, 0) != 0) return;
            int antall = Marshal.ReadInt32(buf);
            var rad = buf + 4;
            for (int i = 0; i < antall; i++)
            {
                if (familie == AF_INET)
                {
                    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid
                    var adr = new IPAddress((uint)Marshal.ReadInt32(rad, 4));
                    int port = Port((uint)Marshal.ReadInt32(rad, 8));
                    int pid = Marshal.ReadInt32(rad, 20);
                    liste.Add(new Lytter(adr, port, pid));
                    rad += 24;
                }
                else
                {
                    // MIB_TCP6ROW_OWNER_PID: localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid
                    var b = new byte[16];
                    Marshal.Copy(rad, b, 0, 16);
                    int port = Port((uint)Marshal.ReadInt32(rad, 20));
                    int pid = Marshal.ReadInt32(rad, 52);
                    liste.Add(new Lytter(new IPAddress(b), port, pid));
                    rad += 56;
                }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
