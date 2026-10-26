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
