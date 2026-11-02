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

    private static readonly Guid KernelNetwork = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private const ulong IPv4 = 0x10, IPv6 = 0x20;

    private readonly Dictionary<(int, IPAddress, int), Strom> _strommer = new();
    private readonly HashSet<IPAddress> _egne;
    private EtwOkt? _okt;
    public string Status { get; private set; }
    public long Hendelser;
    public bool Virker { get; private set; }

    private NettEtw()
    {
        _egne = EgneAdresser();
        Status = "ikke startet";
    }

    /// <summary>Starter lesingen. Uten administrator: null og en grunn.</summary>
    public static NettEtw? Start(out string grunn)
    {
        var e = new NettEtw();
        e._okt = EtwOkt.Start("AISkanner-Nettverk", new[] { (KernelNetwork, IPv4 | IPv6) }, (_, id) => id is 42 or 43 or 58 or 59,
            h => { Interlocked.Increment(ref e.Hendelser); e.Legg(h.Id, h.Data, DateTime.Now); }, out grunn);
        if (e._okt == null) return null;
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

    public void Dispose() { _okt?.Dispose(); _okt = null; Virker = false; }
}
