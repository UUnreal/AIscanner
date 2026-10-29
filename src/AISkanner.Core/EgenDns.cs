using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace AISkanner;

/// <summary>
/// Minimal DNS-klient (RFC 1035) over UDP rett til DNS-serveren nettverkskortet bruker. Går utenom Windows' DNS-klient,
/// så svarene legges ikke i Windows' DNS-buffer. Bare A- og AAAA-poster leses; alt annet i svaret hoppes over.
/// </summary>
internal static class EgenDns
{
    public static List<IPAddress> Servere()
    {
        var liste = new List<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var ip = nic.GetIPProperties();
                if (ip.GatewayAddresses.Count == 0) continue;
                foreach (var d in ip.DnsAddresses)
                    if (d.AddressFamily == AddressFamily.InterNetwork && !liste.Contains(d)) liste.Add(d);
            }
        }
        catch { }
        return liste;
    }

    public static async Task<IPAddress[]> SlaOppAsync(string vert, IReadOnlyList<IPAddress> servere, TimeSpan frist)
    {
        var svar = new List<IPAddress>();
        foreach (var type in new ushort[] { 1, 28 })
            foreach (var server in servere.Take(2))
            {
                var r = await SporAsync(vert, type, server, frist).ConfigureAwait(false);
                if (r == null) continue;
                svar.AddRange(r);
                break;
            }
        return svar.Distinct().ToArray();
    }

    internal static byte[] Sporring(string vert, ushort type, ushort id)
    {
        var b = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var del in vert.TrimEnd('.').Split('.'))
        {
            var a = System.Text.Encoding.ASCII.GetBytes(del);
            if (a.Length == 0 || a.Length > 63) throw new ArgumentException("ugyldig navn");
            b.Add((byte)a.Length); b.AddRange(a);
        }
        b.Add(0); b.Add((byte)(type >> 8)); b.Add((byte)type); b.Add(0); b.Add(1);
        return b.ToArray();
    }

    private static async Task<List<IPAddress>?> SporAsync(string vert, ushort type, IPAddress server, TimeSpan frist)
    {
        try
        {
            using var udp = new UdpClient(server.AddressFamily);
            var id = (ushort)new Random().Next(1, 65535);
            var q = Sporring(vert, type, id);
            await udp.SendAsync(q, q.Length, new IPEndPoint(server, 53)).ConfigureAwait(false);
            var mottak = udp.ReceiveAsync();
            if (await Task.WhenAny(mottak, Task.Delay(frist)).ConfigureAwait(false) != mottak) return null;
            return Tolk(mottak.Result.Buffer, id);
        }
        catch { return null; }
    }

    /// <summary>A- og AAAA-postene i et DNS-svar (også etter CNAME). Null hvis svaret ikke hører til spørringen.</summary>
    internal static List<IPAddress>? Tolk(byte[] s, ushort id)
    {
        if (s.Length < 12 || ((s[0] << 8) | s[1]) != id || (s[2] & 0x80) == 0) return null;
        if ((s[3] & 0x0F) != 0) return new List<IPAddress>();   // NXDOMAIN o.l.
        int qd = (s[4] << 8) | s[5], an = (s[6] << 8) | s[7], p = 12;
        int Hopp(int i) { while (i < s.Length) { int l = s[i]; if (l == 0) return i + 1; if ((l & 0xC0) == 0xC0) return i + 2; i += l + 1; } return s.Length; }
        for (int i = 0; i < qd; i++) p = Hopp(p) + 4;
        var ut = new List<IPAddress>();
        for (int i = 0; i < an && p < s.Length; i++)
        {
            p = Hopp(p);
            if (p + 10 > s.Length) break;
            int type = (s[p] << 8) | s[p + 1], len = (s[p + 8] << 8) | s[p + 9];
            p += 10;
            if (p + len > s.Length) break;
            if (type == 1 && len == 4) ut.Add(new IPAddress(s.Skip(p).Take(4).ToArray()));
            else if (type == 28 && len == 16) ut.Add(new IPAddress(s.Skip(p).Take(16).ToArray()));
            p += len;
        }
        return ut;
    }
}
