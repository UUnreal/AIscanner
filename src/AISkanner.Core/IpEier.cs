using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;

namespace AISkanner;

/// <summary>
/// Hvem eier en IP-adresse (ASN og firma), fra offentlige rutetabeller (OSINT: DB-IP og RouteViews via ip-location-db,
/// CC BY 4.0). Dataene ligger i programmet: ingen IP sendes ut. Eier er registrert data, ikke målt under søket.
/// </summary>
public static class IpEier
{
    public const string Kilde = "DB-IP og RouteViews (ip-location-db, CC BY 4.0), juni 2026";
    private static readonly Lazy<Tabell?> Data = new(Last);

    private sealed class Tabell
    {
        public uint[] Asn = Array.Empty<uint>();
        public string[] Navn = Array.Empty<string>();
        public uint[] Start4 = Array.Empty<uint>();
        public int[] Idx4 = Array.Empty<int>();
        public ulong[] Start6 = Array.Empty<ulong>();
        public int[] Idx6 = Array.Empty<int>();
    }

    private static Tabell? Last()
    {
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.ipeier.bin");
            if (s == null) return null;
            using var d = new DeflateStream(s, CompressionMode.Decompress);
            using var r = new BinaryReader(new BufferedStream(d, 1 << 16));
            if (Encoding.ASCII.GetString(r.ReadBytes(4)) != "ASN1") return null;
            int n = r.ReadInt32();
            var t = new Tabell { Asn = new uint[n + 1], Navn = new string[n + 1] };
            for (int i = 1; i <= n; i++) { t.Asn[i] = r.ReadUInt32(); t.Navn[i] = Encoding.UTF8.GetString(r.ReadBytes(r.ReadByte())); }
            int n4 = r.ReadInt32();
            t.Start4 = new uint[n4];
            for (int i = 0; i < n4; i++) t.Start4[i] = r.ReadUInt32();
            t.Idx4 = Indekser(r, n4);
            int n6 = r.ReadInt32();
            t.Start6 = new ulong[n6];
            for (int i = 0; i < n6; i++) t.Start6[i] = r.ReadUInt64();
            t.Idx6 = Indekser(r, n6);
            return t;
        }
        catch { return null; }
    }

    private static int[] Indekser(BinaryReader r, int n)
    {
        var b = r.ReadBytes(n * 3);
        var ut = new int[n];
        for (int i = 0; i < n; i++) ut[i] = b[3 * i] | b[3 * i + 1] << 8 | b[3 * i + 2] << 16;
        return ut;
    }

    /// <summary>"AS13335 Cloudflare, Inc." eller null når adressen ikke er registrert (eller er lokal).</summary>
    public static string? Finn(IPAddress ip)
    {
        var t = Data.Value;
        if (t == null || IpLand.ErLokal(ip)) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var b = ip.GetAddressBytes();
        int idx;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
            int i = Array.BinarySearch(t.Start4, v);
            if (i < 0) i = ~i - 1;
            idx = i >= 0 ? t.Idx4[i] : 0;
        }
        else
        {
            ulong v = 0;
            for (int k = 0; k < 8; k++) v = v << 8 | b[k];
            int i = Array.BinarySearch(t.Start6, v);
            if (i < 0) i = ~i - 1;
            idx = i >= 0 ? t.Idx6[i] : 0;
        }
        return idx > 0 && idx < t.Navn.Length ? $"AS{t.Asn[idx]} {t.Navn[idx]}" : null;
    }

    public static string? Finn(string ip) => IPAddress.TryParse(ip, out var a) ? Finn(a) : null;
}
