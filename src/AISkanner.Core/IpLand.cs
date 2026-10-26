using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;

namespace AISkanner;

/// <summary>
/// Hvilket land en IP-adresse er registrert i. Oppslaget skjer i en innebygd tabell, aldri på nett.
/// Data: IP to Country Lite fra DB-IP.com (CC BY 4.0). Lages med verktoy/lag-ipland.py.
/// Merk: for store skytjenester (Cloudflare, Azure, AWS) viser dette hvor serveren står, ikke hvem som eier tjenesten.
/// </summary>
public static class IpLand
{
    private static readonly Lazy<Tabell?> Data = new(Last);

    private sealed class Tabell
    {
        public string[] Land = Array.Empty<string>();
        public uint[] Start4 = Array.Empty<uint>();
        public byte[] Land4 = Array.Empty<byte>();
        public ulong[] Start6 = Array.Empty<ulong>();
        public byte[] Land6 = Array.Empty<byte>();
    }

    private static Tabell? Last()
    {
        try
        {
            using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.ipland.bin");
            if (s == null) return null;
            using var d = new DeflateStream(s, CompressionMode.Decompress);
            using var r = new BinaryReader(d);
            if (new string(r.ReadChars(4)) != "IPL1") return null;
            var t = new Tabell { Land = new string[r.ReadUInt16()] };
            for (int i = 0; i < t.Land.Length; i++) t.Land[i] = new string(r.ReadChars(2));
            int n4 = r.ReadInt32();
            t.Start4 = new uint[n4];
            for (int i = 0; i < n4; i++) t.Start4[i] = r.ReadUInt32();
            t.Land4 = r.ReadBytes(n4);
            int n6 = r.ReadInt32();
            t.Start6 = new ulong[n6];
            for (int i = 0; i < n6; i++) t.Start6[i] = r.ReadUInt64();
            t.Land6 = r.ReadBytes(n6);
            return t;
        }
        catch { return null; }
    }

    /// <summary>To-bokstavs landkode (f.eks. "US"), "LAN" for lokalt nett, "CDN" for Cloudflare, eller null hvis ukjent.</summary>
    public static string? Finn(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ErLokal(ip)) return "LAN";
        if (ErCloudflare(ip)) return "CDN";
        var t = Data.Value;
        if (t == null) return null;
        var b = ip.GetAddressBytes();
        string kode;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
            int i = Array.BinarySearch(t.Start4, v);
            if (i < 0) i = ~i - 1;
            if (i < 0) return null;
            kode = t.Land[t.Land4[i]];
        }
        else
        {
            ulong v = 0;
            for (int k = 0; k < 8; k++) v = v << 8 | b[k];
            int i = Array.BinarySearch(t.Start6, v);
            if (i < 0) i = ~i - 1;
            if (i < 0) return null;
            kode = t.Land[t.Land6[i]];
        }
        return kode == "--" || kode == "ZZ" ? null : kode;
    }

    // Cloudflare svarer fra nærmeste by over hele verden (anycast), så et land ville vært misvisende.
    // Mange AI-tjenester (ChatGPT, Claude, Perplexity, Ollama) ligger bak Cloudflare. Liste: cloudflare.com/ips
    private static readonly (byte[] Nett, int Bits)[] Cloudflare = new[]
    {
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    }.Select(n => (IPAddress.Parse(n.Split('/')[0]).GetAddressBytes(), int.Parse(n.Split('/')[1]))).ToArray();

    private static bool ErCloudflare(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        foreach (var (nett, bits) in Cloudflare)
        {
            if (nett.Length != b.Length) continue;
            int hele = bits / 8, rest = bits % 8;
            bool lik = true;
            for (int i = 0; i < hele && lik; i++) lik = b[i] == nett[i];
            if (lik && rest > 0) lik = (b[hele] >> (8 - rest)) == (nett[hele] >> (8 - rest));
            if (lik) return true;
        }
        return false;
    }

    public static bool ErLokal(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] < 32) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254)
                   || (b[0] == 100 && b[1] >= 64 && b[1] < 128);
        return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
    }

    private static readonly Dictionary<string, string> Norske = new(StringComparer.OrdinalIgnoreCase)
    {
        ["LAN"] = "lokalt nett", ["CDN"] = "Cloudflare-nettverket", ["NO"] = "Norge", ["SE"] = "Sverige", ["DK"] = "Danmark", ["FI"] = "Finland", ["IS"] = "Island",
        ["US"] = "USA", ["CA"] = "Canada", ["GB"] = "Storbritannia", ["IE"] = "Irland", ["DE"] = "Tyskland", ["FR"] = "Frankrike",
        ["NL"] = "Nederland", ["BE"] = "Belgia", ["LU"] = "Luxembourg", ["CH"] = "Sveits", ["AT"] = "Østerrike", ["ES"] = "Spania",
        ["IT"] = "Italia", ["PL"] = "Polen", ["CZ"] = "Tsjekkia", ["PT"] = "Portugal", ["EE"] = "Estland", ["LV"] = "Latvia", ["LT"] = "Litauen",
        ["CN"] = "Kina", ["HK"] = "Hongkong", ["TW"] = "Taiwan", ["JP"] = "Japan", ["KR"] = "Sør-Korea", ["KP"] = "Nord-Korea",
        ["SG"] = "Singapore", ["IN"] = "India", ["AU"] = "Australia", ["RU"] = "Russland", ["BY"] = "Belarus", ["UA"] = "Ukraina",
        ["IR"] = "Iran", ["IL"] = "Israel", ["AE"] = "De forente arabiske emirater", ["SA"] = "Saudi-Arabia", ["TR"] = "Tyrkia",
        ["BR"] = "Brasil", ["MX"] = "Mexico", ["ZA"] = "Sør-Afrika", ["VN"] = "Vietnam", ["TH"] = "Thailand", ["MY"] = "Malaysia",
        ["ID"] = "Indonesia",
    };

    public static string Navn(string? kode)
    {
        if (string.IsNullOrEmpty(kode)) return "ukjent land";
        if (Norske.TryGetValue(kode!, out var n)) return n;
        try { return new System.Globalization.RegionInfo(kode!).EnglishName; } catch { return kode!; }
    }
}
