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

    /// <summary>To-bokstavs landkode (f.eks. "US"), "LAN" for lokalt nett, "CDN" for kantservere (Cloudflare, Fastly, CloudFront), eller null hvis ukjent.</summary>
    public static string? Finn(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ErLokal(ip)) return "LAN";
        if (Cdn(ip) != null) return "CDN";
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

    // CDN-er svarer fra nærmeste kantserver (ofte anycast), så IP-adressen sier ikke hvor tjenesten egentlig står.
    // Mange AI-tjenester (ChatGPT, Claude, Perplexity, Ollama) ligger bak Cloudflare.
    // Kilder: cloudflare.com/ips, api.fastly.com/public-ip-list, ip-ranges.amazonaws.com (CLOUDFRONT, GLOBAL, 2026-10-26).
    private static readonly (string Navn, (byte[] Nett, int Bits)[] Nett)[] CdnNett =
    {
        ("Cloudflare", Nett("173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
            "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32")),
        ("Fastly", Nett("23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
            "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20",
            "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
            "2a04:4e40::/32", "2a04:4e42::/32")),
        ("Amazon CloudFront", Nett("3.160.0.0/13", "3.168.0.0/14", "3.172.0.0/17", "3.173.0.0/16", "3.174.0.0/15", "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "13.249.0.0/16", "15.158.0.0/16", "18.64.0.0/14", "18.68.0.0/16", "18.154.0.0/15", "18.160.0.0/15", "18.164.0.0/15", "18.172.0.0/15", "18.238.0.0/15", "18.244.0.0/15", "23.91.0.0/19", "23.228.212.0/23", "23.228.214.0/24", "23.228.220.0/22", "23.228.244.0/24", "23.228.246.0/23", "23.228.248.0/22", "23.234.192.0/18", "24.110.32.0/19", "24.110.128.0/17", "36.103.232.0/25", "36.103.232.128/26", "51.74.192.0/18", "52.46.0.0/18", "52.82.128.0/19", "52.84.0.0/15", "52.124.128.0/17", "52.222.128.0/17", "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/17", "54.230.128.0/18", "54.230.200.0/21", "54.230.208.0/20", "54.230.224.0/19", "54.239.128.0/18", "54.239.192.0/19", "54.240.128.0/18", "58.254.138.0/25", "58.254.138.128/26", "64.252.64.0/18", "64.252.128.0/18", "65.8.0.0/16", "65.9.0.0/17", "65.9.128.0/18", "70.132.0.0/18", "71.152.0.0/17", "99.84.0.0/16", "99.86.0.0/16", "108.138.0.0/15", "108.156.0.0/14", "111.13.171.128/25", "111.13.185.32/27", "111.13.185.64/27", "116.129.226.0/25", "116.129.226.128/26", "118.193.97.64/26", "118.193.97.128/25", "119.147.182.0/25", "119.147.182.128/26", "120.52.12.64/26", "120.52.22.96/27", "120.52.39.128/27", "120.52.153.192/26", "120.232.236.0/25", "120.232.236.128/26", "120.253.240.192/26", "120.253.241.160/27", "120.253.245.128/26", "120.253.245.192/27", "130.176.0.0/17", "130.176.128.0/18", "130.176.192.0/19", "130.176.224.0/20", "143.204.0.0/16", "144.220.0.0/16", "180.163.57.0/25", "180.163.57.128/26", "204.246.164.0/22", "204.246.168.0/21", "204.246.176.0/20", "205.251.202.0/23", "205.251.204.0/22", "205.251.208.0/20", "205.251.249.0/24", "205.251.250.0/23", "205.251.252.0/23", "205.251.254.0/24", "216.137.32.0/19", "2001:3fc6:20::/43", "2400:7fc0:500::/40", "2404:c2c0:500::/40", "2409:8c00:2421:300::/56", "2409:8c00:2421:400::/56", "2600:9000:ddd::/48", "2600:9000:eee::/48", "2600:9000:fff::/48", "2600:9000:1000::/36", "2600:9000:2000::/35", "2600:9000:4000::/36", "2600:9000:5200::/40", "2600:9000:5308::/45", "2600:9000:5310::/44", "2600:9000:5320::/43", "2600:9000:5340::/42", "2600:9000:5380::/41", "2600:9000:6000::/36", "2600:9000:f000::/38", "2600:9000:f400::/40", "2600:9000:f500::/43", "2600:9000:f520::/44", "2600:9000:f534::/46", "2600:9000:f538::/45", "2600:9000:f540::/42", "2600:9000:f580::/41", "2600:9000:f600::/39", "2600:9000:f800::/37", "2600:f0f0:601::/48", "2600:f0f0:602::/47", "2600:f0f0:5504::/46")),
    };

    // Navn i DNS-bufferen som viser at adressen er en kantserver, også når IP-en ikke står i lista over.
    private static readonly (string Slutt, string Navn)[] CdnVerter =
    {
        ("cdn.cloudflare.net", "Cloudflare"), ("fastly.net", "Fastly"), ("fastlylb.net", "Fastly"), ("cloudfront.net", "Amazon CloudFront"),
        ("akamai.net", "Akamai"), ("akamaiedge.net", "Akamai"), ("akamaized.net", "Akamai"), ("edgekey.net", "Akamai"),
        ("edgesuite.net", "Akamai"), ("akamaihd.net", "Akamai"), ("akamaitechnologies.com", "Akamai"),
        ("azurefd.net", "Azure Front Door"), ("azureedge.net", "Azure Front Door"), ("t-msedge.net", "Azure Front Door"),
        ("afd.azureedge.net", "Azure Front Door"), ("googlehosted.com", "Google"), ("l.google.com", "Google"),
        ("edgecastcdn.net", "Edgio"), ("bunnycdn.com", "Bunny CDN"), ("b-cdn.net", "Bunny CDN"),
    };

    private static (byte[], int)[] Nett(params string[] nett) =>
        nett.Select(n => (IPAddress.Parse(n.Split('/')[0]).GetAddressBytes(), int.Parse(n.Split('/')[1]))).ToArray();

    /// <summary>Navnet på CDN-en adressen ligger bak (for eksempel "Cloudflare"), eller null. Ser på IP-en og navnene i DNS-bufferen.</summary>
    public static string? Cdn(IPAddress ip, IEnumerable<string>? navn = null)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var b = ip.GetAddressBytes();
        foreach (var (cdn, liste) in CdnNett)
            foreach (var (nett, bits) in liste)
            {
                if (nett.Length != b.Length) continue;
                int hele = bits / 8, rest = bits % 8;
                bool lik = true;
                for (int i = 0; i < hele && lik; i++) lik = b[i] == nett[i];
                if (lik && rest > 0) lik = (b[hele] >> (8 - rest)) == (nett[hele] >> (8 - rest));
                if (lik) return cdn;
            }
        if (navn != null)
            foreach (var n in navn)
                foreach (var (slutt, cdn) in CdnVerter)
                    if (n.Equals(slutt, StringComparison.OrdinalIgnoreCase) || n.EndsWith("." + slutt, StringComparison.OrdinalIgnoreCase)) return cdn;
        return null;
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
        ["LAN"] = "lokalt nett", ["CDN"] = "skjult bak CDN", ["NO"] = "Norge", ["SE"] = "Sverige", ["DK"] = "Danmark", ["FI"] = "Finland", ["IS"] = "Island",
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
