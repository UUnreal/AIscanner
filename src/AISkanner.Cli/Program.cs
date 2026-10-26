// Kommandolinjeversjon av skanneren. Skriver funn som JSON.
// Brukes til testing og til bedrifter som vil kjøre skanningen via Intune eller lignende.
//   AISkanner.Cli [--nvd] [--uten-historikk] [--regler sti\til\regler.json] [--txt]
using AISkanner;

if (args.Length == 2 && args[0] == "--test-server")
{
    // Intern test: spør én lokal port om den svarer som en AI-tjeneste
    using var klient = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(1) };
    var m = Skanner.Spor(klient, int.Parse(args[1]));
    Console.WriteLine(m == null ? "ikke AI" : "AI: " + string.Join(", ", m));
    return 0;
}

bool nvd = args.Contains("--nvd");
bool historikk = !args.Contains("--uten-historikk");
int i = Array.IndexOf(args, "--regler");
var regler = Regelsett.Last(i >= 0 && i + 1 < args.Length ? args[i + 1] : null);

var status = new Progress<string>(t => Console.Error.WriteLine(t));
var skanner = new Skanner(regler, historikk);
int tn = Array.IndexOf(args, "--test-nett");
if (tn >= 0) skanner.TestNett = () => TestNett.Les(args[tn + 1]);
var funn = await skanner.KjorAsync(nvd, status);
foreach (var (navn, tid) in skanner.Tider.OrderByDescending(t => t.Value)) Console.Error.WriteLine($"  {tid.TotalSeconds,6:0.00} s  {navn}");
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine(args.Contains("--txt") ? Rapport.Tekst(funn, skanner) : Rapport.Json(funn));
return funn.Any(f => f.Risiko == Risiko.Rod) ? 2 : funn.Count > 0 ? 1 : 0;

/// <summary>Intern test: falskt nettverksbilde fra en JSON-fil, så trafikklogikken kan testes uten Windows.</summary>
static class TestNett
{
    public static NettBilde Les(string sti)
    {
        using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(sti));
        var nb = new NettBilde { Sekunder = doc.RootElement.TryGetProperty("sekunder", out var sek) ? sek.GetDouble() : 0 };
        if (nb.Sekunder > 0) nb.Bytes = new();
        int port = 50000;
        foreach (var t in doc.RootElement.GetProperty("tilkoblinger").EnumerateArray())
        {
            int pid = t.GetProperty("pid").GetInt32();
            var ip = System.Net.IPAddress.Parse(t.GetProperty("ip").GetString()!);
            var k = new Tilkobling(pid, System.Net.IPAddress.Parse("192.168.1.10"), port++, ip, 443);
            nb.Tilkoblinger.Add(k);
            nb.Prosesser[pid] = (t.GetProperty("navn").GetString()!, t.TryGetProperty("sti", out var st) ? st.GetString() : null);
            if (t.TryGetProperty("vert", out var v))
            {
                if (!nb.Dns.TryGetValue(ip, out var l)) nb.Dns[ip] = l = new();
                l.Add(v.GetString()!);
                nb.DnsNavn.Add(v.GetString()!);
            }
            if (nb.Bytes != null && t.TryGetProperty("ut", out var ut)) nb.Bytes[k.Nokkel] = (ut.GetInt64(), t.GetProperty("inn").GetInt64());
        }
        if (doc.RootElement.TryGetProperty("dnsNavn", out var dn)) foreach (var n in dn.EnumerateArray()) nb.DnsNavn.Add(n.GetString()!);
        return nb;
    }
}
