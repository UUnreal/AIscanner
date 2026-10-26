// Kommandolinjeversjon av skanneren. Skriver funn som JSON.
// Brukes til testing og til bedrifter som vil kjøre skanningen via Intune eller lignende.
//   AISkanner.Cli [--nvd] [--uten-historikk] [--regler sti\til\regler.json] [--txt]
using AISkanner;

// Test av YARA-motoren: AISkanner.Cli --yara regler.yar fil1 fil2 ... (skriver "fil: regel1 regel2", samme som yara.exe)
if (args.Length >= 2 && args[0] == "--yara")
{
    var y = YaraRegler.Les(File.ReadAllText(args[1]));
    foreach (var f in args.Skip(2))
        Console.WriteLine($"{f}: {string.Join(" ", y.Sjekk(f, int.MaxValue, 0).Select(r => r.Navn).OrderBy(n => n, StringComparer.Ordinal))}");
    return 0;
}
if (args.Length == 2 && args[0] == "--test-server")
{
    // Intern test: spør én lokal port om den svarer som en AI-tjeneste
    using var klient = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(1), MaxResponseContentBufferSize = 4 * 1024 * 1024 };
    var m = Skanner.Spor(klient, int.Parse(args[1]));
    Console.WriteLine(m == null ? "ikke AI" : "AI: " + string.Join(", ", m));
    return 0;
}

// Regresjonstester for risikologikken (kjør: AISkanner.Cli --selvtest). Returnerer 0 når alt er grønt, ellers 1.
// Sikrer at IT-godkjentlisten ikke kan lures av angriper-styrte navn (se v2.13.1).
if (args.Length == 1 && args[0] == "--selvtest")
    return Selvtest.Kjor();

bool nvd = args.Contains("--nvd");
bool historikk = !args.Contains("--uten-historikk");
int i = Array.IndexOf(args, "--regler");
var regler = Regelsett.Last(i >= 0 && i + 1 < args.Length ? args[i + 1] : null);

var status = new Progress<string>(t => Console.Error.WriteLine(t));
var skanner = new Skanner(regler, historikk) { LesNettleserflagg = args.Contains("--flagg") };
int tn = Array.IndexOf(args, "--test-nett");
if (tn >= 0) skanner.TestNett = () => TestNett.Les(args[tn + 1]);
var funn = await skanner.KjorAsync(nvd, status);
foreach (var (navn, tid) in skanner.Tider.OrderByDescending(t => t.Value)) Console.Error.WriteLine($"  {tid.TotalSeconds,6:0.00} s  {navn}");
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine(args.Contains("--txt") ? Rapport.Tekst(funn, skanner) : Rapport.Json(funn, skanner));
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

/// <summary>
/// Regresjonstester for IT-godkjentlisten (v2.13.1): et visningsnavn en angriper kan styre
/// (utvidelsesnavn, mappenavn, filsti) skal aldri gjøre et funn grønt, men ekte gjenkjente
/// produkter og nettsteder skal fortsatt kunne godkjennes.
/// </summary>
static class Selvtest
{
    public static int Kjor()
    {
        int feil = 0;
        void Sjekk(string hva, bool faktisk, bool forventet)
        {
            Console.WriteLine($"{(faktisk == forventet ? "OK  " : "FEIL")} {hva}: {faktisk} (forventet {forventet})");
            if (faktisk != forventet) feil++;
        }

        var liste = new[] { "Microsoft 365 Copilot", "openai.com" };

        // Angriper-styrte navn skal IKKE kunne godkjennes
        var spoofUtv = new Funn { Navn = "Microsoft 365 Copilot (Chrome-utvidelse)", Kategori = "Nettleser-AI", Risiko = Risiko.Rod, Hvorfor = "x" };
        Sjekk("spoof: ukjent utvidelse navngitt som godkjent produkt", Risikoregler.Godkjent(spoofUtv, liste), false);

        var spoofProsjekt = new Funn { Navn = "Python-prosjekt med AI: Microsoft 365 Copilot", Kategori = "Skygge-AI (utvikling)", Risiko = Risiko.Rod, Hvorfor = "x" };
        Sjekk("spoof: prosjektmappe navngitt som godkjent produkt", Risikoregler.Godkjent(spoofProsjekt, liste), false);

        var spoofModell = new Funn { Navn = "AI-modell: Llama", Kategori = "Lokal AI (modell)", Risiko = Risiko.Rod, Hvorfor = "x" };
        spoofModell.Detalj(@"Fil: C:\Users\x\openai.com\llama.gguf · GGUF · 4,7 GB");
        Sjekk("spoof: modell i mappe navngitt som godkjent domene", Risikoregler.Godkjent(spoofModell, liste), false);

        // Ekte gjenkjente ting skal fortsatt kunne godkjennes
        var ekteProdukt = new Funn
        {
            Navn = "Microsoft 365 Copilot", Kategori = "Nettleser-AI", Risiko = Risiko.Rod, Hvorfor = "x",
            Regel = new Produkt { Navn = "Microsoft 365 Copilot", Kategori = "Nettleser-AI", Risiko = "gul", Hvorfor = "y" },
        };
        Sjekk("ekte: gjenkjent produkt fra regelsettet", Risikoregler.Godkjent(ekteProdukt, liste), true);

        var ekteNettsted = new Funn { Navn = "ChatGPT", Kategori = "Nettleser-AI (nettsted)", Risiko = Risiko.Rod, Hvorfor = "x" };
        ekteNettsted.Trafikk.Add(new Mal { Adresse = "api.openai.com" });
        Sjekk("ekte: nettsted godkjent på målt forbindelse", Risikoregler.Godkjent(ekteNettsted, liste), true);

        // Ukjent lokal AI-server skal merkes "Ukjent AI" og være rød (død gren rettet i v2.13.1)
        var server = new Funn { Navn = "Lokal AI-server (ukjent)", Kategori = "Lokal AI", Risiko = Risiko.Rod, Hvorfor = "x" };
        Risikoregler.Bruk(new[] { server }, new Regelsett());
        Sjekk("lokal server: type = Ukjent AI", server.Type == "Ukjent AI", true);
        Sjekk("lokal server: forblir rød", server.Risiko == Risiko.Rod, true);

        Console.WriteLine(feil == 0 ? "SELVTEST OK" : $"SELVTEST FEILET ({feil})");
        return feil == 0 ? 0 : 1;
    }
}
