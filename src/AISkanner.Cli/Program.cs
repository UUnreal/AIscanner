// Kommandolinjeversjon av skanneren. Skriver funn som JSON.
// Brukes til testing og til bedrifter som vil kjøre skanningen via Intune eller lignende.
//   AISkanner.Cli [--fullt] [--nvd] [--uten-historikk] [--uten-agentlogger] [--lytt 0-60] [--regler sti\til\regler.json] [--txt | --revisjon | --kontroll | --nettverk] [--en]
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

// Oversetter JSON fra standard inn til engelsk (for testing av ordlista): AISkanner.Cli --oversett < fil.json
if (args.Length == 1 && args[0] == "--oversett")
{
    Console.OutputEncoding = System.Text.Encoding.UTF8;
    Console.WriteLine(Engelsk.Json(Console.In.ReadToEnd()));
    return 0;
}

// Regresjonstester for risikologikken (kjør: AISkanner.Cli --selvtest). Returnerer 0 når alt er grønt, ellers 1.
// Sikrer at IT-godkjentlisten ikke kan lures av angriper-styrte navn (se v2.13.1).
if (args.Length == 1 && args[0] == "--selvtest")
    return Selvtest.Kjor();

// Søket gjelder brukeren som er logget inn (også når en annen konto, eller SYSTEM via Intune, kjører programmet)
Bruker.Velg();

bool nvd = args.Contains("--nvd");
bool historikk = !args.Contains("--uten-historikk");
int i = Array.IndexOf(args, "--regler");
var regler = Regelsett.Last(i >= 0 && i + 1 < args.Length ? args[i + 1] : null);

// Kontrollmodus: lager kjente spor i en midlertidig mappe og sjekker at hver alarm slår ut. Ingenting lagres.
if (args.Contains("--kontroll"))
{
    var k = Skanner.Kontroll(regler);
    Console.WriteLine(args.Contains("--en") ? string.Join(Environment.NewLine, k.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).Select(l => Engelsk.Til(l))) : k);
    return k.Contains("FEIL") ? 1 : 0;
}

// Viser verdiene i én nøkkel i en registerfil (kopi av NTUSER.DAT, Amcache.hve …), for å prøve lesingen uten Windows
int rg = Array.IndexOf(args, "--registerfil");
if (rg >= 0 && rg + 2 < args.Length)
{
    var hive = Hive.Fra(File.ReadAllBytes(args[rg + 1]));
    var k = hive?.Rot is { } rot ? hive.Finn(rot, args[rg + 2]) : null;
    Console.OutputEncoding = System.Text.Encoding.UTF8;
    if (k == null) { Console.WriteLine("Fant ikke nøkkelen"); return 1; }
    Console.WriteLine($"{k.Navn} · endret {k.Endret:yyyy-MM-dd HH:mm}");
    foreach (var u in hive!.Under(k)) Console.WriteLine($"  [{u.Navn}]");
    foreach (var (n, v) in hive.Verdier(k)) Console.WriteLine($"  {n} = {v}");
    return 0;
}

// Leser en kopi av Amcache.hve og viser AI-funnene i den (for å prøve lesingen uten Windows)
int am = Array.IndexOf(args, "--amcache");
if (am >= 0 && am + 1 < args.Length)
{
    var sk = new Skanner(regler);
    int n = sk.LesAmcache(File.ReadAllBytes(args[am + 1]));
    Console.OutputEncoding = System.Text.Encoding.UTF8;
    Console.WriteLine($"{n} oppføringer");
    foreach (var f in sk.FunnHittil()) { Console.WriteLine(f.Navn); foreach (var d in f.Detaljer.Take(3)) Console.WriteLine("  " + d); }
    return n < 0 ? 1 : 0;
}

var status = new Progress<string>(t => Console.Error.WriteLine(t));
var skanner = new Skanner(regler, historikk) { LesNettleserflagg = args.Contains("--flagg"), Fullt = args.Contains("--fullt"), MedAgentlogger = !args.Contains("--uten-agentlogger"), LytteSekunder = Array.IndexOf(args, "--lytt") is var li && li >= 0 && li + 1 < args.Length && int.TryParse(args[li + 1], out var ls) ? Math.Max(0, Math.Min(60, ls)) : 20 };
int tn = Array.IndexOf(args, "--test-nett");
if (tn >= 0) skanner.TestNett = () => TestNett.Les(args[tn + 1]);
var funn = await skanner.KjorAsync(nvd, status, prosent: args.Contains("--prosent") ? new Progress<int>(p => Console.Error.WriteLine($"  {p} %")) : null);
foreach (var (navn, tid) in skanner.Tider.OrderByDescending(t => t.Value)) Console.Error.WriteLine($"  {tid.TotalSeconds,6:0.00} s  {navn}");
Console.OutputEncoding = System.Text.Encoding.UTF8;
if (args.Contains("--datagrunnlag")) { Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(Revisjon.Datagrunnlag(skanner, args.Contains("--en"), null, funn), new System.Text.Json.JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping })); return 0; }
// Nettverk (live) i kommandolinjen: tre avlesninger med ett sekunds mellomrom, skrevet som JSON. Ingenting lagres.
if (args.Contains("--nettverk"))
{
    using var nv = new Nettverkvisning(skanner);
    for (int r = 0; r < 3; r++)
    {
        if (r > 0) await Task.Delay(1000);
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(nv.Les(), new System.Text.Json.JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
    }
    return 0;
}
if (args.Contains("--revisjon")) { Console.WriteLine(Revisjon.Tekst(funn, skanner, Nettverk.ErAdmin() ? "administrator" : "bruker", args.Contains("--en"))); return 0; }
Console.WriteLine(args.Contains("--csv") ? Rapport.Csv(funn, args.Contains("--en")) : args.Contains("--txt") ? Rapport.Tekst(funn, skanner, args.Contains("--en")) : args.Contains("--en") ? Engelsk.Json(Rapport.Json(funn, skanner)) : Rapport.Json(funn, skanner));
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
            // "lytter": forbindelse inn til en port programmet lytter på (klient på en annen maskin)
            bool inn = t.TryGetProperty("lytter", out var ly) && ly.ValueKind == System.Text.Json.JsonValueKind.Number;
            var k = inn
                ? new Tilkobling(pid, System.Net.IPAddress.Parse("192.168.1.10"), ly.GetInt32(), ip, port++)
                : new Tilkobling(pid, System.Net.IPAddress.Parse("192.168.1.10"), port++, ip, 443);
            if (inn) (nb.Lyttere ??= new()).Add(new TcpTabell.Lytter(System.Net.IPAddress.Any, ly.GetInt32(), pid));
            nb.Tider[k.Nokkel] = (DateTime.Now.AddSeconds(-15), DateTime.Now);
            // "lokal": klient på PC-en koblet til en lokal AI-server (127.0.0.1:port)
            if (t.TryGetProperty("lokal", out var lo) && lo.ValueKind == System.Text.Json.JsonValueKind.Number)
            {
                nb.Tilkoblinger.Remove(k);
                nb.Lokale.Add(new Tilkobling(pid, System.Net.IPAddress.Loopback, port++, System.Net.IPAddress.Loopback, lo.GetInt32()));
                nb.Prosesser[pid] = (t.GetProperty("navn").GetString()!, t.TryGetProperty("sti", out var st2) ? st2.GetString() : null);
                continue;
            }
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
        nb.Lyttere ??= new();
        nb.LytteSekunder = doc.RootElement.TryGetProperty("lytteSekunder", out var ls) ? ls.GetDouble() : 0;
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

        // CDN: adressen er bare nærmeste kantserver, så den skal ikke få land
        var ip = (string a) => System.Net.IPAddress.Parse(a);
        Sjekk("cdn: Cloudflare-adresse", IpLand.Cdn(ip("104.18.32.47")) == "Cloudflare", true);
        Sjekk("cdn: Fastly-adresse", IpLand.Cdn(ip("151.101.1.140")) == "Fastly", true);
        Sjekk("cdn: Akamai fra CNAME-kjeden", IpLand.Cdn(ip("23.50.1.1"), new[] { "api.x.com", "e123.a.akamaiedge.net" }) == "Akamai", true);
        Sjekk("cdn: Cloudflare gir landkode CDN", IpLand.Finn(ip("172.64.155.209")) == "CDN", true);
        // Engelsk: tekst oversettes, stier og domener røres ikke
        Sjekk("engelsk: type", Engelsk.Til("Ukjent AI") == "Unknown AI", true);
        Sjekk("engelsk: sti røres ikke", Engelsk.Til(@"Fil: C:\Users\x\Nedlastinger\modell.gguf · GGUF") == @"File: C:\Users\x\Nedlastinger\modell.gguf · GGUF", true);
        Sjekk("engelsk: land og domene", Engelsk.Til("Sender data til Kina (api.deepseek.com).") == "Sends data to China (api.deepseek.com).", true);

        // Godkjent AI med faresignaler skal ikke bli grønn (godkjenning overstyrer aldri ekte fare)
        var regelsett = new Regelsett(); regelsett.GodkjentAi.Add("Ollama");
        var aapen = new Funn { Navn = "Ollama", Kategori = "Lokal AI", Risiko = Risiko.Rod, Hvorfor = "x", Regel = new Produkt { Navn = "Ollama", Kategori = "Lokal AI", Risiko = "gul", Hvorfor = "y" } };
        aapen.Advarsel("Er åpen mot nettverket. Andre på samme nett kan bruke den uten passord.");
        Risikoregler.Bruk(new[] { aapen }, regelsett);
        Sjekk("godkjent: åpen mot nettverket er rød", aapen.Risiko == Risiko.Rod, true);
        var nedlastet = new Funn { Navn = "Ollama", Kategori = "Lokal AI", Risiko = Risiko.Rod, Hvorfor = "x", Regel = new Produkt { Navn = "Ollama", Kategori = "Lokal AI", Risiko = "gul", Hvorfor = "y" } };
        nedlastet.Advarsel("Kjører fra en nedlastings- eller midlertidig mappe, ikke fra en vanlig installasjon.");
        Risikoregler.Bruk(new[] { nedlastet }, regelsett);
        Sjekk("godkjent: kjører fra nedlastinger er gul", nedlastet.Risiko == Risiko.Gul, true);
        var ren = new Funn { Navn = "Ollama", Kategori = "Lokal AI", Risiko = Risiko.Rod, Hvorfor = "x", Regel = new Produkt { Navn = "Ollama", Kategori = "Lokal AI", Risiko = "gul", Hvorfor = "y" } };
        Risikoregler.Bruk(new[] { ren }, regelsett);
        Sjekk("godkjent: uten faresignaler er grønn", ren.Risiko == Risiko.Gronn, true);

        // Datagrunnlag: feilkoder fra Windows gir riktig utfall (antivirus 225/226 skal aldri se ut som "finnes ikke")
        Sjekk("tilgang: 225 = stoppet av antivirus", Tilgangslogg.Fra(new IOException("x", unchecked((int)0x800700E1))) == Utfall.Blokkert, true);
        Sjekk("tilgang: 226 = stoppet av antivirus", Tilgangslogg.Fra(new IOException("x", unchecked((int)0x800700E2))) == Utfall.Blokkert, true);
        Sjekk("tilgang: 32 = låst", Tilgangslogg.Fra(new IOException("x", unchecked((int)0x80070020))) == Utfall.Laast, true);
        Sjekk("tilgang: ingen adgang = nektet", Tilgangslogg.Fra(new UnauthorizedAccessException()) == Utfall.Nektet, true);
        Sjekk("tilgang: annen feilkilde er ikke Windows-feil", Tilgangslogg.Kode(new IOException("x", 225)) == 0, true);
        Sjekk("engelsk: register-sti røres ikke", Engelsk.Til(@"HKCU\Software\ingen\feil") == @"HKCU\Software\ingen\feil", true);
        // Revisjonsloggen: siste linje er SHA-256 av alt over
        Sjekk("revisjon: SHA-256 stemmer", Revisjon.Sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", true);
        // Revisjonsloggen skal aldri ta med nettleserdata: domener, besøk og tider fra private funn
        var privat = new Funn { Navn = "Mulig AI-nettsted: hemmelig-kunde.ai", Kategori = "Nettleser-AI (nettsted)", Risiko = Risiko.Rod, Hvorfor = "x", Privat = true };
        privat.Merknad("hemmelig-kunde.ai besøkt 12 ganger");
        privat.Detalj("Chrome · Default · hemmelig-kunde.ai · 12 besøk · sist 26. okt. 2026");
        var revisjonstekst = Revisjon.Tekst(new[] { privat }, new Skanner(new Regelsett()), "bruker", false);
        Sjekk("revisjon: ingen domener fra nettleseren", revisjonstekst.Contains("hemmelig-kunde"), false);
        Sjekk("revisjon: ingen besøk fra nettleseren", revisjonstekst.Contains("besøk"), false);
        // Rapportene (tekst og JSON) skal vise hvor AI brukes i nettleseren, men aldri hele adresser
        Sjekk("rapport: tekst viser AI-nettsted", Rapport.Tekst(new[] { privat }).Contains("hemmelig-kunde.ai"), true);
        Sjekk("rapport: JSON viser AI-nettsted", Rapport.Json(new[] { privat }).Contains("hemmelig-kunde.ai"), true);
        Sjekk("cdn: vanlig adresse er ikke CDN", IpLand.Cdn(ip("101.42.18.7"), new[] { "api.deepseek.com" }) == null, true);

        // Ukjente AI-spor: alltid røde, aldri innhold fra økter, kommandoer eller nøkler
        var pf = new byte[0x80 + 64];
        BitConverter.GetBytes(30).CopyTo(pf, 0);
        System.Text.Encoding.ASCII.GetBytes("SCCA").CopyTo(pf, 4);
        System.Text.Encoding.Unicode.GetBytes("OLLAMA.EXE").CopyTo(pf, 0x10);
        BitConverter.GetBytes(new DateTime(2026, 10, 26, 12, 0, 0, DateTimeKind.Utc).ToFileTimeUtc()).CopyTo(pf, 0x80);
        var tolket = Prefetch.Tolk(pf);
        Sjekk("spor: Prefetch gir programnavn og tid", tolket?.Exe == "OLLAMA.EXE" && tolket.Tider.Count == 1, true);
        var toml = Skanner.McpFraToml(new[] { "approval_policy = \"never\"", "[mcp_servers.skall]", "command = \"powershell\"", "args = [\"-enc\", \"QQBBAA\"]", "[annet]", "command = \"x\"" });
        Sjekk("spor: MCP fra Codex-oppsett", toml.Count == 1 && toml[0].Navn == "skall" && toml[0].Kommando == "powershell", true);
        Sjekk("spor: kode etter -enc vises aldri", Skanner.FørsteArgument(toml[0].Argument).Contains("QQBBAA"), false);
        Sjekk("spor: nøkkel i argument vises aldri", Skanner.FørsteArgument("--key sk-proj-ABCDEFGHIJKLMNOPQRSTUV123").Contains("sk-proj"), false);
        var gin = Skanner.GinLinje.Match("[GIN] 2026/10/26 - 22:01:02 | 200 |  1.2345ms |    192.168.1.20 | POST     \"/api/chat\"");
        Sjekk("spor: Ollama-logglinje gir klientadresse", gin.Success && gin.Groups[3].Value == "192.168.1.20" && gin.Groups[5].Value == "/api/chat", true);
        var spor = new Funn { Navn = "MCP-servere: Test", Kategori = Skanner.SporKategori, Risiko = Risiko.Gronn, Hvorfor = "x" };
        Risikoregler.Bruk(new[] { spor }, new Regelsett { GodkjentAi = new() { "MCP-servere: Test" } });
        Sjekk("spor: alltid rødt, også når IT har godkjent navnet", spor.Risiko == Risiko.Rod && spor.Type == "Ukjent AI-spor", true);
        Sjekk("spor: rapporten sier aldri «angrep»", (Rapport.Tekst(new[] { spor }) + Rapport.Tekst(Array.Empty<Funn>())).IndexOf("angrep", StringComparison.OrdinalIgnoreCase) >= 0, false);
        Sjekk("spor: tom rapport sier «fant ingen spor»", Rapport.Tekst(Array.Empty<Funn>()).Contains("fant ingen spor"), true);

        // Misbruksspor: tellere og uttrekk som aldri tar med innhold
        Sjekk("misbruk: skjulte tegn telles (null-bredde, tag-tegn)", Skanner.TellSkjulte("a\u200Bb\uDB40\uDC41c\uFEFF") == 3, true);
        Sjekk("misbruk: BOM først er ikke skjult tegn", Skanner.TellSkjulte("\uFEFFhei") == 0, true);
        Sjekk("misbruk: hook viser bare første ord", Skanner.ForsteOrd("node .claude/setup.mjs --token hemmelig") == "node", true);
        Sjekk("misbruk: nøkkel som første ord skjules", Skanner.ForsteOrd("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX run") == "[skjult]", true);
        var flagg = Skanner.FlaggITekst("start /b claude --dangerously-skip-permissions -p \"slett alt\"");
        Sjekk("misbruk: farlig flagg i autostart", flagg.Any(x => x.Agent == "Claude Code" && x.Flagg == "--dangerously-skip-permissions"), true);
        Sjekk("misbruk: oppgaveteksten tas ikke med", flagg.Any(x => x.Flagg.Contains("slett")), false);
        Sjekk("misbruk: vanlig claude-kommando er ikke farlig", Skanner.FlaggITekst("claude --version").Count == 0, true);
        var kontroll = Skanner.Kontroll(Regelsett.Last());
        Sjekk("kontroll: alle alarmer slår ut med kjente spor", !kontroll.Contains("FEIL") && kontroll.Contains("alarmer slo ut riktig"), true);
        Sjekk("kontroll: midlertidig mappe slettet", kontroll.Contains("Den midlertidige mappa er slettet."), true);
        Sjekk("kart: registernøkkel havner under Registeret", Kart.Plass("Register", @"HKCU\Software\Ollama").StartsWith(@"Registeret\HKCU\"), true);
        Sjekk("kart: fil havner under Disk", Kart.Plass("Fil", @"C:\Users\a\.claude\settings.json") == @"Disk\C:\Users\a\.claude\settings.json", true);
        Sjekk("kart: port havner under Nettverk", Kart.Plass("Port", "127.0.0.1:11434/api/tags").StartsWith(@"Nettverk\"), true);

        Console.WriteLine(feil == 0 ? "SELVTEST OK" : $"SELVTEST FEILET ({feil})");
        return feil == 0 ? 0 : 1;
    }
}
