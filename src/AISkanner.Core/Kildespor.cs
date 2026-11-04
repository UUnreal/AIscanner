using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Spor Windows fører av seg selv, uten at noe må slås på og uten administrator:
/// nedlastingsmerket på modellfiler (Zone.Identifier), personvernloggen for mikrofon, kamera og skjermopptak,
/// UserAssist (programmer startet fra Start og Utforsker) og installasjonsloggen (Windows Installer 1033/1034).
/// Bare lesing. Bare programmer en AI-regel kjenner igjen blir funn; resten telles og vises aldri.
/// </summary>
public sealed partial class Skanner
{
    // ---------- Nedlastingsmerket (Zone.Identifier) ----------

    internal sealed record Nedlastingsmerke(int? Sone, string? Fra, string? Side);

    /// <summary>
    /// Tolker Zone.Identifier: sonen og adressene nettleseren skrev da fila ble lastet ned.
    /// Adressene kortes til skjema, vert og sti; alt etter ? og # fjernes, fordi det kan være nøkler eller signaturer.
    /// </summary>
    internal static Nedlastingsmerke? TolkNedlastingsmerke(string tekst)
    {
        int? sone = null;
        string? fra = null, side = null;
        foreach (var raa in tekst.Split('\n'))
        {
            var l = raa.Trim();
            int lik = l.IndexOf('=');
            if (lik <= 0) continue;
            var nokkel = l.Substring(0, lik).Trim();
            var verdi = l.Substring(lik + 1).Trim();
            if (nokkel.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(verdi, out var z)) sone = z;
            else if (nokkel.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) fra = RensAdresse(verdi);
            else if (nokkel.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) side = RensAdresse(verdi);
        }
        return sone == null && fra == null ? null : new Nedlastingsmerke(sone, fra, side);
    }

    internal static string? RensAdresse(string a)
    {
        if (!Uri.TryCreate(a, UriKind.Absolute, out var u) || u.Scheme is not ("http" or "https" or "ftp")) return null;
        var s = $"{u.Scheme}://{u.Host}{(u.IsDefaultPort ? "" : ":" + u.Port)}{u.AbsolutePath}";
        return s.Length > 200 ? s.Substring(0, 200) + "…" : s;
    }

    internal static string NedlastetTekst(Nedlastingsmerke m) =>
        $"Nedlastet fra: {m.Fra ?? SoneNavn(m.Sone)}{(m.Side != null && m.Side != m.Fra ? $" · lenket fra {m.Side}" : "")} (Windows' nedlastingsmerke, Zone.Identifier)";

    private static string SoneNavn(int? z) => z switch
    {
        0 => "denne PC-en (adressen er ikke lagret)",
        1 => "lokalt nett (adressen er ikke lagret)",
        2 => "klarert nettsted (adressen er ikke lagret)",
        3 => "Internett (adressen er ikke lagret)",
        4 => "blokkert nettsted (adressen er ikke lagret)",
        _ => "ukjent sone (adressen er ikke lagret)",
    };

    /// <summary>Advarsel når adressen selv er et tegn på risiko: offentlig IP uten domenenavn, eller ukryptert http.</summary>
    internal static string? NedlastingsAdvarsel(Nedlastingsmerke m)
    {
        if (m.Fra == null || !Uri.TryCreate(m.Fra.TrimEnd('…'), UriKind.Absolute, out var u)) return null;
        if (IPAddress.TryParse(u.Host.Trim('[', ']'), out var ip) && !IpLand.ErLokal(ip)) return "Lastet ned fra en IP-adresse uten domenenavn.";
        if (u.Scheme == "http") return "Lastet ned uten kryptering (http), så fila kan ha blitt byttet underveis.";
        return null;
    }

    /// <summary>Leser nedlastingsmerket til en fil. Null når fila ikke har et (laget på PC-en, lastet ned av et program, eller merket er fjernet).</summary>
    private static Nedlastingsmerke? LesNedlastingsmerke(string sti)
    {
        if (!Plattform.ErWindows || sti.IndexOf(':', 2) > 0) return null;
        var strom = sti + ":Zone.Identifier";
        try
        {
            using var s = Admintilgang.AapneLes(strom);
            var buf = new byte[4096];
            int n = s.Read(buf, 0, buf.Length);
            Tilgangslogg.Tell("Fil", Utfall.Lest, sted: strom, detalj: "nedlastingsmerket: sone og nettadresse, uten ? og #");
            return TolkNedlastingsmerke(Encoding.UTF8.GetString(buf, 0, n));
        }
        catch { return null; }
    }

    private static void Nedlastingskilde(Funn f, string sti)
    {
        var m = LesNedlastingsmerke(sti);
        if (m == null) return;
        f.Detalj(NedlastetTekst(m));
        if (NedlastingsAdvarsel(m) is { } a) f.Advarsel(a);
    }

    // ---------- Personvernloggen (mikrofon, kamera, skjermopptak) ----------

    private static readonly (string Nokkel, string Hva)[] Personvern =
    {
        ("microphone", "mikrofonen"), ("webcam", "kameraet"),
        ("graphicsCaptureProgrammatic", "skjermopptak"), ("graphicsCaptureWithoutBorder", "skjermopptak"),
    };

    /// <summary>Programnavnet i personvernloggen: pakkenavn for apper, ellers stien med # i stedet for \.</summary>
    internal static string PersonvernProgram(string nokkel, bool upakket) => upakket ? nokkel.Replace('#', '\\') : nokkel;

    /// <summary>
    /// Windows' personvernlogg (Innstillinger &gt; Personvern): hvilke programmer som har brukt mikrofon, kamera eller
    /// skjermopptak, og når sist. Avslører møteopptakere og agenter som ser på skjermen. Bare AI-programmer vises.
    /// Brukerens del (HKCU) og hele PC-ens del (HKLM). Kilde: Velociraptor Windows.Registry.CapabilityAccessManager.
    /// </summary>
    private void Personvernlogg()
    {
        const string rot = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
        int lest = 0;
        foreach (var (hive, hiveNavn) in new[] { (Bruker.Hkcu, "HKCU"), (Microsoft.Win32.Registry.LocalMachine, "HKLM") })
        {
            int forHive = lest;
            foreach (var (nokkel, hva) in Personvern)
            {
                using var k = Tilgangslogg.Nokkel(hive, $@"{rot}\{nokkel}");
                if (k == null) continue;
                var oppforinger = k.GetSubKeyNames().Where(n => !n.Equals("NonPackaged", StringComparison.OrdinalIgnoreCase)).Select(n => (n, false)).ToList();
                using (var u = k.OpenSubKey("NonPackaged"))
                    if (u != null) oppforinger.AddRange(u.GetSubKeyNames().Select(n => (@"NonPackaged\" + n, true)));
                foreach (var (navn, upakket) in oppforinger)
                {
                    using var app = k.OpenSubKey(navn);
                    if (app == null) continue;
                    lest++;
                    var program = PersonvernProgram(upakket ? navn.Substring(12) : navn, upakket);
                    var regel = FinnRegel(program);
                    if (regel == null) continue;
                    DateTime? start = Filtid(Tall(app.GetValue("LastUsedTimeStart")));
                    DateTime? stopp = Filtid(Tall(app.GetValue("LastUsedTimeStop")));
                    if (start == null && stopp == null) continue;
                    bool naa = start != null && (stopp == null || stopp < start);
                    var nar = naa ? $"bruker {hva} nå (startet {Nar(start!.Value, "personvernloggen i Windows")})" : $"brukte {hva} sist {Nar((stopp ?? start)!.Value, "personvernloggen i Windows")}";
                    var f = FraRegel(regel, "Windows' personvernlogg", $"Personvernloggen: {program} {nar}");
                    f.Bruk ??= "Brukt før.";
                    f.Sterkt();
                    f.Merk(naa ? Tilstand.KjorerNa : Tilstand.BruktFor);
                    f.Tidspunkt(null, naa ? start : stopp ?? start);
                    if (nokkel.StartsWith("graphicsCapture", StringComparison.Ordinal))
                        f.Advarsel("Har tatt opp skjermen ifølge Windows' personvernlogg. Det AI-en ser, kan sendes videre.");
                }
            }
            Tilgangslogg.Logg("Register", $@"{hiveNavn}\{rot}", lest > forHive ? Utfall.Lest : Utfall.IkkeFunnet,
                $"{lest - forHive} programmer med tid for mikrofon, kamera og skjermopptak; bare AI-programmer vises, tidene for andre programmer brukes ikke");
        }
    }

    /// <summary>LastUsedTime er QWORD (FILETIME). Tåler også tekst og 8 byte, i tilfelle et program har skrevet den annerledes.</summary>
    private static long Tall(object? v) => v switch
    {
        long l => l,
        int i => i,
        byte[] b when b.Length >= 8 => BitConverter.ToInt64(b, 0),
        string t when long.TryParse(t, out var l) => l,
        _ => 0,
    };

    // ---------- UserAssist ----------

    private static readonly Dictionary<string, string> KjenteMapper = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{6D809377-6AF0-444B-8957-A3773F02200E}"] = "%ProgramFiles%",
        ["{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"] = "%ProgramFiles(x86)%",
        ["{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}"] = "%LOCALAPPDATA%",
        ["{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}"] = "%APPDATA%",
        ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"] = @"%SystemRoot%\System32",
        ["{F38BF404-1D43-42F2-9305-67DE0B28FC23}"] = "%SystemRoot%",
        ["{374DE290-123F-4565-9164-39C4925E467B}"] = @"%USERPROFILE%\Downloads",
        ["{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"] = @"%USERPROFILE%\Desktop",
        ["{5E6C858F-0E22-4760-9AFE-EA3317B67173}"] = "%USERPROFILE%",
        ["{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}"] = @"%APPDATA%\Microsoft\Windows\Start Menu\Programs",
        ["{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}"] = @"%ProgramData%\Microsoft\Windows\Start Menu\Programs",
        ["{9E3995AB-1F9C-4F13-B827-48B24B6C7174}"] = @"%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned",
    };

    internal static string Rot13(string s)
    {
        var c = s.ToCharArray();
        for (int i = 0; i < c.Length; i++)
            if (c[i] is >= 'a' and <= 'z') c[i] = (char)('a' + (c[i] - 'a' + 13) % 26);
            else if (c[i] is >= 'A' and <= 'Z') c[i] = (char)('A' + (c[i] - 'A' + 13) % 26);
        return new string(c);
    }

    /// <summary>Bytter mappe-ID-en først i en UserAssist-sti med mappenavnet, f.eks. %ProgramFiles%.</summary>
    internal static string UserAssistSti(string navn)
    {
        var m = Regex.Match(navn, @"^(\{[0-9A-F-]{36}\})(.*)$", RegexOptions.IgnoreCase);
        return m.Success && KjenteMapper.TryGetValue(m.Groups[1].Value, out var p) ? p + m.Groups[2].Value : navn;
    }

    /// <summary>Windows 7 og nyere: 72 byte, antall starter på byte 4 og siste start (FILETIME) på byte 60.</summary>
    internal static (int Antall, DateTime? Sist)? UserAssistData(byte[] b) =>
        b.Length >= 68 ? (BitConverter.ToInt32(b, 4), Filtid(BitConverter.ToInt64(b, 60))) : null;

    /// <summary>
    /// UserAssist: programmer og snarveier brukeren har startet fra Start, oppgavelinjen eller Utforsker, med antall og
    /// siste gang. Navnene er ROT13-kodet. Blir stående etter at programmet er avinstallert.
    /// </summary>
    private void UserAssist()
    {
        const string rot = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        using var k = Tilgangslogg.Nokkel(Bruker.Hkcu, rot);
        if (k == null) return;
        int lest = 0;
        foreach (var guid in k.GetSubKeyNames())
        {
            using var c = k.OpenSubKey(guid + @"\Count");
            if (c == null) continue;
            foreach (var v in c.GetValueNames())
            {
                var navn = Rot13(v);
                if (navn.StartsWith("UEME_", StringComparison.Ordinal)) continue;
                lest++;
                var sti = UserAssistSti(navn);
                var regel = FinnRegel(sti);
                if (regel == null) continue;
                var data = c.GetValue(v) is byte[] b ? UserAssistData(b) : null;
                if (data is not { } d || (d.Antall <= 0 && d.Sist == null)) continue;
                var f = FraRegel(regel, "Kjørt før", $"UserAssist: {sti} startet fra Start eller Utforsker"
                    + (d.Antall > 0 ? $" {d.Antall} {(d.Antall == 1 ? "gang" : "ganger")}" : "")
                    + (d.Sist is { } t ? $" · sist {Nar(t, "UserAssist i Windows")}" : ""));
                f.Bruk ??= "Brukt før.";
                f.Merk(Tilstand.BruktFor);
                if (d.Sist != null) f.Tidspunkt(null, d.Sist);
            }
        }
        Tilgangslogg.Logg("Register", $@"HKCU\{rot}", Utfall.Lest, $"{lest} programmer og snarveier startet fra Start eller Utforsker; bare navn, antall og siste tid brukes");
    }

    // ---------- Installasjonsloggen (Windows Installer) ----------

    internal sealed record Installasjon(string Produkt, string? Versjon, string? Utgiver, bool Fjernet);

    /// <summary>
    /// MsiInstaller 1033 (installert) og 1034 (fjernet): produktnavn, versjon, språk, status og utgiver.
    /// Bare vellykkede (status 0) teller.
    /// </summary>
    internal static Installasjon? TolkInstallasjon(string? id, Dictionary<string, string> d)
    {
        if (id is not ("1033" or "1034")) return null;
        var produkt = Felt(d, "_0")?.Trim();
        if (string.IsNullOrEmpty(produkt) || Felt(d, "_3")?.Trim() != "0") return null;
        string? Tom(string? x) => string.IsNullOrWhiteSpace(x) ? null : x!.Trim();
        return new Installasjon(produkt!, Tom(Felt(d, "_1")), Tom(Felt(d, "_4")), id == "1034");
    }

    private void Installasjonslogg()
    {
        var sett = new Dictionary<string, (Produkt Regel, Installasjon I, DateTime? Inn, DateTime? Ut)>(StringComparer.OrdinalIgnoreCase);
        Logglest("Application", $"*[System[Provider[@Name='MsiInstaller'] and (EventID=1033 or EventID=1034) and {SisteAar}]]",
            "Windows Installer 1033 og 1034 (installert og fjernet)", 20000, Fullt ? TimeSpan.FromSeconds(20) : TimeSpan.FromSeconds(5), (d, t) =>
            {
                if (TolkInstallasjon(Felt(d, "_id"), d) is not { } i) return;
                var regel = FinnRegel(i.Produkt) ?? (i.Utgiver != null ? FinnRegel($"{i.Produkt} {i.Utgiver}") : null);
                if (regel == null) return;
                var tid = t == DateTime.MinValue ? (DateTime?)null : t;
                sett.TryGetValue(i.Produkt, out var x);
                // Nyeste først: første installering og første fjerning vi ser er de siste
                sett[i.Produkt] = (regel, x.I ?? i, i.Fjernet ? x.Inn : x.Inn ?? tid, i.Fjernet ? x.Ut ?? tid : x.Ut);
            }, "siste 12 måneder");
        foreach (var (produkt, (regel, i, inn, ut)) in sett)
        {
            bool fjernet = ut != null && (inn == null || ut >= inn);
            var tekst = $"Installasjonsloggen: {produkt}{(i.Versjon != null ? " " + i.Versjon : "")}{(i.Utgiver != null ? $" ({i.Utgiver})" : "")}"
                + (inn is { } a ? $" · installert {Nar(a, "installasjonsloggen i Windows")}" : "")
                + (fjernet ? $" · fjernet {Nar(ut!.Value, "installasjonsloggen i Windows")}" : "");
            var f = FraRegel(regel, "Windows Installer", tekst);
            f.Sterkt();
            if (fjernet) { f.Bruk ??= "Installert før, nå fjernet."; f.Merk(Tilstand.BruktFor); }
            else f.Merk(Tilstand.SattOpp);
            f.Tidspunkt(inn, fjernet ? ut : inn);
        }
    }
}

public sealed partial class Skanner
{
    /// <summary>Kontroll av tolkingen i Kildespor.cs med eksempler laget her (ingenting leses fra eller skrives til registeret).</summary>
    private static (int Ok, int Alle) KildesporKontroll(Skanner s, StringBuilder sb)
    {
        int ok = 0, alle = 0;
        void Sjekk(bool riktig, string hva) { alle++; if (riktig) ok++; else sb.AppendLine($"FEIL  Kildespor: {hva}"); }

        // Nedlastingsmerket: adressen uten ? og #, sone alene, IP uten navn og http gir advarsel, about:internet er ingen adresse
        var hf = TolkNedlastingsmerke("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://huggingface.co/TheBloke/x-GGUF/tree/main\r\nHostUrl=https://cdn-lfs.huggingface.co/repos/ab/cd/model.gguf?X-Amz-Signature=HEMMELIG#frag\r\n");
        Sjekk(hf?.Fra == "https://cdn-lfs.huggingface.co/repos/ab/cd/model.gguf" && hf.Sone == 3 && hf.Side == "https://huggingface.co/TheBloke/x-GGUF/tree/main", "Hugging Face-adressen ble ikke tolket riktig");
        Sjekk(hf != null && !NedlastetTekst(hf).Contains("HEMMELIG") && NedlastingsAdvarsel(hf) == null, "signaturen etter ? ble vist, eller https ga advarsel");
        var sone = TolkNedlastingsmerke("[ZoneTransfer]\nZoneId=3\n");
        Sjekk(sone != null && sone.Fra == null && NedlastetTekst(sone).Contains("Internett"), "merke uten adresse ga ikke «Internett»");
        var ip = TolkNedlastingsmerke("[ZoneTransfer]\nZoneId=3\nHostUrl=https://203.0.113.9/m.pt\n");
        Sjekk(ip != null && NedlastingsAdvarsel(ip)?.Contains("IP-adresse") == true, "IP-adresse uten navn ga ikke advarsel");
        var lan = TolkNedlastingsmerke("[ZoneTransfer]\nZoneId=3\nHostUrl=http://192.168.1.20/m.gguf\n");
        Sjekk(lan != null && NedlastingsAdvarsel(lan)?.Contains("http") == true, "http fra lokalt nett ga ikke advarsel om kryptering");
        Sjekk(TolkNedlastingsmerke("[ZoneTransfer]\nZoneId=3\nHostUrl=about:internet\n")?.Fra == null, "about:internet ble tatt som nettadresse");
        Sjekk(TolkNedlastingsmerke("tilfeldig tekst") == null, "tekst uten merke ga et merke");

        // UserAssist: ROT13, mappe-ID, antall og tid
        Sjekk(Rot13("Byynzn") == "Ollama" && Rot13(Rot13("C:\\Programmer\\x.exe")) == "C:\\Programmer\\x.exe", "ROT13 ble feil");
        var ua = UserAssistSti(Rot13(Rot13("{6D809377-6AF0-444B-8957-A3773F02200E}\\Ollama\\ollama app.exe")));
        Sjekk(ua == "%ProgramFiles%\\Ollama\\ollama app.exe", $"mappe-ID ble ikke byttet: {ua}");
        Sjekk(s.FinnRegel(ua) != null, "Ollama startet fra Start ble ikke kjent igjen");
        Sjekk(s.FinnRegel(UserAssistSti("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\notepad.exe")) == null
            && s.FinnRegel("Microsoft.Windows.Photos_8wekyb3d8bbwe") == null, "Notisblokk eller Bilder ble tatt for AI");
        var data = new byte[72];
        BitConverter.GetBytes(5).CopyTo(data, 4);
        var tid = new DateTime(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);
        BitConverter.GetBytes(tid.ToFileTimeUtc()).CopyTo(data, 60);
        var d = UserAssistData(data);
        Sjekk(d is { Antall: 5 } x && x.Sist == tid.ToLocalTime() && UserAssistData(new byte[16]) == null, "antall eller siste tid i UserAssist ble feil");

        // Personvernloggen: # er \ i upakkede programmer, pakkenavn står som de er
        Sjekk(PersonvernProgram("C:#Users#x#AppData#Local#Programs#Ollama#ollama app.exe", true) == @"C:\Users\x\AppData\Local\Programs\Ollama\ollama app.exe"
            && PersonvernProgram("Microsoft.Copilot_8wekyb3d8bbwe", false) == "Microsoft.Copilot_8wekyb3d8bbwe", "programnavn i personvernloggen ble feil");
        Sjekk(Tall(132000000000000000L) == 132000000000000000L && Tall("132000000000000000") == 132000000000000000L && Tall(null) == 0, "tidene i personvernloggen ble ikke lest");

        // Installasjonsloggen: 1033 installert, 1034 fjernet, feilstatus og andre hendelser teller ikke
        Dictionary<string, string> M(string status) => new() { ["_0"] = "Ollama", ["_1"] = "0.5.7", ["_2"] = "1033", ["_3"] = status, ["_4"] = "Ollama" };
        var inn = TolkInstallasjon("1033", M("0"));
        var ut = TolkInstallasjon("1034", M("0"));
        Sjekk(inn is { Fjernet: false, Produkt: "Ollama", Versjon: "0.5.7", Utgiver: "Ollama" } && ut is { Fjernet: true }, "1033/1034 ble ikke tolket");
        Sjekk(TolkInstallasjon("1033", M("1603")) == null && TolkInstallasjon("11707", M("0")) == null, "mislykket installering eller annen hendelse ble tatt med");
        return (ok, alle);
    }
}
