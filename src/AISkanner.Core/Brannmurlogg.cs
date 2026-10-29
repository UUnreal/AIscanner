using System.Globalization;
using System.Net;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Windows-brannmurens logg (pfirewall.log), hvis IT har slått den på. Bare linjer som går til adressene kjente
/// AI-tjenester har akkurat nå: tid, protokoll, port og (i nyere Windows) PID. UDP til port 443 er QUIC (HTTP/3),
/// som TCP-tabellen ikke ser. Adressene til store skytjenester deles og endres, så treffene er middels sikre.
/// </summary>
public sealed partial class Skanner
{
    private void Brannmurlogg()
    {
        var filer = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log") };
        foreach (var profil in new[] { "DomainProfile", "PrivateProfile", "PublicProfile", "StandardProfile" })
        {
            using var k = Tilgangslogg.Nokkel(Registry.LocalMachine, $@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{profil}\Logging");
            if (k?.GetValue("LogFilePath") is string p && p.Length > 0) filer.Add(Environment.ExpandEnvironmentVariables(p));
        }
        Dictionary<IPAddress, List<string>>? ai = null;
        try { if (_aiIp != null && _aiIp.Wait(TimeSpan.FromSeconds(5))) ai = _aiIp.Result; } catch { }
        if (ai == null || ai.Count == 0) return;
        foreach (var fil in filer.Where(File.Exists)) LesBrannmurlogg(fil, ai);
    }

    internal void LesBrannmurlogg(string fil, Dictionary<IPAddress, List<string>> ai)
    {
        var treff = new Dictionary<string, (int Tcp, int Quic, int Udp, DateTime Forst, DateTime Sist, HashSet<int> Pid)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var fs = Admintilgang.AapneLes(fil);
            // Bare de siste 16 MB: loggen roterer, og eldre linjer er uansett borte
            if (fs.Length > 16 * 1024 * 1024) fs.Position = fs.Length - 16 * 1024 * 1024;
            using var r = new StreamReader(fs);
            string[] felt = { "date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port" };
            string? linje;
            while ((linje = r.ReadLine()) != null)
            {
                if (linje.StartsWith("#Fields:", StringComparison.Ordinal)) { felt = linje.Substring(8).Trim().Split(' '); continue; }
                if (linje.Length == 0 || linje[0] == '#') continue;
                var d = linje.Split(' ');
                string? F(string n) { var i = Array.IndexOf(felt, n); return i >= 0 && i < d.Length ? d[i] : null; }
                if (F("action") != "ALLOW" || !IPAddress.TryParse(F("dst-ip"), out var ip) || !ai.TryGetValue(ip, out var verter)) continue;
                if (!DateTime.TryParseExact($"{F("date")} {F("time")}", "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var tid)) continue;
                var vert = verter.FirstOrDefault(v => Tjeneste(v) != null) ?? verter[0];
                var navn = Tjeneste(vert)?.Navn ?? vert;
                treff.TryGetValue(navn, out var t);
                t.Pid ??= new HashSet<int>();
                var proto = F("protocol");
                if (proto == "TCP") t.Tcp++; else if (proto == "UDP" && F("dst-port") == "443") t.Quic++; else if (proto == "UDP") t.Udp++;
                if (t.Forst == default || tid < t.Forst) t.Forst = tid;
                if (tid > t.Sist) t.Sist = tid;
                if (int.TryParse(F("pid"), out var pid) && pid > 4 && t.Pid.Count < 10) t.Pid.Add(pid);
                treff[navn] = t;
            }
            Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil, detalj: "brannmurlogg: bare linjer til AI-adresser");
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", fil, e); return; }
        if (treff.Count == 0) return;
        var f = LeggTil("AI-tjenester i brannmurloggen", "Nettverk", Risiko.Gul,
            "Windows-brannmuren har logget forbindelser til adresser som AI-tjenester bruker.", "Windows", null, enkelt: "AI-trafikk i brannmurloggen");
        foreach (var (navn, t) in treff.OrderByDescending(x => x.Value.Sist))
        {
            var deler = new List<string>();
            if (t.Tcp > 0) deler.Add($"TCP {t.Tcp}");
            if (t.Quic > 0) deler.Add($"QUIC/HTTP3 (UDP 443) {t.Quic}");
            if (t.Udp > 0) deler.Add($"annen UDP {t.Udp}");
            f.Detalj($"{navn}: {string.Join(", ", deler)} · {Nar(t.Forst, "tid i logglinje")} til {Nar(t.Sist, "tid i logglinje")}{(t.Pid.Count > 0 ? $" · PID {string.Join(", ", t.Pid)}" : "")}");
        }
        f.Detalj($"Fil: {fil}");
        f.Merknad("Adressene er slått opp nå. Store skytjenester deler og bytter adresser, så et treff er en indikasjon, ikke et bevis.");
        f.Tidspunkt(treff.Values.Min(t => t.Forst), treff.Values.Max(t => t.Sist));
        f.Merk(Tilstand.BruktFor);
        f.Svakt();
    }
}
