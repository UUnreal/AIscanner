using System.Xml.Linq;

namespace AISkanner;

/// <summary>
/// Stoppet Defender noe under søket? Leser Defenders egen hendelseslogg for tiden søket kjørte:
/// 1116/1117 (trussel funnet / tiltak), 1118/1119 (tiltak feilet), 1121 (ASR-regel), 1123 (beskyttet mappe).
/// Bare hendelser som nevner dette programmet tas med. Loggen krever ofte administrator.
/// Andre antivirusprogrammer har egne logger som ikke leses; der ser vi bare feil 225/226 på selve fila.
/// </summary>
public static class Antivirus
{
    public const string Logg = "Microsoft-Windows-Windows Defender/Operational";

    public sealed class Resultat
    {
        public bool Lest;
        public string? Grunn;
        public int AlleUnderSoket;
        public readonly List<(DateTime Tid, int Id, string Tekst)> Vaare = new();
    }

    public static Resultat Hendelser(DateTime fra)
    {
        var r = new Resultat();
        if (!Plattform.ErWindows) { r.Grunn = "ikke Windows"; Tilgangslogg.Logg("Hendelseslogg", Logg, Utfall.HoppetOver, r.Grunn); return r; }
#if NETFRAMEWORK
        try
        {
            var tid = fra.ToUniversalTime().AddSeconds(-2).ToString("o");
            var sporring = new System.Diagnostics.Eventing.Reader.EventLogQuery(Logg, System.Diagnostics.Eventing.Reader.PathType.LogName,
                $"*[System[(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=1121 or EventID=1123) and TimeCreated[@SystemTime>='{tid}']]]");
            using var leser = new System.Diagnostics.Eventing.Reader.EventLogReader(sporring);
            var egen = Path.GetFileName(Environment.GetCommandLineArgs()[0]);
            for (var h = leser.ReadEvent(); h != null && r.AlleUnderSoket < 500; h = leser.ReadEvent())
            {
                using (h)
                {
                    r.AlleUnderSoket++;
                    var data = XDocument.Parse(h.ToXml()).Descendants().Where(e => e.Name.LocalName == "Data")
                        .ToDictionary(e => (string?)e.Attribute("Name") ?? "", e => e.Value, StringComparer.OrdinalIgnoreCase);
                    string Verdi(string n) => data.TryGetValue(n, out var v) ? v : "";
                    var prosess = Verdi("Process Name");
                    if (!prosess.EndsWith(egen, StringComparison.OrdinalIgnoreCase) && prosess.IndexOf("AISkanner", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    var tekst = h.Id switch
                    {
                        1116 or 1117 => $"Defender fant «{Verdi("Threat Name")}» i {Verdi("Path")}",
                        1118 or 1119 => $"Defender klarte ikke å fjerne «{Verdi("Threat Name")}»",
                        1121 => $"ASR-regel stoppet {Verdi("Path")}",
                        1123 => $"Beskyttet mappe stoppet tilgang til {Verdi("Path")}",
                        _ => $"Hendelse {h.Id}",
                    };
                    r.Vaare.Add((h.TimeCreated ?? DateTime.Now, h.Id, tekst));
                    Tilgangslogg.Logg("Antivirus", Verdi("Path"), Utfall.Blokkert, $"Defender-hendelse {h.Id}: {Verdi("Threat Name")}");
                }
            }
            r.Lest = true;
            Tilgangslogg.Logg("Hendelseslogg", Logg, Utfall.Lest, $"{r.AlleUnderSoket} hendelser under søket, {r.Vaare.Count} gjelder dette programmet");
        }
        catch (UnauthorizedAccessException) { r.Grunn = "krever administrator"; Tilgangslogg.Logg("Hendelseslogg", Logg, Utfall.Nektet, r.Grunn); }
        catch (System.Diagnostics.Eventing.Reader.EventLogNotFoundException) { r.Grunn = "Defender-loggen finnes ikke (annet antivirus?)"; Tilgangslogg.Logg("Hendelseslogg", Logg, Utfall.IkkeFunnet, r.Grunn); }
        catch (Exception e) { r.Grunn = Tilgangslogg.Beskriv(e); Tilgangslogg.Feil("Hendelseslogg", Logg, e); }
#else
        r.Grunn = "bare i Windows-programmet";
        Tilgangslogg.Logg("Hendelseslogg", Logg, Utfall.HoppetOver, r.Grunn);
#endif
        return r;
    }
}
