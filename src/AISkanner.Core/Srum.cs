using System.Runtime.InteropServices;
using System.Text;

namespace AISkanner;

/// <summary>
/// SRUM (System Resource Usage Monitor): Windows teller selv hvor mye hvert program har sendt og mottatt over nettet,
/// time for time, de siste 30–60 dagene. Leses som administrator rett fra System32\sru\SRUDB.dat (bare lesing, ingen
/// kopi). For AI-programmer blir det et ekte bevis på bruk: programmet, mengden og når.
/// </summary>
public sealed partial class Skanner
{
    private const string SrumNett = "{973F5D5C-1D90-4944-BE8E-24B94231A174}";
    public string? SrumStatus { get; private set; }
    /// <summary>Timer med nettbruk lest fra SRUM, og AI-programmer blant dem (til «Sjekket» i Funn).</summary>
    public int SrumRader { get; private set; } = -1;
    public int SrumAi { get; private set; }
    /// <summary>Programmer i id-tabellen. Er den tom, kan ingen nettbruk knyttes til et program: da er SRUM ikke bekreftet.</summary>
    public int SrumProgrammer { get; private set; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string enhet, StringBuilder mal, int lengde);

    private void Srum()
    {
        var fil = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\sru\SRUDB.dat");
        if (!File.Exists(fil)) { Tilgangslogg.Logg("Fil", fil, Utfall.IkkeFunnet, "SRUM finnes ikke"); return; }
        if (!Nettverk.ErAdmin()) { Tilgangslogg.Logg("Fil", fil, Utfall.Nektet, "SRUM krever administrator"); return; }
        // Alle feil gir en grunn i rapporten og i «Sjekket», aldri bare «ikke lest»
        try
        {
            using var s = Admintilgang.AapneLes(fil, 1 << 16);
            LesSrum(s, fil);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            var kode = e is IOException io ? $" (Windows-feil {io.HResult & 0xFFFF})" : "";
            SrumStatus = $"SRUM: kunne ikke leses: {e.GetType().Name}{kode}: {e.Message} [{e.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}]";
            Tilgangslogg.Logg("Fil", fil, Utfall.Feil, SrumStatus);
        }
    }

    internal void LesSrum(Stream s, string fil)
    {
        var klokke = System.Diagnostics.Stopwatch.StartNew();
        var frist = Fullt ? TimeSpan.FromSeconds(40) : TimeSpan.FromSeconds(10);
        EseFil db;
        try { db = new EseFil(s); }
        catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException or InvalidDataException)
        {
            SrumStatus = $"SRUM: feil, katalogen kunne ikke leses ({e.GetType().Name}: {e.StackTrace?.Split('\n').FirstOrDefault()?.Trim()})";
            Tilgangslogg.Logg("Fil", fil, Utfall.Feil, SrumStatus);
            return;
        }
        var idTab = db.Finn("SruDbIdMapTable");
        var nett = db.Finn(SrumNett);
        if (idTab == null)
        {
            SrumStatus = $"SRUM: id-tabellen finnes ikke ({db.Tabeller.Count()} tabeller lest)";
            Tilgangslogg.Logg("Fil", fil, Utfall.Lest, SrumStatus);
            return;
        }

        // Id -> program (sti eller appnavn)
        var program = new Dictionary<int, string>();
        int hoppet = 0, feil = 0;
        if (db.KolonneId(idTab, "IdType") is { } cType && db.KolonneId(idTab, "IdIndex") is { } cIdx && db.KolonneId(idTab, "IdBlob") is { } cBlob)
            foreach (var r in db.Poster(idTab.Rot, () => klokke.Elapsed > frist))
            {
                try
                {
                var p = db.Tolk(r, idTab);
                if (p.Tall(cType) is not (0 or 1 or 2) || p.Tall(cIdx) is not { } idx) continue;
                var b = p.Binar(cBlob, out var hopp);
                if (hopp) hoppet++;
                if (b == null || b.Length < 2) continue;
                var tekst = Encoding.Unicode.GetString(b).TrimEnd('\0');
                if (tekst.Length > 0) program[(int)idx] = tekst;
                }
                catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException) { feil++; }
            }

        // Nettbruk per program siste 30 dager
        var grense = DateTime.Now.AddDays(-30);
        var sum = new Dictionary<int, (long Ut, long Inn, DateTime Forst, DateTime Sist)>();
        int rader = 0, poster = 0, utenTid = 0, utenApp = 0;
        DateTime? eldst = null, nyest = null;
        // Uten nettbrukstabellen (ny PC, eller SRUM av): tilkoblingstabellen viser at lesingen virker, men har ingen mengder
        var tabell = nett ?? db.Finn("{DD6636C4-8929-4683-974E-22C046A43763}");
        bool sideForSide = false;
        var sett = new HashSet<long>();
        if (tabell != null && db.KolonneId(tabell, "TimeStamp") is { } cTid && db.KolonneId(tabell, "AppId") is { } cApp)
            foreach (var r in Rader())
            {
                try
                {
                var p = db.Tolk(r, tabell);
                // Side for side kan samme post finnes i en gammel kopi av en side: AutoIncId telles én gang
                if (sideForSide && db.KolonneId(tabell, "AutoIncId") is { } cId && p.Tall(cId) is { } id && !sett.Add(id)) continue;
                poster++;
                // Tider utenfor SRUM sin levetid (før 2015 eller fram i tid) er feiltolkede poster, ikke ekte timer
                if (p.Tid(cTid) is not { } t || t.Year < 2015 || t > DateTime.Now.AddDays(1)) { utenTid++; continue; }
                if (p.Tall(cApp) is not { } app) { utenApp++; continue; }
                rader++;
                if (eldst == null || t < eldst) eldst = t;
                if (nyest == null || t > nyest) nyest = t;
                if (nett == null || t < grense) continue;
                long ut = db.KolonneId(nett, "BytesSent") is { } cUt ? p.Tall(cUt) ?? 0 : 0, inn = db.KolonneId(nett, "BytesRecvd") is { } cInn ? p.Tall(cInn) ?? 0 : 0;
                sum[(int)app] = sum.TryGetValue((int)app, out var x)
                    ? (x.Ut + ut, x.Inn + inn, t < x.Forst ? t : x.Forst, t > x.Sist ? t : x.Sist)
                    : (ut, inn, t, t);
                }
                catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException) { feil++; }
            }

        IEnumerable<(byte[], int, int)> Rader()
        {
            int n = 0;
            foreach (var r in db.Poster(tabell!.Rot, () => klokke.Elapsed > frist)) { n++; yield return r; }
            if (n > 0) yield break;
            sideForSide = true;
            foreach (var r in db.PosterForEier(tabell.ObjId, () => klokke.Elapsed > frist)) yield return r;
        }

        int ai = 0;
        var enheter = Enheter();
        foreach (var (app, (ut, inn, forst, sist)) in sum)
        {
            if (!program.TryGetValue(app, out var navn)) continue;
            var sti = Dosti(navn, enheter);
            // SRUM har også appnavn og tjenester med tegn Windows ikke godtar i stier (f.eks. «<»): ikke bruk Path på dem
            var ugyldig = sti.IndexOfAny(Path.GetInvalidPathChars()) >= 0;
            var exe = sti.Substring(sti.LastIndexOf('\\') + 1);
            if (exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) exe = exe.Substring(0, exe.Length - 4);
            if (Nettleserprosesser.ContainsKey(exe) || sti.EndsWith("AISkanner.exe", StringComparison.OrdinalIgnoreCase)) continue;
            Funn? f;
            try { f = FunnForProsess(exe, sti.Contains('\\') && !ugyldig ? sti : null) ?? (FinnRegel(sti) is { } regel ? FraRegel(regel, "Kjørt før", null!) : null); }
            catch (ArgumentException) { feil++; continue; }
            if (f == null) continue;
            f.Detalj($"SRUM (Windows' ressursbruk, {fil}): {sti} sendte {Rapport.Storrelse(ut)} og mottok {Rapport.Storrelse(inn)} siste 30 dager · {Tid(forst)}–{Tid(sist)}");
            f.Merk(Tilstand.BruktFor);
            f.Sterkt();
            f.Tidspunkt(forst, sist);
            ai++;
        }
        SrumRader = nett != null ? rader : -1; SrumAi = ai; SrumProgrammer = program.Count;
        SrumStatus = $"SRUM: {rader} {(nett != null ? $"timer med nettbruk av {poster} poster ({(poster == 0 ? db.RotInfo(nett) : sideForSide ? $"lest side for side: treet fra rotside {nett.Rot} var tomt, {db.RotInfo(nett)}" : $"rot side {nett.Rot}")})" : "rader i tilkoblingstabellen (nettbrukstabellen finnes ikke)")} ({(eldst != null ? $"{Tid(eldst)}–{Tid(nyest)}" : "ingen")}), {program.Count} programmer i id-tabellen{(hoppet > 0 ? $", {hoppet} lange eller komprimerte navn ikke lest" : "")}{(utenTid + utenApp > 0 ? $", {utenTid + utenApp} av {poster} rader kunne ikke tolkes (kolonner {Kolonner(tabell!)})" : "")}, {(feil + db.Feil > 0 ? $"{feil + db.Feil} poster kunne ikke tolkes, " : "")}{db.SiderLest} sider ({db.Side / 1024} kB) lest på {klokke.Elapsed.TotalSeconds:0.0} s; {ai} AI-programmer med nettbruk";
        Tilgangslogg.Logg("Fil", fil, Utfall.Lest, SrumStatus + ". Siste timer kan mangle (Windows skriver dem inn senere). Bare programnavn, mengder og tider brukes.");
    }

    private static string Kolonner(EseFil.Tabell t) =>
        string.Join(" ", t.Kolonner.Values.OrderBy(k => k.Id).Where(k => k.Id < 256).Select(k => $"{k.Id}:{k.Navn}/{k.Type}"));

    private static Dictionary<string, string> Enheter()
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!Plattform.ErWindows) return d;
        foreach (var disk in Environment.GetLogicalDrives())
        {
            var bokstav = disk.TrimEnd('\\');
            var sb = new StringBuilder(260);
            if (QueryDosDevice(bokstav, sb, sb.Capacity) > 0) d[sb.ToString()] = bokstav;
        }
        return d;
    }

    /// <summary>\Device\HarddiskVolume3\Program Files\x.exe blir C:\Program Files\x.exe.</summary>
    internal static string Dosti(string sti, Dictionary<string, string> enheter)
    {
        foreach (var (enhet, bokstav) in enheter)
            if (sti.StartsWith(enhet + "\\", StringComparison.OrdinalIgnoreCase)) return bokstav + sti.Substring(enhet.Length);
        return sti;
    }
}
