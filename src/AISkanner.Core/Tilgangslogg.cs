using System.Collections.Concurrent;
using System.Security;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>Hvordan det gikk da programmet prøvde å lese noe.</summary>
/// <summary>Dekket: stedet er en lenke eller en mappe som en annen sjekk går gjennom, så innholdet er søkt der.</summary>
public enum Utfall { Lest, IkkeFunnet, Nektet, Laast, Blokkert, HoppetOver, Tidsgrense, Feil, Dekket }

/// <summary>Én ting programmet prøvde å lese: hvilken sjekk, hva slags ting, hvor, og hvordan det gikk.</summary>
public sealed record Tilgang(DateTime Tid, string Sjekk, string Hva, string Mal, Utfall Utfall, string? Detalj);

/// <summary>
/// Datagrunnlaget for søket: alt programmet prøvde å lese, hvorfor (hvilken sjekk), og om det lyktes.
/// Ligger bare i minnet. Vises i utviklermodus og skrives til fil bare når brukeren har valgt revisjonslogg.
/// Store gjennomganger (alle mapper på disken) telles i stedet for å logges én og én; alt som feiler, logges enkeltvis.
/// Logger aldri innhold, adresser fra nettleserhistorikken eller verdier av nøkler, bare stier og navn.
/// </summary>
public sealed class Tilgangslogg
{
    public const int MaksOppforinger = 20000;

    private readonly ConcurrentQueue<Tilgang> _liste = new();
    private readonly ConcurrentDictionary<(string Sjekk, string Hva, Utfall Utfall), int> _antall = new();
    private readonly ConcurrentDictionary<string, byte> _engang = new();
    private int _lagt;
    // Dekning per disk: mapper som er listet, filer og byte i dem. Hver mappe telles én gang.
    private readonly ConcurrentDictionary<string, long[]> _disk = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _talteMapper = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Per disk (C:\): mapper listet, filer og byte i dem. Grunnlaget for «dekket X av Y» i datagrunnlaget.</summary>
    public IEnumerable<(string Disk, long Mapper, long Filer, long Bytes)> Disker =>
        _disk.Select(x => (x.Key, Interlocked.Read(ref x.Value[0]), Interlocked.Read(ref x.Value[1]), Interlocked.Read(ref x.Value[2]))).OrderBy(x => x.Key);

    /// <summary>Loggen for søket som kjører nå. Ett søk om gangen.</summary>
    public static Tilgangslogg? Aktiv { get; set; }

    /// <summary>Sjekken som kjører i denne tråden (følger med inn i oppgaver den starter).</summary>
    public static readonly AsyncLocal<string?> Sjekk = new();

    public IReadOnlyCollection<Tilgang> Oppforinger => _liste;

    /// <summary>Alle steder søket rørte, som et tre (Datagrunnlag → Kart). Bare i minnet.</summary>
    public Kart Kart { get; } = new();
    public bool Avkortet => _lagt > MaksOppforinger;

    /// <summary>Antall per sjekk, type og utfall. Telles også når lista er full.</summary>
    public IEnumerable<(string Sjekk, string Hva, Utfall Utfall, int Antall)> Antall =>
        _antall.Select(x => (x.Key.Sjekk, x.Key.Hva, x.Key.Utfall, x.Value)).OrderBy(x => x.Sjekk, StringComparer.Ordinal).ThenBy(x => x.Hva, StringComparer.Ordinal);

    // ---------- Logging (statisk, så alle sjekkene kan bruke den uten å sende loggen rundt) ----------

    private static string Navn => Sjekk.Value ?? "Søket";

    public static void Logg(string hva, string mal, Utfall utfall, string? detalj = null)
    {
        var l = Aktiv;
        if (l == null) return;
        var sjekk = Navn;
        l._antall.AddOrUpdate((sjekk, hva, utfall), 1, (_, n) => n + 1);
        l.Kart.Legg(Kart.Plass(hva, mal), sjekk, utfall, detalj);
        if (Interlocked.Increment(ref l._lagt) <= MaksOppforinger) l._liste.Enqueue(new Tilgang(DateTime.Now, sjekk, hva, mal, utfall, detalj));
    }

    /// <summary>Teller uten å logge hver enkelt (for gjennomgang av mange mapper).</summary>
    public static void Tell(string hva, Utfall utfall, int n = 1, string? sted = null, string? detalj = null)
    {
        var l = Aktiv;
        if (l == null || n <= 0) return;
        l._antall.AddOrUpdate((Navn, hva, utfall), n, (_, x) => x + n);
        if (sted != null) l.Kart.Legg(Kart.Plass(hva, sted), Navn, utfall, detalj);
    }

    /// <summary>Legger et sted på kartet uten å telle det (det er talt et annet sted, f.eks. skyfiler per mappe).</summary>
    public static void BareKart(string hva, string sted, Utfall utfall, string? detalj = null) =>
        Aktiv?.Kart.Legg(Kart.Plass(hva, sted), Navn, utfall, detalj);

    /// <summary>Teller én mappe i gjennomgangen og legger den på kartet med antall filer og samlet størrelse.</summary>
    public static void TellMappe(string mappe, Utfall utfall, long filer = 0, long bytes = 0, string? detalj = null)
    {
        var l = Aktiv;
        if (l == null) return;
        l._antall.AddOrUpdate((Navn, "Mappe", utfall), 1, (_, x) => x + 1);
        l.Kart.Legg(Kart.Plass("Mappe", mappe), Navn, utfall, detalj, filer, bytes);
        if (utfall == Utfall.Lest && l._talteMapper.TryAdd(mappe.TrimEnd('\\', '/'), 0))
        {
            string? rot = null;
            try { rot = Path.GetPathRoot(mappe); } catch { }
            if (!string.IsNullOrEmpty(rot))
            {
                var t = l._disk.GetOrAdd(rot!.ToUpperInvariant(), _ => new long[3]);
                Interlocked.Increment(ref t[0]);
                Interlocked.Add(ref t[1], filer);
                Interlocked.Add(ref t[2], bytes);
            }
        }
    }

    /// <summary>Logger bare første gang per nøkkel i søket (f.eks. at tidsgrensen ble nådd).</summary>
    public static void EnGang(string nokkel, string hva, string mal, Utfall utfall, string? detalj = null)
    {
        var l = Aktiv;
        if (l != null && l._engang.TryAdd(nokkel, 0)) Logg(hva, mal, utfall, detalj);
    }

    public static void Feil(string hva, string mal, Exception e)
    {
        var u = Fra(e);
        Logg(hva, mal, u, u == Utfall.IkkeFunnet ? null : Beskriv(e));
    }

    /// <summary>Gjør om en feil til et utfall. Antivirus som stopper en fil gir ERROR_VIRUS_INFECTED (225) eller ERROR_VIRUS_DELETED (226).</summary>
    public static Utfall Fra(Exception e)
    {
        int kode = Kode(e);
        return e switch
        {
            UnauthorizedAccessException or SecurityException => Utfall.Nektet,
            FileNotFoundException or DirectoryNotFoundException => Utfall.IkkeFunnet,
            OperationCanceledException or TimeoutException => Utfall.Tidsgrense,
            IOException when kode is 225 or 226 => Utfall.Blokkert,
            IOException when kode is 32 or 33 => Utfall.Laast,
            IOException when kode is 5 or 1920 => Utfall.Nektet,
            IOException when kode is 2 or 3 => Utfall.IkkeFunnet,
            _ => Utfall.Feil,
        };
    }

    /// <summary>Windows-feilkoden i en feil (HRESULT 0x8007xxxx), ellers 0.</summary>
    public static int Kode(Exception e) => (e.HResult & 0xFFFF0000) == 0x80070000 ? e.HResult & 0xFFFF : 0;

    public static string Beskriv(Exception e)
    {
        int kode = Kode(e);
        return kode switch
        {
            225 => "Windows-feil 225: stoppet av antivirus (Defender eller annet)",
            226 => "Windows-feil 226: fila ble fjernet av antivirus",
            32 => "Windows-feil 32: fila er i bruk av et annet program",
            33 => "Windows-feil 33: deler av fila er låst",
            5 => "Windows-feil 5: ingen tilgang",
            _ => $"{e.GetType().Name}{(kode != 0 ? $" (Windows-feil {kode})" : "")}",
        };
    }

    /// <summary>Kjører en lesing og logger hvordan det gikk. Gir standardverdien hvis den feiler.</summary>
    public static T Prov<T>(string hva, string mal, Func<T> les, T standard, bool loggOk = true)
    {
        try
        {
            var v = les();
            if (loggOk) Logg(hva, mal, Utfall.Lest);
            return v;
        }
        catch (Exception e) { Feil(hva, mal, e); return standard; }
    }

    /// <summary>Åpner en registernøkkel og logger om den fantes eller om tilgang ble nektet.</summary>
    public static RegistryKey? Nokkel(RegistryKey rot, string sti)
    {
        var navn = $@"{Kort(rot)}\{sti}";
        try
        {
            var k = rot.OpenSubKey(sti);
            Logg("Register", navn, k == null ? Utfall.IkkeFunnet : Utfall.Lest);
            return k;
        }
        catch (Exception e) { Feil("Register", navn, e); return null; }
    }

    private static string Kort(RegistryKey rot) => rot.Name switch
    {
        "HKEY_LOCAL_MACHINE" => "HKLM",
        "HKEY_CURRENT_USER" => "HKCU",
        "HKEY_CLASSES_ROOT" => "HKCR",
        "HKEY_USERS" => "HKU",
        var n when n.StartsWith(@"HKEY_USERS\", StringComparison.Ordinal) => "HKU" + n.Substring(10),
        _ => rot.Name,
    };
}
