using Regel = AISkanner.YaraRegler.Regel;

namespace AISkanner.YaraMotor;

/// <summary>Funksjon i en modul, f.eks. math.entropy(0, filesize).</summary>
internal delegate object? Funksjon(Kontekst k, object?[] a);

/// <summary>Struktur i en modul (pe, pe.sections[0], ...). Felt kan være tall, tekst, lister, ordbøker eller funksjoner.</summary>
internal sealed class Struktur
{
    public readonly Dictionary<string, object?> Felt = new(StringComparer.Ordinal);
    public object? this[string navn] { get => Felt.TryGetValue(navn, out var v) ? v : null; set => Felt[navn] = value; }
}

/// <summary>Alt om filen som sjekkes: dataene, treffene, regelresultater og variabler i løkker.</summary>
internal sealed class Kontekst
{
    /// <summary>Filer opp til denne størrelsen kan leses mer av hvis en regel trenger det (hash av hele filen, data utenfor start/slutt).</summary>
    public const long MaksEkstraLesing = 64L * 1024 * 1024;

    public readonly List<Bit> Biter;
    public readonly long Filstorrelse;
    private readonly string? _fil;
    private byte[]? _hele;
    public Dictionary<Streng, SortedDictionary<long, int>> Treff = new();
    public readonly Dictionary<Regel, bool> Regelresultat = new();
    public readonly Func<Regel, bool> KjorRegel;
    public readonly Dictionary<string, object?> Variabler = new(StringComparer.Ordinal);
    public Streng? Anonym;
    public Regel? Gjeldende;
    private readonly Dictionary<string, object?> _moduler = new(StringComparer.Ordinal);

    public Kontekst(List<Bit> biter, long filstorrelse, string? fil, Func<Regel, bool> kjorRegel)
    {
        Biter = biter; Filstorrelse = filstorrelse; _fil = fil; KjorRegel = kjorRegel;
    }

    /// <summary>Bytes i filen fra posisjon, eller null hvis de ikke er tilgjengelige.</summary>
    public byte[]? Les(long fra, long lengde)
    {
        if (fra < 0 || lengde < 0 || fra + lengde > Filstorrelse) return null;
        foreach (var b in Biter)
            if (fra >= b.Start && fra + lengde <= b.Start + b.Data.Length)
            {
                var ut = new byte[lengde];
                Array.Copy(b.Data, fra - b.Start, ut, 0, lengde);
                return ut;
            }
        var hele = Hele();
        if (hele == null) return null;
        var r = new byte[lengde];
        Array.Copy(hele, fra, r, 0, lengde);
        return r;
    }

    /// <summary>Samme som Les, men uten kopi når området ligger samlet i minnet.</summary>
    public ArraySegment<byte>? Omrade(long fra, long lengde)
    {
        if (fra < 0 || lengde < 0 || fra + lengde > Filstorrelse) return null;
        foreach (var b in Biter)
            if (fra >= b.Start && fra + lengde <= b.Start + b.Data.Length)
                return new ArraySegment<byte>(b.Data, (int)(fra - b.Start), (int)lengde);
        var hele = Hele();
        if (hele == null) return null;
        return new ArraySegment<byte>(hele, (int)fra, (int)lengde);
    }

    /// <summary>Antall av hver byteverdi i et område. Deles av math.entropy, mean, count, percentage og mode.</summary>
    public readonly Dictionary<(long, long), long[]> Histogrammer = new();

    public int Byte(long pos)
    {
        foreach (var b in Biter)
            if (pos >= b.Start && pos < b.Start + b.Data.Length) return b.Data[pos - b.Start];
        var h = Hele();
        return h != null && pos >= 0 && pos < h.Length ? h[pos] : -1;
    }

    /// <summary>Hele filen, bare når den er liten nok og bare når en regel ber om det.</summary>
    private byte[]? Hele()
    {
        if (_hele != null) return _hele;
        if (Biter.Count == 1 && Biter[0].Start == 0 && Biter[0].Data.Length == Filstorrelse) return _hele = Biter[0].Data;
        if (_fil == null || Filstorrelse > MaksEkstraLesing) return null;
        try
        {
            using var s = new FileStream(_fil, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var d = new byte[s.Length];
            s.LesAlt(d);
            return _hele = d;
        }
        catch { return null; }
    }

    public object? Modul(string navn)
    {
        if (_moduler.TryGetValue(navn, out var m)) return m;
        m = navn switch
        {
            "pe" => Moduler.Pe(this),
            "math" => Moduler.Math(),
            "hash" => Moduler.Hash(),
            "time" => Moduler.Tid(),
            "string" => Moduler.Tekst(),
            "console" => Moduler.Konsoll(),
            _ => null,   // dotnet, elf, macho, magic, cuckoo: ikke støttet, gir "udefinert"
        };
        _moduler[navn] = m;
        return m;
    }

    public SortedDictionary<long, int>? TreffFor(Streng s) => Treff.TryGetValue(s, out var t) ? t : null;
}
