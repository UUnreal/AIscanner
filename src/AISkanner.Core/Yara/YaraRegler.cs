using System.Reflection;
using System.Text;
using AISkanner.YaraMotor;

namespace AISkanner;

/// <summary>
/// YARA uten libyara: leser og kjører vanlige YARA-regler (ai-modeller.yar), som også kan kjøres med yara.exe.
/// Alle strenger i alle regler søkes i én runde (Aho-Corasick), og betingelsene er ferdig oversatt til funksjoner,
/// så hver fil leses bare én gang. Leser starten og slutten av filen, ikke hele modellen, og kjører ingenting.
/// </summary>
public sealed class YaraRegler
{
    public sealed class Regel
    {
        public string Navn = "";
        public readonly List<string> Tagger = new();
        public readonly Dictionary<string, string> Meta = new(StringComparer.OrdinalIgnoreCase);
        public string Beskrivelse => Meta.TryGetValue("beskrivelse", out var b) ? b : Navn;
        public Risiko? Risiko => Meta.TryGetValue("risiko", out var r) ? r switch { "rod" => AISkanner.Risiko.Rod, "gul" => AISkanner.Risiko.Gul, "gronn" => AISkanner.Risiko.Gronn, _ => null } : null;
        public bool Ondsinnet => Tagger.Contains("ondsinnet");

        internal bool Privat, Global;
        internal readonly List<Streng> StrengListe = new();
        internal Func<Kontekst, object?> Betingelse = _ => false;
        public override string ToString() => Navn;
    }

    public List<Regel> Regler { get; } = new();
    public string Kilde { get; private set; } = "innebygd";
    private Strengsok? _sok;
    private Strengsok Sok => _sok ??= new Strengsok(Regler.SelectMany(r => r.StrengListe));

    /// <summary>ai-modeller.yar ved siden av programmet hvis den finnes (så bedriften kan legge til egne regler), ellers de innebygde.</summary>
    public static YaraRegler Last(string? sti = null)
    {
        sti ??= Path.Combine(AppContext.BaseDirectory, "ai-modeller.yar");
        string? feil = null;
        if (File.Exists(sti))
        {
            try { var y = Les(File.ReadAllText(sti)); y.Kilde = sti; return y; }
            catch (Exception e) { feil = $"innebygde, fordi {Path.GetFileName(sti)} har feil: {e.Message}"; }
        }
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.ai-modeller.yar")
                      ?? throw new InvalidOperationException("Mangler innebygde YARA-regler.");
        using var r = new StreamReader(s, Encoding.UTF8);
        var inn = Les(r.ReadToEnd());
        if (feil != null) inn.Kilde = feil;
        return inn;
    }

    public static YaraRegler Les(string tekst)
    {
        var y = new YaraRegler();
        y.Regler.AddRange(Parser.Les(tekst));
        return y;
    }

    /// <summary>Kjører reglene på starten og slutten av en fil. Returnerer reglene som slo til.</summary>
    public List<Regel> Sjekk(string fil, int hode = 8 << 20, int hale = 1 << 20, bool bareOndsinnede = false)
    {
        try
        {
            using var fs = Admintilgang.AapneLes(fil, 1 << 16);
            long lengde = fs.Length;
            var a = new byte[(int)Math.Min(lengde, hode)];
            fs.LesAlt(a);
            byte[]? b = null;
            if (lengde > a.Length && hale > 0)
            {
                long fra = Math.Max(a.Length, lengde - hale);
                b = new byte[(int)(lengde - fra)];
                fs.Position = fra;
                fs.LesAlt(b);
            }
            return Kjor(a, b, lengde, fil, bareOndsinnede);
        }
        catch { return new List<Regel>(); }
    }

    public List<Regel> Sjekk(byte[] hode, byte[]? hale, long filstorrelse, bool bareOndsinnede = false)
    {
        try { return Kjor(hode, hale, filstorrelse, null, bareOndsinnede); }
        catch { return new List<Regel>(); }
    }

    private List<Regel> Kjor(byte[] hode, byte[]? hale, long filstorrelse, string? fil, bool bareOndsinnede)
    {
        var biter = new List<Bit> { new(hode, 0) };
        if (hale is { Length: > 0 }) biter.Add(new Bit(hale, filstorrelse - hale.Length));

        var underveis = new HashSet<Regel>();
        Kontekst k = null!;
        bool KjorRegel(Regel r)
        {
            if (k.Regelresultat.TryGetValue(r, out var v)) return v;
            if (!underveis.Add(r)) return false;   // regel som peker på seg selv
            var forrige = k.Gjeldende;
            k.Gjeldende = r;
            try { v = V.Sann(r.Betingelse(k)); }
            catch { v = false; }
            finally { k.Gjeldende = forrige; underveis.Remove(r); }
            return k.Regelresultat[r] = v;
        }
        k = new Kontekst(biter, filstorrelse, fil, KjorRegel) { Treff = Sok.Sok(biter) };

        // En global regel som ikke slår til stopper alle reglene for denne filen
        foreach (var r in Regler)
            if (r.Global && !KjorRegel(r)) return new List<Regel>();

        var treff = new List<Regel>();
        foreach (var r in Regler)
        {
            if (r.Privat || (bareOndsinnede && !r.Ondsinnet)) continue;
            if (KjorRegel(r)) treff.Add(r);
        }
        return treff;
    }
}
