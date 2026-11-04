namespace AISkanner;

/// <summary>
/// YARA-reglene (ai-modeller.yar) kjøres på alle AI-modeller som blir funnet, og på små pickle-, PyTorch- og Keras-filer.
/// Små modeller sjekkes bare hvis de første bytene viser at det er pickle, zip eller HDF5, og da bare den første MB-en.
/// </summary>
public sealed partial class Skanner
{
    private YaraRegler? _yara;
    public YaraRegler Yara => _yara ??= YaraRegler.Last();

    private static readonly HashSet<string> PickleEndelser = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".bin", ".joblib", ".keras", ".h5", ".hdf5", ".npy", ".model", ".mar", ".nemo",
    };

    /// <summary>Små filer som kan være modeller med skjult kode. Store modeller sjekkes i LeggTilModell.</summary>
    private void SjekkLitenModell(FileInfo fil, FilFunn ff, long lengde)
    {
        if (!PickleEndelser.Contains(fil.Extension)) return;
        if (lengde < 16 || lengde > 200L * 1024 * 1024) return;
        try
        {
            var hode = new byte[8];
            using (var s = Admintilgang.AapneLes(fil.FullName))
            {
                Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName);
                if (s.Read(hode, 0, 8) < 8) return;
            }
            // Protokoll 2-5 har hode (0x80). Protokoll 0-1 har ikke: de starter med en opkode, som GLOBAL «c» eller MARK «(».
            bool pickle = (hode[0] == 0x80 && hode[1] is >= 2 and <= 5)
                || (fil.Extension.Equals(".pkl", StringComparison.OrdinalIgnoreCase) || fil.Extension.Equals(".pickle", StringComparison.OrdinalIgnoreCase)) && hode[0] is (byte)'c' or (byte)'(' or (byte)']' or (byte)'}';
            bool zip = hode[0] == 0x50 && hode[1] == 0x4B && hode[2] == 3 && hode[3] == 4;
            bool hdf5 = hode[0] == 0x89 && hode[1] == 0x48 && hode[2] == 0x44 && hode[3] == 0x46;
            bool npy = hode[0] == 0x93 && hode[1] == (byte)'N';
            if (!pickle && !zip && !hdf5 && !npy) return;
        }
        catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); return; }
        var treff = Yara.Sjekk(fil.FullName, 1 << 20, 0, bareOndsinnede: true);
        if (treff.Count > 0) lock (ff) ff.Farlige.Add((fil.FullName, lengde, treff));
    }

    private void LeggTilFarlige(FilFunn ff)
    {
        foreach (var (sti, lengde, treff) in ff.Farlige.Take(30))
        {
            DateTime? endret = null, opprettet = null;
            try { var fi = new FileInfo(sti); endret = fi.LastWriteTime; opprettet = fi.CreationTime; } catch { }
            var f = LeggTil($"Farlig AI-modellfil: {Path.GetFileName(sti)}", "Lokal AI (modell)", Risiko.Rod, treff[0].Beskrivelse, "YARA",
                $"Fil: {sti} · {Rapport.Storrelse(lengde)} · endret {Tid(endret)}");
            f.Bruk = $"Funnet av YARA-regelen {treff[0].Navn}.";
            f.Sterkt();
            f.LeggTilModeller(1);
            f.Tidspunkt(opprettet < endret ? opprettet : endret, endret);
            Nedlastingskilde(f, sti);
            foreach (var r in treff) f.Detalj($"YARA: {r.Navn} · {r.Beskrivelse}");
            if (ErRisikabelPlass(sti)) f.Advarsel("Ligger i en nedlastings- eller midlertidig mappe.");
        }
    }

    /// <summary>Kjører alle reglene på en modell som er funnet, og gjør funnet rødt hvis en farlig regel slår til.</summary>
    private void YaraPaModell(string sti, Funn f)
    {
        foreach (var r in Yara.Sjekk(sti))
        {
            f.Detalj($"YARA: {r.Navn} · {r.Beskrivelse}");
            if (r.Risiko == Risiko.Rod)
            {
                f.Risiko = Risiko.Rod;
                f.Advarsel(r.Beskrivelse);
            }
        }
    }
}
