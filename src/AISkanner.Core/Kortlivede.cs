namespace AISkanner;

/// <summary>
/// Programmer som startet og stoppet mens søket lyttet. Uten 4688 eller Sysmon ville de ikke blitt sett:
/// et skript som kjører i to sekunder, en AI-kommando fra en planlagt oppgave. Samme regler som for prosesser som kjører.
/// </summary>
public sealed partial class Skanner
{
    internal void KortlivedeProsesser(NettBilde nb)
    {
        int ai = 0;
        foreach (var k in nb.Kortlivede)
        {
            var kilde = $"startet og stoppet under søket (sett {k.Sett:HH:mm:ss}–{k.Borte:HH:mm:ss}, PID {k.Pid})";
            if (Kommandolinje.ErTolk(k.Navn))
            {
                if (k.Linje != null && Vurder(k.Navn, k.Sti, 0, k.Linje, null, k.Sett, kilde) != null) ai++;
                continue;
            }
            if (FinnRegel($"{k.Navn} {k.Sti}") is not { } r) continue;
            var f = FraRegel(r, "Kjørt før", $"Kjørte kort: {k.Sti ?? k.Navn} · {kilde}");
            f.Merk(Tilstand.BruktFor);
            f.Tidspunkt(k.Sett, k.Borte);
            ai++;
        }
        Tilgangslogg.Logg("Prosesser", "Prosesslista under lyttingen (hvert halve sekund)", Utfall.Lest,
            $"{nb.Kortlivede.Count} programmer startet og stoppet under søket; {ai} traff en AI-regel");
    }
}
