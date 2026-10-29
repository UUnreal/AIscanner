namespace AISkanner;

/// <summary>
/// Hvor mye AI-programmene bruker skjermkortet (GPU) og NPU-en til beregning akkurat nå, fra Windows' ytelsestellere
/// («GPU Engine»: Compute og Cuda). Måles to ganger med ett sekunds mellomrom. Bare tall per prosess, ingen innhold.
/// </summary>
public sealed partial class Skanner
{
    private void GpuBruk()
    {
#if NETFRAMEWORK
        if (_aiPid.IsEmpty) return;
        try
        {
            if (!System.Diagnostics.PerformanceCounterCategory.Exists("GPU Engine")) { Tilgangslogg.Logg("Register", "Ytelsestellere: GPU Engine", Utfall.IkkeFunnet, "Windows har ikke GPU-tellere på denne PC-en"); return; }
            var kat = new System.Diagnostics.PerformanceCounterCategory("GPU Engine");
            var navn = kat.GetInstanceNames().Where(n => n.IndexOf("engtype_Compute", StringComparison.OrdinalIgnoreCase) >= 0 || n.IndexOf("engtype_Cuda", StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            var tellere = new List<(int Pid, System.Diagnostics.PerformanceCounter T)>();
            foreach (var n in navn)
            {
                var m = System.Text.RegularExpressions.Regex.Match(n, @"^pid_(\d+)_");
                if (!m.Success || !_aiPid.ContainsKey(int.Parse(m.Groups[1].Value))) continue;
                var t = new System.Diagnostics.PerformanceCounter("GPU Engine", "Utilization Percentage", n, true);
                t.NextValue();
                tellere.Add((int.Parse(m.Groups[1].Value), t));
            }
            Tilgangslogg.Logg("Register", "Ytelsestellere: GPU Engine", Utfall.Lest, "bare bruk av beregning (Compute/Cuda) for AI-prosesser");
            if (tellere.Count == 0) return;
            Thread.Sleep(1000);
            foreach (var g in tellere.GroupBy(x => x.Pid))
            {
                float sum = 0;
                foreach (var (_, t) in g) { try { sum += t.NextValue(); } catch { } t.Dispose(); }
                if (sum < 1 || !_aiPid.TryGetValue(g.Key, out var ai)) continue;
                ai.Funn.Detalj($"PID {g.Key}: bruker GPU/NPU til beregning nå: {Math.Min(100, sum):0} %");
                ai.Funn.Merk(Tilstand.KjorerNa);
            }
        }
        catch (Exception e) { Tilgangslogg.Logg("Register", "Ytelsestellere: GPU Engine", Utfall.Feil, Tilgangslogg.Beskriv(e)); }
#endif
    }
}
