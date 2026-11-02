namespace AISkanner;

/// <summary>
/// Hvor mye prosesser bruker skjermkortet (GPU) og NPU-en til beregning akkurat nå, fra Windows' ytelsestellere
/// («GPU Engine»: Compute og Cuda). Måles to ganger med ett sekunds mellomrom. Bare tall per prosess, ingen innhold.
/// </summary>
public sealed partial class Skanner
{
    private void GpuBruk()
    {
        if (_aiPid.IsEmpty) return;
        foreach (var g in GpuBeregning(null, pid => _aiPid.ContainsKey(pid)) ?? new())
        {
            if (!_aiPid.TryGetValue(g.Key, out var ai)) continue;
            ai.Funn.Detalj($"PID {g.Key}: bruker GPU/NPU til beregning nå: {Math.Min(100, g.Value.Prosent):0} %");
            ai.Funn.Merk(Tilstand.KjorerNa);
        }
    }

    /// <summary>PID → (prosessnavn, prosent) for prosessene som bruker GPU/NPU til beregning nå (minst 1 %). null hvis det ikke kunne måles.</summary>
    internal static Dictionary<int, (string Navn, float Prosent)>? GpuBeregning(Func<string, bool>? navn, Func<int, bool>? pidOk = null)
    {
#if NETFRAMEWORK
        try
        {
            if (!System.Diagnostics.PerformanceCounterCategory.Exists("GPU Engine")) { Tilgangslogg.Logg("Register", "Ytelsestellere: GPU Engine", Utfall.IkkeFunnet, "Windows har ikke GPU-tellere på denne PC-en"); return null; }
            var kat = new System.Diagnostics.PerformanceCounterCategory("GPU Engine");
            var tellere = new List<(int Pid, string Navn, System.Diagnostics.PerformanceCounter T)>();
            var navnFor = new Dictionary<int, string?>();
            foreach (var n in kat.GetInstanceNames())
            {
                if (n.IndexOf("engtype_Compute", StringComparison.OrdinalIgnoreCase) < 0 && n.IndexOf("engtype_Cuda", StringComparison.OrdinalIgnoreCase) < 0) continue;
                var m = System.Text.RegularExpressions.Regex.Match(n, @"^pid_(\d+)_");
                if (!m.Success) continue;
                int pid = int.Parse(m.Groups[1].Value);
                if (pidOk != null && !pidOk(pid)) continue;
                if (!navnFor.TryGetValue(pid, out var pn))
                    { try { using var p = System.Diagnostics.Process.GetProcessById(pid); pn = p.ProcessName; } catch { pn = null; } navnFor[pid] = pn; }
                if (pn == null || (navn != null && !navn(pn))) continue;
                var t = new System.Diagnostics.PerformanceCounter("GPU Engine", "Utilization Percentage", n, true);
                t.NextValue();
                tellere.Add((pid, pn, t));
            }
            Tilgangslogg.Logg("Register", "Ytelsestellere: GPU Engine", Utfall.Lest, "bare bruk av beregning (Compute/Cuda) per prosess");
            var svar = new Dictionary<int, (string, float)>();
            if (tellere.Count == 0) return svar;
            Thread.Sleep(1000);
            foreach (var g in tellere.GroupBy(x => x.Pid))
            {
                float sum = 0;
                foreach (var (_, _, t) in g) { try { sum += t.NextValue(); } catch { } t.Dispose(); }
                if (sum >= 1) svar[g.Key] = (g.First().Navn, sum);
            }
            return svar;
        }
        catch (Exception e) { Tilgangslogg.Logg("Register", "Ytelsestellere: GPU Engine", Utfall.Feil, Tilgangslogg.Beskriv(e)); return null; }
#else
        return null;
#endif
    }
}
