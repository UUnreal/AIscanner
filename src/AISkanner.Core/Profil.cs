using System.Collections.Concurrent;
using System.Diagnostics;

namespace AISkanner;

/// <summary>Midlertidig måling av trådtid per del (bare CLI med --profil).</summary>
public static class Profil
{
    public static bool Pa;
    public static readonly ConcurrentDictionary<string, long[]> Data = new();

    public static void Tid(string navn, Action a) => Tid(navn, () => { a(); return 0; });

    public static T Tid<T>(string navn, Func<T> f)
    {
        if (!Pa) return f();
        var t = Stopwatch.GetTimestamp();
        try { return f(); }
        finally
        {
            var x = Data.GetOrAdd(navn, _ => new long[2]);
            Interlocked.Add(ref x[0], Stopwatch.GetTimestamp() - t);
            Interlocked.Increment(ref x[1]);
        }
    }

    public static IEnumerable<string> Linjer() => Data.OrderByDescending(x => x.Value[0])
        .Select(x => $"{x.Value[0] / (double)Stopwatch.Frequency,9:0.00} s trådtid  {x.Value[1],9} ganger  {x.Key}");
}
