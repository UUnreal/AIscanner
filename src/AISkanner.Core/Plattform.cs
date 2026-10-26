using System.Diagnostics;

namespace AISkanner;

/// <summary>
/// Små hjelpere som gjør at samme kode kjører på .NET Framework 4.8 (innebygd i Windows, gir en liten exe)
/// og på .NET 8 (brukes bare til testing på Linux).
/// </summary>
internal static class Plattform
{
    public static readonly bool ErWindows = Environment.OSVersion.Platform == PlatformID.Win32NT;
    public static readonly int EgenPid = Process.GetCurrentProcess().Id;

    public static bool Inneholder(this string s, string verdi) => s.IndexOf(verdi, StringComparison.OrdinalIgnoreCase) >= 0;

    public static void LesAlt(this Stream s, byte[] buf)
    {
        int lest = 0;
        while (lest < buf.Length)
        {
            int n = s.Read(buf, lest, buf.Length - lest);
            if (n <= 0) throw new EndOfStreamException();
            lest += n;
        }
    }

    /// <summary>Alle filer under en mappe, uten å følge snarveier/koblinger og uten å stoppe på mapper vi ikke får lese.</summary>
    public static IEnumerable<FileInfo> Filer(string mappe, string monster = "*", int maksDybde = int.MaxValue)
    {
        var ko = new Stack<(DirectoryInfo Mappe, int Dybde)>();
        try { ko.Push((new DirectoryInfo(mappe), 0)); } catch { yield break; }
        while (ko.Count > 0)
        {
            var (d, dybde) = ko.Pop();
            FileInfo[] filer;
            DirectoryInfo[] under;
            try { filer = d.GetFiles(monster); } catch { filer = Array.Empty<FileInfo>(); }
            try { under = dybde < maksDybde ? d.GetDirectories() : Array.Empty<DirectoryInfo>(); } catch { under = Array.Empty<DirectoryInfo>(); }
            foreach (var f in filer)
            {
                bool kobling;
                try { kobling = (f.Attributes & FileAttributes.ReparsePoint) != 0; } catch { continue; }
                if (!kobling) yield return f;
            }
            foreach (var u in under)
            {
                try { if ((u.Attributes & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                ko.Push((u, dybde + 1));
            }
        }
    }

#if NETFRAMEWORK
    public static void Deconstruct<TK, TV>(this KeyValuePair<TK, TV> kv, out TK nokkel, out TV verdi)
    {
        nokkel = kv.Key;
        verdi = kv.Value;
    }
#endif
}

