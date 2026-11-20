using System.Reflection;

namespace AISkanner;

/// <summary>MIT-lisensen, bakt inn i programmet (--lisens). Samme tekst som LICENSE i repoet.</summary>
public static class Lisens
{
    public static string Tekst()
    {
        using var s = typeof(Lisens).Assembly.GetManifestResourceStream("AISkanner.LICENSE");
        if (s == null) return "MIT License";
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
