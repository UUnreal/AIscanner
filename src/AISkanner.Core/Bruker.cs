using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Hvem søket gjelder: brukeren som er logget inn på skjermen, ikke kontoen programmet kjører som.
/// Når IT godkjenner «Søk som admin» med sin egen konto (UAC med annen bruker), kjører programmet som IT-kontoen.
/// Da peker %USERPROFILE%, %LOCALAPPDATA% og HKCU på IT-kontoen, og søket ville sett feil profil.
/// Velg() finner den innloggede brukeren (Windows-økta), og setter profilstiene og HKCU til den brukeren.
/// Leser bare stier og registernøkler Windows selv har lagt ut for brukeren (Volatile Environment, ProfileList).
/// </summary>
public static class Bruker
{
    /// <summary>Brukeren søket gjelder, som DOMENE\navn.</summary>
    public static string Navn { get; private set; } = Konto();

    /// <summary>Kontoen programmet kjører som, når den er en annen enn brukeren (f.eks. IT-kontoen). Ellers null.</summary>
    public static string? KjortAv { get; private set; }

    /// <summary>Registeret til brukeren søket gjelder (HKCU, eller HKEY_USERS\&lt;SID&gt; når en annen konto kjører programmet).</summary>
    public static RegistryKey Hkcu { get; private set; } = Registry.CurrentUser;

    /// <summary>Sann når søket gjelder en annen bruker enn kontoen programmet kjører som.</summary>
    public static bool Annen => KjortAv != null;

    /// <summary>Hvis valget ikke lyktes: hvorfor. Vises i Datagrunnlag og rapporten.</summary>
    public static string? Feil { get; private set; }

    private static bool _valgt;

    private static string Konto() =>
        string.IsNullOrEmpty(Environment.UserDomainName) ? Environment.UserName : $"{Environment.UserDomainName}\\{Environment.UserName}";

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sesjon, int klasse, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr minne);
    private const int WTS_CURRENT_SESSION = -1, WTSUserName = 5, WTSDomainName = 7;

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();

    private static string? Sesjon(int sesjon, int klasse)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sesjon, klasse, out var buf, out _) || buf == IntPtr.Zero) return null;
        try { return Marshal.PtrToStringUni(buf); }
        finally { WTSFreeMemory(buf); }
    }

    /// <summary>Kalles én gang ved oppstart, før noe leser profilstier. Gjør ingenting utenfor Windows
    /// eller når programmet kjører som den innloggede brukeren selv.</summary>
    public static void Velg()
    {
        if (_valgt || !Plattform.ErWindows) return;
        _valgt = true;
        try
        {
            // Økta programmet kjører i. Kjører det uten økt (som SYSTEM fra Intune eller en planlagt oppgave), brukes
            // den som er logget inn på skjermen.
            int sesjon = WTS_CURRENT_SESSION;
            var navn = Sesjon(sesjon, WTSUserName);
            if (string.IsNullOrEmpty(navn) && WTSGetActiveConsoleSessionId() is var k && k != 0xFFFFFFFF)
                navn = Sesjon(sesjon = (int)k, WTSUserName);
            if (string.IsNullOrEmpty(navn)) return;   // ingen er logget inn
            var domene = Sesjon(sesjon, WTSDomainName);
            var bruker = string.IsNullOrEmpty(domene) ? navn! : $"{domene}\\{navn}";
            var sid = Sid(bruker, navn!, domene);
            if (sid == null) { Feil = $"Fant ikke kontoen til {bruker}. Søket gjelder {Konto()}."; return; }
            var egen = WindowsIdentity.GetCurrent().User?.Value;
            if (string.Equals(sid, egen, StringComparison.OrdinalIgnoreCase)) return;   // samme konto, også når den er hevet til admin

            // Brukerens register er lastet så lenge brukeren er logget inn
            var hkcu = Registry.Users.OpenSubKey(sid);
            if (hkcu == null) { Feil = $"Fant ikke registeret til {bruker} (HKEY_USERS\\{sid}). Søket gjelder {Konto()}."; return; }

            // Volatile Environment er stiene Windows ga brukeren ved innlogging (også omdirigerte mapper)
            var miljo = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            using (var v = hkcu.OpenSubKey("Volatile Environment"))
                foreach (var n in v?.GetValueNames() ?? Array.Empty<string>())
                    if (v!.GetValue(n) is string s && s.Length > 0) miljo[n] = s;
            if (!miljo.ContainsKey("USERPROFILE"))
                using (var p = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"))
                    if (p?.GetValue("ProfileImagePath") is string pp) miljo["USERPROFILE"] = Environment.ExpandEnvironmentVariables(pp);
            if (!miljo.TryGetValue("USERPROFILE", out var hjem) || !Directory.Exists(hjem))
            {
                hkcu.Dispose();
                Feil = $"Fant ikke profilmappa til {bruker}. Søket gjelder {Konto()}.";
                return;
            }
            Legg(miljo, "APPDATA", Path.Combine(hjem, "AppData", "Roaming"));
            Legg(miljo, "LOCALAPPDATA", Path.Combine(hjem, "AppData", "Local"));
            miljo["USERNAME"] = navn!;
            if (!string.IsNullOrEmpty(domene)) miljo["USERDOMAIN"] = domene!;

            // Brukerens egne miljøvariabler (OneDrive, HF_HOME, OLLAMA_MODELS, Path …). Bare navn som peker på stier;
            // verdier av AI-nøkler leses aldri (de hoppes over her og bare navnet telles i Sanntid).
            string? brukerPath = null;
            using (var e = hkcu.OpenSubKey("Environment"))
                foreach (var n in e?.GetValueNames() ?? Array.Empty<string>())
                {
                    if (Skanner.ErNokkelNavn(n) || n.Equals("TEMP", StringComparison.OrdinalIgnoreCase) || n.Equals("TMP", StringComparison.OrdinalIgnoreCase)) continue;
                    if (e!.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string s) continue;
                    s = Utvid(s, miljo);
                    if (n.Equals("Path", StringComparison.OrdinalIgnoreCase)) brukerPath = s;
                    else Legg(miljo, n, s);
                }
            using (var m = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
                if (m?.GetValue("Path", null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string mp)
                    miljo["Path"] = Utvid(mp, miljo) + (brukerPath is { Length: > 0 } ? ";" + brukerPath : "");

            // Variabler IT-kontoen har, men brukeren ikke har, fjernes (ellers ville IT-kontoens HF_HOME o.l. blitt søkt)
            using (var e = Registry.CurrentUser.OpenSubKey("Environment"))
                foreach (var n in e?.GetValueNames() ?? Array.Empty<string>())
                    if (!miljo.ContainsKey(n) && !n.Equals("TEMP", StringComparison.OrdinalIgnoreCase) && !n.Equals("TMP", StringComparison.OrdinalIgnoreCase))
                        Environment.SetEnvironmentVariable(n, null);
            foreach (var (n, s) in miljo) Environment.SetEnvironmentVariable(n, s);
            Environment.SetEnvironmentVariable("HOMEDRIVE", Path.GetPathRoot(hjem)?.TrimEnd('\\'));
            Environment.SetEnvironmentVariable("HOMEPATH", hjem.Substring(Math.Min(2, hjem.Length)));

            KjortAv = Konto();
            Navn = bruker;
            Hkcu = hkcu;
        }
        catch (Exception e)
        {
            Feil = $"Kunne ikke finne den innloggede brukeren ({e.GetType().Name}). Søket gjelder {Konto()}.";
        }
    }

    private static void Legg(Dictionary<string, string> d, string n, string v) { if (!d.ContainsKey(n)) d[n] = v; }

    /// <summary>SID-en til brukeren: fra Windows' kontooppslag, ellers fra den innloggede brukerens register
    /// (HKEY_USERS\&lt;SID&gt;\Volatile Environment har USERNAME og USERDOMAIN, også for Entra ID-kontoer).</summary>
    private static string? Sid(string bruker, string navn, string? domene)
    {
        try { return ((SecurityIdentifier)new NTAccount(bruker).Translate(typeof(SecurityIdentifier))).Value; }
        catch { }
        foreach (var sid in Registry.Users.GetSubKeyNames())
        {
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase) || !sid.StartsWith("S-1-", StringComparison.Ordinal)) continue;
            using var v = Registry.Users.OpenSubKey(sid + @"\Volatile Environment");
            if (v?.GetValue("USERNAME") is string n && n.Equals(navn, StringComparison.OrdinalIgnoreCase)
                && (string.IsNullOrEmpty(domene) || (v.GetValue("USERDOMAIN") as string ?? "").Equals(domene, StringComparison.OrdinalIgnoreCase)))
                return sid;
        }
        return null;
    }

    /// <summary>%VAR% byttes med brukerens verdi når vi har den, ellers med prosessens.</summary>
    private static string Utvid(string s, Dictionary<string, string> miljo) =>
        System.Text.RegularExpressions.Regex.Replace(s, "%([^%]+)%", m =>
            miljo.TryGetValue(m.Groups[1].Value, out var v) ? v : Environment.GetEnvironmentVariable(m.Groups[1].Value) ?? m.Value);

    /// <summary>Mappen «Dokumenter» til brukeren søket gjelder.</summary>
    public static string Dokumenter()
    {
        if (Annen)
            using (var k = Hkcu.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"))
                if (k?.GetValue("Personal") is string p && p.Length > 0) return p;
        return Annen ? Path.Combine(Environment.GetEnvironmentVariable("USERPROFILE") ?? "", "Documents")
                     : Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    }
}
