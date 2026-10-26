using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace AISkanner;

/// <summary>
/// Hvem som har signert et program. Firmanavnet i filinfo kan hvem som helst skrive,
/// så en kjent utgiver regnes bare som kjent når Windows bekrefter at signaturen er gyldig.
/// Sjekker ikke tilbakekalling over nettet (ingen nettverkstrafikk).
/// </summary>
internal static class Signatur
{
    private static readonly Guid VerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct FilInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid handling, ref TrustData data);

    private static readonly Dictionary<string, string?> Hurtig = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Organisasjonen i et gyldig signatursertifikat, eller null hvis filen ikke er gyldig signert.</summary>
    public static string? Utgiver(string fil)
    {
        if (!Plattform.ErWindows) return null;
        lock (Hurtig) if (Hurtig.TryGetValue(fil, out var kjent)) return kjent;
        string? svar = null;
        var info = new FilInfo { cbStruct = (uint)Marshal.SizeOf<FilInfo>(), pcwszFilePath = fil };
        var p = Marshal.AllocHGlobal(Marshal.SizeOf<FilInfo>());
        try
        {
            Marshal.StructureToPtr(info, p, false);
            var data = new TrustData
            {
                cbStruct = (uint)Marshal.SizeOf<TrustData>(),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 0,     // WTD_REVOKE_NONE
                dwUnionChoice = 1,           // WTD_CHOICE_FILE
                pFile = p,
                dwStateAction = 0,           // WTD_STATEACTION_IGNORE
                dwProvFlags = 0x10 | 0x1000, // ingen tilbakekallingssjekk, ingen nedlasting
            };
            if (WinVerifyTrust(IntPtr.Zero, VerifyV2, ref data) == 0)
            {
                var emne = X509Certificate.CreateFromSignedFile(fil).Subject;
                var m = Regex.Match(emne, @"(?:^|,\s*)O=(""[^""]+""|[^,]+)");
                if (!m.Success) m = Regex.Match(emne, @"(?:^|,\s*)CN=(""[^""]+""|[^,]+)");
                svar = m.Success ? m.Groups[1].Value.Trim('"', ' ') : emne;
            }
        }
        catch { }
        finally
        {
            Marshal.DestroyStructure<FilInfo>(p);
            Marshal.FreeHGlobal(p);
        }
        lock (Hurtig) Hurtig[fil] = svar;
        return svar;
    }
}
