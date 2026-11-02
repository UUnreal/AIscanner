using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Kan BIOS eller PC-produsenten legge inn AI? To spor, bare lesing:
/// 1) WPBT-tabellen i fastvaren (ACPI): et program BIOS ber Windows kjøre ved hver oppstart (lagres som System32\wpbbin.exe).
/// 2) Tjenester og drivere som er endret siste 7 dager, med firma fra filinfo, sjekket mot AI-reglene.
/// Det som vises, er fakta fra PC-en. Selve AI-funnene kommer fra de vanlige sjekkene.
/// </summary>
public sealed partial class Skanner
{
    public List<string> Fastvarelinjer { get; } = new();
    /// <summary>Hver tjeneste og driver endret siste 7 dager (vises når «Tjenester endret 7 d» trykkes).</summary>
    public List<string> EndredeTjenester { get; } = new();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(uint signatur, uint tabell, byte[]? buffer, uint lengde);

    [DllImport("advapi32.dll")]
    private static extern int RegQueryInfoKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle n, IntPtr klasse, IntPtr klasseLengde, IntPtr reservert,
        IntPtr undernokler, IntPtr maksNokkel, IntPtr maksKlasse, IntPtr verdier, IntPtr maksVerdinavn, IntPtr maksVerdi, IntPtr sikkerhet, out long sistSkrevet);

    private void Fastvare()
    {
        lock (Fastvarelinjer) { Fastvarelinjer.Clear(); EndredeTjenester.Clear(); }
        Wpbt();
        NyeTjenester();
    }

    private void Wpbt()
    {
        const uint Acpi = 0x41435049, WpbtId = 0x54425057; // 'ACPI', 'WPBT'
        uint n = GetSystemFirmwareTable(Acpi, WpbtId, null, 0);
        if (n < 52)
        {
            Tilgangslogg.Logg("Fastvare", "WPBT-tabellen (ACPI)", Utfall.Lest, "finnes ikke");
            lock (Fastvarelinjer) Fastvarelinjer.Add("Fastvare (BIOS): ingen WPBT-tabell. BIOS ber ikke Windows starte noe program.");
            return;
        }
        var b = new byte[n];
        GetSystemFirmwareTable(Acpi, WpbtId, b, n);
        var oem = Encoding.ASCII.GetString(b, 10, 6).Trim('\0', ' ');
        int argLengde = BitConverter.ToUInt16(b, 50);
        Tilgangslogg.Logg("Fastvare", "WPBT-tabellen (ACPI)", Utfall.Lest, $"finnes, fra {oem}");
        var exe = Environment.ExpandEnvironmentVariables(@"%SystemRoot%\System32\wpbbin.exe");
        var linje = new StringBuilder($"Fastvare (BIOS): WPBT-tabell fra {oem} finnes. BIOS ber Windows starte et program ved hver oppstart");
        if (argLengde > 0) linje.Append($" (med {argLengde / 2} tegn argumenter, vises ikke)");
        string? produkt = null;
        if (File.Exists(exe))
        {
            var fi = new FileInfo(exe);
            try { produkt = FileVersionInfo.GetVersionInfo(exe).ProductName; } catch { }
            linje.Append($" · {exe} · {Rapport.Storrelse(fi.Length)} · endret {Tid(fi.LastWriteTime)} · {Signatur.Utgiver(exe) ?? "ikke gyldig signert"}");
            if (!string.IsNullOrWhiteSpace(produkt)) linje.Append($" · {produkt!.Trim()}");
            if (Sha256(exe) is { } h) linje.Append($" · SHA-256 {h}");
        }
        else linje.Append($" · {exe} finnes ikke nå");
        bool av = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager")?.GetValue("DisableWpbtExecution") is int v && v != 0;
        linje.Append(av ? " · stoppet av Windows (DisableWpbtExecution)" : "");
        var regel = FinnRegel($"{produkt} {exe}");
        linje.Append(regel != null ? $" · AI-regel traff: {regel.Navn}." : " · ingen AI-regel traff.");
        lock (Fastvarelinjer) Fastvarelinjer.Add(linje.ToString());
        if (regel != null)
        {
            var f = FraRegel(regel, "Starter med Windows", $"Startes av BIOS (WPBT fra {oem}): {exe}");
            f.Sterkt();
        }
    }

    private void NyeTjenester()
    {
        var grense = DateTime.Now.AddDays(-7);
        var firma = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var ai = new List<string>();
        int antall = 0;
        using var rot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (rot == null) return;
        foreach (var navn in rot.GetSubKeyNames())
        {
            try
            {
                using var k = rot.OpenSubKey(navn);
                if (k == null || RegQueryInfoKey(k.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var ft) != 0) continue;
                if (DateTime.FromFileTimeUtc(ft).ToLocalTime() < grense) continue;
                var bilde = k.GetValue("ImagePath") as string;
                if (string.IsNullOrEmpty(bilde)) continue;
                antall++;
                var sti = Programsti(bilde!);
                string? selskap = null, produkt = null;
                if (sti != null && File.Exists(sti))
                    try { var vi = FileVersionInfo.GetVersionInfo(sti); selskap = vi.CompanyName?.Trim(); produkt = vi.ProductName; } catch { }
                var kort = string.IsNullOrEmpty(selskap) ? "ukjent firma" : Firma(selskap!);
                firma[kort] = firma.TryGetValue(kort, out var c) ? c + 1 : 1;
                lock (Fastvarelinjer) EndredeTjenester.Add($"{DateTime.FromFileTimeUtc(ft).ToLocalTime():yyyy-MM-dd HH:mm} · {navn} · {kort} · {sti ?? "programsti ukjent"}");
                if (FinnRegel($"{navn} {k.GetValue("DisplayName")} {produkt} {sti}") is { } r) ai.Add($"{navn} ({r.Navn})");
            }
            catch { }
        }
        Tilgangslogg.Logg("Register", @"HKLM\SYSTEM\CurrentControlSet\Services", Utfall.Lest, $"{antall} tjenester og drivere endret siste 7 dager");
        lock (Fastvarelinjer) Fastvarelinjer.Add(antall == 0
            ? "Tjenester og drivere endret siste 7 dager: ingen."
            : $"Tjenester og drivere endret siste 7 dager: {antall} ({string.Join(", ", firma.OrderByDescending(x => x.Value).Take(6).Select(x => $"{x.Key} {x.Value}"))}). "
              + (ai.Count == 0 ? "Ingen AI-regel traff." : $"AI-regel traff: {string.Join(", ", ai.Take(6))}."));
    }

    private static string? Programsti(string bilde)
    {
        var s = Environment.ExpandEnvironmentVariables(bilde.Trim());
        if (s.StartsWith("\"")) { int slutt = s.IndexOf('"', 1); return slutt > 1 ? s.Substring(1, slutt - 1) : null; }
        if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) s = Environment.ExpandEnvironmentVariables("%SystemRoot%") + s.Substring(11);
        else if (s.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase)) s = Path.Combine(Environment.ExpandEnvironmentVariables("%SystemRoot%"), s);
        else if (s.StartsWith(@"\??\")) s = s.Substring(4);
        int ext = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (ext < 0) ext = s.IndexOf(".sys", StringComparison.OrdinalIgnoreCase);
        return ext > 0 ? s.Substring(0, ext + 4) : null;
    }
}
