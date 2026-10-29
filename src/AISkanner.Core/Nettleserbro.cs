using System.Text.Json;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Broer mellom nettleseren og PC-en (Native Messaging): et program på PC-en som en utvidelse kan snakke med.
/// Og utvidelser som IT tvinger inn (ExtensionInstallForcelist). Leser bare registeret og vertens manifest.
/// </summary>
public sealed partial class Skanner
{
    private static readonly (string Nettleser, string Nokkel)[] Broer =
    {
        ("Chrome", @"SOFTWARE\Google\Chrome\NativeMessagingHosts"),
        ("Edge", @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts"),
        ("Brave", @"SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts"),
        ("Chromium", @"SOFTWARE\Chromium\NativeMessagingHosts"),
        ("Firefox", @"SOFTWARE\Mozilla\NativeMessagingHosts"),
    };

    private void NettleserBroer()
    {
        if (!Plattform.ErWindows) return;
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (rot, rotNavn) in new[] { (Bruker.Hkcu, "HKCU"), (Registry.LocalMachine, "HKLM") })
            foreach (var (nettleser, sti) in Broer)
            {
                using var k = Tilgangslogg.Nokkel(rot, sti);
                if (k == null) continue;
                foreach (var vert in k.GetSubKeyNames())
                {
                    using var v = k.OpenSubKey(vert);
                    var manifest = v?.GetValue(null) as string;
                    if (string.IsNullOrEmpty(manifest) || !sett.Add($"{nettleser}|{vert}")) continue;
                    VurderBro(nettleser, $@"{rotNavn}\{sti}\{vert}", vert, Environment.ExpandEnvironmentVariables(manifest!));
                }
            }
    }

    internal void VurderBro(string nettleser, string nokkel, string vert, string manifest)
    {
        string? program = null, beskrivelse = null;
        var opphav = new List<string>();
        using (var doc = LesJson(manifest, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Path.GetFileName(manifest) }))
            if (doc?.RootElement is { ValueKind: JsonValueKind.Object } m)
            {
                program = Str(m, "path");
                beskrivelse = Str(m, "description");
                opphav.AddRange(Liste(m, "allowed_origins").Concat(Liste(m, "allowed_extensions"))
                    .Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!));
            }
        if (program != null && !Path.IsPathRooted(program)) program = Path.Combine(Path.GetDirectoryName(manifest) ?? "", program);
        var r = FinnRegel($"{vert} {beskrivelse} {program}") ?? FinnRegel($"{vert} {beskrivelse}", utvidelse: true);
        var tekst = $" {vert} {beskrivelse} ".ToLowerInvariant().Replace('_', ' ').Replace('.', ' ');
        bool ukjentAi = r == null && _regler.UkjentUtvidelseOrd.Any(tekst.Contains);
        if (r == null && !ukjentAi) return;
        var navn = r != null ? $"{r.Navn}: bro fra {nettleser}" : $"Ukjent AI-bro fra {nettleser}";
        var detalj = $"{nettleser}: {vert} → {program ?? "(fant ikke programmet i manifestet)"}";
        var f = r != null
            ? LeggTil(navn, r.Kategori, RisikoTekst.Fra(r.Risiko), r.HvorforEnkelt ?? r.Hvorfor, $"Nettleserbro i {nettleser}", detalj, r, r.Enkelt)
            : LeggTil(navn, SporKategori, Risiko.Rod, "Et program på PC-en som nettleserutvidelser kan snakke med, og som har AI i navnet. Vi vet ikke hvem som lager det.",
                $"Nettleserbro i {nettleser}", detalj);
        f.Detalj($"Registernøkkel: {nokkel}");
        f.Detalj($"Manifest: {manifest}");
        if (opphav.Count > 0) f.Detalj($"Utvidelser som kan bruke broen: {string.Join(", ", opphav.Take(5))}{(opphav.Count > 5 ? $" (+{opphav.Count - 5})" : "")}");
        f.Merknad("En nettleserutvidelse kan starte dette programmet på PC-en og sende data begge veier.");
        f.Merk(Tilstand.SattOpp);
        f.Sterkt();
    }

    private HashSet<string>? _tvungne;

    /// <summary>Utvidelser IT tvinger inn med ExtensionInstallForcelist (Chrome, Edge, Brave). Bare ID-ene.</summary>
    private HashSet<string> TvungneUtvidelser()
    {
        if (_tvungne != null) return _tvungne;
        var sett = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (Plattform.ErWindows)
            foreach (var rot in new[] { Registry.LocalMachine, Bruker.Hkcu })
                foreach (var sti in new[] { @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist", @"SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist" })
                {
                    using var k = Tilgangslogg.Nokkel(rot, sti);
                    if (k == null) continue;
                    foreach (var n in k.GetValueNames())
                        if (k.GetValue(n) is string s && s.Split(';')[0].Trim() is { Length: 32 } id) sett.Add(id);
                }
        return _tvungne = sett;
    }
}

public sealed partial class Skanner
{
    private System.Text.RegularExpressions.Regex? _aiApiRegex;

    /// <summary>
    /// Adresser til AI-tjenester (API-ene i regelfila) i utvidelsens egen JavaScript. Viser at utvidelsen er laget for å
    /// snakke med AI-tjenesten, ikke at den har sendt noe. Maks 200 filer og 4 MB per utvidelse (12 MB i fullt søk); teksten beholdes aldri.
    /// </summary>
    internal void UtvidelseAiAdresser(string hvor, string? navn, string mappe)
    {
        if (string.IsNullOrWhiteSpace(navn) || !Directory.Exists(mappe)) return;
        _aiApiRegex ??= new System.Text.RegularExpressions.Regex(
            @"(?<![\w.-])(" + string.Join("|", _regler.AiTjenester.SelectMany(t => t.Domener).Where(d => d.Contains('.')).Distinct().OrderByDescending(d => d.Length).Select(System.Text.RegularExpressions.Regex.Escape)) + @")(?![\w-])",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
        var treff = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        long lest = 0;
        foreach (var fil in Plattform.Filer(mappe, "*.js", 6).Take(200))
        {
            if (fil.Length > 2 * 1024 * 1024 || lest > (Fullt ? 12 : 4) * 1024 * 1024) continue;
            try
            {
                var tekst = File.ReadAllText(fil.FullName);
                lest += fil.Length;
                foreach (System.Text.RegularExpressions.Match m in _aiApiRegex.Matches(tekst)) treff.Add(m.Value.ToLowerInvariant());
            }
            catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); }
        }
        if (lest > 0) Tilgangslogg.Tell("Fil", Utfall.Lest, sted: mappe, detalj: "utvidelsens JavaScript: bare adresser til AI-tjenester");
        if (treff.Count == 0) return;
        var tjenester = treff.Select(v => (Vert: v, Tj: Tjeneste(v))).ToList();
        var nettleser = hvor.Split(' ')[0];
        var visning = $"{Kutt(navn!, 40)} ({nettleser}-utvidelse)";
        Funn f;
        lock (_funn) _funn.TryGetValue(visning, out f!);
        if (f == null)
        {
            // Ukjent AI er rødt (skygge-AI) til IT har godkjent den
            f = LeggTil(visning, "Nettleser-AI", Risiko.Rod,
                "Utvidelsen er laget for å snakke med AI-tjenester: adressene står i koden. Vi vet ikke hva den sender.",
                $"Utvidelse i {hvor}", $"{hvor}: {mappe}", enkelt: "Utvidelse med AI-adresser");
            f.Svakt();
        }
        else f.Sterkt();
        f.Detalj($"Koden nevner: {string.Join(", ", tjenester.Take(8).Select(t => t.Tj != null ? $"{t.Vert} ({t.Tj.Navn}{(t.Tj.Land != null ? ", " + IpLand.Navn(t.Tj.Land) : "")})" : t.Vert))}");
        f.Merk(Tilstand.SattOpp);
    }
}
