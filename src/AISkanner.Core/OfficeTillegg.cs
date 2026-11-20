using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace AISkanner;

/// <summary>
/// Tillegg i Word, Excel, Outlook og PowerPoint med AI: COM-tillegg i registeret og nettbaserte tillegg (Office-
/// tillegg fra butikken eller IT) i Wef-mappa. Bare navn, beskrivelse og om tillegget lastes. Dokumenter røres aldri.
/// </summary>
public sealed partial class Skanner
{
    private static readonly Regex OfficeAiOrd = new(@"\b(ai|gpt\w*|\w*gpt|llm|chatbot|copilot|openai|anthropic|claude|gemini)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] OfficeApper = { "Word", "Excel", "Outlook", "PowerPoint", "OneNote", "MS Project", "Visio" };

    private readonly SortedSet<string> _vbom = new();

    /// <summary>AccessVBOM på + AI-agent på PC-en: agenten kan styre Office gjennom makroer. Advarsel på agentfunnene.</summary>
    internal void Vbom()
    {
        string[] apper;
        lock (_vbom) apper = _vbom.ToArray();
        if (apper.Length == 0) return;
        List<Funn> agenter;
        lock (_funn) agenter = _funn.Values.Where(f => f.Kategori == "Skygge-AI (agent)" || f.Advarsler.Any(a => a.StartsWith("Personlig agent"))).ToList();
        foreach (var f in agenter)
            f.Advarsel($"Office lar andre programmer skrive og kjøre makroer ({string.Join(", ", apper)}: AccessVBOM). Agenten kan styre Word, Excel og Outlook den veien.");
    }

    private void OfficeTillegg()
    {
        if (!Plattform.ErWindows) return;
        foreach (var (rot, rotNavn) in new[] { (Bruker.Hkcu, "HKCU"), (Registry.LocalMachine, "HKLM") })
            foreach (var bit in new[] { "", @"WOW6432Node\" })
                foreach (var app in OfficeApper)
                {
                    var sti = $@"SOFTWARE\{bit}Microsoft\Office\{app}\Addins";
                    using var k = Tilgangslogg.Nokkel(rot, sti);
                    if (k == null) continue;
                    foreach (var id in k.GetSubKeyNames())
                    {
                        using var t = k.OpenSubKey(id);
                        var navn = t?.GetValue("FriendlyName") as string ?? id;
                        var besk = t?.GetValue("Description") as string;
                        int last = t?.GetValue("LoadBehavior") is int l ? l : -1;
                        VurderOfficeTillegg(app, navn, besk, id, $@"{rotNavn}\{sti}\{id}", last >= 0 ? ((last & 1) != 0 ? "lastes når Office starter" : "lastes ikke nå") : null);
                    }
                }
        // G3: «Stol på tilgang til VBA-prosjektmodellen» (AccessVBOM = 1): andre programmer kan skrive og kjøre makroer i Office.
        // Bare verdien leses. Blir en advarsel på AI-agenter som finnes (Vbom), aldri et eget funn. Kilde: learn.microsoft.com (AccessVBOM)
        foreach (var (rot, rotNavn) in new[] { (Bruker.Hkcu, "HKCU"), (Registry.LocalMachine, "HKLM") })
            foreach (var del in new[] { "", @"Policies\" })
                foreach (var app in new[] { "Word", "Excel", "PowerPoint", "Outlook" })
                {
                    using var k = Tilgangslogg.Nokkel(rot, $@"SOFTWARE\{del}Microsoft\Office\16.0\{app}\Security");
                    if (k?.GetValue("AccessVBOM") is int v && v == 1) lock (_vbom) _vbom.Add($"{app} ({rotNavn})");
                }
        // Nettbaserte tillegg: manifestene Office har hentet ned (DisplayName og Description i XML)
        var wef = Utvid(@"%LOCALAPPDATA%\Microsoft\Office\16.0\Wef");
        if (Directory.Exists(wef))
            foreach (var fil in Plattform.Filer(wef, "*", 6).Where(f => f.Length < 512 * 1024 && (f.Extension.Length == 0 || f.Extension.Equals(".xml", StringComparison.OrdinalIgnoreCase))).Take(500))
            {
                string tekst;
                try { tekst = File.ReadAllText(fil.FullName); Tilgangslogg.Tell("Fil", Utfall.Lest, sted: fil.FullName, detalj: "Office-tillegg: bare navn og beskrivelse"); }
                catch (Exception e) { Tilgangslogg.Feil("Fil", fil.FullName, e); continue; }
                if (tekst.IndexOf("<OfficeApp", StringComparison.Ordinal) < 0) continue;
                string? Felt(string n) => Regex.Match(tekst, $@"<{n}\s+DefaultValue=""([^""]{{1,200}})""") is { Success: true } m ? m.Groups[1].Value : null;
                var navn = Felt("DisplayName");
                if (navn != null) VurderOfficeTillegg("Office", navn, Felt("Description"), Path.GetFileName(fil.FullName), fil.FullName, "nettbasert tillegg");
            }
    }

    internal void VurderOfficeTillegg(string app, string navn, string? beskrivelse, string id, string hvorFra, string? status)
    {
        var r = FinnRegel($"{navn} {id}") ?? FinnRegel($"{navn} {beskrivelse}", utvidelse: true);
        // Strengere enn for nettleserutvidelser: «assistant» og «summary» er vanlige ord i Office-tillegg
        bool ukjentAi = r == null && OfficeAiOrd.IsMatch($"{navn} {beskrivelse}");
        if (r == null && !ukjentAi) return;
        var visning = $"{Kutt(navn, 40)} (tillegg i {app})";
        var f = r != null
            ? LeggTil(visning, r.Kategori, RisikoTekst.Fra(r.Risiko), r.HvorforEnkelt ?? r.Hvorfor, $"Office-tillegg i {app}", $"{app}: {hvorFra}", r, r.Enkelt)
            : LeggTil(visning, SporKategori, Risiko.Rod, "Ukjent AI-tillegg i Office. Det kan lese dokumentene og e-posten du har åpne. Vi vet ikke hvem som lager det.",
                $"Office-tillegg i {app}", $"{app}: {hvorFra}");
        if (status != null) f.Detalj($"{app}: {status}");
        f.Merk(Tilstand.SattOpp);
        if (r != null) f.Sterkt(); else f.Svakt();
    }
}
