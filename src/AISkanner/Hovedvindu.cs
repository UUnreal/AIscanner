using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace AISkanner.App;

/// <summary>
/// Vinduet. Skjermbildene er HTML (ui/index.html) vist i WebView2, så designet kan se ut som en iPhone-app.
/// Siden er bygd inn i programmet, laster ingenting fra nett og kan ikke navigere bort.
/// </summary>
public sealed class Hovedvindu : Form
{
    private readonly WebView2 _web = new() { Dock = DockStyle.Fill };
    private readonly Regelsett _regler = Regelsett.Last();
    private List<Funn> _resultat = new();
    private Skanner? _skanner;
    private bool _soker;
    private CancellationTokenSource? _nvdStopp;
    private readonly string[] _args;

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <param name="args">--sok: startet på nytt som administrator for å måle datamengde, så søk med en gang.</param>
    public Hovedvindu(string[] args)
    {
        _args = args;
        Text = "AI-skanner";
        ClientSize = new Size(980, 760);
        MinimumSize = new Size(560, 600);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(242, 242, 247);
        _web.DefaultBackgroundColor = BackColor;
        Controls.Add(_web);
        Load += async (_, _) => await StartAsync();
    }

    private async Task StartAsync()
    {
        try
        {
            // WebView2 må ha en mappe mens vinduet er åpent. Den er ny for hver kjøring og slettes når programmet lukkes,
            // så programmet lagrer ingenting mellom søk.
            RyddVindusdata(alle: true);
            var data = Path.Combine(Rot, $"Vindu-{System.Diagnostics.Process.GetCurrentProcess().Id}");
            var miljo = await CoreWebView2Environment.CreateAsync(null, data);
            await _web.EnsureCoreWebView2Async(miljo);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            MessageBox.Show(this,
                "Denne PC-en mangler Microsoft Edge WebView2, som AI-skanneren trenger for å vise vinduet.\n\n" +
                "Last den ned gratis fra Microsoft: https://developer.microsoft.com/microsoft-edge/webview2/",
                "AI-skanner", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Close();
            return;
        }

        var w = _web.CoreWebView2;
        w.Settings.AreDevToolsEnabled = false;
        w.Settings.AreDefaultContextMenusEnabled = false;
        w.Settings.AreDefaultScriptDialogsEnabled = false;
        w.Settings.AreBrowserAcceleratorKeysEnabled = false;
        w.Settings.IsStatusBarEnabled = false;
        w.Settings.IsZoomControlEnabled = false;
        w.Settings.IsPasswordAutosaveEnabled = false;
        w.Settings.IsGeneralAutofillEnabled = false;
        // Siden får aldri forlate seg selv eller åpne nye vinduer
        bool forste = true;
        w.NavigationStarting += (_, e) => { if (!forste) e.Cancel = true; forste = false; };
        w.NewWindowRequested += (_, e) => e.Handled = true;
        w.WebMessageReceived += async (_, e) => await MottaAsync(e.WebMessageAsJson);
        // Siden får vite om vi kjører som administrator, så startknappene viser riktig valg
        w.NavigationCompleted += (_, _) =>
        {
            Send(new { type = "modus", admin = Nettverk.ErAdmin() });
            if (_args.Contains("--sok")) Send(new { type = "start" });
        };

        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.ui.index.html")!;
        using var r = new StreamReader(s, Encoding.UTF8);
        w.NavigateToString(await r.ReadToEndAsync());
    }

    private static readonly string Rot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AISkanner");

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        base.OnFormClosed(e);
        _web.Dispose();
        // Nettleserdelen bruker et øyeblikk på å avslutte. Prøv i opptil 3 sekunder.
        for (int i = 0; i < 15 && !RyddVindusdata(alle: false); i++) Thread.Sleep(200);
    }

    /// <summary>Sletter vindusdata. alle: også rester etter tidligere kjøringer som ble avbrutt. Returnerer true når alt er borte.</summary>
    private static bool RyddVindusdata(bool alle)
    {
        try
        {
            if (!Directory.Exists(Rot)) return true;
            var egen = $"Vindu-{System.Diagnostics.Process.GetCurrentProcess().Id}";
            foreach (var d in Directory.GetDirectories(Rot))
            {
                var navn = Path.GetFileName(d);
                if (!alle && navn != egen) continue;
                if (alle && navn == egen) continue;
                if (navn.StartsWith("Vindu-") || navn.StartsWith("WebView2"))
                    try { Directory.Delete(d, true); } catch { }
            }
            if (Directory.GetFileSystemEntries(Rot).Length == 0) Directory.Delete(Rot);
            return !Directory.Exists(Path.Combine(Rot, egen));
        }
        catch { return false; }
    }

    private void Send(object melding) => _web.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(melding, Json));

    private async Task MottaAsync(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var m = doc.RootElement;
        var type = m.TryGetProperty("type", out var t) ? t.GetString() : null;
        if (type == "sok" && !_soker)
        {
            // Historikk og sikkerhetshull er alltid med. Bare IT kan slå dem av med --uten-historikk / --uten-nvd.
            await SokAsync(!_args.Contains("--uten-nvd"), !_args.Contains("--uten-historikk"));
        }
        else if (type == "lagre") Lagre();
        else if (type == "admin" && !_soker)
        {
            // Allerede administrator: søk med en gang. Ellers starter programmet på nytt via Windows sin godkjenning (UAC).
            if (Nettverk.ErAdmin()) await SokAsync(!_args.Contains("--uten-nvd"), !_args.Contains("--uten-historikk"));
            else StartSomAdmin(!_args.Contains("--uten-nvd"), !_args.Contains("--uten-historikk"));
        }
        else if (type == "vis" && m.TryGetProperty("sti", out var sti)) VisIUtforsker(sti.GetString());
    }

    private async Task SokAsync(bool nvd, bool historikk)
    {
        _soker = true;
        _nvdStopp?.Cancel();
        try
        {
            var klokke = System.Diagnostics.Stopwatch.StartNew();
            _skanner = new Skanner(_regler, historikk);
            // Sikkerhetshull slås opp etter at resultatet vises, så søket ikke venter på nettet
            _resultat = await Task.Run(() => _skanner.KjorAsync(false));
            var farlige = new HashSet<string>(_regler.HoyrisikoLand, StringComparer.OrdinalIgnoreCase);
            long sendt = _resultat.SelectMany(f => f.Trafikk).Sum(m => m.Ut ?? 0);
            Send(new
            {
                type = "resultat",
                info = new
                {
                    sekunder = klokke.Elapsed.TotalSeconds,
                    dataMalt = _skanner.DataMalt,
                    maleSekunder = _skanner.MaleSekunder,
                    sendtTekst = Rapport.Storrelse(sendt),
                    nvd = nvd ? "sjekker" : "av",
                    admin = Nettverk.ErAdmin(),
                    telling = Oversikt.Telling(_resultat) is var t ? new { modeller = t.Modeller, nettsteder = t.Nettsteder, utvidelser = t.Utvidelser, apper = t.Apper } : null,
                },
                funn = _resultat.Select(f => new
                {
                    risiko = f.Risiko.ToString().ToLowerInvariant(),
                    gruppe = f.Gruppe,
                    forst = f.Forst != null && f.Sist != null && f.Forst.Value.Date != f.Sist.Value.Date ? Skanner.Tid(f.Forst) : null,
                    sist = f.Sist == null ? null : (DateTime.Now - f.Sist.Value).TotalMinutes < 2 ? "nå" : Skanner.Tid(f.Sist),
                    navn = f.Navn,
                    kortnavn = Oversikt.Navn(f),
                    punkt = Oversikt.Punkt(f),
                    lokasjon = Oversikt.Lokasjon(f),
                    type = f.Type,
                    grunn = f.RisikoGrunn,
                    kommerFra = f.OpprinnelseLand == null ? null : IpLand.Navn(f.OpprinnelseLand),
                    selskap = f.Opprinnelse,
                    kommerFraFarlig = f.OpprinnelseLand != null && farlige.Contains(f.OpprinnelseLand),
                    senderTil = Risikoregler.SenderTil(f).Select(k => new { land = IpLand.Navn(k), kode = k, farlig = farlige.Contains(k) }),
                    ingenLand = Risikoregler.IngenLand(f),
                    kort = f.Kort,
                    merk = f.Advarsler.Skip(1).Concat(f.Merknader).ToList(),
                    steder = f.Detaljer,
                    trafikk = f.Trafikk.Select(m => new
                    {
                        adresse = m.Adresse,
                        tjeneste = m.Tjeneste,
                        landKode = m.Land,
                        ip = m.Ip,
                        tilLand = m.Land == "LAN" ? null : IpLand.Navn(m.EierLand ?? (m.Land == "CDN" ? null : m.Land)),
                        land = m.Land == "CDN" ? (m.EierLand != null ? $"Cloudflare · {IpLand.Navn(m.EierLand)}" : "Cloudflare") : IpLand.Navn(m.Land),
                        farlig = (m.Land != null && farlige.Contains(m.Land)) || (m.EierLand != null && farlige.Contains(m.EierLand)),
                        antall = m.Antall,
                        data = m.Ut == null ? null : $"↑ {Rapport.Storrelse(m.Ut.Value)}  ↓ {Rapport.Storrelse(m.Inn ?? 0)}",
                    }),
                }),
            });
        }
        catch (Exception e)
        {
            Send(new { type = "feil", tekst = "Søket stoppet: " + e.Message });
            return;
        }
        finally { _soker = false; }
        if (!nvd) return;
        // Et nytt søk stopper oppslagene fra forrige
        var stopp = _nvdStopp = new CancellationTokenSource();
        try
        {
            await Nvd.SjekkAsync(_resultat, null, stopp.Token,
                f => Send(new { type = "nvd", navn = f.Navn, merk = f.Advarsler.Skip(1).Concat(f.Merknader).ToList() }));
            Send(new { type = "nvdFerdig" });
        }
        catch { }
    }

    /// <summary>Åpner Utforsker med fila eller mappa markert. Bare stier som faktisk står i et funn godtas.</summary>
    private void VisIUtforsker(string? sti)
    {
        if (string.IsNullOrWhiteSpace(sti) || !_resultat.Any(f => f.Detaljer.Any(d => d.Contains(sti!)))) return;
        sti = sti!.Trim();
        if (!File.Exists(sti) && !Directory.Exists(sti)) sti = Path.GetDirectoryName(sti);
        if (sti == null || (!File.Exists(sti) && !Directory.Exists(sti))) return;
        // Full sti til Windows' egen Utforsker, så en falsk explorer.exe i programmappa eller arbeidsmappa ikke kan kjøres i stedet.
        var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        if (!File.Exists(explorer)) return;
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(explorer, $"/select,\"{sti}\"") { UseShellExecute = false });
    }

    /// <summary>
    /// Datamengde kan bare måles av administrator. Starter programmet på nytt med Windows' vanlige spørsmål om tillatelse (UAC).
    /// </summary>
    private void StartSomAdmin(bool nvd, bool historikk)
    {
        if (Nettverk.ErAdmin() || _soker) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Application.ExecutablePath, "--sok" + (nvd ? "" : " --uten-nvd") + (historikk ? "" : " --uten-historikk"))
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            Close();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // Brukeren sa nei i Windows sin godkjenning
            Send(new { type = "feil", tekst = "Admin ble ikke godkjent. Søk som bruker, eller prøv igjen." });
        }
    }

    private void Lagre()
    {
        using var dlg = new SaveFileDialog
        {
            Filter = "Rapport (*.txt)|*.txt|Data for IT (*.json)|*.json",
            // Tidsstempel med sekunder, så hver rapport får et eget navn
            FileName = $"AI-rapport_{Environment.MachineName}_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            OverwritePrompt = false,
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var innhold = dlg.FilterIndex == 2 ? Rapport.Json(_resultat, _skanner) : Rapport.Tekst(_resultat, _skanner);
        // Skriver aldri over en rapport som finnes: legg til (2), (3) ...
        var sti = dlg.FileName;
        for (int n = 2; File.Exists(sti); n++)
            sti = Path.Combine(Path.GetDirectoryName(dlg.FileName)!, $"{Path.GetFileNameWithoutExtension(dlg.FileName)} ({n}){Path.GetExtension(dlg.FileName)}");
        using var fs = new FileStream(sti, FileMode.CreateNew, FileAccess.Write);
        using var w = new StreamWriter(fs, new UTF8Encoding(true));
        w.Write(innhold);
    }
}
