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
    // Språk: følger Windows til brukeren trykker på et flagg. Lagres ikke mellom kjøringer.
    private bool _engelsk = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName is not ("nb" or "nn" or "no");
    private bool _vist;
    private double _sekunder;
    private string _nvdStatus = "av";
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
            Send(new { type = "modus", admin = Nettverk.ErAdmin(), sprak = _engelsk ? "en" : "no" });
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
        else if (type == "sprak" && m.TryGetProperty("sprak", out var sp))
        {
            // Bytter språk uten nytt søk: samme funn sendes på nytt, oversatt
            _engelsk = sp.GetString() == "en";
            if (_vist && !_soker) SendResultat(behold: true);
        }
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
            _sekunder = klokke.Elapsed.TotalSeconds;
            _nvdStatus = nvd ? "sjekker" : "av";
            _vist = true;
            SendResultat(behold: false);
        }
        catch (Exception e)
        {
            Send(new { type = "feil", tekst = (_engelsk ? "The scan stopped: " : "Søket stoppet: ") + e.Message });
            return;
        }
        finally { _soker = false; }
        if (!nvd) return;
        // Et nytt søk stopper oppslagene fra forrige
        var stopp = _nvdStopp = new CancellationTokenSource();
        try
        {
            await Nvd.SjekkAsync(_resultat, null, stopp.Token,
                f => Send(new { type = "nvd", id = _resultat.IndexOf(f), merk = f.Advarsler.Skip(1).Concat(f.Merknader).Select(x => _engelsk ? Engelsk.Til(x) : x).ToList() }));
            _nvdStatus = "ferdig";
            Send(new { type = "nvdFerdig" });
        }
        catch { }
    }

    /// <summary>Sender funnene til vinduet på valgt språk. Brukes etter søket og når brukeren bytter språk.</summary>
    private void SendResultat(bool behold)
    {
        string? T(string? s) => _engelsk ? Engelsk.Til(s) : s;
        var farlige = new HashSet<string>(_regler.HoyrisikoLand, StringComparer.OrdinalIgnoreCase);
        long sendt = _resultat.SelectMany(f => f.Trafikk).Sum(m => m.Ut ?? 0);
        Send(new
        {
            type = "resultat",
            behold,
            info = new
            {
                sekunder = _sekunder,
                dataMalt = _skanner.DataMalt,
                maleSekunder = _skanner.MaleSekunder,
                sendtTekst = T(Rapport.Storrelse(sendt)),
                nvd = _nvdStatus,
                admin = Nettverk.ErAdmin(),
                telling = Oversikt.Telling(_resultat) is var t ? new { modeller = t.Modeller, nettsteder = t.Nettsteder, utvidelser = t.Utvidelser, apper = t.Apper } : null,
            },
            funn = _resultat.Select((f, id) => new
            {
                id,
                risiko = f.Risiko.ToString().ToLowerInvariant(),
                gruppe = f.Gruppe,
                forst = f.Forst != null && f.Sist != null && f.Forst.Value.Date != f.Sist.Value.Date ? T(Skanner.Tid(f.Forst)) : null,
                sist = f.Sist == null ? null : (DateTime.Now - f.Sist.Value).TotalMinutes < 2 ? T("nå") : T(Skanner.Tid(f.Sist)),
                naa = f.Sist != null && (DateTime.Now - f.Sist.Value).TotalMinutes < 2,
                navn = T(f.Navn),
                kortnavn = T(Oversikt.Navn(f)),
                punkt = T(Oversikt.Punkt(f)),
                lokasjon = T(Oversikt.Lokasjon(f)),
                type = T(f.Type),
                grunn = T(f.RisikoGrunn),
                kommerFra = f.OpprinnelseLand == null ? null : T(IpLand.Navn(f.OpprinnelseLand)),
                selskap = T(f.Opprinnelse),
                kommerFraFarlig = f.OpprinnelseLand != null && farlige.Contains(f.OpprinnelseLand),
                senderTil = Risikoregler.SenderTil(f).Select(k => new { land = T(IpLand.Navn(k)), kode = k, farlig = farlige.Contains(k) }),
                ingenLand = T(Risikoregler.IngenLand(f)),
                lokalt = Risikoregler.IngenLand(f).StartsWith("Ingen", StringComparison.Ordinal),
                kort = T(f.Kort),
                merk = f.Advarsler.Skip(1).Concat(f.Merknader).Select(T).ToList(),
                steder = f.Detaljer.Select(T).ToList(),
                trafikk = f.Trafikk.Select(m => new
                {
                    adresse = m.Adresse,
                    tjeneste = T(m.Tjeneste),
                    landKode = m.Land,
                    cdn = m.Cdn,
                    ip = m.Ip.Select(x => new { ip = x.Ip, kode = x.Land, cdn = x.Cdn, land = T(x.Cdn != null ? $"skjult bak {x.Cdn}" : IpLand.Navn(x.Land)), farlig = x.Land != null && farlige.Contains(x.Land) }),
                    tilLand = m.Land == "LAN" ? null : T(IpLand.Navn(m.EierLand ?? (m.Land == "CDN" ? null : m.Land))),
                    land = T(m.Land == "CDN" ? $"Skjult bak {m.Cdn ?? "CDN"}" : IpLand.Navn(m.Land)),
                    farlig = (m.Land != null && farlige.Contains(m.Land)) || (m.EierLand != null && farlige.Contains(m.EierLand)),
                    antall = m.Antall,
                    data = m.Ut == null ? null : T($"↑ {Rapport.Storrelse(m.Ut.Value)}  ↓ {Rapport.Storrelse(m.Inn ?? 0)}"),
                }),
            }),
        });
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
            Send(new { type = "feil", tekst = _engelsk ? "Admin was not approved. Scan as user, or try again." : "Admin ble ikke godkjent. Søk som bruker, eller prøv igjen." });
        }
    }

    private void Lagre()
    {
        using var dlg = new SaveFileDialog
        {
            Filter = _engelsk ? "Report (*.txt)|*.txt|Data for IT (*.json)|*.json" : "Rapport (*.txt)|*.txt|Data for IT (*.json)|*.json",
            // Tidsstempel med sekunder, så hver rapport får et eget navn
            FileName = $"{(_engelsk ? "AI-report" : "AI-rapport")}_{Environment.MachineName}_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            OverwritePrompt = false,
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var innhold = dlg.FilterIndex == 2 ? (_engelsk ? Engelsk.Json(Rapport.Json(_resultat, _skanner)) : Rapport.Json(_resultat, _skanner)) : Rapport.Tekst(_resultat, _skanner, _engelsk);
        // Skriver aldri over en rapport som finnes: legg til (2), (3) ...
        var sti = dlg.FileName;
        for (int n = 2; File.Exists(sti); n++)
            sti = Path.Combine(Path.GetDirectoryName(dlg.FileName)!, $"{Path.GetFileNameWithoutExtension(dlg.FileName)} ({n}){Path.GetExtension(dlg.FileName)}");
        using var fs = new FileStream(sti, FileMode.CreateNew, FileAccess.Write);
        using var w = new StreamWriter(fs, new UTF8Encoding(true));
        w.Write(innhold);
    }
}
