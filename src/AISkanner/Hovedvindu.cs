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
    // Reglene lastes i bakgrunnen mens vinduet og WebView2 starter, så de ikke forsinker oppstarten
    private readonly Task<Regelsett> _reglerLast = Task.Run(() => Regelsett.Last());
    private Regelsett _regler => _reglerLast.GetAwaiter().GetResult();
    private List<Funn> _resultat = new();
    private Skanner? _skanner;
    private bool _soker;
    private CancellationTokenSource? _lyttStopp;
    private int _revisjonAntall;
    private CancellationTokenSource? _nvdStopp;
    // Språk: følger Windows til brukeren trykker på et flagg. Lagres ikke mellom kjøringer.
    private bool _engelsk = System.Globalization.CultureInfo.CurrentUICulture.TwoLetterISOLanguageName is not ("nb" or "nn" or "no");
    // Revisjonslogg: av til brukeren velger Ja på startskjermen. Da skrives én ny fil per søk, aldri over en gammel.
    private bool _revisjon;
    private bool _fullt;
    private string? _revisjonSti;
    private bool _vist;
    private readonly bool _mork = MorkModus();
    private double _sekunder;
    private string _nvdStatus = "av";
    private readonly string[] _args;

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <param name="args">--sok: startet på nytt som administrator for å måle datamengde, så søk med en gang.</param>
    public Hovedvindu(string[] args)
    {
        _args = args;
        // Valgene følger med når programmet startes på nytt som administrator
        _revisjon = args.Contains("--revisjon");
        _fullt = args.Contains("--fullt");
        if (args.Contains("--en")) _engelsk = true;
        else if (args.Contains("--no")) _engelsk = false;
        Text = "AI-skanner";
        ClientSize = new Size(980, 760);
        MinimumSize = new Size(560, 600);
        StartPosition = FormStartPosition.CenterScreen;
        // Samme bakgrunn som siden (lys eller mørk etter Windows), så vinduet aldri skifter farge når det åpnes
        BackColor = _mork ? Color.FromArgb(17, 17, 19) : Color.FromArgb(242, 242, 245);
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
            // Rester etter tidligere kjøringer slettes i bakgrunnen; det kan være mange filer og skal ikke holde igjen vinduet
            _ = Task.Run(() => RyddVindusdata(alle: true));
            var data = Path.Combine(Rot, $"Vindu-{System.Diagnostics.Process.GetCurrentProcess().Id}");
            var miljo = await CoreWebView2Environment.CreateAsync(null, data);
            await _web.EnsureCoreWebView2Async(miljo);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            Vis();
            MessageBox.Show(this,
                "Denne PC-en mangler Microsoft Edge WebView2, som AI-skanneren trenger for å vise vinduet.\n\n" +
                "Last den ned gratis fra Microsoft: https://developer.microsoft.com/microsoft-edge/webview2/",
                "AI-skanner", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Close();
            return;
        }

        var w = _web.CoreWebView2;
        // Siden følger samme tema som vinduet, også om WebView2 ville valgt noe annet
        try { w.Profile.PreferredColorScheme = _mork ? CoreWebView2PreferredColorScheme.Dark : CoreWebView2PreferredColorScheme.Light; } catch { }
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
            // Fra Windows startet prosessen (også lasting av .NET) til vinduet er klart
            Program.OppstartMs ??= Program.FraStart();
            Send(new { type = "modus", admin = Nettverk.ErAdmin(), sprak = _engelsk ? "en" : "no", revisjon = _revisjon, fullt = _fullt, oppstartMs = Program.OppstartMs });
            if (_args.Contains("--sok")) Send(new { type = "start" });
        };

        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.ui.index.html")!;
        using var r = new StreamReader(s, Encoding.UTF8);
        w.NavigateToString(await r.ReadToEndAsync());
    }

    private static readonly string Rot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AISkanner");

    // Vinduet holdes usynlig (DWM-skjult) til siden er tegnet. Ellers ser man først et tomt vindu og så innholdet,
    // som ser ut som to vinduer. Skjult vindu tegnes likevel, så WebView2 starter som før.
    [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int verdi, int storrelse);
    private const int DWMWA_CLOAK = 13;
    private bool _skjult;

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        int paa = 1;
        try { _skjult = DwmSetWindowAttribute(Handle, DWMWA_CLOAK, ref paa, sizeof(int)) == 0; } catch { }
        // Mørk tittellinje når Windows er i mørk modus (Windows 10 20H1 og nyere)
        if (_mork) try { DwmSetWindowAttribute(Handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref paa, sizeof(int)); } catch { }
        // Sikkerhetsnett: vises uansett etter 3 s, så vinduet aldri blir borte
        if (_skjult) _ = Task.Delay(3000).ContinueWith(_ => { try { BeginInvoke(new Action(Vis)); } catch { } });
    }

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    private void Vis()
    {
        if (IsDisposed) return;
        if (_skjult)
        {
            _skjult = false;
            int av = 0;
            try { DwmSetWindowAttribute(Handle, DWMWA_CLOAK, ref av, sizeof(int)); } catch { }
        }
        // Innholdet tones inn først når vinduet er synlig
        try { Send(new { type = "vist" }); } catch { }
    }

    /// <summary>Windows-innstillingen «Velg appmodus: Mørk» for brukeren som er logget inn.</summary>
    private static bool MorkModus()
    {
        try
        {
            using var k = Bruker.Hkcu.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch { return false; }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _lyttStopp?.Cancel();
        StoppAlleFolg();
        StoppNettverk();
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
            // Rotmappa slettes bare ved lukking. Ved oppstart kan WebView2 holde på å lage vår egen mappe i den.
            if (!alle && Directory.GetFileSystemEntries(Rot).Length == 0) Directory.Delete(Rot);
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
        // Siden har tegnet ferdig startskjermen (riktig språk og admin-valg): vis vinduet, så toner innholdet inn
        if (type == "klar") { Vis(); return; }
        if (type is "sok" or "admin" && m.TryGetProperty("revisjon", out var rv)) _revisjon = rv.ValueKind == JsonValueKind.True;
        if (type is "sok" or "admin" && m.TryGetProperty("fullt", out var fu)) _fullt = fu.ValueKind == JsonValueKind.True;
        if (type == "sok" && !_soker)
        {
            // Historikk og sikkerhetshull er alltid med. Bare IT kan slå dem av med --uten-historikk / --uten-nvd.
            await SokAsync(!_args.Contains("--uten-nvd"), !_args.Contains("--uten-historikk"));
        }
        else if (type == "lagre") Lagre();
        else if (type == "logg" && _skanner != null && !_soker) SendLogg();
        else if (type == "admin" && !_soker)
        {
            // Allerede administrator: søk med en gang. Ellers starter programmet på nytt via Windows sin godkjenning (UAC).
            if (Nettverk.ErAdmin()) await SokAsync(!_args.Contains("--uten-nvd"), !_args.Contains("--uten-historikk"));
            else StartSomAdmin(!_args.Contains("--uten-nvd"), !_args.Contains("--uten-historikk"));
        }
        else if (type == "vis" && m.TryGetProperty("sti", out var sti)) VisIUtforsker(sti.GetString());
        else if (type == "folg" && m.TryGetProperty("id", out var fid) && fid.TryGetInt32(out var id))
        {
            if (m.TryGetProperty("pa", out var pa) && pa.ValueKind == JsonValueKind.True) StartFolg(id);
            else StoppFolg(id);
        }
        else if (type == "prosess" && m.TryGetProperty("pid", out var ppid) && ppid.TryGetInt32(out var pid)) await SendProsessAsync(pid);
        else if (type == "nettverk")
        {
            if (m.TryGetProperty("pa", out var npa) && npa.ValueKind == JsonValueKind.True) StartNettverk();
            else StoppNettverk();
        }
        else if (type == "sprak" && m.TryGetProperty("sprak", out var sp))
        {
            // Bytter språk uten nytt søk: samme funn sendes på nytt, oversatt
            _engelsk = sp.GetString() == "en";
            if (_vist && !_soker) SendResultat(behold: true);
            if (_vist && !_soker && m.TryGetProperty("logg", out var lg) && lg.ValueKind == JsonValueKind.True) SendLogg();
        }
    }

    private async Task SokAsync(bool nvd, bool historikk)
    {
        _soker = true;
        _nvdStopp?.Cancel();
        _lyttStopp?.Cancel();
        StoppAlleFolg();
        StoppNettverk();
        try
        {
            var klokke = System.Diagnostics.Stopwatch.StartNew();
            _skanner = new Skanner(_regler, historikk) { MedAgentlogger = !_args.Contains("--uten-agentlogger"), LytteSekunder = LytteSekunder(_args), LyttIBakgrunnen = true, Fullt = _fullt };
            // Sikkerhetshull slås opp etter at resultatet vises, så søket ikke venter på nettet
            _revisjonSti = null;
            // Progress<int> sender tilbake til UI-tråden; søkesirkelen viser 0–100 % fra faktisk fremdrift
            var prosent = new Progress<int>(p => Send(new { type = "prosent", p }));
            // Fullt søk tar minutter: siden får vite hvor mange mapper som er gått gjennom og hvor lang tid som er brukt
            var aktiv = _skanner;
            using var fremdrift = new System.Windows.Forms.Timer { Interval = 1000 };
            fremdrift.Tick += (_, _) => Send(new { type = "fremdrift", mapper = aktiv.MapperLest, sekunder = (int)klokke.Elapsed.TotalSeconds, fullt = aktiv.Fullt });
            fremdrift.Start();
            _resultat = await Task.Run(() => _skanner.KjorAsync(false, prosent: prosent));
            fremdrift.Stop();
            _sekunder = klokke.Elapsed.TotalSeconds;
            _nvdStatus = nvd ? "sjekker" : "av";
            _vist = true;
            // Lytter vi fortsatt på nettverket, skrives revisjonsloggen når lyttingen er ferdig, med alt som ble sett
            if (_revisjon && !_skanner.LytterNa) SkrivRevisjon(null);
            SendResultat(behold: false);
        }
        catch (Exception e)
        {
            if (_revisjon && _skanner != null) SkrivRevisjon(e.Message);
            Send(new { type = "feil", tekst = (_engelsk ? "The scan stopped: " : "Søket stoppet: ") + e.Message });
            return;
        }
        finally { _soker = false; }
        var skanner = _skanner!;
        if (skanner.LytterNa) _ = LyttFerdigAsync(skanner);
        if (!nvd) return;
        // Et nytt søk stopper oppslagene fra forrige
        var stopp = _nvdStopp = new CancellationTokenSource();
        try
        {
            await Nvd.SjekkAsync(_resultat, null, stopp.Token,
                f => Send(new { type = "nvd", id = _resultat.IndexOf(f), merk = f.Advarsler.Skip(1).Concat(f.Merknader).Select(x => _engelsk ? Engelsk.Til(x) : x).ToList() }));
            _nvdStatus = "ferdig";
            Send(new { type = "nvdFerdig" });
            // NVD-oppslagene kommer etter søket: de legges til sist i revisjonsloggen, med ny kontrollsum
            // Er loggen ikke skrevet ennå (lyttingen går fortsatt), kommer oppslagene med når den skrives.
            if (_revisjonSti is { } revisjonSti && _skanner == skanner)
            {
                var nye = skanner.Logg.Oppforinger.Skip(_revisjonAntall).ToList();
                if (nye.Count > 0)
                {
                    _revisjonAntall += nye.Count;
                    var gammel = File.ReadAllText(revisjonSti, Encoding.UTF8);
                    using var fs = new FileStream(revisjonSti, FileMode.Append, FileAccess.Write);
                    using var w = new StreamWriter(fs, new UTF8Encoding(false));
                    w.Write(Revisjon.Tillegg(gammel, nye, _engelsk));
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Resultatet er vist; lyttevinduet går videre. Vinduet får sekundene som er igjen, og så funnene på nytt med
    /// alt nettverket viste i hele vinduet. Et nytt søk stopper lyttingen fra forrige.
    /// </summary>
    private async Task LyttFerdigAsync(Skanner skanner)
    {
        var stopp = _lyttStopp = new CancellationTokenSource();
        try
        {
            var liste = await skanner.FullforLyttingAsync(new Progress<int>(s => { if (_skanner == skanner && !_soker) Send(new { type = "lytter", igjen = s }); }), stopp.Token);
            if (liste == null || _skanner != skanner || _soker) return;
            _resultat = liste;
            if (_revisjon) SkrivRevisjon(null);
            SendResultat(behold: true);
        }
        catch (OperationCanceledException) { }
        catch (Exception e)
        {
            System.Diagnostics.Debug.WriteLine($"Lytting feilet: {e.Message}");
            if (_skanner == skanner && !_soker) { if (_revisjon) SkrivRevisjon(null); SendResultat(behold: true); }
        }
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
                dataMalt = _skanner!.DataMalt,
                maleSekunder = _skanner.MaleSekunder,
                sendtTekst = T(Rapport.Storrelse(sendt)),
                nvd = _nvdStatus,
                admin = Nettverk.ErAdmin(),
                fullt = _skanner.Fullt,
                bruker = Bruker.Navn,
                kjortAv = Bruker.KjortAv,
                brukerFeil = Bruker.Feil == null ? null : T(Bruker.Feil),
                revisjon = _revisjonSti,
                revisjonFeil = _revisjon && _revisjonSti == null && !_skanner.LytterNa,
                lytter = _skanner.LytterNa,
                lytteSekunder = _skanner.LytteSekunder,
                telling = Oversikt.Telling(_resultat) is var t ? new { totalt = t.Totalt, modeller = t.Modeller, nettsteder = t.Nettsteder, utvidelser = t.Utvidelser, apper = t.Apper, innebygd = t.Innebygd, spor = t.Spor, itregler = t.ItRegler, hoy = t.Hoy, middels = t.Middels, lav = t.Lav, ukjent = t.Ukjent, modellNavn = Oversikt.ModellNavn(_resultat).Select(n => T(n)).ToList() } : null,
            },
            funn = _resultat.Select((f, id) => new
            {
                id,
                // «ukjent», «rod», «gul» eller «gronn»: samme gruppe som opptellingen øverst
                risiko = Oversikt.Risikogruppe(f),
                gruppe = f.Gruppe,
                forst = f.Forst != null && f.Sist != null && f.Forst.Value.Date != f.Sist.Value.Date ? T(Skanner.Tid(f.Forst)) : null,
                sist = f.Sist == null ? null : (DateTime.Now - f.Sist.Value).TotalMinutes < 2 ? T("nå") : T(Skanner.Tid(f.Sist)),
                naa = f.Sist != null && (DateTime.Now - f.Sist.Value).TotalMinutes < 2,
                navn = T(f.Navn),
                kortnavn = T(Oversikt.Navn(f)),
                versjon = T(f.Versjon),
                versjonKilde = T(f.VersjonKilde),
                status = T(Oversikt.Status(f)),
                tilstander = Oversikt.Tilstander(f).Select(x => T(x)).ToList(),
                treffsikkerhet = T(Oversikt.Treffsikkerhet(f)),
                spor = f.Spor,
                godkjenning = T(f.Godkjenning),
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
                folgbar = _skanner.KanFolges(f),
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
        if (string.IsNullOrWhiteSpace(sti)) return;
        if (sti != _revisjonSti && !_visbare.Contains(sti!) && !_resultat.Any(f => f.Detaljer.Any(d => d.Contains(sti!)))) return;
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
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Application.ExecutablePath, "--sok" + (nvd ? "" : " --uten-nvd") + (historikk ? "" : " --uten-historikk") + (_args.Contains("--uten-agentlogger") ? " --uten-agentlogger" : "") + (Array.IndexOf(_args, "--lytt") is var li && li >= 0 && li + 1 < _args.Length ? $" --lytt {LytteSekunder(_args)}" : "") + (_revisjon ? " --revisjon" : "") + (_fullt ? " --fullt" : "") + (_engelsk ? " --en" : " --no"))
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

    /// <summary>
    /// Skriver revisjonsloggen for søket: én ny fil med tidsstempel i Dokumenter\AI-skanner. Skriver aldri over en fil som finnes.
    /// Inneholder bare stier, navn og utfall: aldri adresser fra nettleseren, filinnhold eller verdier av nøkler.
    /// </summary>
    private void SkrivRevisjon(string? feil)
    {
        try
        {
            var mappe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "AI-skanner");
            Directory.CreateDirectory(mappe);
            var navn = $"{(_engelsk ? "AI-audit" : "AI-revisjon")}_{Environment.MachineName}_{DateTime.Now:yyyy-MM-dd_HH-mm-ss}";
            var sti = Path.Combine(mappe, navn + ".txt");
            for (int n = 2; File.Exists(sti); n++) sti = Path.Combine(mappe, $"{navn} ({n}).txt");
            _revisjonAntall = _skanner!.Logg.Oppforinger.Count;
            var tekst = Revisjon.Tekst(_resultat, _skanner!, Nettverk.ErAdmin() ? "administrator" : "bruker", _engelsk, feil);
            using var fs = new FileStream(sti, FileMode.CreateNew, FileAccess.Write);
            using var w = new StreamWriter(fs, new UTF8Encoding(false));
            w.Write(tekst);
            _revisjonSti = sti;
        }
        catch { _revisjonSti = null; }
    }

    /// <summary>Utviklermodus: alt søket prøvde å lese, hvorfor, og hvordan det gikk. Ingenting av dette lagres.</summary>
    /// <summary>--lytt N: lyttevindu i sekunder (0 til 60). Standard 20.</summary>
    internal static int LytteSekunder(string[] args)
    {
        var i = Array.IndexOf(args, "--lytt");
        return i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out var n) ? Math.Max(0, Math.Min(60, n)) : 20;
    }

    // ---------- Følg med: datamengde live for valgte funn, bare mens vinduet er åpent ----------

    private readonly Dictionary<int, (Folger Folger, System.Windows.Forms.Timer Klokke)> _folg = new();

    private void StartFolg(int id)
    {
        if (_skanner == null || _soker || id < 0 || id >= _resultat.Count || _folg.ContainsKey(id)) return;
        var folger = new Folger(_skanner, _resultat[id]);
        var klokke = new System.Windows.Forms.Timer { Interval = 1000 };
        bool opptatt = false;
        klokke.Tick += async (_, _) =>
        {
            if (opptatt) return;
            opptatt = true;
            try
            {
                var p = await Task.Run(folger.Les);
                if (!_folg.ContainsKey(id)) return;
                Send(new
                {
                    type = "folgdata", id, admin = folger.MalerData,
                    tid = p.Tid.ToString("HH:mm:ss"), ut = p.UtPerSek, inn = p.InnPerSek, n = p.Forbindelser, til = p.Mottakere,
                });
            }
            catch (Exception e) { System.Diagnostics.Debug.WriteLine($"Følg med: {e.Message}"); }
            finally { opptatt = false; }
        };
        _folg[id] = (folger, klokke);
        klokke.Start();
    }

    private void StoppFolg(int id)
    {
        if (!_folg.TryGetValue(id, out var x)) return;
        _folg.Remove(id);
        x.Klokke.Stop();
        x.Klokke.Dispose();
        x.Folger.Dispose();
    }

    // «Nettverk»: hvem som snakker med AI-tjenester nå, hvert sekund mens visningen er åpen. Bare i minnet.
    private (Nettverkvisning Visning, System.Windows.Forms.Timer Klokke)? _nettverk;

    private void StartNettverk()
    {
        if (_skanner == null || _soker || _nettverk != null) return;
        var visning = new Nettverkvisning(_skanner);
        var klokke = new System.Windows.Forms.Timer { Interval = 1000 };
        var farlige = new HashSet<string>(_regler.HoyrisikoLand, StringComparer.OrdinalIgnoreCase);
        bool opptatt = false;
        async void Tikk()
        {
            if (opptatt) return;
            opptatt = true;
            try
            {
                var b = await Task.Run(visning.Les);
                if (_nettverk?.Visning != visning) return;
                string? T(string? x) => _engelsk ? Engelsk.Til(x) : x;
                Send(new
                {
                    type = "nettdata", admin = visning.MalerData, tid = b.Tid.ToString("HH:mm:ss"), ut = b.UtPerSek, inn = b.InnPerSek, andre = b.AndreForbindelser, andreNettleser = b.AndreNettleser,
                    udp = b.UdpHint.Select(u => new { program = u.Program, porter = u.Porter, nettleser = u.Nettleser }),
                    rader = b.Rader.Select(r => new
                    {
                        nokkel = $"{r.Pid}|{r.Tjeneste}", program = r.Program, sti = r.Sti, pid = r.Pid, tjeneste = r.Tjeneste, vert = r.Vert,
                        land = T(r.Cdn != null ? $"Skjult bak {r.Cdn}" : r.Land != null ? IpLand.Navn(r.Land) : r.AlleLand.Count > 1 ? $"{r.AlleLand.Count} land" : null),
                        eier = r.EierLand == null ? null : T(IpLand.Navn(r.EierLand)),
                        farlig = r.AlleLand.Any(farlige.Contains) || (r.EierLand != null && farlige.Contains(r.EierLand)),
                        ai = T(r.Ai), uavklart = r.Uavklart,
                        n = r.Forbindelser, ut = r.UtPerSek, inn = r.InnPerSek, kjent = r.Kjent, nettleser = r.Nettleser,
                    }),
                });
            }
            catch (Exception e) { System.Diagnostics.Debug.WriteLine($"Nettverk: {e.Message}"); }
            finally { opptatt = false; }
        }
        klokke.Tick += (_, _) => Tikk();
        _nettverk = (visning, klokke);
        klokke.Start();
        Tikk();
    }

    // Stier vist i prosessdetaljene i Nettverk; bare de kan åpnes i Utforsker derfra
    private readonly HashSet<string> _visbare = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Hva en prosess i Nettverk er og hvem som startet den. Leser aldri kommandolinjen.</summary>
    private async Task SendProsessAsync(int pid)
    {
        var info = await Task.Run(() => Prosesstre.Om(pid));
        string? T(string? x) => _engelsk ? Engelsk.Til(x) : x;
        string? Tid(DateTime? t) => t == null ? null : t.Value.Date == DateTime.Today ? t.Value.ToString("HH:mm:ss") : T(Skanner.Tid(t));
        if (info == null) { Send(new { type = "prosessinfo", pid, borte = true }); return; }
        foreach (var s in new[] { info.Sti }.Concat(info.StartetAv.Select(l => l.Sti)))
            if (s != null) { _visbare.Add(s); if (Path.GetDirectoryName(s) is { } d) _visbare.Add(d); }
        Send(new
        {
            type = "prosessinfo", pid, navn = info.Navn, sti = info.Sti, startet = Tid(info.Startet),
            produkt = info.Produkt, beskrivelse = info.Beskrivelse, selskap = info.Selskap, signert = info.Signert, egen = info.Egen, brutt = info.KjedenBrutt,
            av = info.StartetAv.Select(l => new { pid = l.Pid, navn = l.Navn, sti = l.Sti, startet = Tid(l.Startet), egen = l.Egen }),
        });
    }

    private void StoppNettverk()
    {
        if (_nettverk is not { } x) return;
        _nettverk = null;
        x.Klokke.Stop();
        x.Klokke.Dispose();
        x.Visning.Dispose();
    }

    private void StoppAlleFolg() { foreach (var id in _folg.Keys.ToList()) StoppFolg(id); }

    private void SendLogg() => Send(new { type = "logg", d = Revisjon.Datagrunnlag(_skanner!, _engelsk, _revisjonSti, _resultat) });

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
