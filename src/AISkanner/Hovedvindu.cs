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
    private bool _soker;

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public Hovedvindu()
    {
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
            var data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AISkanner", "WebView2");
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

        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("AISkanner.ui.index.html")!;
        using var r = new StreamReader(s, Encoding.UTF8);
        w.NavigateToString(await r.ReadToEndAsync());
    }

    private void Send(object melding) => _web.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(melding, Json));

    private async Task MottaAsync(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var m = doc.RootElement;
        var type = m.TryGetProperty("type", out var t) ? t.GetString() : null;
        if (type == "sok" && !_soker)
        {
            bool nvd = m.TryGetProperty("nvd", out var n) && n.ValueKind == JsonValueKind.True;
            bool historikk = !m.TryGetProperty("historikk", out var h) || h.ValueKind != JsonValueKind.False;
            await SokAsync(nvd, historikk);
        }
        else if (type == "lagre") Lagre();
        else if (type == "vis" && m.TryGetProperty("sti", out var sti)) VisIUtforsker(sti.GetString());
    }

    private async Task SokAsync(bool nvd, bool historikk)
    {
        _soker = true;
        try
        {
            var steg = new Progress<int>(nr => Send(new { type = "steg", nr }));
            var status = new Progress<string>(tekst => { if (tekst.StartsWith("Sjekker kjente")) Send(new { type = "status", tekst = "Sjekker kjente sikkerhetshull på nett…" }); });
            _resultat = await Task.Run(() => new Skanner(_regler, historikk).KjorAsync(nvd, status, default, steg));
            Send(new
            {
                type = "resultat",
                funn = _resultat.Select(f => new { risiko = f.Risiko.ToString().ToLowerInvariant(), navn = f.Navn, kort = f.Kort, steder = f.Detaljer }),
            });
        }
        catch (Exception e)
        {
            Send(new { type = "feil", tekst = "Søket stoppet: " + e.Message });
        }
        finally { _soker = false; }
    }

    /// <summary>Åpner Utforsker med fila eller mappa markert. Bare stier som faktisk står i et funn godtas.</summary>
    private void VisIUtforsker(string? sti)
    {
        if (string.IsNullOrWhiteSpace(sti) || !_resultat.Any(f => f.Detaljer.Any(d => d.Contains(sti!)))) return;
        sti = sti!.Trim();
        if (!File.Exists(sti) && !Directory.Exists(sti)) sti = Path.GetDirectoryName(sti);
        if (sti == null || (!File.Exists(sti) && !Directory.Exists(sti))) return;
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", $"/select,\"{sti}\"") { UseShellExecute = false });
    }

    private void Lagre()
    {
        using var dlg = new SaveFileDialog
        {
            Filter = "Rapport (*.html)|*.html|Data for IT (*.json)|*.json",
            FileName = $"AI-skanner-{Environment.MachineName}-{DateTime.Now:yyyy-MM-dd}",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var innhold = dlg.FilterIndex == 2 ? Rapport.Json(_resultat) : Rapport.Html(_resultat);
        File.WriteAllText(dlg.FileName, innhold, new UTF8Encoding(true));
    }
}
