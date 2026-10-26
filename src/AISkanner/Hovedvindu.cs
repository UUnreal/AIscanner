using System.Text;

namespace AISkanner.App;

public sealed class Hovedvindu : Form
{
    private static readonly Dictionary<Risiko, Color> Farger = new()
    {
        [Risiko.Rod] = Color.FromArgb(253, 214, 212),
        [Risiko.Gul] = Color.FromArgb(255, 241, 190),
        [Risiko.Gronn] = Color.FromArgb(214, 242, 218),
    };

    private readonly Regelsett _regler;
    private readonly Button _sok = new();
    private readonly Button _lagre = new();
    private readonly CheckBox _nvd = new();
    private readonly Label _rod = new(), _gul = new(), _gronn = new();
    private readonly ListView _liste = new();
    private readonly ToolStripStatusLabel _status = new();
    private List<Funn> _resultat = new();

    public Hovedvindu()
    {
        _regler = Regelsett.Last();
        Text = "AI-skanner";
        Size = new Size(1150, 720);
        MinimumSize = new Size(800, 450);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10f);
        BackColor = Color.White;

        var topp = new Panel { Dock = DockStyle.Top, Height = 140, Padding = new Padding(20, 12, 20, 8) };
        var tittel = new Label { Text = "AI-skanner", Font = new Font("Segoe UI", 20f, FontStyle.Bold), AutoSize = true, Location = new Point(18, 10) };
        var under = new Label
        {
            Text = "Finner lokal AI, skygge-AI og nettleser-AI på denne PC-en. Leser bare, endrer ingenting, sender ingenting.",
            ForeColor = Color.DimGray, AutoSize = true, Location = new Point(21, 52),
        };

        _sok.Text = "Søk";
        _sok.Font = new Font("Segoe UI", 14f, FontStyle.Bold);
        _sok.Size = new Size(170, 46);
        _sok.Location = new Point(21, 82);
        _sok.BackColor = Color.FromArgb(30, 90, 200);
        _sok.ForeColor = Color.White;
        _sok.FlatStyle = FlatStyle.Flat;
        _sok.FlatAppearance.BorderSize = 0;
        _sok.Click += async (_, _) => await SokAsync();

        _nvd.Text = "Sjekk kjente sårbarheter på nett (sender bare produktnavn til NVD)";
        _nvd.AutoSize = true;
        _nvd.Location = new Point(210, 84);

        var merker = new FlowLayoutPanel { Location = new Point(208, 106), AutoSize = true, WrapContents = false };
        foreach (var (l, r) in new[] { (_rod, Risiko.Rod), (_gul, Risiko.Gul), (_gronn, Risiko.Gronn) })
        {
            l.AutoSize = true;
            l.Padding = new Padding(8, 2, 8, 2);
            l.Margin = new Padding(0, 0, 8, 0);
            l.BackColor = Farger[r];
            l.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
            l.Visible = false;
            merker.Controls.Add(l);
        }

        _lagre.Text = "Lagre rapport";
        _lagre.Size = new Size(150, 38);
        _lagre.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _lagre.Location = new Point(ClientSize.Width - 175, 86);
        _lagre.Enabled = false;
        _lagre.Click += (_, _) => Lagre();

        topp.Controls.AddRange(new Control[] { tittel, under, _sok, _nvd, merker, _lagre });

        _liste.Dock = DockStyle.Fill;
        _liste.View = View.Details;
        _liste.FullRowSelect = true;
        _liste.GridLines = true;
        _liste.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        foreach (var (navn, bredde) in new[] { ("Risiko", 80), ("Navn", 250), ("Type", 170), ("Funnet", 240), ("Hvorfor", 900) })
            _liste.Columns.Add(navn, bredde);
        _liste.DoubleClick += (_, _) => VisDetaljer();
        _liste.KeyDown += (_, e) => { if (e.KeyCode == Keys.Enter) VisDetaljer(); };

        var statuslinje = new StatusStrip();
        _status.Text = "Trykk Søk for å starte. Dobbeltklikk en linje for detaljer.";
        statuslinje.Items.Add(_status);

        Controls.Add(_liste);
        Controls.Add(topp);
        Controls.Add(statuslinje);
        AcceptButton = _sok;
    }

    private async Task SokAsync()
    {
        _sok.Enabled = _lagre.Enabled = false;
        _liste.Items.Clear();
        foreach (var l in new[] { _rod, _gul, _gronn }) l.Visible = false;
        UseWaitCursor = true;
        try
        {
            var status = new Progress<string>(t => _status.Text = t);
            bool nvd = _nvd.Checked;
            _resultat = await Task.Run(() => new Skanner(_regler).KjorAsync(nvd, status));

            _liste.BeginUpdate();
            foreach (var f in _resultat)
            {
                var hvorfor = f.Merknader.Count > 0 ? string.Join(" ", f.Merknader) + "  " + f.Hvorfor : f.Hvorfor;
                var rad = new ListViewItem(new[] { RisikoTekst.Vis(f.Risiko), f.Navn, f.Kategori, string.Join(", ", f.Hvor), hvorfor })
                {
                    BackColor = Farger[f.Risiko],
                    Tag = f,
                };
                _liste.Items.Add(rad);
            }
            _liste.EndUpdate();

            int Antall(Risiko r) => _resultat.Count(f => f.Risiko == r);
            _rod.Text = $"{Antall(Risiko.Rod)} røde";
            _gul.Text = $"{Antall(Risiko.Gul)} gule";
            _gronn.Text = $"{Antall(Risiko.Gronn)} grønne";
            foreach (var l in new[] { _rod, _gul, _gronn }) l.Visible = true;
            _status.Text = _resultat.Count == 0
                ? "Ferdig. Fant ingen kjente AI-verktøy. Merk: AI brukt i vanlige nettleserfaner kan ikke oppdages."
                : "Ferdig. Dobbeltklikk en linje for detaljer.";
            _lagre.Enabled = true;
        }
        catch (Exception e)
        {
            _status.Text = "Søket feilet: " + e.Message;
        }
        finally
        {
            _sok.Enabled = true;
            UseWaitCursor = false;
        }
    }

    private void VisDetaljer()
    {
        if (_liste.SelectedItems.Count == 0 || _liste.SelectedItems[0].Tag is not Funn f) return;
        var sb = new StringBuilder()
            .AppendLine($"Risiko: {RisikoTekst.Vis(f.Risiko)}")
            .AppendLine($"Type: {f.Kategori}")
            .AppendLine($"Funnet: {string.Join(", ", f.Hvor)}")
            .AppendLine().AppendLine(f.Hvorfor);
        if (f.Merknader.Count > 0) sb.AppendLine().AppendLine(string.Join(Environment.NewLine, f.Merknader));
        if (f.Detaljer.Count > 0) sb.AppendLine().AppendLine("Detaljer:").AppendLine(string.Join(Environment.NewLine, f.Detaljer));

        using var vindu = new Form
        {
            Text = f.Navn, Size = new Size(720, 460), StartPosition = FormStartPosition.CenterParent,
            Font = Font, MinimizeBox = false, ShowInTaskbar = false,
        };
        var boks = new TextBox
        {
            Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical,
            Text = sb.ToString(), BackColor = Farger[f.Risiko], BorderStyle = BorderStyle.None,
        };
        vindu.Controls.Add(boks);
        vindu.ShowDialog(this);
    }

    private void Lagre()
    {
        using var dlg = new SaveFileDialog
        {
            Filter = "Nettside (*.html)|*.html|Data for IT (*.json)|*.json",
            FileName = $"AI-skanner-{Environment.MachineName}-{DateTime.Now:yyyy-MM-dd}",
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        var innhold = dlg.FilterIndex == 2 ? Rapport.Json(_resultat) : Rapport.Html(_resultat);
        File.WriteAllText(dlg.FileName, innhold, new UTF8Encoding(true));
        _status.Text = "Rapport lagret: " + dlg.FileName;
    }
}
