using System.Net;
using System.Text;
using System.Text.Json;

namespace AISkanner;

public static class Rapport
{
    public const string Begrensning =
        "Skanneren finner kjente spor. Den kan ikke se AI brukt i vanlige nettleserfaner, og et tomt resultat betyr ikke at PC-en er fri for AI.";

    public static string Html(IReadOnlyList<Funn> liste)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var farge = new Dictionary<Risiko, string> { [Risiko.Rod] = "#fde2e1", [Risiko.Gul] = "#fff4cc", [Risiko.Gronn] = "#e3f6e5" };
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"no\"><head><meta charset=\"utf-8\"><title>AI-skanner rapport</title>")
          .Append("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}table{border-collapse:collapse;width:100%}")
          .Append("td,th{border:1px solid #ccc;padding:6px 8px;vertical-align:top;text-align:left}small{color:#555}</style></head><body>")
          .Append("<h1>AI-skanner rapport</h1>")
          .Append($"<p>PC: {E(Environment.MachineName)} &middot; Bruker: {E(Environment.UserName)} &middot; {DateTime.Now:yyyy-MM-dd HH:mm}</p>")
          .Append("<table><tr><th>Risiko</th><th>Navn</th><th>Type</th><th>Funnet</th><th>Hvorfor</th></tr>");
        foreach (var f in liste)
        {
            var info = string.Join("<br>", f.Merknader.Concat(f.Detaljer).Select(E));
            sb.Append($"<tr style=\"background:{farge[f.Risiko]}\"><td><b>{RisikoTekst.Vis(f.Risiko)}</b></td><td>{E(f.Navn)}</td><td>{E(f.Kategori)}</td>")
              .Append($"<td>{E(string.Join(", ", f.Hvor))}</td><td>{E(f.Hvorfor)}<br><small>{info}</small></td></tr>");
        }
        sb.Append($"</table><p><small>{E(Begrensning)}</small></p></body></html>");
        return sb.ToString();
    }

    public static string Json(IReadOnlyList<Funn> liste) => JsonSerializer.Serialize(new
    {
        pc = Environment.MachineName,
        tid = DateTimeOffset.Now,
        funn = liste.Select(f => new
        {
            risiko = f.Risiko.ToString().ToLowerInvariant(),
            f.Navn, f.Kategori, f.Hvor, f.Hvorfor, f.Merknader, f.Detaljer,
        }),
    }, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
}
