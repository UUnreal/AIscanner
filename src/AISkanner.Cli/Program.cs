// Kommandolinjeversjon av skanneren. Skriver funn som JSON.
// Brukes til testing og til bedrifter som vil kjøre skanningen via Intune eller lignende.
//   AISkanner.Cli [--nvd] [--uten-historikk] [--regler sti\til\regler.json]
using AISkanner;

if (args.Length == 2 && args[0] == "--test-server")
{
    // Intern test: spør én lokal port om den svarer som en AI-tjeneste
    using var klient = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(1) };
    var m = Skanner.Spor(klient, int.Parse(args[1]));
    Console.WriteLine(m == null ? "ikke AI" : "AI: " + string.Join(", ", m));
    return 0;
}

bool nvd = args.Contains("--nvd");
bool historikk = !args.Contains("--uten-historikk");
int i = Array.IndexOf(args, "--regler");
var regler = Regelsett.Last(i >= 0 && i + 1 < args.Length ? args[i + 1] : null);

var status = new Progress<string>(t => Console.Error.WriteLine(t));
var funn = await new Skanner(regler, historikk).KjorAsync(nvd, status);
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine(Rapport.Json(funn));
return funn.Any(f => f.Risiko == Risiko.Rod) ? 2 : funn.Count > 0 ? 1 : 0;
