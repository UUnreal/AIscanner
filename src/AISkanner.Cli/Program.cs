// Kommandolinjeversjon av skanneren. Skriver funn som JSON.
// Brukes til testing og til bedrifter som vil kjøre skanningen via Intune eller lignende.
//   AISkanner.Cli [--nvd] [--regler sti\til\regler.json]
using AISkanner;

bool nvd = args.Contains("--nvd");
int i = Array.IndexOf(args, "--regler");
var regler = Regelsett.Last(i >= 0 && i + 1 < args.Length ? args[i + 1] : null);

var status = new Progress<string>(t => Console.Error.WriteLine(t));
var funn = await new Skanner(regler).KjorAsync(nvd, status);
Console.OutputEncoding = System.Text.Encoding.UTF8;
Console.WriteLine(Rapport.Json(funn));
return funn.Any(f => f.Risiko == Risiko.Rod) ? 2 : funn.Count > 0 ? 1 : 0;
