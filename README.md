# AI-skanner

Finner AI på en Windows-PC, deler funnene i **Lokal AI**, **Nettleser** og **Skjult på PC**, og sorterer etter risiko: **rød**, **gul**, **grønn**.
Ett vindu, én knapp: **Søk**.

Den kjenner igjen AI på innhold og oppførsel, ikke bare på navn. Ukjent AI får alltid høy risiko.

- **AI-modeller** gjenkjennes på filformatet (GGUF, safetensors, PyTorch, ONNX, TFLite, Keras), også uten navn.
  Familien (Llama, Qwen, DeepSeek, Gemma, Phi, Mistral m.fl.) leses av modellens arkitektur og ordforråd, også når filen har fått nytt navn.
  Hver modell får en ID som er lik på alle PC-er (SHA-256 eller fingeravtrykk).
- **AI lagt inn av leverandører**: modeller og AI-motorer som Microsoft, NVIDIA, Adobe, Zoom, PC-produsenten og andre har lagt i Windows-apper,
  Program Files, ProgramData og AppData. Hvert funn får leverandør (bekreftet med signatur) og dato det kom på PC-en. Ubekreftet = rød.
- **AI-API-er i Chrome og Edge**: om Prompt API, Summarizer, Writer, Rewriter, Proofreader, Classifier og LiteRT-LM er på, av eller blokkert av IT.
- **AI-motorer** i programmer (llama.cpp, ONNX Runtime, PyTorch, OpenVINO, DirectML m.fl.).
- **Lokale AI-servere**: programmer som svarer som en AI-tjeneste, med modellene de har lastet. Rød hvis åpen mot nettverket.
- **AI-kode**: Python- og Node-prosjekter med AI- og agentbiblioteker.
- **Registeret**: AI-regler fra IT, lenker og høyreklikkmenyer fra AI-apper, programmer som åpner modellfiler, Ollama åpen mot nettverket, Windows Recall.
- **AI-nøkler**: om nøkler som `OPENAI_API_KEY` finnes (aldri verdien).
- **Nettleser-AI**: AI-utvidelser, AI-nettsteder du har brukt (bruksspor og historikk, analysert i minnet og aldri lagret),
  ukjente AI-nettsteder, AI-modeller lagret i nettleseren, og innebygd AI i Chrome og Edge.
- **Hvor AI sender data**: hvilke tjenester og land hvert AI-program er koblet til akkurat nå, fra Windows' egne tabeller.
  Programmer som snakker med AI-tjenester i det skjulte blir røde. Med administrator måles også hvor mye som sendes.
- **Kjente produkter** (Ollama, ChatGPT, Claude Code, Cursor, DeepSeek m.fl.) får navn og risiko fra [`regler.json`](src/AISkanner.Core/regler.json).

## Sikkerhet først
- Leser bare. Endrer, sletter eller installerer ingenting. Trenger ikke administrator (`asInvoker`). Bare måling av datamengde ber om det, og bare når du trykker på den.
- Starter ingen skript eller kommandolinjer. Vinduet bruker Microsoft Edge WebView2.
- Sender ingenting om deg ut. Sårbarhetssjekken sender bare produktnavn (f.eks. «ollama») til NVD.
- Åpner aldri nettleserens passord, informasjonskapsler eller lommebøker. Håndhevet i koden (`Skanner.LovligeFiler`).
- Historikk leses bare hvis bryteren er på, analyseres i minnet og lagres aldri.
- Risikoreglene ligger åpent i [`regler.json`](src/AISkanner.Core/regler.json). Legg en egen `regler.json`
  ved siden av exe-filen for å overstyre.

Se [IT-INFO.md](IT-INFO.md) for nøyaktig hva som leses, og [CODE_SIGNING.md](CODE_SIGNING.md) for signering og personvern.

## Ingenting lagres
Hvert søk gjøres fra bunnen av. Programmet lagrer ingenting mellom søk. Bare rapporten du selv laster ned blir igjen.

## På gjøremålslisten
Skanning av andre enheter på nettverket. Krever mer tilgang og godkjenning, så den er utsatt.

## Begrensninger
Skanneren finner spor, ikke alt. Forbindelser vises bare mens programmene er åpne. Land for skytjenester er der serveren står.
Et tomt resultat betyr ikke at PC-en er fri for AI. Den skanner bare innlogget bruker.

## Liten og rask
- Hele programmet er rundt 3,5 MB, som 7-Zip. Det bruker .NET Framework 4.8 og SQLite-motoren som allerede finnes i Windows,
  og Microsoft Edge WebView2 for vinduet. Byggeløypa stopper hvis programmet blir større enn 10 MB.
- Alle sjekkene kjører samtidig. Det som tar tid er å gå gjennom filene på disken; den stopper uansett etter 45 sekunder.
  Rapporten viser hvor lang tid søket tok og hvilke sjekker som var tregest.

## Bygge selv
Krever .NET 8 SDK (bygger .NET Framework 4.8-programmet).

```
dotnet publish src/AISkanner -c Release -o publish
```

Kommandolinjeversjon som skriver JSON (for testing eller utrulling via Intune):

```
dotnet run --project src/AISkanner.Cli -- [--nvd] [--regler sti\regler.json]
```
Exit-kode: 0 = ingen funn, 1 = gule/grønne funn, 2 = minst ett rødt funn.

## Lisens
MIT. Landtabellen er IP to Country Lite fra [DB-IP.com](https://db-ip.com) (CC BY 4.0).
