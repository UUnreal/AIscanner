# AI-skanner

Finner AI på en Windows-PC og sorterer funnene etter risiko: **rød**, **gul**, **grønn**.
Ett vindu, én knapp: **Søk**.

Den kjenner igjen AI på innhold og oppførsel, ikke bare på navn. Ukjent AI får alltid høy risiko.

- **AI-modeller** gjenkjennes på filformatet (GGUF, safetensors, PyTorch, ONNX, TFLite, Keras), også uten navn.
- **AI-motorer** i programmer (llama.cpp, ONNX Runtime, PyTorch, OpenVINO, DirectML m.fl.).
- **Lokale AI-servere**: programmer som svarer som en AI-tjeneste, med modellene de har lastet. Rød hvis åpen mot nettverket.
- **AI-kode**: Python- og Node-prosjekter med AI- og agentbiblioteker.
- **AI-nøkler**: om nøkler som `OPENAI_API_KEY` finnes (aldri verdien).
- **Nettleser-AI**: AI-utvidelser, AI-nettsteder du har brukt (bruksspor og historikk, analysert i minnet og aldri lagret),
  ukjente AI-nettsteder, AI-modeller lagret i nettleseren, og innebygd AI i Chrome og Edge.
- **Kjente produkter** (Ollama, ChatGPT, Claude Code, Cursor, DeepSeek m.fl.) får navn og risiko fra [`regler.json`](src/AISkanner.Core/regler.json).

## Sikkerhet først
- Leser bare. Endrer, sletter eller installerer ingenting. Ber aldri om administrator (`asInvoker`).
- Starter ingen skript eller kommandolinjer. Vinduet bruker Microsoft Edge WebView2.
- Sender ingenting ut. Valgfri sårbarhetssjekk sender bare produktnavn til NVD.
- Åpner aldri nettleserens passord, informasjonskapsler eller lommebøker. Håndhevet i koden (`Skanner.LovligeFiler`).
- Historikk leses bare hvis bryteren er på, analyseres i minnet og lagres aldri.
- Risikoreglene ligger åpent i [`regler.json`](src/AISkanner.Core/regler.json). Legg en egen `regler.json`
  ved siden av exe-filen for å overstyre.

Se [IT-INFO.md](IT-INFO.md) for nøyaktig hva som leses, og [CODE_SIGNING.md](CODE_SIGNING.md) for signering og personvern.

## Begrensninger
Skanneren finner kjente spor, ikke alt. AI brukt i en vanlig nettleserfane (chatgpt.com osv.) oppdages ikke.
Et tomt resultat betyr ikke at PC-en er fri for AI. Den skanner bare innlogget bruker.

## Bygge selv
Krever .NET 8 SDK på Windows.

```
dotnet publish src/AISkanner -c Release -o publish
```

Kommandolinjeversjon som skriver JSON (for testing eller utrulling via Intune):

```
dotnet run --project src/AISkanner.Cli -- [--nvd] [--regler sti\regler.json]
```
Exit-kode: 0 = ingen funn, 1 = gule/grønne funn, 2 = minst ett rødt funn.

## Lisens
MIT
