# AI-skanner

Finner AI på en Windows-PC og sorterer funnene etter risiko: **rød**, **gul**, **grønn**.
Ett vindu, én knapp: **Søk**.

- **Lokal AI:** Ollama, LM Studio, GPT4All, llama.cpp, Jan, ComfyUI, store modellfiler (.gguf, .safetensors, .onnx),
  og AI-servere som er åpne mot nettverket.
- **Skygge-AI:** ChatGPT, Claude, Copilot, Perplexity, DeepSeek, og AI-agenter som Claude Code, Codex, Gemini CLI,
  Aider, Cursor, Windsurf, Cline og Continue.
- **Nettleser-AI:** AI-utvidelser i Chrome, Edge, Brave, Vivaldi, Opera og Firefox, og innebygd AI i
  Chrome (Gemini Nano) og Edge, inkludert om bedriftspolicy blokkerer den.

## Sikkerhet først
- Leser bare. Endrer, sletter eller installerer ingenting. Ber aldri om administrator (`asInvoker`).
- Starter ingen andre programmer. Ingen PowerShell, ingen skript.
- Sender ingenting ut. Valgfri sårbarhetssjekk sender bare produktnavn til NVD.
- Åpner aldri nettleserens passord, informasjonskapsler, historikk eller lommebøker. Dette er håndhevet i koden
  (`Skanner.LovligeFiler`): de eneste filene som leses er `manifest.json`, `messages.json` og `extensions.json`.
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
