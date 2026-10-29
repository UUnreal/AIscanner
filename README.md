# AI-skanner

Finner AI på en Windows-PC og sorterer funnene etter risiko: 🔴 høy, 🟡 middels og 🟢 lav.
Ett vindu, én knapp: **Søk**.

AI-skanner kjenner igjen AI på innholdet i filer og på hvordan programmer oppfører seg. Navnelister brukes bare til
å sette riktig navn på det som allerede er funnet. Ukjent AI og skygge-AI får alltid høy risiko.

- **Versjon:** 2.19.12 (se [CHANGELOG.md](CHANGELOG.md))
- **Plattform:** Windows 10 og 11, x64
- **Lisens:** [MIT](LICENSE)
- **Status:** testversjon, ikke signert. 2.8–2.16 er ikke kjørt på ekte Windows, og alarmene i 2.17 er ikke kontrollert der (se [Status](#status)).

## Innhold

- [Hva den finner](#hva-den-finner)
- [Kom i gang](#kom-i-gang)
- [Risiko](#risiko)
- [Personvern og sikkerhet](#personvern-og-sikkerhet)
- [Tilpasse for en bedrift](#tilpasse-for-en-bedrift)
- [Kommandolinje](#kommandolinje)
- [Bygge selv](#bygge-selv)
- [Begrensninger](#begrensninger)
- [Status](#status)
- [Dokumentasjon](#dokumentasjon)

## Hva den finner

Funnene deles i fire grupper.

| Gruppe | Eksempler |
|---|---|
| **Lokal AI** | Modellfiler (GGUF, safetensors, PyTorch, ONNX, TFLite, Keras), også uten navn. Lokale AI-servere som Ollama og LM Studio. Programmer med AI-motor (llama.cpp, ONNX Runtime, PyTorch, OpenVINO; DirectML bare sammen med en av dem). |
| **Nettleser** | AI-nettsteder som er brukt (bruksspor og historikk), AI-utvidelser og ukjente AI-nettsteder. |
| **Skjult på PC** | AI-agenter og kodeverktøy, AI lagt inn av leverandører (Microsoft, NVIDIA, Adobe, PC-produsenten), nettlesermodeller som Gemini Nano, AI-API-er i Chrome og Edge, AI-nøkler, registeret og programmer som sender data til AI-tjenester i det skjulte. |
| **Ukjente AI-spor** | MCP-servere, «godkjenn alt» og hooks i AI-agenter, AI-servere brukt fra andre maskiner, ukjente programmer som snakker med AI, agentøkter som har vært borti nøkler, skjulte tegn i CLAUDE.md og AGENTS.md, ferdigheter som laster ned kode, agenter i autostart med farlige flagg, kjente dårlige pakker, filer og domener. Alltid røde. Bare tider og stier, aldri innhold. |

For hver AI viser skanneren:

- **Type**, for eksempel lokal modell, AI-nettsted, AI-agent, fra leverandør eller godkjent av IT.
- **Ligger her**: kort sted i tabellen og full sti når du trykker. Knappen «Vis» åpner stedet i Utforsker.
- **Kommer fra**: selskapet og landet bak, fra signatur, modellfamilie eller tjenestelisten.
- **Sender data til**: land og tjenester programmet er koblet til akkurat nå, fra Windows' egne tabeller.
  Med administrator måles også hvor mye data som sendes.
- **Modellidentitet**: familien (Llama, Qwen, DeepSeek, Gemma, Phi, Mistral m.fl.) leses av arkitektur og ordforråd.
  Hver modell får en ID som er lik på alle PC-er (SHA-256 eller fingeravtrykk).
- **Farlige modeller**: YARA-regler finner modeller som kjører kode når de lastes. Reglene ligger i den åpne fila
  [`ai-modeller.yar`](src/AISkanner.Core/ai-modeller.yar).
- **Kjente sårbarheter**: antall CVE-er i NVD for kjente produkter.

## Kom i gang

1. Last ned zip-fila og pakk den ut til en mappe.
2. Start `AISkanner.exe`. Programmet trenger ikke installasjon eller administrator.
3. Trykk den runde knappen i midten for å søke som bruker, eller ringen rundt for å søke som administrator.
   Som administrator får du også datamengde og programmer som kjører som administrator, men Windows ber om godkjenning.
   Søket starter. Filgjennomgangen stopper etter 45 sekunder uansett.
4. Trykk på en AI for å se detaljer. **Last ned rapport** lagrer en tekstfil (.txt) som åpnes i Notisblokk.

Krav: .NET Framework 4.8 og Microsoft Edge WebView2 Runtime. Begge følger med Windows 10 og 11.
Hele mappa er rundt 3,7 MB.

Programmet er ikke signert ennå, så Windows SmartScreen viser en advarsel. Trykk «Mer info» og «Kjør likevel».
På en jobb-PC må du spørre IT først (se [IT-INFO.md](IT-INFO.md)).

## Risiko

| Farge | Betyr | Eksempler |
|---|---|---|
| 🔴 Høy | Ukjent AI, skygge-AI, farlig modellfil, data til høyrisikoland, AI åpen mot nettverket | Modell uten kjent familie, ChatGPT i nettleseren uten godkjenning, pickle med `os.system` |
| 🟡 Middels | Kjent AI fra Windows, nettleseren eller en signert leverandør, med noe å følge med på | Gemini Nano i Chrome, leverandørmodeller over 500 MB |
| 🟢 Lav | Kjent og bekreftet, eller godkjent av IT | AI på `godkjent-ai.txt`, signert leverandør-AI under 500 MB |

**Skygge-AI** er AI som ikke er lagt inn av Windows, en signert leverandør eller IT. Det gjelder AI-nettsteder,
nettleserutvidelser, agenter, kodeverktøy, AI-apper, modeller brukeren har lagt inn selv og AI-nøkler.
På en jobb-PC blir derfor de fleste funn røde helt til IT har fylt ut godkjentlista.

Se [docs/ARKITEKTUR.md](docs/ARKITEKTUR.md#risikomodell) for hele modellen.

## Personvern og sikkerhet

- **Leser bare.** Programmet endrer, sletter og installerer ingenting. Det kjører som vanlig bruker (`asInvoker`).
  Bare søk som administrator ber om det, og bare når du velger det.
- **Starter ingen skript eller kommandolinjer**, og pakker seg ikke ut til `%TEMP%`.
- **Åpner aldri** passord, informasjonskapsler, `Web Data`, lommebøker i nettleseren eller verdien av API-nøkler.
  Det håndheves i koden (`Skanner.LovligeFiler`).
- **Nettleserhistorikken** leses direkte og skrivebeskyttet, og fila kopieres aldri. Bare AI-domener, antall besøk
  og tidspunkt beholdes, og bare i minnet. Fulle adresser og sidetitler beholdes aldri. Ingenting lagres av seg selv:
  bare rapporten du selv laster ned, viser AI-domenene, besøk og tider, så den viser hvor AI brukes.
- **Lagrer ingenting** mellom søk. Det eneste som blir igjen, er rapporten du selv laster ned, og revisjonsloggen
  hvis du velger Ja på startskjermen.
- **Ingen AI i programmet.** Funnene kommer fra faste regler (filformat, YARA, `regler.json` og kjente adresser),
  ikke fra en AI-modell. Samme PC og samme regler gir samme svar.
- **Datagrunnlag.** Knappen øverst til høyre i resultatet viser alt søket leste, hva det ikke fikk lest (nektet, låst,
  stoppet av antivirus, tidsgrense) og SHA-256 av reglene som ga resultatet.
- **Sender nesten ingenting ut.** Etter søket sendes bare produktord som `ollama` til NVD (nvd.nist.gov).
  PC-navn, brukernavn og stier sendes aldri. Lokale AI-servere spørres bare på `127.0.0.1`.

Se [SECURITY.md](SECURITY.md) for trusselmodellen og hvordan du melder fra om sårbarheter, og
[IT-INFO.md](IT-INFO.md) for nøyaktig hva som leses.

> **Jobb-PC:** Å lese ansattes nettleserhistorikk er innsyn etter e-postforskriften. Arbeidsgiver må følge
> reglene om kontrolltiltak eller slå av historikken med `--uten-historikk`.

## Tilpasse for en bedrift

Legg filer ved siden av `AISkanner.exe`. Da brukes de i stedet for de innebygde.

| Fil | Hva den gjør |
|---|---|
| `godkjent-ai.txt` | AI bedriften har godkjent. Ett navn eller domene per linje. Blir grønt. |
| `regler.json` | Kjente produkter, AI-nettsteder, AI-tjenester, høyrisikoland, modellfamilier og selskapsland. |
| `ai-modeller.yar` | YARA-regler for modellfiler. Har fila en feil, brukes de innebygde reglene. |

Se [docs/REGELFILER.md](docs/REGELFILER.md) for format og eksempler.

## Kommandolinje

Vinduet tar disse valgene:

```
AISkanner.exe [--uten-nvd] [--uten-historikk]
```

Kommandolinjeversjonen skriver JSON eller tekst. Den kan brukes til testing, eller til utrulling med for eksempel Intune:

```
AISkanner.Cli [--nvd] [--uten-historikk] [--regler sti\regler.json] [--txt] [--flagg]
AISkanner.Cli --yara regler.yar fil1 [fil2 …]
```

| Valg | Virkning |
|---|---|
| `--uten-nvd` | Vinduet: slår av NVD-oppslaget. |
| `--uten-historikk` | Leser ikke nettleserhistorikk. |
| `--nvd` | Kommandolinjen: slår på NVD-oppslaget, som er av der som standard. |
| `--regler <sti>` | Bruker en annen `regler.json`. |
| `--txt` | Skriver tekstrapport i stedet for JSON. |
| `--flagg` | Leser AI-flagg fra `Local State` i Chrome og Edge. Av som standard (se [SECURITY.md](SECURITY.md)). |
| `--yara` | Kjører YARA-regler på filer og skriver samme format som `yara.exe`. |
| `--selvtest` | Kjører selvtesten av risikologikken. Exit-kode 0 når alt er grønt. |

Exit-kode: `0` = ingen funn, `1` = bare gule eller grønne funn, `2` = minst ett rødt funn.

## Bygge selv

Krever .NET 8 SDK. Den bygger også .NET Framework 4.8-programmet, også på Linux.

```
dotnet build AISkanner.sln -c Release
dotnet publish src/AISkanner -c Release -o publish
```

Byggeløypa (`.github/workflows/bygg.yml`) bygger på `windows-latest`, kjører en røyktest, stopper hvis programmet
er større enn 10 MB og skriver SHA-256 for alle filer til `SHA256.txt`. Se [CONTRIBUTING.md](CONTRIBUTING.md).

## Begrensninger

- Skanneren finner spor, ikke alt. Et tomt resultat betyr ikke at PC-en er fri for AI.
- Den skanner bare innlogget bruker.
- Filene inne i WSL leses ikke. SRUM, Amcache og MFT leses ikke.
- Forbindelser vises bare mens programmene er åpne. QUIC/UDP vises ikke.
- «Sender data til» viser hvor serveren står eller hvor selskapet hører hjemme, ikke nødvendigvis hvor dataene lagres.
- YARA-motoren mangler modulene `dotnet`, `elf`, `macho`, `magic` og `cuckoo`.
- Bare Windows. Mac og Linux er ikke støttet.
- Andre enheter på nettverket skannes ikke. Det står på gjøremålslista, men krever mer tilgang og godkjenning.

## Status

| Del | Status |
|---|---|
| Skannemotor | Testet på Linux med falske PC-profiler. Kjørt på ekte Windows til og med 2.7. 2.17.0 startet og søkte på én Windows-PC (ingen nye funn). |
| Ukjente AI-spor og lyttevindu (2.16–2.17) | Alle 29 alarmer slår ut i kontrollmodus på Linux. Ikke kontrollert på Windows: kjør `AISkanner.exe --kontroll`. |
| Vindu (WebView2) | Kjørt på Windows i 2.3, 2.5 og 2.7. Tabellvisningen fra 2.8 og 2.10 er bare testet i nettleser med eksempeldata. |
| YARA-motor | Testet mot YARA 4.5.4 med 134 regler, uten avvik. |
| NVD-oppslag | Ikke testet, fordi byggemiljøet stenger for nettet. |
| Søk som admin, datamengde og UAC | Ikke testet på Windows. |
| Edge-modellmappe og `leverandorAi` med `bekreftet: false` | Mappenavnene er antatt, ikke sjekket på en ekte PC. |
| Kodesignering | Ikke på plass. Planen er SignPath Foundation ([CODE_SIGNING.md](CODE_SIGNING.md)). |

## Dokumentasjon

| Dokument | For hvem |
|---|---|
| [CHANGELOG.md](CHANGELOG.md) | Alle: hva som er endret i hver versjon |
| [IT-INFO.md](IT-INFO.md) | IT og sikkerhet: nøyaktig hva som leses, nettverk, EDR og godkjenning |
| [SECURITY.md](SECURITY.md) | Melde fra om sårbarheter, trusselmodell |
| [docs/ARKITEKTUR.md](docs/ARKITEKTUR.md) | Utviklere: komponenter, søkeflyt, risikomodell og YARA-motor |
| [docs/REGELFILER.md](docs/REGELFILER.md) | IT og utviklere: `regler.json`, `godkjent-ai.txt` og `ai-modeller.yar` |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Bidragsytere: bygging, testing, kodestil og utgivelser |
| [CODE_SIGNING.md](CODE_SIGNING.md) | Signeringspolicy |

## Lisens

MIT, se [LICENSE](LICENSE).
Landtabellen er IP to Country Lite fra [DB-IP.com](https://db-ip.com), lisensiert under CC BY 4.0.
