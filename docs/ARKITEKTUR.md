# Arkitektur

Dette dokumentet er for utviklere. Det forklarer hvordan AI-skanner er bygget, hvordan et søk går, og hvordan
risikoen settes. For hva som leses på PC-en, se [IT-INFO.md](../IT-INFO.md). For trusselmodellen, se
[SECURITY.md](../SECURITY.md).

## Prinsipper

Disse prinsippene styrer alle valg i koden. En endring som bryter dem, må begrunnes i pull requesten.

1. **Bare lesing.** Ingenting endres, slettes eller installeres. Ingen skript eller kommandoer startes, og ingen kode fra filer kjøres.
2. **Innhold og oppførsel før navn.** AI kjennes igjen på filformat, AI-motorer, nettverk og API-svar.
   Navnelistene i `regler.json` gir bare navn til det som allerede er funnet.
3. **Ukjent er rødt.** Det vi ikke kan identifisere, regnes som høy risiko.
4. **Ingenting lagres.** Alt regnes ut på nytt i hvert søk. Data fra nettleseren blir aldri lagret.
5. **Bare målte data.** Datamengde og land kommer fra Windows' egne tabeller, ikke fra anslag.
6. **Lite og raskt.** Byggeløypa stopper over 10 MB. Bare .NET Framework 4.8, `winsqlite3.dll` og WebView2,
   som alle følger med Windows. Ingen innebygd kjøretid, ingen libyara.
7. **Én skjerm.** Brukerflaten har én knapp og én tabell, uten rulling og uten råd.

## Prosjekter

```
AISkanner.sln
├── src/AISkanner.Core/   Skannemotoren (net48 + net8.0). All logikk ligger her.
├── src/AISkanner/        Windows-programmet (net48, WinForms + WebView2). Tynt skall rundt Core.
│   └── ui/index.html     Hele brukerflaten (HTML, CSS, JS), bygget inn som ressurs.
├── src/AISkanner.Cli/    Kommandolinje (net8.0). JSON/tekst, exit-kode, testverktøy.
├── tests/yara/           Testregler og testfiler for YARA-motoren.
└── verktoy/              Python-skript: IP-landtabell, YARA-sammenligning.
```

`AISkanner.Core` bygges for to rammeverk. `net48` er det som sendes ut. `net8.0` finnes bare for at kommandolinjen og
testene kan kjøre på Linux. `Polyfills.cs` og `Plattform.cs` jevner ut forskjellene, og `WinSqlite.cs` finner
`libsqlite3` på Linux.

## Kjernefiler

| Fil | Ansvar |
|---|---|
| `Skanner.cs` | Søkeflyten: kjører alle sjekker samtidig, slår sammen funn, tar tiden. `LovligeFiler` er lesesperren. |
| `Funn.cs` | Datamodellen: `Funn`, `Risiko`, `Mal` (forbindelse). |
| `Regler.cs` | Leser `regler.json` (innebygd eller ved siden av exe) og `godkjent-ai.txt`. |
| `Sanntid.cs` | Prosesser og AI-motorer, lokale AI-servere (også Ollama-modeller lastet nå via `/api/ps`), AI-nøkler (navn på miljøvariabler og i `.env`-filer, aldri verdier), filgjennomgang (modeller og AI-kode). |
| `Misbruk.cs` | Flere ukjente AI-spor (hooks, skjulte tegn, ferdigheter, autostart med farlige flagg, lenker, kjente filer). Filgjennomgangen samler kandidater; de vurderes etterpå. |
| `Angrep.cs` | Angrep på AI-agenter: sårbare AI-verktøy (`saarbareVersjoner`), Shai-Hulud-filer i `node_modules`, AI-trafikk til en annen vert, instruksjonsfiler i Nedlastinger, `npx skills add`, Gemini i Chrome, Windows' MCP-koblinger (ODR). |
| `Etw.cs` | `EtwOkt`: én sanntidsøkt mot Windows' hendelseskilder (admin). Brukes av `NettEtw` og `Vakt`. Bare i minnet. |
| `Vakt.cs` | Vakt: følger AI-agentene og prosessene de starter live (prosesser, filåpninger, TCP, DNS, endringer i agentoppsett). Eies av vinduet; røde hendelser blir funn via `Skanner.VaktTilFunn`. |
| `NettEtw.cs` | UDP per program (QUIC, STUN, DNS) fra Kernel-Network, via `EtwOkt`. |
| `Nettverkvisning.cs` | «Nettverk» (live): hvilke programmer som snakker med AI-tjenester nå, per sekund. Bare i minnet. |
| `Prosesstre.cs` | Hvem som startet en prosess (Toolhelp), signatur, filinfo og starttid. Skannerens egne prosesser. |
| `Lytting.cs` | Lyttevindu under søket og «Følg med» (datamengde live). Bare i minnet. |
| `Kart.cs` | Kartet i Datagrunnlag: steder fra `Tilgangslogg` og diskgjennomgangen som et tre med antall, størrelse, utfall og funn. Bare i minnet. |
| `Kontroll.cs` | Kontrollmodus (`--kontroll`): falske spor i en midlertidig mappe, sjekker at hver alarm slår ut, sletter mappa. |
| `UkjenteSpor.cs` | Ukjente AI-spor: MCP-oppsett med tilgangskart (`McpTilganger`), «godkjenn alt», serverlogger, agentøkter (bare metadata), skript med AI-nøkkel, dårlige pakkeversjoner. Alle røde. |
| `Kommandolinje.cs`, `Tolkere.cs` | Kommandolinjen til tolkere og AI-funn: skript, modul, pakke, modellfil og risikoflagg. Skriptfila sjekkes for AI-biblioteker. Argumentene vises aldri. |
| `Historikk.cs`, `Hive.cs` | Windows-historikk som admin: Prefetch, BAM, Amcache (egen leser for registerfiler), TaskCache, hendelse 4688, Sysmon og DNS-loggen. Samme leser tar andre brukeres `NTUSER.DAT` (`Skanner.AndreBrukeresRegisterfiler`). |
| `ModellFormat.cs` | Kjenner igjen modellformater på de første bytene, og leser GGUF- og safetensors-hodet. |
| `ModellGjenkjenning.cs` | Modellfamilie fra arkitektur og ordforråd, modell-ID (SHA-256 eller fingeravtrykk), Ollama-navn. |
| `Leverandor.cs` | AI lagt inn av leverandører i AppData, ProgramData, Program Files, WindowsApps og SystemApps. |
| `Signatur.cs` | Authenticode med `WinVerifyTrust`, uten tilbakekallingssjekk over nett. |
| `NettsideAi.cs` | AI-modeller som nettsider kjører i nettleseren (WebLLM, Transformers.js, MediaPipe, wllama) fra Cache Storage, IndexedDB-blobber og File System. |
| `Nettsteder.cs` | AI-nettsteder fra `site_engagement` og historikk, AI-utvidelser og modeller lagret i IndexedDB. |
| `NettleserModeller.cs` | Modeller nettleserne laster ned (Gemini Nano, Edge-modeller, TranslateKit m.fl.). |
| `NettleserApi.cs` | Status for innebygde AI-API-er i Chrome og Edge. |
| `Register.cs` | AI-regler fra IT, lenkeprotokoller, filtilknytninger, høyreklikkmenyer, Ollama-miljø, Recall. |
| `TcpTabell.cs`, `Nettverk.cs`, `Trafikk.cs` | Lyttende porter, åpne forbindelser, DNS-buffer og datamåling med EStats. |
| `IpLand.cs` + `ipland.bin` | IP til land, innebygd tabell fra DB-IP Lite. |
| `YaraSjekk.cs` + `Yara/` | Kjører `ai-modeller.yar` på modellfiler. |
| `Risikoregler.cs` | Siste steg: type, risiko, risikogrunn og «kommer fra». |
| `Oversikt.cs` | Kort navn, kort lokasjon og stikkord på tre ord for tabellen og rapporten. |
| `Nvd.cs` | Antall CVE-er i NVD. Sender bare produktordet. |
| `Rapport.cs` | Tekstrapport (UTF-8 med BOM) og JSON. |
| `ProsessSti.cs` | Filsti for en prosess med minst mulig tilgang. |

## Et søk, steg for steg

```
Søk
 │
 ├─ Datamaling.Start()            (bare som admin: slå på EStats for åpne forbindelser)
 │
 ├─ 11 sjekker samtidig (Task.WhenAll), hver tidtatt i Skanner.Tider
 │    Prosesser + AI-motorer        Installerte programmer      Oppstart
 │    AI-verktøy + AI-nøkler        Lokale porter og AI-servere  Nettleserutvidelser
 │    AI-nettsteder (historikk)     Innebygd AI i Chrome/Edge    Filgjennomgang (maks 45 s)
 │    Registeret                    Leverandør-AI (maks 40 s)
 │         └─ modeller → ModellFormat → ModellGjenkjenning → YaraSjekk
 │
 ├─ Trafikk(NettBilde.Hent)       forbindelser → DNS-buffer → land → kobles til funn
 │                                (venter til minst 5 s måletid når datamengde måles)
 │
 ├─ Risikoregler.Bruk             type, endelig risiko, risikogrunn, kommer fra
 │
 ├─ Resultat sendes til vinduet   sortert etter risiko, deretter navn
 │
 └─ Nvd.SjekkAsync                i bakgrunnen etter resultatet, oppdaterer funn ett og ett
```

Hver sjekk kaller `LeggTil(navn, kategori, risiko, …)`. Funn med samme navn slås sammen, og høyeste risiko vinner
(`RisikoTekst.Hoyeste`). En sjekk som feiler, skrives til `Debug` og stopper ikke de andre.

### Kategori og gruppe

`Funn.Kategori` er en tekst som `"Lokal AI (modell)"`, `"Nettleser-AI (nettsted)"` eller `"Skygge-AI (agent)"`.
`Funn.Gruppe` leses av prefikset: `Nettleser…` gir *nettleser*, `Lokal…` gir *lokal*, og alt annet gir *skjult*.
`Risikoregler.Type` leser også kategorien. Endrer du en kategoritekst, må du sjekke begge stedene.

## Risikomodell

Risikoen settes i to trinn.

**Trinn 1: sjekkene.** Hver sjekk setter en foreløpig risiko ut fra det den ser. Eksempler:

| Funn | Rød | Gul | Grønn |
|---|---|---|---|
| Modellfil | Kan kjøre kode, eller ligger på et ukjent sted | Kjent sted og trygt format | |
| Leverandør-AI | Utgiver ukjent eller ikke bekreftet | Bekreftet, modeller ≥ 500 MB | Bekreftet, under 500 MB |
| AI-motor i prosess | Kjører fra Nedlastinger, eller ukjent | Etter `regler.json` | Kjent, signert utgiver |
| Python/Node-prosjekt | Agentbibliotek | Andre AI-biblioteker | |
| Nettlesermodell | | Ukjent modellmappe | Kjent modell (Gemini Nano m.fl.) |
| Lokal AI-server | Ukjent program, eller åpen mot nettverket | Kjent produkt, etter `regler.json` | |

**Trinn 2: `Risikoregler.Bruk`.** Kjøres etter alle sjekkene og etter trafikken:

```
type = Type(funn)                                    (Ukjent AI, AI-nettsted, AI-agent, Fra leverandør, …)
farlig = «Farlig AI-modellfil» eller sender data til høyrisikoland

hvis ikke ukjent og ikke farlig og står på godkjentlista → type «Godkjent av IT»:
    åpen mot nettverket eller høyrisikoland            → RØD
    nedlastingsmappe, skjult kode, blokkert av IT       → GUL
    ellers                                              → GRØNN
ellers hvis ukjent                                   → RØD
ellers hvis skygge-AI (ErSkygge(type))               → RØD
ellers                                               → beholder risikoen fra trinn 1
hvis farlig                                          → RØD uansett
```

Typer som regnes som **skygge-AI**: AI-nettsted, nettleserutvidelse, AI-agent, AI i kode, nettleserflagg, AI-app,
lokal modell, lokal AI-app, AI-nøkler og «Skygge-AI» (program som snakker med en AI-tjeneste).

Typer som **beholder risikoen fra trinn 1**: Fra Windows (Recall, Copilot), Fra leverandør, Innebygd i nettleser og IT-regel.

**Ukjent AI**: funn som heter «Ukjent …» eller «Farlig AI-modellfil», leverandør-AI med ukjent eller ubekreftet
utgiver, modeller der familien er ukjent, ukjente lokale AI-servere («Lokal AI-server (…)») og «Mulige AI-nettsteder».
Ukjente AI-utvidelser får typen «Nettleserutvidelse» og er røde fordi de er skygge-AI.

**Godkjentlista** (`Risikoregler.Godkjent`) matcher på navn bare når navnet kommer fra regelsettet (`f.Regel != null`)
eller er et gjenkjent nettsted. Domener matches bare mot målte forbindelser, og mot detaljene i nettstedsfunn. Navn fra
filer, mapper og utvidelsesmanifester godtas aldri, fordi brukeren kan styre dem (rettet i 2.13.1).

**Kommer fra** tas fra utgiveren i signaturen, ellers fra første kjente selskap eller produkt i navnet
(`selskapsland` i `regler.json`). **Sender data til** er målte forbindelser, tjenestens land og oppslag i DNS-bufferen.

## Modellidentitet

Det finnes ingen felles ID for AI-modeller. `ModellGjenkjenning` kombinerer tre ting:

1. **Eksakt identitet.** Ollama og Hugging Face lagrer filer under SHA-256, så hashen kan leses av filnavnet uten å
   lese fila. Ellers lages et fingeravtrykk av størrelse, første MB og siste MB.
2. **Metadata.** Navn, organisasjon og «laget fra» i GGUF-hodet, safetensors-hodet og `config.json`.
3. **Modellens DNA.** Arkitektur og størrelsen på ordforrådet (`modellfamilier` i `regler.json`). Dette følger
   familien selv om fila får nytt navn eller blir finjustert.

Når navnet peker på én familie og innholdet på en annen, vises begge: «DeepSeek, bygget på Qwen».
Sikkerhetsnivået er *sikker*, *sannsynlig* eller *ukjent*.

## YARA-motor

`src/AISkanner.Core/Yara/` er en egen YARA-motor i C#, uten libyara.

| Fil | Ansvar |
|---|---|
| `Leksikon.cs` | Deler regelteksten i tokens. |
| `Parser.cs` | Bygger regler og gjør hver betingelse om til en ferdig C#-funksjon (lukning). |
| `Strenger.cs` | Tekst, hex og regex. Alle strenger i alle regler søkes i én runde med Aho-Corasick. Lange hex-hopp deles i kjeder. Regex kjøres bare der det finnes en mulig start. |
| `Moduler.cs` | `pe`, `math`, `hash`, `time`, `string` og `console`. |
| `Kontekst.cs` | Fila som sjekkes: innleste biter, treff og variabler i løkker. |
| `YaraRegler.cs` | Laster regler (fil ved siden av exe, ellers innebygd) og kjører dem på en fil. |

**Hva som leses:** for modeller de første 8 MB og siste 1 MB. For små pickle-, PyTorch-, Keras- og NumPy-filer
(under 200 MB) den første MB-en, men bare når de første 8 bytene viser formatet. En regel som trenger mer, for eksempel
hash av hele fila, får lese hele fila hvis den er under 64 MB (`Kontekst.MaksEkstraLesing`).

**Kompatibilitet:** testet mot YARA 4.5.4 med 134 regler i `tests/yara/test.yar`, uten avvik
(`verktoy/sammenlign-yara.py`). Ikke støttet: modulene `dotnet`, `elf`, `macho`, `magic` og `cuckoo`, `pe.version_info`
og fulle signaturfelt i `pe`.

**Feil i regelfila:** hvis `ai-modeller.yar` ved siden av programmet ikke kan leses, brukes de innebygde reglene, og
rapporten sier hvorfor.

## Nettverk og datamengde

- `TcpTabell` og `Nettverk.Tilkoblinger` bruker `GetExtendedTcpTable` (IPv4 og IPv6) med eier-PID.
- Vertsnavn kommer fra DNS-bufferen (`DnsGetCacheDataTable` og `DnsQuery_W` med `DNS_QUERY_NO_WIRE_QUERY`).
  Det gjøres aldri nye oppslag.
- Land kommer fra `ipland.bin`, en sortert tabell med IP-områder. Den lages med `verktoy/lag-ipland.py`.
- Datamengde krever administrator. `Datamaling.Start()` slår på `TcpConnectionEstatsData` for forbindelsene som er
  åpne når søket starter, og leser og slår dem av etter søket. Vinduet starter seg selv på nytt med `runas` og `--sok`.
- Nettleserprosesser vises bare med forbindelser til kjente AI-tjenester.

## Brukerflaten

`Hovedvindu.cs` er et WinForms-vindu med én WebView2-kontroll. Siden lastes med `NavigateToString` fra den innebygde
ressursen `ui/index.html`. All annen navigering stoppes, nye vinduer blokkeres, og utviklerverktøy og høyreklikkmeny er av.

Vinduet og siden snakker med JSON-meldinger:

| Retning | `type` | Innhold |
|---|---|---|
| Side → program | `sok` | Start søk |
| Side → program | `lagre` | Lagre rapport |
| Side → program | `admin` | Søk som administrator. Starter på nytt med UAC hvis programmet ikke allerede er administrator. |
| Side → program | `vis` | Åpne `sti` i Utforsker. Stien må stå i et funn. |
| Program → side | `modus` | Om programmet kjører som administrator |
| Program → side | `start` | Start søket med en gang (etter omstart som administrator) |
| Program → side | `resultat` | Alle funn og søkeinfo |
| Program → side | `nvd` | NVD-merknader for ett funn |
| Program → side | `nvdFerdig` | NVD-oppslaget er ferdig |
| Program → side | `feil` | Søket stoppet |

Siden kan også åpnes i en vanlig nettleser. Da brukes eksempeldata (`demo()`), og det er slik skjermbildene i
`design/` er laget.

## Ytelse

- Alle sjekker kjører samtidig. Filgjennomgangen deles per toppmappe.
- Filgjennomgangen stopper etter 45 s, leverandørsøket etter 40 s.
- Bare filer over 20 MB får lest de første 64 bytene. Skyfiler i OneDrive hoppes over, så ingenting lastes ned.
- Rapporten viser total søketid og de tregeste sjekkene.

## Hvorfor det er bygget slik

| Valg | Grunn |
|---|---|
| C# og .NET Framework 4.8 | Følger med Windows. Programmet ble 3,7 MB i stedet for 159 MB med .NET 8. PowerShell ble stoppet av EDR. |
| WebView2 | Gir Apple-utseendet. Følger med Windows 10 og 11, og brukes også av nye Outlook og Teams. |
| `winsqlite3.dll` | SQLite som følger med Windows, så vi slipper en ekstra DLL. `immutable` gjør at historikken kan leses uten å kopiere fila og uten låser. |
| Egen YARA-motor | libyara er en usignert, innebygd DLL som EDR reagerer på. Vi bestemmer selv hvor mye som leses. |
| Ingen minnelesing av prosesser | v0.3 åpnet `lsass` med lesetilgang og ble stoppet av Defender og Sentinel. |
| Ingen selvutpakking | Utpakking til `%TEMP%` ligner skadevare. |
