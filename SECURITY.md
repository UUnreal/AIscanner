# Sikkerhet

AI-skanner leser sensitive steder på en PC: prosesser, nettverk, registeret, nettleserdata og filer i brukerprofilen.
Sikkerhet går derfor foran funksjoner. Dette dokumentet sier hvordan du melder fra om sårbarheter, hva vi
forsvarer oss mot, og hva som ikke er løst ennå.

## Støttede versjoner

Bare siste versjon får sikkerhetsrettinger.

| Versjon | Støttet |
|---|---|
| 2.13.x | Ja |
| 2.12 og eldre | Nei |
| 0.1–0.4 (PowerShell og .NET 8) | Nei, utgått |

## Melde fra om en sårbarhet

**Ikke opprett en offentlig sak (issue) for sårbarheter.**

1. Bruk GitHub sin private varsling: fanen **Security** i repoet, og deretter **Report a vulnerability**.
2. Beskriv hva som er sårbart, hvilken versjon du har brukt, hvordan feilen kan utløses, og hva en angriper oppnår.
3. Du får svar innen 7 dager. Vi avtaler med deg når feilen gjøres kjent, normalt etter at en retting er ute,
   og senest etter 90 dager.

Vedlikeholder: Jørund. Prosjektet har ingen dusørordning (bug bounty).

## Trusselmodell

### Hva vi beskytter

1. **Brukerens personvern.** Nettleserhistorikk, passord, informasjonskapsler, API-nøkler og dokumenter skal aldri
   leses, lagres eller sendes ut.
2. **PC-en.** Skanneren skal ikke kunne brukes til å kjøre kode, få høyere rettigheter eller endre noe.
3. **Riktig svar.** En angriper skal ikke kunne gjemme farlig AI eller gjøre den grønn.

### Hvem vi forsvarer oss mot

| Angriper | Eksempel | Forsvar |
|---|---|---|
| Ondsinnede filer på disken | Modellfil, utvidelsesmanifest eller SQLite-fil laget for å krasje eller lure parseren | Leser bare begrensede deler (64 byte, metadata-hode, 8 MB + 1 MB for YARA, og hele fila bare hvis den er under 64 MB og en regel trenger det), grenser på størrelse og antall, ingen kodekjøring, misformede filer testet (2.11) |
| Ondsinnet lokalt program | Lytter på en port og svarer med et enormt eller falskt svar | Maks tre `GET` til `127.0.0.1`, kort tidsgrense, maks 4 MB svar, ingen omdirigering, ingen proxy |
| Filer ved siden av programmet | Falsk DLL, `explorer.exe` eller regelfil i samme mappe eller arbeidsmappa | Arbeidsmappa er tatt ut av DLL-søket, full sti til Utforsker, 2 s tidsgrense på regex (2.11) |
| Navn brukeren styrer | Utvidelse eller mappe som kaller seg det samme som en godkjent AI | Godkjenning bare på navn fra regelsettet og domener fra målte forbindelser (2.13.1) |
| Innhold i resultatet | Utvidelsesnavn eller modellnavn med HTML eller skript | All tekst fra funn escapes (`esc()` i `index.html`) før den vises. Siden er bygget inn, kan ikke navigere bort eller åpne nye vinduer, og utviklerverktøy og høyreklikkmeny er av |
| Nettverket | Avlytting av NVD-oppslaget | HTTPS, og bare produktord sendes |

### Utenfor modellen

- En angriper som allerede er administrator eller kan skrive i mappa der `AISkanner.exe` ligger. Da kan programmet
  byttes ut. Dette løses bare med kodesignering og installasjon i en beskyttet mappe som Program Files.
- AI som bevisst skjuler seg, for eksempel en rootkit eller kryptert modell. Skanneren finner spor, ikke alt.
- Andre brukere på samme PC. Skanneren ser bare innlogget bruker.

## Hva programmet leser, og hva det aldri leser

Full liste står i [IT-INFO.md](IT-INFO.md). Kort sagt:

**Leser** (bare lesing): prosessliste og filstier, TCP-tabeller, DNS-bufferen, deler av registeret, mappenavn og
størrelser, de første bytene og metadata-hodet i modellfiler, utvidelsesmanifester, `Preferences` (bare
`site_engagement`) og nettleserhistorikk (`History` og `places.sqlite`, bare AI-domener beholdes, og bare i minnet). AI-domener med nettleser, besøk og tider står bare i rapporten brukeren
selv laster ned.

**Leser aldri:** `Login Data` (passord), `Cookies`, `Web Data`, `Local Extension Settings` (lommebøker), verdien av
API-nøkler, e-post eller dokumentinnhold, og minnet til andre prosesser. `lsass`, `csrss`, `winlogon` og
Defender-prosesser åpnes ikke.

**Håndhevet i koden:** `Skanner.LovligeFiler` er de eneste filnavnene som åpnes for å lese innholdet:
`manifest.json`, `messages.json`, `extensions.json`, `Preferences`, `History` og `places.sqlite`. I tillegg leses de
første bytene og metadata-hodet i store filer for å kjenne igjen modellformater, og YARA leser begrensede deler av modellfiler.

**Unntak, av som standard:** `Local State` i Chrome og Edge inneholder AI-flaggene, men også nettleserens krypterte
nøkkel. Den leses bare med `AISkanner.Cli --flagg`. Da leser en strømleser bare `browser.enabled_labs_experiments`,
hopper over alt annet uten å tolke det, og nuller ut bytene etterpå. Vinduet har ikke dette valget.

**Ingen AI-modell i programmet.** Gjenkjenningen er regelbasert: filformat (GGUF, safetensors, ONNX og flere),
YARA-regler, `regler.json` og kjente adresser. Det finnes ingen modell som kan gi ulike svar på samme data, og ingen
modell som kan lures med innhold i filene den leser.

**Datagrunnlag og revisjonslogg** inneholder bare stier, navn og utfall. Revisjonsloggen skrives bare når brukeren
velger Ja, med `FileMode.CreateNew`. SHA-256-linjen oppdager endringer, men beviser ikke opphav: den som kan skrive
fila, kan regne ut ny sum.

## Herding

| Tiltak | Hvor |
|---|---|
| Kjører alltid som vanlig bruker (`asInvoker`). Administrator bare for måling av datamengde, etter UAC-spørsmål. | `app.manifest`, `Hovedvindu.cs` |
| Prosesser åpnes med `PROCESS_QUERY_LIMITED_INFORMATION`. Minne leses aldri. | `ProsessSti.cs` |
| Pakker seg ikke ut, er ikke komprimert og starter ingen skript. | `AISkanner.csproj` |
| Historikk åpnes skrivebeskyttet og `immutable` med Windows' egen `winsqlite3.dll`. Fila kopieres aldri. | `WinSqlite.cs`, `Nettsteder.cs` |
| WebView2-siden er bygget inn og kan ikke navigere bort. Mappen per kjøring slettes når programmet lukkes. | `Hovedvindu.cs` |
| «Vis» åpner bare stier som finnes og står i et funn, med full sti til Utforsker. | `Hovedvindu.cs` |
| Arbeidsmappa er tatt ut av DLL-søket. | `src/AISkanner/Program.cs` |
| Svar fra lokale porter er begrenset til 4 MB. | `Sanntid.cs` |
| Språkkoder fra utvidelser valideres før de brukes i stier. | `Skanner.cs` |
| Regex har en tidsgrense på 2 sekunder i vinduet, og 1 sekund i godkjentlista (også i kommandolinjen). | `src/AISkanner/Program.cs`, `Risikoregler.cs` |
| Godkjentlista godtar bare navn fra regelsettet og domener fra målte forbindelser. | `Risikoregler.cs` |
| Byggeløypa skriver SHA-256 for hver fil. Bygget er deterministisk. | `bygg.yml`, `AISkanner.csproj` |

## Kjente svakheter

Disse er kjent og ikke rettet i 2.13.1.

1. **Programmet er ikke signert.** Windows og EDR kan ikke vite at fila kommer fra prosjektet, og en falsk
   `AISkanner.exe` eller DLL i samme mappe kan ikke oppdages. Planen er SignPath Foundation, se
   [CODE_SIGNING.md](CODE_SIGNING.md). Inntil da bør IT godkjenne på SHA-256 fra `SHA256.txt` og legge programmet
   i en mappe vanlige brukere ikke kan skrive til, ikke i Nedlastinger.
2. **Godkjentlista er en tillitsbeslutning IT tar.** Fra 2.13.1 godkjennes navn bare når de kommer fra regelsettet
   eller et gjenkjent nettsted, og domener bare mot målte forbindelser og nettstedsfunn. Navn fra utvidelser, mapper og
   filer godtas ikke. Ukjent AI, skygge-AI uten godkjenning, farlige modellfiler og data til høyrisikoland er alltid
   røde. IT bør likevel bare føre opp eksakte produktnavn og offisielle domener.
3. **Herdingen av DLL-søk og regex-tidsgrense gjelder bare vinduet** (`AISkanner.exe`), ikke `AISkanner.Cli`. Det er
   med vilje. Kommandolinjen er et verktøy for IT og utrulling i kontrollerte miljøer, ikke noe vanlige brukere laster
   ned og starter fra Nedlastinger. Taket på 4 MB for lokale HTTP-svar gjelder begge.
4. **Regelfiler ved siden av programmet** (`regler.json`, `godkjent-ai.txt`, `ai-modeller.yar`) leses uten signatur.
   Den som kan skrive i programmappa, kan endre hva som blir rødt og grønt. Det samme gjelder punkt 1.
5. **P/Invoke-strukturer** for TCP6, DNS-poster og EStats er ikke kontrollert på ekte Windows siden 2.7.

## Personvern og lov

Historikksøket er innsyn i elektronisk lagret materiale. En arbeidsgiver som bruker skanneren på ansattes PC-er må
følge e-postforskriften og arbeidsmiljølovens regler om kontrolltiltak, eller slå av historikken med `--uten-historikk`.
