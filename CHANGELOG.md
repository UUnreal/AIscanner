# Endringslogg

Alle merkbare endringer i AI-skanner står her.

Formatet følger [Keep a Changelog 1.1.0](https://keepachangelog.com/no/1.1.0/), og prosjektet bruker
[Semantisk versjonering](https://semver.org/lang/no/) fra og med neste utgivelse.

Kategoriene er:

- **Lagt til** (Added) for nye funksjoner.
- **Endret** (Changed) for endringer i funksjoner som fantes fra før.
- **Fjernet** (Removed) for funksjoner som er tatt bort.
- **Rettet** (Fixed) for feilrettinger.
- **Sikkerhet** (Security) for sårbarheter og herding.

> **Om versjonsnumrene før 3.0.** Versjon 0.1 til 2.10 ble laget på én dag (26. oktober 2026) som testutgaver
> til én PC. Numrene fulgte ikke SemVer strengt: flere 2.x-utgaver endret risikoregler og brukerflate på måter
> som etter SemVer ville krevd ny hovedversjon. Ingen av dem er publisert som GitHub-utgivelse. Fra første
> offentlige utgivelse gjelder SemVer slik det står i [CONTRIBUTING.md](CONTRIBUTING.md#versjoner).
>
> **«Ikke testet på Windows»** betyr at koden er bygget og testet på Linux med falske PC-profiler,
> men ikke kjørt på en ekte Windows-PC. Siste versjon som er kjørt på ekte Windows er 2.7.

## [Ikke utgitt]

### Lagt til
- `AISkanner.Cli --selvtest`: sju kontroller av risikologikken, blant annet at godkjentlista ikke kan lures med falske
  navn eller domener i filstier.
- Utviklerdokumentasjon: `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/ARKITEKTUR.md` og
  `docs/REGELFILER.md`. `README.md`, `IT-INFO.md` og `CODE_SIGNING.md` er skrevet om og oppdatert.

## [2.28.1] - 2026-10-29

### Rettet
- **`AISkanner.exe.config` er borte fra mappa, for andre gang, og nå med sperre.** 2.15.1 fjernet den ved å flytte
  DLL-ene til en undermappe, som ikke startet (se 2.15.2), og fila kom tilbake. Nå ligger DLL-ene fortsatt ved siden
  av programmet, men fila trengs ikke: `Program.AnnenVersjon` godtar en annen versjon av et av programmets egne
  biblioteker i samme mappe (samme navn og nøkkel) og laster det med vanlig lasting (`Assembly.Load`), ikke
  `LoadFrom`. Byggingen lager ikke fila lenger (`AutoGenerateBindingRedirects`, `GenerateSupportedRuntime` av).
- Byggeløypa stopper hvis en `.config` eller en annen fil som heter `AISkanner*` dukker opp i mappa.
- Ny lastetest i byggeløypa: mappa merkes «fra Internett» slik den blir etter nedlasting, og `AISkanner.exe
  --lastetest` laster bibliotekene og kjører alle alarmene i selve programmet (.NET Framework 4.8), uten vindu.
- `LES-MEG-FORST.txt` nevner ikke lenger `.config`-fila.

## [2.28.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 177 av 177.

### Lagt til
- **Filter på risiko:** Høy, Middels, Lav og Ukjent øverst i resultatet kan trykkes på for å vise bare den gruppen.
  Trykk igjen eller på «Alle» for å se alt. Tallene er de samme som før, og lista viser nøyaktig så mange rader.
- **Hvem og hvordan** for AI som kjører: konto, om den kjører som administrator, hvem som startet den og SHA-256 av
  programfila.
- **AI-agenter som kjører kommandoer nå:** skall, tolkere og verktøy en AI-agent har startet, vises på agenten
  (bare programnavnet).
- **Oppstart som er slått av** i Oppgavebehandling (StartupApproved) vises med tid, og teller ikke som «Satt opp».
- **Skript i oppstart og planlagte oppgaver** sjekkes for AI på innholdet, også `.vbs`, `.bat` og `.cmd`. For tolkere
  leses argumentene i oppgaven i minnet, som en kommandolinje, og vises aldri.
- `wscript` og `cscript` regnes som tolkere.

### Endret
- «Aldri lest, med vilje» er delt i «Aldri åpnet» og «Lest i minnet, aldri vist», så lista stemmer med hva søket
  faktisk gjør etter 2.26.0.

### Fjernet
- Rådtekstene (`rad`) i `regler.json` og i koden. De ble ikke vist, og programmet skal bare vise data.

## [2.27.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 175 av 175.

### Lagt til
- **Status per funn:** Kjører nå, Brukt før, Satt opp eller Finnes. Alle som gjelder, står i detaljene og rapporten;
  den sterkeste står i lista. AI som bare finnes i Windows' historikk, står som «Brukt før», ikke «Finnes».
- **Treffsikkerhet per funn:** Høy, Middels eller Lav, med antall uavhengige spor. Høy krever et spor på innholdet
  eller oppførselen (modellhode, import i kode, svar som AI-tjeneste, trafikk, YARA) eller minst to uavhengige spor.
- **Godkjenning per funn:** Godkjent av IT, Blokkert av IT eller Ikke vurdert.
- **Blokkeringsliste fra IT:** `blokkert-ai.txt` ved siden av programmet, eller `blokkertAi` i `regler.json`. AI på
  lista blir rød med «Blokkert av IT, men finnes på PC-en», også når den samtidig er godkjent. Samme sterke identitet
  som godkjentlista.
- JSON-rapporten har `status`, `tilstander`, `treffsikkerhet`, `spor` og `godkjenning`.

### Endret
- Flaggene fra kommandolinjen (åpen mot nettverket, offentlig lenke, agent uten spørsmål, kode fra modellen, gjemt
  base64) gjør også godkjent AI rød.

## [2.26.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 167 av 167.

### Lagt til
- **Kommandolinjer for tolkere og AI-funn.** For python, node, bun, deno, powershell, pwsh, java og uv leses
  kommandolinjen fra Windows og sammenlignes med reglene i minnet. Skriptet tolken kjører, sjekkes for AI-biblioteker
  (`import openai`, `require("@anthropic-ai/sdk")` …), navn på AI-tjenester og nøkler. Det som vises, er skriptfila,
  modul eller pakke og regelen som slo til. Argumentene vises aldri.
- Flagg som øker risikoen gir rødt: åpen mot nettverket (`--host 0.0.0.0`, `--listen`), offentlig lenke (`--share`),
  agent uten spørsmål (`--dangerously-skip-permissions`, `--yolo`, `--full-auto`) og `--trust-remote-code`.
  Modellfila etter `-m` vises.
- PowerShell med base64-kodet kode (`-enc`) som bruker AI blir et ukjent AI-spor. Koden pakkes ut i minnet og vises aldri.
- IT kan slå av kommandolinjene med `lesKommandolinjer: false` i `regler.json` eller `LesKommandolinjer` = 0 under
  `HKLM\SOFTWARE\Policies\AISkanner`.
- **Windows-historikk som administrator**, i en egen sjekk:
  - Prefetch for alle programmer: kjent AI kjørt før, AI-biblioteker Python og Node har lastet, og programmer som har
    åpnet `.gguf`- eller `.safetensors`-filer.
  - BAM: siste kjøretid per konto for AI-programmer.
  - Amcache.hve, lest rett fra disken og tolket med en egen leser for registerfiler: sti, versjon, utgiver og SHA-1, også
    for AI som er avinstallert.
  - Siste kjøretid for planlagte oppgaver som starter AI (TaskCache).
  - Hendelse 4688, Sysmon 1 og 22 og DNS-loggen i Windows når de er slått på: AI-programmer startet de siste 30
    dagene, og programmer som har slått opp AI-tjenester.
- `AISkanner.Cli --amcache <fil>` leser en kopi av Amcache.hve og viser AI-funnene i den.

### Endret
- Sjekken «Når AI-programmer sist kjørte (admin)», som bare så på en fast liste med programnavn, er erstattet av
  Windows-historikken over. Prefetch og BAM sjekkes nå mot alle reglene.
- Trafikk fra en tolk knyttes til skriptet den kjører, ikke til python.exe.

## [2.25.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 158 av 158.

### Lagt til
- **Målt dekning per disk** i datagrunnlaget: filer og GB søket gikk gjennom, mot GB i bruk på disken, og hvor mange
  filhoder som ble lest. Gjør det mulig å se om fullt søk faktisk dekker PC-en.
- **AI-trafikk fra nettlesere med egen DNS.** Chrome og Edge slår ofte opp navn selv (sikker DNS, DoH), så Windows'
  DNS-buffer mangler navnet og forbindelsen til ChatGPT så ut som en ukjent IP-adresse. Programmet slår nå selv opp
  adressene til de kjente AI-tjenestene og kjenner igjen forbindelsen når nettleseren har tjenesten i nettverkslageret
  sitt. Om sikker DNS er på, står i datagrunnlaget.
- **Låste filer leses rett fra disken** som administrator (for eksempel `WebCacheV01.dat`), bare lesing.
- Nytt utfall i datagrunnlaget: **«dekket av annen sjekk»** for lenker og mapper som søkes et annet sted.

### Endret
- **Fullt søk går gjennom alt**, også Windows-mappa, papirkurven, `Config.Msi` og `System Volume Information`.
  Lenkene `All Users`, `Default User` og `Documents and Settings`, og Program Files og ProgramData, står som «dekket av
  annen sjekk» i stedet for «hoppet over».
- Porter som ikke svarer på HTTP, er «sjekket, ingenting der» i stedet for «tidsgrense». Windows' egne tjenester
  spørres ikke. Fullt søk har ikke lenger tidsgrense for npx-cachen og agentøkter.
- **«Søk igjen»** går tilbake til startskjermen, så man kan velge bruker eller admin og hurtig- eller fullt søk.

## [2.24.0] - 2026-10-29

Nytt utseende. Ingen endring i hva som søkes, hvordan risiko settes eller hva rapporten inneholder.
Ikke testet på Windows ennå.

### Endret
- **Designsystem.** Fem skriftstørrelser (12, 14, 20, 28 og 40 px, Windows 11 sin Fluent-rampe), to vekter og tre
  hjørner (8 px, 14 px og rund). Før var det 21 skriftstørrelser og 15 hjørner. Blått brukes bare på det som kan
  trykkes, risikofarge bare på prikker og risikolinja. Ukjent er en rød ring, så den skilles fra Høy uten å lese farge.
  Ingen etiketter med STORE BOKSTAVER. Bare systemfonter.
- **Startskjermen** har ett spørsmål og én knapp: sirkelen søker som bruker, ringen rundt som admin, forklart i én
  linje. Hurtigsøk eller fullt søk er en liten bryter. Revisjonsloggen og forklaringen av hva som søkes ligger under
  «Hva søkes?». Står revisjonsloggen på, sier bunnlinja det.
- **Resultatet** er gruppert etter risiko (Høy, Ukjent, Middels, Lav). Gruppetallet, tallet i risikolinja og
  overskriften teller de samme radene. Hver rad har navn, type og sted på to linjer, og hvor dataene går til høyre.
  Typelinja under overskriften er fjernet, typen står på hver rad. Rapporten er uendret.
- **Funn, Nettverk og Datagrunnlag** er tre faner. Knappen heter «Lagre rapport».
- **Detaljen** åpnes ved siden av lista, så lista blir stående. Kommer fra og sender til står i én flyt, så hvorfor.
  Modell-ID og de andre linjene om modellen ligger bak «Detaljer». Filstier vises i vanlig skrift.
- **Datagrunnlag → Oversikt** viser alt søket sjekket som én stablet linje: lest, ingenting der, hoppet over og ikke
  dekket (med nektet, låst og resten forklart). Delene summerer til tallet over og til fanen «Alt søket sjekket».
  Nuller i tabellen er svake. «Regler og bevis» heter «Regler».
- **Bunnlinja** er kortere: oppstart, søketid, hurtig eller fullt, bruker eller admin, og om noe er lagret.
  Sikkerhetshull nevnes bare mens de sjekkes eller hvis de ikke ble sjekket.
- Språkvalget står alltid øverst til høyre.

## [2.23.1] - 2026-10-29

### Rettet
- Datagrunnlag: fanen «Alt søket leste» talte linjer i lista, mens flisene i Oversikt talte alt som ble sjekket, så de
  to tallene var ulike. Fanen heter nå «Alt søket sjekket» og viser samme tall som flisene til sammen. Lista sier hvor
  mange av dem som bare er talt (filer i en mappe) og ikke har egen linje.

## [2.23.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 155 av 155.

### Lagt til
- **Versjon på funnene.** Lest fra det som står på PC-en: programfila (`ProductVersion`), lista over installerte
  programmer (`DisplayVersion`), Microsoft Store-pakken, utvidelsens `manifest.json`, GGUF-feltet `general.version`,
  revisjonen i Hugging Face-lageret og versjonsmappa til nettleserens egen modell. Vises ved navnet i lista, i
  detaljene og i rapporten med hvor den er lest fra. Står ingen versjon på PC-en, vises ingen.
- **AI som gjemmer seg.** Et AI-program som kjører under et annet navn enn det produsenten ga programfila
  (`OriginalFilename`/`InternalName`), blir funnet og merket rødt. Modellfiler som er merket skjult, har endelsen til en
  film, et bilde eller et dokument, eller ligger i en skjult datastrøm (ADS, bare i fullt søk, strømmer på minst 50 MB),
  merkes rødt med forklaring. IT-godkjenning overstyrer ikke disse merkene.
- **Som administrator: lesing for sikkerhetskopi.** `SeBackupPrivilege`, som administratoren allerede har, slås på for
  søket. Mapper og filer som er låst for alle andre, kan da listes og filhodet leses. Bare lesing; ingen rettigheter
  eller filer endres. Står i datagrunnlaget.
- **Prosesser Windows nekter å åpne** får programstien fra Windows' prosessliste (`SystemProcessIdInformation`) uten at
  prosessen åpnes.
- **OneDrive-filer** som bare ligger i skyen, sjekkes på navn og størrelse uten å lastes ned. En modellfil der blir
  «AI-modell i OneDrive».

### Endret
- **Oppstart uten blink.** Vinduet har samme bakgrunn som siden (lys eller mørk etter Windows), mørk tittellinje i mørk
  modus, vises først når startskjermen er tegnet med riktig språk og valg, og innholdet toner mykt inn.
- Fullt søk hopper ikke lenger over buffer-, logg- og spillmapper hos leverandører. Antivirusets egne mapper røres
  fortsatt ikke. Lokale porter får 3 sekunder til å svare i fullt søk (0,8 i hurtigsøk).
- Datagrunnlag: «finnes ikke» heter nå «sjekket, ingenting der». Det er steder som er sjekket og er tomme, ikke hull.
- Hovedsiden til selskaper som står på lista (for eksempel mistral.ai og x.ai) vises ikke lenger som «ukjent
  AI-nettsted». Bruken telles på tjenestene deres (Le Chat, API-konsollen).

### Rettet
- Datagrunnlag: med én sjekk valgt viste filterknappene tall for hele søket, så en knapp kunne vise et tall mens lista var tom.
  Tallene gjelder nå den valgte sjekken.

## [2.22.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 152 av 152.

### Lagt til
- **Alle nettlesere på PC-en, ikke bare de kjente.** Chromium-nettlesere finnes på `User Data\Local State` (bare at
  fila finnes), for eksempel Comet, Arc, Yandex, Chromium og Thorium. Firefox-varianter finnes med `profiles.ini`
  (LibreWolf, Waterfox, Zen, Floorp og Firefox fra Microsoft Store). Utvidelser, AI-nettsteder i historikken og
  innebygde modeller sjekkes i alle. Thunderbird tas ikke med.
- **AI bygget inn i flere nettlesere:**
  - Leo i Brave, med IT-policyen `BraveAIChatEnabled` (grønn når IT har slått den av);
  - Aria i Opera, Opera GX og Opera Air;
  - AI-chatbot i sidefeltet i Firefox og varianter (`browser.ml.chat.provider` i `prefs.js`, bare `browser.ml.*` leses);
  - lokale AI-modeller som Firefox har lastet ned (også ONNX uten endelse i nettleserens lagring).
- **Nye regler:** Comet (AI-nettleser fra Perplexity), AI-agenter i terminalen (opencode, Goose, GitHub Copilot CLI,
  Qwen Code, Amp, Crush), Kiro, møteapper (Granola, Krisp) og møteopptakere som nettleserutvidelser (Otter, Fireflies,
  tl;dv, Read AI). Hver regel har en `kilde`.
- `--kontroll` har en ny linje for nettlesere og de nye reglene, også at Thunderbird og «Read Aloud» ikke treffer.

## [2.21.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 140 av 140.

### Lagt til
- **Fullt søk av PC.** Nytt valg på startskjermen over søkeknappen: «Hurtigsøk» (sekunder, din profil og de kjente
  AI-stedene) eller «Fullt søk av PC» (minutter). Fullt søk bruker de samme reglene, men går gjennom:
  - alle brukerprofiler i `C:\Users`, også AppData og mapper som starter med punktum (unntatt `.git`, `.svn`, `.hg`);
  - alt i roten av C:\ (unntatt Windows, papirkurv og systemmapper; Program Files og ProgramData har egen sjekk);
  - alle faste og flyttbare disker (USB, SD-kort), uten dybdegrense. Nettverksdisker tas ikke med;
  - filhodet til alle filer over 20 MB uansett endelse, så en modell omdøpt til .mp4, .zip eller .png blir funnet;
  - programstien i planlagte oppgaver (`System32\Tasks`, bare `<Command>`, aldri argumentene; krever som regel admin);
  - Run/RunOnce og installerte programmer for andre brukere som er logget inn.
  Tidsgrensen på disken er 30 minutter i stedet for 45 sekunder. Mens søket går, viser skjermen antall mapper og tid
  brukt. Bunnlinjen sier «Fullt søk av PC» eller «Hurtigsøk». Som vanlig bruker hoppes mapper uten tilgang over, og
  Datagrunnlag viser hvilke. Valget følger med når programmet startes på nytt som admin (`--fullt`). CLI: `--fullt`.
- Begge søkene følger modellmapper flyttet med `OLLAMA_MODELS`, `HF_HOME`, `HF_HUB_CACHE` og `TRANSFORMERS_CACHE`.
- `--kontroll` har en ny linje for fullt søk: en modell omdøpt til .mp4 og en i en punktum-mappe finnes bare med fullt søk.

### Rettet
- Siste nullable-advarsel i CI (`Hovedvindu.cs`).

## [2.20.0] - 2026-10-29

Ikke testet på Windows ennå. `--kontroll` gir 138 av 138.

### Rettet
- **«Søk som admin» med IT-konto søkte i feil profil.** Når admin ble godkjent med en annen konto, søkte programmet i
  IT-kontoens profil, register og nettlesere. Nå finner det brukeren som er logget inn på skjermen (Windows-økta), og
  søker i den brukerens profil og register (`HKEY_USERS\<SID>`). Stiene kommer fra registeret til brukeren
  (Volatile Environment, ProfileList). AI-nøkler telles bare fra brukerens register, aldri fra IT-kontoens miljø.
  Bunnlinjen, rapporten og revisjonsloggen sier hvem søket gjaldt, og hvem som godkjente. Kjøres CLI-en som SYSTEM
  (Intune), gjelder søket den som er logget inn på skjermen. Ny fil: `Bruker.cs`.
- **«1 av N»-pilen under LIGGER HER virket ikke.** Første forsøk på å få plass til alt nullstilte siden. Nå holder
  «1 av N» seg stille når man blar, og venstre/høyre-pil på tastaturet virker også.
- **To vinduer ved oppstart.** Vinduet holdes skjult (DWM) til siden er tegnet, så man ser bare ett vindu. Vises uansett
  etter 3 sekunder.
- **Datagrunnlag:** Windows sine kompatibilitetslenker i profilen (Mine dokumenter, Cookies, Maler, Recent, Programdata,
  Lokale innstillinger, AndrMask …) sto som «nektet tilgang». Nå står de som «kompatibilitetslenke, innholdet søkt i
  <ekte sti>», og teller ikke som ikke dekket. Lenker i roten av profilen følges ikke lenger (som i resten av søket).
  Beskyttede prosesser (csrss, dwm, fontdrvhost, LsaIso …) står som «beskyttet Windows-prosess etter navn (ikke AI)».
- **CI:** `actions/checkout@v5`, `actions/setup-dotnet@v5` og `actions/upload-artifact@v6` (Node 24). Nullable-advarslene
  i `Yara/Kontekst.cs`, `Yara/Strenger.cs` og `Skanner.cs` er rettet; bygget har ingen kodeadvarsler.

## [2.19.12] - 2026-10-29

Venter på test på Windows.

### Rettet
- **Tallene stemmer.** Overskriften, linja under og risikolinja teller de samme radene. Hver rad i tabellen er ett
  funn, og hvert funn står i nøyaktig én art og én risikogruppe (`Oversikt.Art`, `Oversikt.Risikogruppe`). Før kunne
  overskriften bli større enn Høy + Middels + Lav: samleradene «Mulige AI-nettsteder (N)» og «Flere AI-modeller (N)»
  ble telt som N i overskriften, men som én rad i risikolinja.
- **Ukjent er en egen gruppe** ved siden av Høy, Middels og Lav: ukjent AI, ukjente AI-spor og mulige AI-nettsteder.
  Ukjent er fortsatt alltid rød (samme farge, stripete i baren) og står som «Ukjent» i risikokolonnen. Rapporten viser
  «🔴 UKJENT» på slike rader og et eget tall for ukjent i toppen. JSON-rapporten har `telling`, `risikogruppe` og `art`.
- Hvert mulige AI-nettsted er sin egen rad («Mulig AI-nettsted: …»), og hver lokal AI-modell er sin egen rad. Det er
  ingen samlerader lenger. Revisjonsloggen skriver bare «Mulig AI-nettsted», aldri domenet.
- AI-regler fra IT står i linja under overskriften som «sett med AI-regler fra IT», siden raden vises i tabellen.
- Ny linje i `--kontroll`: tallene skal stemme med radene, både i kontrollsporene og i et sett med alle slags rader.

## [2.19.11] - 2026-10-28

Venter på test på Windows.

### Endret
- Overskriften heter «lokale AI-funn på PC» i stedet for «AI-funn», så det er klart at alt er funnet på denne PC-en
  (filer, nettleserdata og programmer). Samme tekst står øverst i rapporten.

## [2.19.10] - 2026-10-28

Venter på test på Windows.

### Endret
- **Overskriften er alle AI-funn**, og linja under viser hva de er: lokale AI-modeller først, så nettsteder,
  utvidelser, apper og agenter, programmer med innebygd AI og ukjente spor. Summen av linja er tallet i overskriften.
  Før sto bare de lokale AI-modellene i overskriften, og det var uklart hva tallet betydde når resten var langt større.
  Samme tekst står øverst i rapporten.
- Når det bare er én eller to lokale AI-modeller, står navnet i parentes (for eksempel språkmodellen i Chrome).

### Rettet
- **Samme komponent blir én rad.** Leverandørfunn med navn fra regelfila får ikke lenger utgiveren bak navnet, så
  to kopier der den ene er signert «Microsoft Windows» og den andre «Microsoft Corporation» ikke blir to rader.
  Utgiveren kortes til firmaet (`Firma`), og versjonsnummer på slutten av pakkenavn fjernes (`UtenVersjon`). Hver
  mappe står fortsatt i detaljene, og raden sier hvor mange mapper den gjelder.
- **Windows App SDK (Windows ML)** er en kjent leverandørkomponent. `Microsoft.WindowsAppRuntime.1.8`, `.2` osv.
  er versjoner av samme pakke, og blir én rad. Kilde i `regler.json`.

## [2.19.9] - 2026-10-28

Gjennomgang av falske AI-funn i reglene for skygge-AI, nettsteder og nettverk. Venter på test på Windows.
Hver endret regel har kilde i `regler.json` eller i en kommentar, og en linje i `--kontroll` (blokka «Falske treff»).

### Endret
- **Overskriften teller bare AI-modeller som kan kjøres for seg selv**: modellfiler på disk, farlige modellfiler,
  språkmodellen i nettleseren og ukjente modellfiler. Små modeller som en leverandør har bygget inn i et program
  (ONNX i Office, Teams, Bilder, Paint, drivere) eller i nettleseren (tale, oversettelse, svindelvern) ble før telt
  som én AI-modell per fil. Nå telles hvert slikt program én gang, som «program med innebygd AI» i linja under
  overskriften (`Funn.Innebygde`, `Oversikt.Telling`). Funnene er de samme, og risikoen er uendret.
- Leverandørfunn skriver «innebygde modellfiler» i stedet for «AI-modeller».

### Rettet
- **DirectML alene gir ikke lenger et AI-funn.** DirectML følger med Edge, WebView2, Teams, spill og videoprogrammer
  som aldri kjører en AI-modell. Det teller bare sammen med en ekte AI-motor (ONNX Runtime, llama.cpp osv.) eller
  modellfiler (`BareGrafikkMotor`).
- **Microsoft 365-startsiden er ikke Copilot.** `m365.cloud.microsoft` er startsiden for Microsoft 365 (tidligere
  portal.office.com) og ga «Microsoft 365 Copilot» for alle som åpner Office på nett. Bare `copilot.cloud.microsoft`
  teller nå. Eksemplet i `godkjent-ai.txt` og `docs/REGELFILER.md` er rettet.
- **Presentasjonssider er ikke bruk av AI.** Et besøk på `devin.ai`, `cognition.ai`, `mistral.ai`, `x.ai` eller
  `groq.com` ga et AI-nettsted. Nå teller bare stedene der tjenesten brukes: `app.devin.ai`, `console.mistral.ai`,
  `grok.com`, `console.x.ai`, `console.groq.com` og `chat.groq.com`. `auth.mistral.ai` er fjernet, fordi Le Chat
  bruker den samme innloggingen, så én bruk ble to funn (Mistral og Mistral Le Chat).
- **Små lagrede data teller ikke som bruk.** Et nettsted som bare har lagret under 1 MB (statistikk eller
  innloggingsstatus fra ett besøk) og ellers ikke er brukt, blir ikke et funn.
- **Edge sine egne småmodeller er kjent**: `AutofillAiModelCache`, `ProvenanceDataTensors` og
  `Edge Techscam Detection`. Før kunne de bli «Ukjent AI-modell i Edge» (rød).
- **Nettverk: hele `volces.com` er ikke AI.** Det er Volcano Engine-skyen (lagring, CDN). Bare Doubao-API-et
  `ark.cn-beijing.volces.com` teller.
- **Zip-filer med en data-mappe er ikke PyTorch-modeller.** Gjenkjenningen krever nå oppsettet PyTorch selv lager
  (`<navn>/data.pkl`, `<navn>/data/0`, `<navn>/version`). Før kunne en `.nupkg`, `.vsix` eller `.jar` over 20 MB
  bli en rød modell.

## [2.19.8] - 2026-10-28

Ikke testet på Windows ennå. `--kontroll` gir 104 av 104.

### Endret
- **De fire knappene øverst til høyre tar mye mindre plass.** Høyde 32 px (8 pt-rutenett, som Apple og Material 3).
  Nettverk og Datagrunnlag er nå én segmentkontroll (samme form som språkvalget); den åpne visningen er en hvit pille,
  og nytt trykk lukker den som før. Søk igjen er en lys tonal knapp. Last ned rapport er eneste fylte knapp, så den
  viktigste handlingen er tydeligst.
- **Roligere farger for lang bruk.** Ingen ren svart eller ren hvit flate: bakgrunn `#f2f2f5`/`#111113`, tekst
  `#1d1d1f`/`#e6e6eb`. Trafikklyset er beholdt, men tonet ned (rød `#d65a50`, gul `#d9a032`, grønn `#4aa56a`).
  Fargene er delt i tre roller: signal (prikker og streker), myk (bakgrunn bak merker) og tekst (mørkere/lysere
  variant som er lett å lese).
- **All tekst oppfyller WCAG 2.2 AA (minst 4,5:1).** Målt blant annet: hvit på blå knapp 5,9:1 (lys) og 5,1:1 (mørk),
  rød tekst `#b3261e` på hvitt 6,5:1, gul tekst `#875400` 6,4:1, grønn tekst `#1b7339` 5,9:1. På de myke merkebakgrunnene er
  laveste verdi 5,3:1.

## [2.19.7] - 2026-10-28

Ikke testet på Windows. `--kontroll` gir 104 av 104.

### Rettet
- **De kinesiske reglene fra 2.19.6 er sjekket mot kilder på nettet i dag, og hver regel har fått en `kilde`-URL.**
  Rettet: Vidu bruker `vidu.io` (ikke vidu.com/vidu.cn), Baidu ERNIE bruker også `wenxin.baidu.com` (ernie.baidu.com
  fjernet). Fjernet fordi de ikke kunne bekreftes: `yuewen.cn`, `moonshot.cn`, `tongyi.com`, `api.01.ai` og
  `modelscope.ai`. Lagt til: `ark.eu-west.bytepluses.com` (BytePlus i Europa) og `token.sensenova.cn` (nyere
  SenseNova-adresse).
- **Trae ga feiltreff på Tencent QQ.** Regelen så etter ordet «trae», og QQ har en fil som heter `TRAE.DLL`. Nå kjennes
  Trae bare igjen på `Trae.exe`, `Trae CN.exe` og installasjonsmappene `%LOCALAPPDATA%\Programs\Trae` og
  `Trae CN`. Kontrollen sjekker at QQ-fila ikke treffer.

## [2.19.6] - 2026-10-28

Ikke testet på Windows. Reglene er kontrollert med `--kontroll` (98 av 98) og selvtesten.

### Lagt til
- **Bedre dekning av kinesisk AI.** Fra før: DeepSeek, Qwen, Kimi, Doubao, Zhipu/GLM, MiniMax, Kling, Baidu ERNIE-API og
  modellfamiliene Qwen, DeepSeek, GLM, Yi, Kimi, InternLM, Baichuan og MiniCPM. Nytt:
  - Nettsteder: ERNIE/Yiyan (Baidu), Yuanbao og Hunyuan (Tencent), Coze og Jimeng/Dreamina (ByteDance), StepFun/Yuewen,
    01.AI, Baichuan, iFlytek Spark, SenseChat, Vidu. Flere adresser for Kimi (kimi.ai, moonshot.cn), Qwen (qwen.ai,
    tongyi.com) og Doubao (cici.com, utenlandsversjonen).
  - API-er brukt av programmer: Tencent Hunyuan, BytePlus ModelArk og Coze (ByteDance), Trae/MarsCode, StepFun, 01.AI,
    Baichuan, iFlytek Spark, SenseNova, SiliconFlow (kinesisk drift av DeepSeek og Qwen) og ModelScope (Alibabas
    modellbibliotek, der modeller lastes ned fra Kina).
  - Programmer og utvidelser: Trae (ByteDances AI-IDE), Doubao, Yuanbao, Qwen/Tongyi Lingma, Kimi, Baidu Comate,
    CodeGeeX, Tencent CodeBuddy og iFlyCode.
  - Modellfamilier på arkitektur: Hunyuan (Tencent), ERNIE 4.5 (Baidu), Seed-OSS (ByteDance), MiniMax-M2, Ling/Ring
    (Ant Group) og dots.llm (rednote). Qwen3-Next, Qwen3-VL-MoE, GLM-4V og InternVL legges til eksisterende familier.
    Ordforrådsstørrelse er ikke lagt inn for de nye; de kjennes igjen på arkitektur eller navn.
  - Selskap og land for de nye navnene, så «Kommer fra» viser Kina og riktig selskap.
- **Kontroll av reglene for Kina** i `--kontroll`: 26 vertsnavn skal treffe en tjeneste i Kina med høy risiko, 12
  vanlige kinesiske nettsteder (baidu.com, qq.com, aliyun.com, tiktok.com, capcut.com …) skal ikke treffe, 6 program-
  og utvidelsesstier skal kjennes igjen og 3 skal ikke (blant annet en bruker som heter Kimi), og 20 arkitekturer skal
  peke entydig på en kinesisk familie. I tillegg: et AI-program som sender til DeepSeek, blir rødt med «Sender data
  til Kina».

Data som sendes til Kina, var allerede høy risiko (Kina står på lista over høyrisikoland). En kinesisk modell som
kjører lokalt, vises fortsatt som «Kommer fra Kina» og «Kjører lokalt, data sendes ikke dit»; det er ikke det samme som
at data sendes til Kina.

Kilder: leverandørenes egne nettsteder og API-dokumentasjon, og arkitekturnavnene i llama.cpp og Hugging Face
transformers. Adressene er ikke slått opp på nettet av programmet.

## [2.19.5] - 2026-10-28

Ikke testet på Windows. Visningen er testet i nettleser, bredt og smalt vindu, norsk og engelsk.

### Endret
- **Alle valgene samlet til høyre øverst.** Nettverk, Datagrunnlag, Søk igjen og Last ned rapport er fire like
  knapper i én rad, med språkvalget over. Nettverk og Datagrunnlag var små lenker i bunnlinja og så ikke ut som noe
  man kunne trykke på. Den som er åpen, har en ring rundt seg, og et nytt trykk lukker den. I smalt vindu brytes
  raden under overskriften. Bunnlinja har bare status igjen (og «Mål datamengde» når man ikke er administrator).

## [2.19.4] - 2026-10-28

Ikke testet på Windows. Visningen er testet i nettleser med eksempeldata.

### Lagt til
- **Trykk på en rad i Nettverk for å finne opphavet.** Under raden vises prosessen: navn fra filinfo, PID, når den
  startet, hvem som har signert fila (eller at den ikke har gyldig signatur), full sti med «Vis» som åpner mappa, og
  hvem som startet den med sti og resten av kjeden (for eksempel ms-teams ‹ explorer). Er forelderen avsluttet, står
  det. Prosesslista leses fra Windows (Toolhelp), prosesser åpnes bare med minst mulig tilgang. Kommandolinjer leses
  aldri. Ingenting lagres. Samme linjer som «Ligger her»; ingen ny layout.

### Rettet
- **AI-skannerens egen nettleserdel ble vist og talt.** Vinduet bruker WebView2, og msedgewebview2-prosessene den
  starter ble tatt med i Nettverk og i søket. Nå hoppes AI-skanneren og alt den har startet over overalt.
- **msedgewebview2 het «Microsoft Edge Installer».** Navnet på innebygd AI hos leverandører ble tatt fra den største
  exe-fila i mappa, og i WebView2 er det `Installer\setup.exe`. Nå velges ikke installasjons- og oppdateringsprogrammer.
- **WebView2 regnes som en nettleser.** Teams, Outlook og Widgets viser nettsider i WebView2; forbindelsene er deres,
  ikke WebView2-ens. Før ble alle forbindelsene vist som «Kan ikke avgjøre» under WebView2. Nå vises bare de som går
  til AI-tjenester, merket med programmet den kjører i («WebView2 i Microsoft Teams»). Resten telles som nettleser.

## [2.19.3] - 2026-10-28

Ikke testet på Windows. Kjernen er testet på Linux med falske nettbilder, visningen i nettleser med eksempeldata.
Ingen skjermer har endret utseende; bare tekst i felt som fantes fra før.

### Endret
- **Resultatet vises når sjekkene er ferdige, ikke etter lyttevinduet.** Før ventet søket alltid til nettverket var
  lyttet på i 20 sekunder (`--lytt`), så søketiden var aldri under 20 s. Nå vises resultatet straks sjekkene er ferdige
  (på test-PC-en 1,2 s), og lyttingen fortsetter i bakgrunnen. Bunnlinja viser «Lytter på nettverket: N s igjen».
  Når vinduet er gått, oppdateres funnene med alt nettverket viste. Revisjonsloggen skrives først da, med alt.
  Kommandolinja (`AISkanner.Cli`) venter som før.
- **Bunnlinja viser oppstartstiden** («Oppstart 1,8 s»): fra Windows startet prosessen til vinduet er klart.
- «Sendt ut» heter nå «Sendt ut under søket», fordi tallet gjelder lyttevinduet, ikke nå. Mens lyttingen går, vises
  ikke noe tall: et halvt tall skal ikke stå ved siden av et helt.
- Oppstart: reglene lastes og gamle vindusdata ryddes i bakgrunnen, så vinduet ikke venter på dem.
- **Nettverk viser mer.** Kjente AI-programmer fra søket vises med alle forbindelsene sine, også de der vi ikke kan
  avgjøre tjenesten. Det står «Kan ikke avgjøre» og «adressen har ikke noe navn i DNS-bufferen», ikke en gjetning.
  Det samme gjelder et program som snakker med en AI-tjeneste: alle forbindelsene dets vises. Går forbindelsene til
  flere land, står antall land, ikke ett av dem.
- Nettverk sier hvorfor noe ikke vises: antall andre forbindelser og hvor mange av dem som er fra nettlesere (navnet
  kan ha gått ut av DNS-bufferen, eller nettleseren bruker DNS over HTTPS), og antall åpne UDP-porter hos nettlesere og
  AI-programmer (kan være QUIC/HTTP/3, som ikke synes). Tom liste sier at AI-nettsteder fra historikken ikke trenger
  være åpne nå.

### Rettet
- Datamengde: lyttingen i bakgrunnen, Nettverk og Følg med kan måle samme forbindelse samtidig. Før kunne den som
  ble lukket først, slå av telleren for de andre. Nå slås telleren av først når den siste er ferdig.
- Lest to ganger (først resultatet, så hele lyttevinduet) gir ikke doble linjer eller gamle tall ved siden av nye.

## [2.19.2] - 2026-10-28

Ikke testet på Windows.

### Rettet
- **Mulig årsak til at 2.19 og 2.19.1 ikke kom i gang på Windows.** I 2.19 ble lokale porter spurt i 16 tråder som
  hver sto og ventet på svaret (`.GetResult()`), samtidig som de andre sjekkene brukte trådpoolen. På .NET Framework
  4.8 kan det sulte ut trådpoolen, så tidsavbruddene og hele søket stopper opp. Nå er spørringene helt asynkrone, og
  ingen tråd står og venter. Samme porter, adresser og tidsgrense som før.

## [2.19.1] - 2026-10-28

Ikke testet på Windows.

### Endret
- **Søkesirkelen viser 0–100 %.** Prosenten regnes ut fra faktisk fremdrift: ferdige sjekker (70 %), hvor lenge
  lyttevinduet har lyttet mot lengden (25 %) og analysen til slutt (5 %). Den går aldri bakover og når 100 % først når
  søket er ferdig. `AISkanner.Cli --prosent` skriver prosenten til standard feil.

### Rettet
- Telleren for ferdige sjekker ble aldri talt opp når ingen lyttet på den (`steg?.Report(Interlocked.Increment(...))`
  hoppet over hele kallet). Ingen synlig feil før nå, men prosenten hadde stått på 0.

## [2.19.0] - 2026-10-28

Ikke testet på Windows. Visningen er testet i nettleser med eksempeldata, kjernen med et falskt nettbilde på Linux.

### Lagt til
- **Nettverk (live).** Ny knapp nederst i resultatet: hvilke programmer som snakker med AI-tjenester akkurat nå, med
  AI-tjeneste, vertsnavn, land eller CDN og antall forbindelser, og som administrator sendt og mottatt per sekund i et
  diagram (alle, eller trykk på en rad for ett program). Ukjente programmer står øverst i rødt. Oppdateres hvert sekund
  bare mens visningen er åpen. Ingen pakkefangst, ingen driver, ingenting lagres. UDP og QUIC står som blindsone.
- `AISkanner.Cli --nettverk`: tre avlesninger som JSON (virker også med `--test-nett`).

### Endret
- **«Spør lokale programmer» er raskere.** Portene spørres samtidig (16 om gangen), og en port som ikke svarer innen
  0,8 s, spørres ikke om de to andre adressene. Mange porter som ikke svarer, gir ikke lenger lang ventetid.
  Samme porter og adresser som før.

## [2.18.1] - 2026-10-27

Ikke testet på Windows. Testet i nettleser med data fra en falsk PC-profil.

### Rettet
- **Ingenting i Datagrunnlag kunne trykkes på.** Nå åpner hvert tall i Oversikt (lest, finnes ikke, nektet tilgang,
  låst, stoppet av antivirus, hoppet over, tidsgrense, feil) lista over nøyaktig de stedene, med sjekk og grunn. En rad
  i «Per sjekk» åpner alt den sjekken rørte, og et tall i raden åpner bare det utfallet. En linje i lista åpner stedet på
  kartet med infovinduet.
- Ting som før bare ble talt, har nå sti og grunn: mapper i gjennomgangen (dybdegrense, mapper med punktum, tidsgrense,
  skyfiler per mappe), leverandørmapper, prosesser (nektet, systemprosess, sikkerhetsprosess) og filer over 1 MB.
  Filer som leses inne i en mappe, telles fortsatt bare per mappe. Lista sier hvor mange som bare er talt.

## [2.18.0] - 2026-10-27

Ikke testet på Windows. Kartvisningen er testet i nettleser med data fra en falsk PC-profil.

### Lagt til
- **Kart i Datagrunnlag**, som SpaceSniffer: alle steder søket rørte (disk, register, nettverk og annet) som klikkbare
  fliser. Størrelsen er antall ting søket så på eller samlet filstørrelse (bryter «Antall/Størrelse»), fargen er høyeste
  risiko på stedet eller under, og stiplet kant betyr at noe ikke ble lest. Klikk for å gå inn, brødsmuler for å gå ut.
  Infovinduet viser full sti, antall, størrelse, utfall, sjekker, merknader og funn, og et funn åpnes med ett klikk.
  Bare i minnet. Kommer aldri i rapporten eller revisjonsloggen.
- Gjennomgangen av disken teller nå filer og samlet størrelse per mappe (bare i minnet, til kartet).
- Selvtest: stier, registernøkler og porter havner riktig på kartet.

## [2.17.1] - 2026-10-27

Ikke testet på Windows. 2.17.0 startet på én ekte Windows-PC uten nye funn; om alarmene virker der, er ikke bekreftet.

### Lagt til
- **Kontrollmodus: `AISkanner.exe --kontroll`** (og `AISkanner.Cli --kontroll`, exit-kode 1 ved feil). Lager kjente,
  ufarlige spor i en midlertidig mappe under `%TEMP%`, kjører de samme sjekkene mot den mappa, viser OK/FEIL for hver
  av 29 alarmer pluss en sjekk av at ingen nøkler, kommandoer eller øktinnhold kom med, og sletter mappa. Ingenting
  lagres, ingenting sendes. Uten dette kan «ingen funn» ikke skilles fra «sjekken virker ikke».
  `Kontroller-alarmene.cmd` i zip-fila starter den med dobbeltklikk.
  Ikke kontrollert: symlinker, Prefetch/BAM, Run-nøkkelen og ekte nettverkstabeller (nettverksreglene kjøres mot et
  kunstig nettbilde).
- **Flere MCP-plasseringer:** Claude fra Microsoft Store (`%LOCALAPPDATA%\Packages\*Claude*\LocalCache\Roaming\Claude`),
  Windsurf (`.codeium\windsurf\mcp_config.json`), LM Studio (`.lmstudio\mcp.json`), VS Code Insiders (`mcp.json`),
  og Cline og Roo Code (`globalStorage` under Code, Code - Insiders, Cursor og Windsurf).
- Selvtest: kontrollmodus skal gi 30 av 30.

## [2.17.0] - 2026-10-27

Ikke testet på Windows.

### Lagt til
- **Lyttevindu.** TCP-tabellen leses hvert 250. ms og DNS-bufferen hvert 2. sekund i minst 20 sekunder mens søket
  går, så korte AI-kall også blir sett. Ingen pakkefangst, ingenting lagres. `--lytt 0-60` endrer lengden (0 = ett
  øyeblikksbilde som før). Bare TCP: UDP og QUIC (HTTP/3) står som blindsone i rapporten.
- **AI-server brukt fra annen maskin** (Ukjent AI-spor, rødt): forbindelse inn til porten en lokal AI-server lytter på
  (Ollama, LM Studio m.fl.) fra en annen adresse enn PC-en. Viser klient, land, tid og datamengde (admin).
- **Ukjent program snakker med AI** (Ukjent AI-spor, rødt): program uten kjent utgiver, eller fra Nedlastinger/Temp,
  med forbindelse til en AI-tjeneste. Kjente utgivere vises som før som skygge-AI.
- **Følg med.** Hake i detaljene til et funn viser datamengden sendt og mottatt per sekund i et diagram, de siste
  2 minuttene, mens vinduet er åpent. Krever administrator for datamengde; uten vises antall forbindelser. Lagres
  ikke og logges ikke.
- **Flere ukjente AI-spor** fra studien om AI-misbruk. Alle røde «Ukjent AI-spor», bare metadata:
  - Hooks i Claude Code (bare hendelse og første ord i kommandoen), oppgaver i `.vscode\tasks.json` som kjører når
    mappa åpnes, og kjørbare skript rett i `.claude\` eller `.vscode\`.
  - `enableAllProjectMcpServers`, `enabledMcpjsonServers` og `WebFetch` uten grense eller mot uttakstjenester.
    MCP-servere som kjører kode skrevet rett i oppsettet (`node -e`, `python -c`).
  - Symlinker og junctions i prosjektmapper som peker inn i agentoppsett (målet leses, lenken følges ikke).
  - Skjulte tegn (null-bredde, tag-tegn, retningsstyring) i `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`,
    `.cursor\rules\*.mdc`, `copilot-instructions.md` m.fl. Bare antallet vises.
  - `.gemini\.env` i prosjektmapper (bare at den finnes).
  - Ferdigheter og tillegg (`.claude\skills`, `.claude\plugins`, `.codex\skills`, OpenClaw) med nedlasting og
    kjøring av kode, lange base64-blokker, passordbeskyttede zip-filer eller uttakstjenester.
  - Fjernkode fra Hugging Face som har kjørt (`transformers_modules`), modellkode som bruker nettet, og Ollama-modeller
    fra ukjente registre.
  - AI-agenter som startes av seg selv med farlige flagg (`--dangerously-skip-permissions`, `--yolo` m.fl.) fra
    Run-nøkkelen, Oppstart-mappa, PowerShell-profiler og `.bashrc`. Bare agent og flagg vises.
  - Flere AI-agenter startet uten menneske innen samme minutt.
  - Ukjent program på PC-en som bruker den lokale AI-serveren (127.0.0.1:11434 eller 1234).
  - Nettleserutvidelser som ikke er AI, men har tilgang til ChatGPT, Claude, Gemini m.fl., og kjente dårlige ID-er.
  - Kjente filer (`iocFiler`) og domener i DNS-bufferen (`iocDomener`) fra AI-misbruk, og pip-pakker i kjente
    dårlige versjoner (litellm 1.82.7 og 1.82.8). Typosquat-pakker (`claud-code`, `cloude-code`) i alle versjoner.
  - Modellfiler (.pt, .pth, .bin, .ckpt) som egentlig er 7z-arkiver (nullifAI).
  - MCP-verktøy i npx-cachen med skjulte tegn eller `<IMPORTANT>`-blokker.
- Nye blindsoner i rapporten: prompt injection uten agentlogg, lesing av nøkkelfiler uten revisjon, MCP-servere som
  endrer seg etter godkjenning, AI-nettlesere i agentmodus og kommandolinjer.

### Ikke bygget
- Kommandolinjene til programmer som kjører (WMI) og kommandoer i Windows-hendelseslogger (Sysmon 1, 4688, 4104).
  Programmet leser aldri kommandolinjer.

### Rettet
- Agentøkter: en melding fra brukeren ble talt to ganger når linja hadde både `"type":"user"` og `"role":"user"`,
  så økter uten menneske ble ikke sett.

## [2.16.0] - 2026-10-27

Ikke testet på Windows.

### Lagt til
- **Ukjente AI-spor**, en fjerde gruppe i resultatet og rapporten. Oppsett og logger etter AI-agenter og AI-tjenester
  der vi ikke vet hvem som satte dem opp eller hvorfor. Alle er «Ukjent AI-spor» og røde, også om IT har godkjent
  navnet. Programmet sier aldri at PC-en er angrepet. Rapporten og revisjonsloggen sier «fant spor (N)» eller
  «fant ingen spor».
  - MCP-servere i Claude Desktop, Claude Code, Cursor, VS Code, Gemini CLI og Codex, også i prosjektmapper
    (`.mcp.json`, `.vscode\mcp.json`). MCP-servere på IT-lista hoppes over. `env` (der nøklene ligger) leses aldri.
  - «Godkjenn alt»: `bypassPermissions` og `Bash` uten å spørre i Claude Code, `approval_policy = "never"` og
    `danger-full-access` i Codex, `chat.tools.autoApprove` i VS Code og Cursor (CVE-2025-53773).
  - Ollama brukt fra andre maskiner: klientadresser i `server.log` som ikke er denne PC-en, med første og siste
    tid. LM Studio: andre adresser i serverloggen.
  - Agentøkter i Claude Code, Codex, Gemini CLI og GitHub Copilot: bare tider, antall og om en økt nevner nøkler
    (`.ssh`, `.aws`, `.env` m.fl.), henter tokens, laster ned og kjører kode, sletter mye eller lager GitHub-repo.
    Bare økter med slike treff blir spor. Teksten i økta beholdes aldri. Av med `--uten-agentlogger`.
  - Skript i Oppstart, Temp og ProgramData som snakker med en AI-tjeneste og har en API-nøkkel i seg. Nøkkelen vises ikke.
  - Kjente dårlige pakkeversjoner fra `regler.json` (`daarligeVersjoner`): nx (s1ngularity), postmark-mcp,
    @bitwarden/cli og Amazon Q-utvidelsen, i globale npm-pakker, npm-logger og VS Code-utvidelser.
  - Som administrator: når AI-programmer sist kjørte, fra Prefetch og BAM.
  - Blindsoner står i rapporten. WSL er installert, men filene der leses ikke.
- Kolonnen «Viktigst» og telleren øverst viser sporene.

### Endret
- Revisjonsloggen viser om agentøkter ble sjekket, antall spor og blindsoner.

## [2.15.2] - 2026-10-26

Ikke testet på Windows.

### Rettet
- **2.15.1 startet ikke.** DLL-ene lå i undermappa `bibliotek` og ble lastet med `Assembly.LoadFrom`. Filer fra en
  nedlastet zip har merket «fra Internett» (Zone.Identifier), og .NET Framework nekter `LoadFrom` på slike filer
  (`NotSupportedException`), mens vanlig lasting ved siden av programmet virker. Mappa er tilbake til oppsettet fra
  2.15.0, som er det som har kjørt på Windows: DLL-er og `AISkanner.exe.config` ved siden av `AISkanner.exe`.
- **Programmet forsvinner aldri uten forklaring.** Alle feil ved oppstart og under kjøring vises i en melding med
  versjon, mappe og hele feilen. Ctrl+C kopierer teksten.
- `LES-MEG-FORST.txt` i mappa sier hvilken fil som er programmet (`AISkanner.exe`, type «Program») og at
  `AISkanner.exe.config` er innstillinger. Byggeløypa sjekker at det er nøyaktig én `.exe`.

## [2.15.1] - 2026-10-26

Ikke testet på Windows. Startet ikke på Windows, se 2.15.2.

### Rettet
- **Ryddig programmappe, ingen `AISkanner.exe.config`.** Med skjulte filendelser i Windows så `AISkanner.exe.config`
  ut som en ekstra `AISkanner.exe`, og den kan ikke kjøres. Nå ligger bare `AISkanner.exe`, `ai-modeller.yar` og
  `godkjent-ai.txt` øverst. Alle DLL-er og `WebView2Loader.dll` ligger i `bibliotek`. Programmet finner dem selv
  (`Program.FinnBibliotek`), uansett versjon, så `.config`-fila med `bindingRedirect` trengs ikke.
- Byggeløypa stopper hvis det havner en `.config` eller mer enn én `.exe` øverst i mappa.

## [2.15.0] - 2026-10-26

Ikke testet på Windows.

### Sikkerhet
- **Godkjent AI med faresignaler ble grønn.** En AI på godkjentlista ble grønn selv om den var åpen mot nettverket
  eller kjørte fra en nedlastingsmappe. Nå blir den rød (åpen mot nettverket, høyrisikoland) eller gul (nedlastinger,
  skjult kode, blokkert av IT), med grunnen «Godkjent av IT, men: …». Tre nye kontroller i selvtesten.

### Lagt til
- **Datagrunnlag (utviklermodus).** «Datagrunnlag» nederst i resultatet viser alt søket prøvde å lese, hvilken sjekk
  som gjorde det og hvordan det gikk: lest, finnes ikke, nektet tilgang, låst, stoppet av antivirus, hoppet over,
  tidsgrense eller feil. Fire faner: Oversikt (totaler, Defender og per sjekk), Ikke dekket (det søket ikke fikk
  lest, og hvorfor), Alt søket leste (med filter per utfall) og Regler og bevis (SHA-256 av programmet og
  regelfilene, og det som aldri leses med vilje). Ingenting av dette lagres.
- **Antivirus.** Feil 225 og 226 fra Windows vises som «stoppet av antivirus». Som administrator leses Defenders egen
  logg (hendelse 1116–1123) for tiden søket kjørte, og hendelser som gjelder dette programmet vises.
- **Revisjonslogg Ja/Nei** på startskjermen. Nei (standard): ingenting lagres. Ja: én ny fil per søk i
  `Dokumenter\AI-skanner\AI-revisjon_<PC>_<dato>_<tid>.txt`, aldri over en gammel. Inneholder versjon, modus,
  start og slutt, SHA-256 av program og regelfiler, tid og utfall per sjekk, Defender, funnene og hver tilgang.
  Siste linje er SHA-256 av alt over. NVD-oppslag legges til sist med ny kontrollsum. Aldri nettadresser, innhold i
  filer eller verdier av nøkler. Valget følger med når programmet starter på nytt som administrator.
- **«Ingen AI i programmet»** på startskjermen, i rapporten, i revisjonsloggen og i datagrunnlaget. Funnene kommer fra
  faste regler (filformat, YARA, `regler.json` og kjente adresser), ikke fra en AI-modell.
- Rapporten har en linje med datagrunnlaget: hvor mye som ble lest, og hva som ikke ble dekket.
- `AISkanner.Cli --revisjon` skriver revisjonsloggen, `--datagrunnlag` skriver datagrunnlaget som JSON.
- Selvtesten har 14 nye kontroller (nå 29): feilkoder til utfall (225/226 = antivirus), register-stier oversettes ikke,
  SHA-256, og at revisjonsloggen aldri får domener eller besøk fra nettleseren.

### Endret
- **Rapporten viser hvor AI brukes i nettleseren, også i JSON.** Tekstrapporten tok allerede med AI-domene, nettleser
  og profil, besøk og tider, mens JSON fjernet dem. Nå er de like: begge viser nettleser-AI, og begge mangler hele
  adresser og sidetitler. Regelen er at nettleserdata analyseres i minnet og aldri lagres av seg selv; bare rapporten
  brukeren selv laster ned, inneholder disse funnene. Revisjonsloggen har bare navn, type og sted.
- En sjekk som krasjer, vises nå som «feil» under Ikke dekket i stedet for å se ut som «ingen funn».
- Språkvalget følger med når programmet starter på nytt som administrator.
- Samme versjonsnummer i programmet, kjernen og kommandolinjen (`src/Directory.Build.props`).

## [2.14.0] - 2026-10-26

Ikke testet på Windows.

### Lagt til
- **Kart og IP-adresser.** Trykk på en AI etter søket: «Hvor dataene går» viser et verdenskart med landene
  dataene går til (rødt for høyrisikoland, blått ellers), en nål med antall IP-adresser per land, og hver
  IP-adresse med sitt land og datamengde. Kartet er innebygd (Natural Earth via world-atlas, 82 kB) og henter
  ingenting fra nettet. Kartet viser land, ikke by. `verktoy/lag-kart.py` lager kartdataene.
- **CDN-er.** IP-adresser bak Cloudflare, Fastly og Amazon CloudFront (kjente adresseblokker), og bak Akamai,
  Azure Front Door og Google (navn i DNS-bufferen), får ikke noe land. Der står det «Tjenesten skjuler IP-en»
  og hvilken CDN, fordi adressen bare er nærmeste kantserver.
- Selvtesten (`--selvtest`) kjører i byggeløypa.
- **Norsk og engelsk.** Flagg for NO og EN øverst til høyre på startskjermen og ved knappene i resultatet. Ett trykk
  bytter all tekst med en gang, også funnene som vises, uten nytt søk. Rapporten lastes ned på valgt språk
  (`AI-report_…` på engelsk). Språket følger Windows til brukeren velger selv, og valget lagres ikke.
  Tekstene fra skanneren oversettes med ordlista `src/AISkanner.Core/engelsk.txt`. Tekst som mangler i lista, står
  igjen på norsk. `AISkanner.Cli --en` gir rapport og JSON på engelsk.

## [2.13.1] - 2026-10-26

Ikke testet på Windows.

### Sikkerhet
- **Middels: godkjentlista kunne lures med navn som en angriper styrer.** En ukjent AI-utvidelse fikk typen
  «Nettleserutvidelse» og ikke «Ukjent AI». En utvidelse som kalte seg det samme som et godkjent produkt, for eksempel
  «Microsoft 365 Copilot», kunne derfor bli grønn, også med tilgang til alle nettsider. Det samme gjaldt navn på
  prosjektmapper og modeller i mapper med samme navn som et godkjent domene. Nå godkjennes navn bare når de kommer
  fra regelsettet eller fra et gjenkjent nettsted, og domener godkjennes bare mot målte forbindelser og nettstedsfunn,
  aldri mot filstier (`Risikoregler.Godkjent`).
- Regex i godkjentlista har en tidsgrense på 1 sekund. Den gjelder også `AISkanner.Cli`.

### Rettet
- Ukjente lokale AI-servere får nå typen «Ukjent AI». Sjekken `k == "AI-server"` i `Risikoregler.Type` slo aldri til
  og er fjernet. Serverne var røde også før, men som skygge-AI.

## [2.13.0] - 2026-10-26

Ikke testet på Windows.

### Endret
- Overskriften teller AI-modeller, og under står nettsteder, utvidelser og apper, for eksempel «N AI-modeller,
  N AI-nettsteder, N nettleserutvidelser og N AI-apper og agenter» (`Oversikt.Telling`). Samme telling står i rapporten.
- Rapporten får et eget filnavn med tidspunkt ned til sekundet (`AI-rapport_<PC>_<dato>_<tid>.txt`) og skriver aldri
  over en rapport som finnes fra før. Da legges (2), (3) osv. til.
- Toppen av rapporten viser når søket ble kjørt og når rapporten ble laget.

### Lagt til
- IP-adressene hver forbindelse gikk til (høyst 8 per mål), i detaljvisningen.

## [2.12.0] - 2026-10-26

Ikke testet på Windows.

### Lagt til
- Startskjermen har to valg i én knapp: den runde knappen i midten søker som bruker, og ringen rundt søker som
  administrator. Søk som administrator starter programmet på nytt med Windows' godkjenning (UAC) og gir mer data:
  datamengde, og programmer som kjører som administrator.
- Resultatet og rapporten viser om søket ble kjørt som bruker eller som administrator («Søkt som»).
- Melding når brukeren sier nei i godkjenningen.

## [2.11.0] - 2026-10-26

Sikkerhetsherding etter en gjennomgang av koden i 2.10. Brukeren ser ingen endring. Ikke testet på Windows.

### Sikkerhet
- **Høy: DLL-kapring.** Vinduet tar arbeidsmappa ut av DLL-søket (`SetDefaultDllDirectories` og `SetDllDirectory("")`
  i `src/AISkanner/Program.cs`). En falsk `winsqlite3.dll`, `iphlpapi.dll`, `wintrust.dll` eller `dnsapi.dll` i mappa
  programmet startes fra, blir ikke lenger lastet. `WebView2Loader.dll` lastes fortsatt fra programmappa.
- **Middels: falsk Utforsker.** «Vis» starter Utforsker med full sti (`%WINDIR%\explorer.exe`) i stedet for bare
  `explorer.exe` (`Hovedvindu.cs`).
- **Middels: minnebruk ved lokal HTTP.** Svar fra lokale porter er begrenset til 4 MB (`MaxResponseContentBufferSize`
  i `Sanntid.cs` og `AISkanner.Cli`). Et ondsinnet lokalt program kan ikke lenger fylle minnet med et svar på flere GB.
- **Lav: sti-traversering.** Språkkoden (`default_locale`) fra manifestet til en nettleserutvidelse må være en vanlig
  språkkode før den brukes i en sti (`Skanner.cs`). `..\..\` kan ikke lenger peke ut av `_locales`.
- **Lav: ReDoS.** Alle regulære uttrykk i vinduet har en tidsgrense på 2 sekunder. En ondsinnet `ai-modeller.yar`
  kan ikke lenger henge programmet.
- DLL-søket og regex-tidsgrensen gjelder bare vinduet. Kommandolinjen er et IT-verktøy for kontrollerte miljøer.
- Parserne for GGUF, safetensors, ONNX og pickle er testet med misformede og store filer. De hang ikke og krasjet ikke.

### Kjente svakheter som ikke er rettet
- Godkjentlista sammenlignet med navn og stier som brukeren selv kan styre (middels). Rettet i 2.13.1.
- Programmet er ikke signert.

## [2.10.0] - 2026-10-26

Ikke testet på Windows.

### Lagt til
- Fast risikomodell i `Risikoregler.cs`, som kjøres som siste steg i hvert søk. Hvert funn får **Type**,
  **Risikogrunn** (én setning) og **Kommer fra** (selskap og land).
- Godkjentliste fra IT. Filen `godkjent-ai.txt` ligger ved siden av programmet (ett navn eller domene per linje),
  eller IT kan bruke `godkjentAi` i `regler.json`. AI på lista blir grønn.
- `selskapsland` i `regler.json`: kobler selskap og produkt til hjemland, for feltet «Kommer fra».
- Ny resultatskjerm med kolonnene **AI · Risiko · Type · Ligger her · Sender data til**.
  Over tabellen står antallet og en rød, gul og grønn fordelingslinje.
- I detaljvisningen står **Kommer fra → Sender data til**, risikogrunnen og hele stien.

### Endret
- **Ukjent AI og skygge-AI er alltid røde.** Skygge-AI er *AI som ikke er lagt inn av Windows, en signert
  leverandør eller IT*. Det gjelder AI-nettsteder, nettleserutvidelser, agenter, kodeverktøy, AI-apper,
  modeller brukeren har lagt inn selv og AI-nøkler. På en jobb-PC uten godkjentliste blir derfor de fleste funn røde.
- Godkjentlista overstyrer aldri disse: ukjent AI, farlige modellfiler og AI som sender data til høyrisikoland.
  De er røde uansett.
- Høyrisikoland i «Sender data til» vises i rødt.

## [2.9.1] - 2026-10-26

### Endret
- Tekstrapporten viser risiko som 🔴 HØY, 🟡 MIDDELS og 🟢 LAV per AI, både i oversikten og i detaljene,
  og antallet per farge øverst. Fila lagres som UTF-8 med BOM, så Notisblokk viser fargene. Ellers er rapporten uendret.

## [2.9.0] - 2026-10-26

Ikke testet på Windows.

### Lagt til
- Full YARA-motor i C# (`src/AISkanner.Core/Yara/`), uten libyara og uten ekstra DLL:
  - YARA 4-syntaks: tekststrenger (`nocase`, `wide`, `ascii`, `fullword`, `xor`, `base64`, `base64wide`, `private`),
    hex med jokertegn, nibbles, `~`, hopp og alternativer, og regex (`/i`, `/s`, også `wide`).
  - Alle betingelser: `of`, `for … of`, `for … in`, `at`, `in`, `#`, `@`, `!`, regning, bitoperasjoner,
    `contains` og `matches`, regelreferanser, regelsett, `global` og `private`.
  - Modulene `pe`, `math`, `hash`, `time`, `string` og `console`.
  - Alle strenger i alle regler søkes i én runde (Aho-Corasick). Lange hex-hopp deles i kjeder, slik YARA gjør det.
- `AISkanner.Cli --yara regler.yar fil …`, som skriver samme format som `yara.exe`.
- `verktoy/sammenlign-yara.py` og `tests/yara/`, som sammenligner motoren med ekte YARA.
  Testet mot YARA 4.5.4 med 134 regler, uten avvik.

### Endret
- YARA-leseren fra 2.7 (`Yara.cs`) er erstattet av den nye motoren.
- Fart: en tung test på en fil på 100 MB gikk ned fra 11 s til 3 s. AI-reglene tar 0,6 s på samme fil.

### Kjente begrensninger
- Modulene `dotnet`, `elf`, `macho`, `magic` og `cuckoo` mangler. De gir «udefinert», slik YARA gjør uten modulen.
- `pe.version_info` er tom, og signaturfeltene i `pe` er forenklet.

## [2.8.0] - 2026-10-26

Ikke testet på Windows.

### Lagt til
- `Oversikt.cs`: én kort linje per funn med det viktigste på høyst tre ord, for eksempel «Skjult kode»,
  «Sender til Kina», «Ukjent utgiver» eller «AI-API åpent». Det farligste vinner. Lokasjonen vises kort,
  for eksempel «Chrome», «Nedlastinger» eller «Program Files\Lenovo».
- Tekstrapporten starter med samme oversiktstabell som skjermen.

### Endret
- Resultatet er én tabell med kolonnene **AI-modell · Risiko · Lokasjon**. Hele stien vises når du trykker på en rad.

### Fjernet
- Alle råd («Gjør:» og «Hva du bør gjøre»), både på skjermen og i rapporten. Programmet viser bare data.
- Fliser og sidebytting i resultatvisningen.

## [2.7.0] - 2026-10-26

Sist kjørt på ekte Windows. Gemini Nano i Chrome og OpenVINO-modeller fra Lenovo ble funnet.

### Lagt til
- YARA-regler for AI-modeller i den åpne fila `ai-modeller.yar`. Den er bygget inn i programmet, og ligger
  også ved siden av exe-fila, der IT kan endre den. Den kan kjøres med vanlig `yara.exe`.
  - Formatregler for GGUF, safetensors, PyTorch, pickle, Keras (HDF5 og v3), TFLite og OpenVINO.
  - Regler for farlige modeller: pickle som kaller `os.system`, `subprocess`, `exec`, `eval` eller nettverk,
    Keras Lambda-lag, GGUF-chatmaler med Python-internals (CVE-2024-34359) og Windows-programmer eller skall
    gjemt i modellfiler.
- Reglene kjøres på alle modeller som blir funnet (første 8 MB og siste 1 MB). Små pickle-, PyTorch-, Keras- og
  NumPy-filer sjekkes også (første 1 MB), men bare når de første 8 bytene viser riktig format.
- Nytt rødt funn: «Farlig AI-modellfil».
- Startskjermen sier at søket tar med kjente sikkerhetshull, AI-API-er og YARA-regler.

## [2.6.0] - 2026-10-26

### Lagt til
- 25 flere kjente AI-tjenester i `regler.json`, blant dem Mistral, Devin og ZeroGPT.

### Endret
- Søket starter rett fra én knapp, uten valg. Sjekken av sårbarheter (NVD) og historikk er alltid med.
  IT kan slå dem av med `--uten-nvd` og `--uten-historikk`.
- NVD-oppslaget kjører i bakgrunnen etter at resultatet vises, så søket venter ikke på nettet.
- Resultatet er én liste sortert etter risiko.
- Ukjente `.ai`- og «gpt»-nettsteder er samlet i ett gult funn, «Mulige AI-nettsteder (N)». Før ble hvert av dem
  et eget rødt funn. Et domenenavn alene beviser ikke at et nettsted er AI.
- Når flere domener i lista passer, vinner det lengste.

### Fjernet
- Bryterne på startskjermen.
- Faner og risikofilter i resultatet.

## [2.5.0] - 2026-10-26

Kjørt på ekte Windows.

### Lagt til
- **AI lagt inn av leverandører** (`Leverandor.cs`). Søket går gjennom AppData (Local, Roaming, LocalLow),
  ProgramData, Program Files, Program Files (x86), WindowsApps og SystemApps, og stopper etter maks 40 sekunder.
  AI kjennes igjen på modellfiler (`.onnx`, `.ort`, `.tflite`, `.litertlm`, `.dlc`, `.engine`, `.pte`, OpenVINO og andre)
  og på AI-motorer. Funnene samles per program.
- Leverandøren bekreftes med Authenticode (`Signatur.cs`, `WinVerifyTrust` uten nettoppslag) eller med
  `AppxManifest.xml` i mapper som bare Windows kan skrive til. Firmanavn i filinfo alene regnes ikke som bekreftet,
  og ubekreftet leverandør gir rødt.
- `leverandorAi` i `regler.json`. Oppføringer med `bekreftet: false` har mappenavn som ikke er sjekket på en ekte PC.
- **AI-API-er i Chrome og Edge** (`NettleserApi.cs`): status for Prompt API, Summarizer, Writer, Rewriter,
  Proofreader, Classifier og LiteRT-LM. Statusen bygger på policyer, nettleserversjon og modellmapper.
- Lesing av AI-flagg fra `Local State` (`Skanner.LesNettleserflagg`). Funksjonen er **av** som standard, og kan
  bare slås på med `--flagg` i kommandolinjeversjonen.
- Rapporten viser søketid og de tregeste sjekkene.

### Endret
- Nettlesermodeller og leverandør-AI er flyttet til gruppen «Skjult på PC».
- Filgjennomgangen fra 2.0 hopper over AppData, siden leverandørsøket dekker den.

### Ikke bekreftet
- At Chrome bruker policyen `BuiltInAIAPIsEnabled` på samme måte som Edge, de eksakte flaggnavnene, og om det
  finnes et eget «Classifier API».

## [2.4.0] - 2026-10-26

### Lagt til
- `NettleserModeller.cs`: finner AI-modeller som nettleserne laster ned, i alle Chromium-nettlesere og kanaler.
  Kjente mapper er blant andre `OptGuideOnDeviceModel` (Gemini Nano), `EdgeLLMOnDeviceModel`, `TranslateKit`,
  `screen_ai` og `SODA`. Ukjente mapper med modellinnhold blir også funnet.
- Første og siste besøk per AI-nettsted og profil, fra `visits` og `moz_historyvisits`.
- Første og siste spor per funn (`Funn.Forst` og `Funn.Sist`), på skjermen og i rapporten.
- Piltastene blar mellom funn. Funnsteder vises side for side, uten rulling.

### Endret
- Ryddigere oppsett med mindre tomrom.
- Maks 500 detaljer per funn.

### Rettet
- Gemini Nano ble ikke funnet av 2.3. Søket etter nettlesermodeller er skrevet om, og 2.7 finner modellen. Hva som var feil i 2.3, er ikke bekreftet.

## [2.3.0] - 2026-10-26

Kjørt på ekte Windows.

### Lagt til
- Tre grupper: **Lokal AI**, **Nettleser** og **Skjult på PC** (`Funn.Gruppe`), både i vinduet og i rapporten.
- Modellidentitet (`ModellGjenkjenning.cs`):
  - Familien (Llama, Qwen, DeepSeek, Gemma, Phi, Mistral m.fl.) leses av arkitektur og ordforråd, også når fila har fått nytt navn.
  - Når navnet og innholdet peker på hver sin familie, vises begge, for eksempel «DeepSeek, bygget på Qwen».
  - Sikkerhetsnivåene er *sikker*, *sannsynlig*, *bare navnet* og *ukjent*.
  - Modell-ID er SHA-256 når Ollama eller Hugging Face har lagret fila under hashen. Ellers er det et fingeravtrykk
    av størrelse, første MB og siste MB.
  - Ollama-manifester gir modellnavn.
- `modellfamilier` i `regler.json`.
- Registeret (`Register.cs`): AI-regler fra IT under `SOFTWARE\Policies`, lenkeprotokoller, programmer som åpner
  modellfiler, `App Paths`, høyreklikkmenyer, `RunOnce`, `OLLAMA_HOST` og `OLLAMA_ORIGINS`, og om mappen til Windows Recall finnes.

### Endret
- Ingenting lagres mellom søk. WebView2-mappen er unik per kjøring (`%LOCALAPPDATA%\AISkanner\Vindu-<pid>`),
  slettes når programmet lukkes, og rester ryddes ved neste start.

## [2.2.0] - 2026-10-26

### Lagt til
- **Hvor AI sender data** (`Trafikk.cs`, `Nettverk.cs`, `IpLand.cs`):
  - Åpne TCP-forbindelser per prosess hentes med `GetExtendedTcpTable`.
  - Vertsnavn hentes fra Windows' DNS-buffer, uten nye oppslag.
  - Land hentes fra en innebygd tabell (DB-IP Lite, CC BY 4.0, `ipland.bin`, bygget med `verktoy/lag-ipland.py`).
  - Cloudflare-adresser merkes «via Cloudflare».
- Målt datamengde per forbindelse med administrator (`SetPerTcpConnectionEStats`). Programmet startes på nytt
  med UAC bare når brukeren trykker på det.
- Nytt funn «Skygge-AI»: et program som ikke er kjent som AI, men som snakker med en AI-tjeneste.
- `aiTjenester` og `hoyrisikoLand` (CN, RU, IR, KP, BY) i `regler.json`, og `land` på `aiNettsteder`.
- Tekstrapport (.txt, åpnes i Notisblokk) og JSON-rapport.
- `AISkanner.Cli --test-nett fil.json` for å teste trafikklogikken uten Windows.

### Endret
- Alt på én skjerm uten rulling: fliser, en liste med sider og et detaljpanel.
- Søkeskjermen viser bare «Søker etter AI…».

## [2.1.0] - 2026-10-26

### Endret
- Programmet er krympet fra 159 MB (67 MB zip) til rundt 2 MB. Det bruker nå .NET Framework 4.8 i stedet for
  innebygd .NET 8. Kjernebiblioteket bygges for både `net48` og `net8.0`, og `net8.0` brukes bare til tester på Linux.
- Nettleserhistorikken leses med SQLite-motoren i Windows (`winsqlite3.dll`, `WinSqlite.cs`), med `immutable`
  og skrivebeskyttet tilgang. Fila kopieres aldri.
- Alle sjekker kjører samtidig, og tiden for hver måles (`Skanner.Tider`). Filgjennomgangen stopper etter 45 sekunder.

### Lagt til
- Hvert funn viser hvor det ble funnet. Knappen «Vis» åpner stien i Utforsker, men bare stier som hører til et funn.
- Byggeløypa stopper hvis programmet blir større enn 10 MB.

### Fjernet
- Innebygd .NET 8-kjøretid og `Microsoft.Data.Sqlite`.

## [2.0.0] - 2026-10-26

### Lagt til
- Nytt utseende i Apple-stil, med HTML i Microsoft Edge WebView2 (`ui/index.html`, bygget inn i programmet).
  Mørk modus følger Windows.
- AI gjenkjennes på innhold og oppførsel, ikke på navn (`Sanntid.cs`, `ModellFormat.cs`):
  - modellfiler gjenkjennes på de første bytene (GGUF, safetensors, PyTorch, ONNX, TFLite, Keras), med navn og
    størrelse fra GGUF- og safetensors-hodet
  - AI-motorer ved siden av programmer som kjører
  - lokale AI-servere: maks tre lesende `GET`-kall til `127.0.0.1`
  - Python- og Node-prosjekter med AI- og agentbiblioteker
  - AI-nøkler i miljøvariabler (bare navnet, aldri verdien)
- Nettleser-AI (`Nettsteder.cs`):
  - AI-nettsteder fra bruksspor (`site_engagement` i `Preferences`) og historikk. Bare AI-domener, antall besøk
    og tidspunkt beholdes, og bare i minnet.
  - Ukjente AI-nettsteder.
  - AI-modeller lagret av nettsider i IndexedDB.
- Ukjent AI er alltid rød.
- `Funn.Privat`: funn fra nettleserdata vises på skjermen, men lagres aldri automatisk.

### Endret
- Lista over kjente produkter gir bare navn og risiko. Den er ikke lenger hovedmåten AI blir funnet på.

### Fjernet
- Vinduet i WinForms.

## [0.4.0] - 2026-10-26

Kjørt på ekte Windows (jobb-PC, testen var godkjent og IT var varslet).

### Sikkerhet
- Prosesser åpnes nå med minst mulig tilgang (`PROCESS_QUERY_LIMITED_INFORMATION` og `QueryFullProcessImageName`).
  Versjon 0.3 åpnet alle prosesser med lesetilgang til minnet, også `lsass`. Det ligner passordtyveri og fikk
  Microsoft Defender og Sentinel til å stoppe programmet. Systemprosesser og Defender-prosesser røres ikke.
- Programmet pakker seg ikke lenger ut til `%TEMP%` og er ikke komprimert. Begge deler ligner skadevare.

## [0.3.0] - 2026-10-26

### Lagt til
- Skrevet om fra PowerShell til C#/.NET 8: `AISkanner.Core` (skannemotoren), `AISkanner` (WinForms-vindu) og
  `AISkanner.Cli` (JSON, exit-kode 0/1/2).
- `regler.json` er bygget inn i programmet. En egen `regler.json` ved siden av exe-fila overstyrer den.
- Kjører alltid som vanlig bruker (`asInvoker`).
- Kildekoden er gjort klar for åpen kildekode: MIT-lisens, README, `CODE_SIGNING.md` og byggeløype i GitHub Actions.
- Sjekken av sårbarheter mot NVD er flyttet over fra PowerShell (`Nvd.cs`). Den sender bare produktordet fra regelfila.

### Fjernet
- PowerShell-skript og `.bat`-oppstart.

### Kjent problem
- Ble stoppet av Microsoft Defender og Sentinel på en jobb-PC. Rettet i 0.4.

## [0.2.0] - 2026-10-26

PowerShell-prototype. Utgått.

### Lagt til
- `IT-INFO.txt` med hva skanneren leser, og hasher for godkjenning.

### Sikkerhet
- Sperre i koden mot å åpne passord, informasjonskapsler og historikk i nettleseren.

## [0.1.0] - 2026-10-26

PowerShell-prototype. Utgått.

### Lagt til
- Første versjon: ett vindu med én Søk-knapp og funn sortert etter rød, gul og grønn risiko.
- Finner lokale AI-verktøy, modellfiler, AI-servere åpne mot nettverket, AI-agenter (Claude Code, Codex, Cursor),
  AI-utvidelser i nettleserne og innebygd AI i Chrome og Edge.
- Risikoregler i en egen fil som kan redigeres.
- Valgfri sjekk av kjente sårbarheter mot NVD. Den sender bare produktnavnet.

[Ikke utgitt]: https://github.com/OWNER/ai-skanner/compare/v2.13.1...HEAD
[2.13.1]: https://github.com/OWNER/ai-skanner/compare/v2.13.0...v2.13.1
[2.13.0]: https://github.com/OWNER/ai-skanner/compare/v2.12.0...v2.13.0
[2.12.0]: https://github.com/OWNER/ai-skanner/compare/v2.11.0...v2.12.0
[2.11.0]: https://github.com/OWNER/ai-skanner/compare/v2.10.0...v2.11.0
[2.10.0]: https://github.com/OWNER/ai-skanner/compare/v2.9.1...v2.10.0
[2.9.1]: https://github.com/OWNER/ai-skanner/compare/v2.9.0...v2.9.1
[2.9.0]: https://github.com/OWNER/ai-skanner/compare/v2.8.0...v2.9.0
[2.8.0]: https://github.com/OWNER/ai-skanner/compare/v2.7.0...v2.8.0
[2.7.0]: https://github.com/OWNER/ai-skanner/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/OWNER/ai-skanner/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/OWNER/ai-skanner/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/OWNER/ai-skanner/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/OWNER/ai-skanner/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/OWNER/ai-skanner/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/OWNER/ai-skanner/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/OWNER/ai-skanner/compare/v0.4.0...v2.0.0
[0.4.0]: https://github.com/OWNER/ai-skanner/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/OWNER/ai-skanner/releases/tag/v0.3.0
