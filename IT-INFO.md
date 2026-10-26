# AI-skanner: informasjon til IT og sikkerhet

## Formål
Kartlegger AI-verktøy på én Windows-PC (lokal AI, skygge-AI, nettleser-AI) og viser dem sortert etter risiko.
Kjøres manuelt av innlogget bruker. Ingen installasjon, ingen tjeneste, ingen persistens. Trenger ikke admin.
Administrator brukes bare hvis brukeren selv trykker «Mål datamengde» (se under).

## Hvordan den kjører
`AISkanner.exe` er et .NET Framework 4.8-program (følger med Windows 10 og 11). Hele mappa er rundt 3,5 MB.
Det installeres ikke, pakker ikke ut noe til `%TEMP%`, er ikke komprimert, starter ingen skript eller kommandolinjer, og kjører som vanlig bruker (`asInvoker`).
Vinduet vises med Microsoft Edge WebView2 (som nye Outlook og Teams). WebView2 starter sine egne `msedgewebview2.exe`-prosesser
og bruker en midlertidig mappe som slettes når programmet lukkes (se «Ingenting lagres»). Siden er bygd inn i programmet, laster ingenting fra nett og kan ikke navigere bort.

## Hva den leser (kun lesing, ingenting endres)
- Prosessliste og filsti for prosesser (`PROCESS_QUERY_LIMITED_INFORMATION` + `QueryFullProcessImageName`).
  Minnet til andre prosesser leses aldri. lsass, csrss, winlogon og Defender-prosesser åpnes ikke.
- Filnavn i mappa til programmer som kjører, for å se etter AI-motorer (onnxruntime, ggml/llama, torch, OpenVINO, DirectML m.fl.)
- Installerte programmer (Uninstall-nøkler), Store-apper (nøkkelnavn), tjenester, Run-nøkler, Oppstart-mapper, navn på planlagte oppgaver
- Lyttende TCP-porter med eierprosess (`GetExtendedTcpTable`). For porter på localhost/0.0.0.0 eid av vanlige brukerprosesser
  sendes maks tre lesende `GET`-kall til `127.0.0.1` (`/api/tags`, `/v1/models`, `/sdapi/v1/sd-models`) for å se om programmet er en AI-server.
- Navn (aldri verdier) på miljøvariabler som `OPENAI_API_KEY`, og om `%USERPROFILE%\.cache\huggingface\token` finnes (åpnes ikke)
- Gjennomgang av brukerprofilen (utenom AppData) og andre faste disker (ikke Windows, Program Files eller ProgramData):
  - for filer over 20 MB leses de første 64 bytene for å kjenne igjen AI-modellformater (GGUF, safetensors, PyTorch, ONNX, TFLite, Keras).
    For GGUF og safetensors leses også metadata-hodet (modellnavn, arkitektur, antall parametre). Selve modellvektene leses ikke.
  - mappenavn i `site-packages` og `node_modules` for å finne AI-biblioteker
  - OneDrive-filer som bare ligger i skyen hoppes over, så ingenting lastes ned.
- Nettlesere (Chrome, Edge, Brave, Vivaldi, Opera, Firefox):
  - `manifest.json` og `messages.json` for utvidelser, `extensions.json` i Firefox
  - `Preferences` (bare nettstedenes bruksscore, `site_engagement`)
  - mappenavn og størrelse under `IndexedDB` og Firefox `storage\default`
  - **historikk** (`History` og `places.sqlite`), hvis brukeren lar bryteren stå på. Filen åpnes direkte, skrivebeskyttet og uten låser.
    Den kopieres aldri. Lesingen bruker SQLite-motoren som følger med Windows (`winsqlite3.dll`). Bare vertsnavn som matcher AI-tjenester, antall besøk og tidspunkt for første og siste besøk (fra `visits`/`moz_historyvisits`) beholdes i minnet. Fulle adresser og titler beholdes ikke.
    Ingenting fra nettleserdata lagres automatisk. Hvis brukeren selv laster ned tekstrapporten, står nettleserfunn med nettleser, profil og nettstedsnavn (aldri hele adresser).
- Policyverdien `GenAILocalFoundationalModelSettings` for Chrome og Edge
- AI-modeller nettleserne laster ned (nytt i 2.4): mappenavn, størrelser og datoer i nettleserdata for Chrome, Edge (alle kanaler), Brave, Vivaldi og Opera,
  f.eks. `OptGuideOnDeviceModel` (Gemini Nano), `TranslateKit`, `screen_ai`, `SODA`. Ukjente mapper med modellfiler kjennes igjen på de første bytene.
- **AI lagt inn av leverandører** (nytt i 2.5): `%LOCALAPPDATA%`, `%APPDATA%`, `AppData\LocalLow`, `%ProgramData%`, `Program Files`, `Program Files (x86)`,
  `Program Files\WindowsApps` og `Windows\SystemApps` gås gjennom (Defender-mapper, cacher, nettleserdata og spillbiblioteker hoppes over, maks 40 sekunder).
  AI kjennes igjen på innholdet: modellfiler (`.onnx`, `.ort`, `.tflite`, `.litertlm`, `.dlc`, `.engine`, `.pte`, OpenVINO `.xml`+`.bin`, og store filer med
  modellformat i de første bytene) og AI-motorer (`onnxruntime`, `DirectML`, `openvino`, `ggml`, `Qnn*` m.fl.). Funnene samles per program.
  Leverandøren bekreftes med **gyldig Authenticode-signatur** (`WinVerifyTrust`, uten tilbakekallingssjekk over nettet) eller med `AppxManifest.xml` i
  mapper bare Windows kan skrive til. Firmanavnet i filinfo alene regnes ikke som bekreftet. Dato lagt inn = eldste opprettelsesdato på AI-filene.
  Ukjent eller ubekreftet leverandør = høy risiko. Kjent leverandør = lav, eller middels hvis modellene er over 500 MB.
- **YARA-regler for AI-modeller** (nytt i 2.7): reglene ligger i den åpne fila `ai-modeller.yar` ved siden av programmet (kan også kjøres med vanlig `yara.exe`;
  IT kan endre eller legge til regler). Kjøres med en innebygd YARA-leser i C# (ingen libyara, ingen ekstra DLL). Leser første 8 MB og siste 1 MB av hver
  modell som blir funnet. Små filer med endelser som `.pt`, `.pth`, `.pkl`, `.ckpt`, `.bin`, `.keras`, `.h5`, `.npy` sjekkes bare hvis de 8 første bytene viser
  pickle, zip, HDF5 eller NumPy, og da bare første 1 MB. Reglene finner pickle som kaller `os.system`/`subprocess`/`exec`/`eval`/nettverk, Keras Lambda-lag,
  GGUF-chatmaler med Python-internals (CVE-2024-34359) og Windows-programmer gjemt i modellfiler. Treff gir rødt funn. Ingenting kjøres, lastes eller endres.
- **Full YARA-motor** (nytt i 2.9): egen C#-motor, fortsatt uten libyara og uten ekstra DLL. Støtter YARA 4-syntaksen: tekst (`nocase`, `wide`, `ascii`,
  `fullword`, `xor`, `base64`, `base64wide`, `private`), hex med jokertegn, nibbles, `~`, hopp og alternativer, regex (`/i`, `/s`, også `wide`),
  alle betingelser (`of`, `for … of`, `for … in`, `at`, `in`, `#`, `@`, `!`, regning, bitoperasjoner, `contains`/`matches` m.fl., regelreferanser og
  regelsett, `global`/`private`) og modulene `pe`, `math`, `hash`, `time`, `string` og `console`. Alle strenger i alle regler søkes i én runde
  (Aho-Corasick), betingelsene er ferdig oversatt før søket, og hex med lange hopp deles i kjeder som i YARA. Testet mot YARA 4.5.4 med 134 regler:
  ingen avvik (`verktoy/sammenlign-yara.py`, `tests/yara/test.yar`). Ikke støttet: modulene `dotnet`, `elf`, `macho`, `magic` og `cuckoo`
  (gir «udefinert», som i YARA uten modulen), `pe.version_info` er tom, og signaturfeltene i `pe` er forenklet. Har `ai-modeller.yar` ved siden av
  programmet en feil, brukes de innebygde reglene, og rapporten sier hvorfor.
- **AI-API-er i Chrome og Edge** (nytt i 2.5): status for Prompt API, Summarizer, Writer, Rewriter, Proofreader, Classifier og LiteRT-LM-motoren.
  Bygger på policyene `GenAILocalFoundationalModelSettings` og `BuiltInAIAPIsEnabled` (HKLM/HKCU), nettleserversjonen (mappenavnet under `Application`),
  og hvilke modellmapper som finnes. Flagg i `chrome://flags` leses ikke som standard, fordi de ligger i filen `Local State` sammen med nettleserens
  krypterte nøkkel. Slås det på, leses bare lista `browser.enabled_labs_experiments` med en strømleser som hopper over alt annet, og bytene nulles ut etterpå.
- **Nettverksforbindelser nå** (nytt i 2.2): etablerte TCP-forbindelser med eierprosess (`GetExtendedTcpTable`, `TCP_TABLE_OWNER_PID_CONNECTIONS`).
  Vertsnavn hentes fra Windows' DNS-buffer (`DnsGetCacheDataTable` og `DnsQuery_W` med `DNS_QUERY_NO_WIRE_QUERY`, samme kilde som `ipconfig /displaydns`).
  Det gjøres ingen nye DNS-oppslag og ingen omvendte oppslag. Land slås opp i en innebygd tabell (IP to Country Lite fra DB-IP.com, CC BY 4.0).
  Nettleserprosesser vises bare med forbindelser til kjente AI-tjenester, aldri annen surfing. Programmer som ikke er kjent som AI,
  men som snakker med en AI-tjeneste (`aiTjenester` i `regler.json`), blir et eget funn.

- **Registeret** (nytt i 2.3), bare lesing: AI-regler fra IT under `SOFTWARE\Policies` (Windows Copilot, Recall, Edge, Chrome, Office),
  lenkeprotokoller (`SOFTWARE\Classes\<navn>` med `URL Protocol`), hvilke programmer som åpner modellfiler (`.gguf`, `.safetensors` m.fl.),
  `App Paths`, høyreklikkmenyer, `RunOnce`, navn på miljøvariabler for AI-nøkler (aldri verdiene), og verdiene til `OLLAMA_HOST`/`OLLAMA_ORIGINS`
  (sier om Ollama er åpen mot nettverket). Om mappen for Windows Recall finnes (innholdet leses ikke). SAM, SECURITY og lagret legitimasjon røres aldri.
- **Modellidentitet** (nytt i 2.3): for hver modellfil leses metadata-hodet (arkitektur, ordforråd, antall lag, «laget fra») og `config.json` ved siden av.
  Modell-ID er SHA-256 når Ollama eller Hugging Face allerede har lagret filen under hashen (ingen ekstra lesing), ellers et fingeravtrykk
  av størrelse + første og siste MB (leser 2 MB per modell). Ollamas manifestfiler leses for å finne modellnavn.

## Ingenting lagres
Hvert søk gjøres fra bunnen av. Programmet har ingen cache, ingen hasher fra før og ingen historikk over søk.
WebView2 trenger en midlertidig mappe mens vinduet er åpent (`%LOCALAPPDATA%\AISkanner\Vindu-<pid>`). Den slettes når programmet lukkes,
og rester etter avbrutte kjøringer slettes ved neste start. Det eneste som blir igjen er rapporten brukeren selv velger å laste ned.

## Måling av datamengde (valgfritt, krever administrator)
Uten administrator viser skanneren hvor AI-programmene er koblet, men ikke hvor mye de sender. Windows gir ikke vanlige brukere tilgang til tellerne.
Trykker brukeren «Ikke målt / Trykk for å måle», startes programmet på nytt via vanlig UAC-spørsmål (`runas`).
Som administrator slår skanneren på Windows' egne TCP-tellere (`SetPerTcpConnectionEStats`, `TcpConnectionEstatsData`, samme som Ressursovervåking)
for forbindelsene som er åpne når søket starter, leser dem når søket er ferdig (`GetPerTcpConnectionEStats`), og slår dem av igjen.
Tallene er byte faktisk sendt og mottatt i måleperioden (typisk 10–30 sekunder), ikke anslag. Forbindelser som åpnes underveis måles ikke.
QUIC/UDP (brukes av noen nettlesere mot Google og Cloudflare) vises ikke, fordi Windows ikke knytter UDP-trafikk til en motpart.

## Hva den aldri leser
Passord (`Login Data`), informasjonskapsler (`Cookies`), `Web Data`, `Local State`, krypteringsnøkler, lommebokdata i utvidelser
(`Local Extension Settings`), verdien av API-nøkler, e-post eller dokumentinnhold.
Håndhevet i koden: `Skanner.LovligeFiler` er de eneste filnavnene som åpnes for lesing av innhold (i tillegg til de første bytene av store filer).

## Nettverk
Til `127.0.0.1` som beskrevet over. Ingen DNS-oppslag, ingen IP-oppslag på nett. Sårbarhetssjekken er alltid med (fra 2.6): etter at resultatet vises,
sendes bare produktordet fra regelfila for kjente produkter som ble funnet (f.eks. `ollama`) til `services.nvd.nist.gov`. Aldri PC-navn, brukernavn eller stier.
Bedriften kan slå den av med `AISkanner.exe --uten-nvd`, og historikken med `--uten-historikk`.

## Personvern på jobb-PC
Historikksøket er innsyn i elektronisk lagret materiale. En arbeidsgiver som bruker skanneren på ansattes PC-er må følge e-postforskriften
og arbeidsmiljølovens regler om kontrolltiltak, eller slå av historikksøket (kommandolinje: `--uten-historikk`).

## Kan EDR reagere?
Lesing av nettleserhistorikk, DNS-bufferen og nettverkstabellen, og gjennomgang av filer, kan ligne rekognosering. Signerte utgivelser og godkjenning på signatur eller hash løser det.

## Godkjenning (allowlist)
Godkjenn på signatur når utgivelsene er signert, ellers på SHA256-hash av `AISkanner.exe` (står i `SHA256.txt`).
