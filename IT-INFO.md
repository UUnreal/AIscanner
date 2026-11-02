# AI-skanner: informasjon til IT og sikkerhet

Gjelder versjon 2.41.0. Endringer per versjon står i [CHANGELOG.md](CHANGELOG.md). Trusselmodell og kjente svakheter
står i [SECURITY.md](SECURITY.md).

## Kort fortalt

- Kartlegger AI på én Windows-PC (lokal AI, skygge-AI og nettleser-AI) og sorterer funnene etter risiko.
- Kjøres manuelt av innlogget bruker. Ingen installasjon, ingen tjeneste og ingen persistens.
- Leser bare. Endrer, sletter og installerer ingenting.
- Trenger ikke administrator. Bare søk som administrator ber om det, og bare når brukeren velger det.
- Sender bare produktord (for eksempel `ollama`) til NVD. Ellers bare `127.0.0.1`.
- Lagrer ingenting mellom søk, med mindre brukeren velger revisjonslogg (se under).
- Har ingen AI-modell. Funnene kommer fra faste regler: filformat, YARA, `regler.json` og kjente adresser.

## Hvordan den kjører

| | |
|---|---|
| Program | `AISkanner.exe`, .NET Framework 4.8 (følger med Windows 10 og 11). Hele mappa er rundt 3,7 MB. |
| Rettigheter | `asInvoker`. Ber aldri om administrator ved oppstart. |
| Vindu | Microsoft Edge WebView2, som nye Outlook og Teams. Starter egne `msedgewebview2.exe`-prosesser. |
| Side | Bygget inn i programmet. Laster ingenting fra nett, kan ikke navigere bort, ingen utviklerverktøy. |
| Utpakking | Ingen. Programmet er ikke komprimert og pakker ingenting ut til `%TEMP%`. |
| Skript | Starter ingen skript, kommandolinjer eller PowerShell. Programmet starter bare `%WINDIR%\explorer.exe` når brukeren trykker «Vis», og seg selv på nytt når brukeren velger å søke som administrator. |
| DLL-er | Arbeidsmappa er tatt ut av DLL-søket (fra 2.11). Systembiblioteker lastes fra System32. DLL-ene ligger ved siden av programmet. Det finnes ingen `AISkanner.exe.config` (fra 2.28.1): programmet godtar selv nyere versjoner av sine egne biblioteker i samme mappe, med samme navn og nøkkel, og lastetesten i byggeløypa kjører programmet fra en mappe merket «fra Internett». Stopper programmet med en feil, vises den i en melding som kan kopieres med Ctrl+C. |

## Hva den leser

Alt er bare lesing. Ingenting endres.

### Prosesser og programmer

- Prosessliste og filsti, med `PROCESS_QUERY_LIMITED_INFORMATION` og `QueryFullProcessImageName`. Nekter Windows å
  åpne prosessen, hentes stien fra Windows' prosessliste (`NtQuerySystemInformation`, `SystemProcessIdInformation`)
  uten å åpne den. **Minnet til andre prosesser leses aldri.** `lsass`, `csrss`, `winlogon` og Defender-prosesser åpnes ikke.
- Versjonsfeltene i programfila (`FileVersionInfo`): produktversjon, og `OriginalFilename`/`InternalName` for å se om
  et AI-program kjører under et annet navn.
- Filnavn i mappa til programmer som kjører, for å finne AI-motorer (`onnxruntime`, `ggml`/`llama`, `torch`,
  `openvino`, `DirectML` m.fl.). `DirectML` alene regnes ikke som AI, fordi det følger med mange programmer som
  aldri kjører en AI-modell.
- Installerte programmer (Uninstall-nøkler), Store-apper (nøkkelnavn), tjenester, Run- og RunOnce-nøkler,
  Oppstart-mapper og navn på planlagte oppgaver.
- Globale npm-pakker og kommandoer i `PATH`, bare om fila finnes.

### Lokale AI-servere

- Lyttende TCP-porter med eierprosess (`GetExtendedTcpTable`).
- For porter på localhost eller `0.0.0.0` som eies av vanlige brukerprosesser, sendes maks tre lesende `GET` til
  `127.0.0.1`: `/api/tags`, `/v1/models` og `/sdapi/v1/sd-models`. Svarer Ollama, spørres også `/api/ps` (hvilke
  modeller som er lastet i minnet nå). Tidsgrense 800 ms, maks 4 MB svar,
  ingen omdirigering og ingen proxy. Maks 80 porter. Portene spørres samtidig, 16 om gangen. Svarer en port ikke innen
  800 ms, prøves ikke de to andre adressene på den porten (det står i Datagrunnlag).

### Filer på disken

- **Brukerprofilen og andre faste disker** (ikke Windows, Program Files, ProgramData eller AppData). Stopper etter 45 sekunder.
- **Fullt søk av PC** (valg på startskjermen, CLI `--fullt`): i tillegg alle brukerprofiler i `C:\Users`, alt i roten av
  C:\ (også `Windows`, `$Recycle.Bin`, `Config.Msi`, `System Volume Information` og `Recovery`; Program Files og
  ProgramData gås gjennom av sjekken for leverandør-AI og står som «dekket av annen sjekk»), alle faste og flyttbare
  disker (USB, SD), uten dybdegrense og med 30 minutters tidsgrense. Lenker (`All Users`, `Documents and Settings`)
  følges ikke; målet søkes direkte og lenken står som «dekket av annen sjekk». Datagrunnlaget viser per disk hvor mange
  filer og hvor mange GB som ble gått gjennom, mot GB i bruk, og hvor mange filhoder som ble lest. Filhodet sjekkes på alle filer over 20 MB uansett endelse. Programstien (`<Command>`) i
  `System32\Tasks` leses; argumentene brukes aldri. Run/RunOnce og avinstallering leses for andre innloggede brukere
  (`HKEY_USERS\<SID>`). Nettverksdisker tas aldri med. Uten admin hoppes mapper uten tilgang over og vises i Datagrunnlag.
- **Flyttede modellmapper:** `OLLAMA_MODELS`, `HF_HOME`, `HF_HUB_CACHE` og `TRANSFORMERS_CACHE` følges i begge søk.
  - Filer over 20 MB: de første 64 bytene, for å kjenne igjen modellformater (GGUF, safetensors, PyTorch, ONNX, TFLite, Keras).
  - GGUF og safetensors: også metadata-hodet (navn, arkitektur, antall parametre). Selve modellvektene leses ikke.
  - Modell-ID: fra filnavnet når Ollama eller Hugging Face har lagret fila under SHA-256. Ellers et fingeravtrykk av
    størrelse, første MB og siste MB (2 MB lesing per modell). `config.json` og Ollama-manifester leses for navn.
  - Mappenavn i `site-packages` og `node_modules`, for å finne AI-biblioteker.
  - Filer i OneDrive som bare ligger i skyen, sjekkes på navn og størrelse og lastes aldri ned.
  - **Låste filer** (feil 32/33, for eksempel `WebCacheV01.dat`) leses som administrator rett fra disken: fila åpnes bare
    for å finne hvor den ligger (`FSCTL_GET_RETRIEVAL_POINTERS`), og de samme klyngene leses fra `\\.\C:`. Bare lesing,
    ingen skyggekopi lages. Komprimerte og krypterte filer leses ikke slik.
- **AI lagt inn av leverandører:** `%LOCALAPPDATA%`, `%APPDATA%`, `AppData\LocalLow`, `%ProgramData%`, `Program Files`,
  `Program Files (x86)`, `Program Files\WindowsApps` og `Windows\SystemApps`. Stopper etter 40 sekunder.
  Defender-mapper, cacher, nettleserdata og spillbiblioteker hoppes over.
  - Modellfiler (`.onnx`, `.ort`, `.tflite`, `.litertlm`, `.dlc`, `.engine`, `.pte`, OpenVINO `.xml` og `.bin`, og store
    filer med modellformat i de første bytene) og AI-motorer, samlet per program.
  - Leverandøren bekreftes med gyldig Authenticode-signatur (`WinVerifyTrust`, uten tilbakekallingssjekk over nett)
    eller med `AppxManifest.xml` i mapper bare Windows kan skrive til. Firmanavn i filinfo alene regnes ikke som bekreftet.
  - Dato lagt inn er eldste opprettelsesdato på AI-filene.
- **YARA-regler** (`ai-modeller.yar`) kjøres på modellfiler som blir funnet:
  - Store modeller: første 8 MB og siste 1 MB.
  - Små filer (`.pt`, `.pth`, `.pkl`, `.ckpt`, `.bin`, `.keras`, `.h5`, `.npy` m.fl., under 200 MB): første 1 MB, men bare
    hvis de første 8 bytene viser pickle, zip, HDF5 eller NumPy.
  - Hele fila leses bare hvis den er under 64 MB og en regel trenger det, for eksempel `hash.sha256(0, filesize)`.
    De innebygde reglene gjør ikke det.
  - Ingenting kjøres, lastes eller pakkes ut.

### Nettlesere

Chrome, Edge (alle kanaler), Brave, Vivaldi, Opera og Firefox, og alle andre nettlesere som finnes på PC-en:
hver Chromium-nettleser (Comet, Arc, Yandex, Chromium, Thorium …) har en mappe `User Data` med fila `Local State`
to nivåer ned i `%LOCALAPPDATA%` eller `%APPDATA%`. Bare at fila finnes sjekkes; `Local State` åpnes ikke.
Firefox-varianter (LibreWolf, Waterfox, Zen, Floorp, Firefox fra Microsoft Store) finnes med `profiles.ini`, der bare
stiene til profilene leses. Thunderbird tas ikke med.

| Fil eller sted | Hva som brukes |
|---|---|
| `manifest.json`, `messages.json` (utvidelser), `extensions.json` (Firefox) | Navn, beskrivelse og tilganger for utvidelser |
| `Preferences` | Bare bruksscore per nettsted (`site_engagement`) |
| `History`, `places.sqlite` | Se under |
| `IndexedDB`, Firefox `storage\default` | Mappenavn og størrelse, for modeller lagret av nettsider |
| `Service Worker\CacheStorage`, `WebStorage` (med `QuotaManager`), `File System`, IndexedDB-blobber, Firefox `caches.sqlite` | Nettstedet, størrelse, dato og filhodet til filer over 1 MB. Adressen i filhodet beholdes bare når den er en modellfil (WebLLM, ONNX, GGUF, TFLite, safetensors); andre adresser forkastes straks. Aldri sideinnhold, samtaler eller skjemadata |
| Modellmapper i brukerdata | Mappenavn, størrelse og dato, for eksempel `OptGuideOnDeviceModel` (Gemini Nano), `EdgeLLMOnDeviceModel`, `TranslateKit`, `screen_ai`, `SODA` |
| Versjonsmappe under `Application` | Nettleserversjon, for AI-API-status |
| `prefs.js` (Firefox og varianter) | Bare `browser.ml.enable`, `browser.ml.chat.enabled` og `browser.ml.chat.provider` (hvilken AI-chatbot sidefeltet bruker) |
| Firefox `storage` | Filer over 5 MB som er AI-modeller (GGUF, ONNX med produsentnavn, TFLite …), for lokale AI-modeller |
| `HKLM`/`HKCU\SOFTWARE\Policies\BraveSoftware\Brave` | `BraveAIChatEnabled`: om IT har slått av Leo |

**Historikk:** fila åpnes direkte, skrivebeskyttet og uten låser (`immutable`), med SQLite-motoren i Windows
(`winsqlite3.dll`). Den kopieres aldri. Bare vertsnavn som matcher AI-tjenester, antall besøk og første og siste
besøk beholdes, og bare i minnet. Fulle adresser og sidetitler beholdes aldri. Kan slås av med `--uten-historikk`.

**AI-flagg** i `chrome://flags` ligger i `Local State`, sammen med nettleserens krypterte nøkkel. Den fila leses
**ikke** av vinduet. Bare `AISkanner.Cli --flagg` leser den, og da bare lista `browser.enabled_labs_experiments`
med en strømleser som hopper over alt annet. Bytene nulles ut etterpå.

### Registeret

- AI-regler fra IT under `SOFTWARE\Policies` (Windows Copilot, Recall, Click to Do, Edge, Chrome, Office), blant dem
  `GenAILocalFoundationalModelSettings`, `BuiltInAIAPIsEnabled`, `HubsSidebarEnabled`, `CopilotPageContext` og `GeminiSettings`.
- Lenkeprotokoller (`SOFTWARE\Classes\<navn>` med `URL Protocol`), programmer som åpner modellfiler
  (`.gguf`, `.safetensors` m.fl.), `App Paths` og høyreklikkmenyer.
- Verdiene til `OLLAMA_HOST` og `OLLAMA_ORIGINS`, som sier om Ollama er åpen mot nettverket.
- Navn (aldri verdier) på miljøvariabler for AI-nøkler, for eksempel `OPENAI_API_KEY`.
- Om mappen for Windows Recall finnes. Innholdet leses ikke.
- Som admin: andre brukeres `NTUSER.DAT` (profiler fra `ProfileList` som ikke er logget inn), lest rett fra disken
  og tolket i minnet. Bare `Run`/`RunOnce`, `Uninstall` og navn (aldri verdier) på miljøvariabler for AI-nøkler.
- SAM, SECURITY og lagret legitimasjon røres aldri.

### Nøkler

Bare *at* en nøkkel finnes: navn på miljøvariabler, og om `%USERPROFILE%\.cache\huggingface\token` finnes.
Fila åpnes ikke, og verdien leses aldri. `.env`-filer (og `.env.local` osv., ikke `.example`, `.sample`,
`.template`) som filgjennomgangen finner, leses linje for linje: bare navnet på AI-nøkler som har en verdi. Verdien
sjekkes bare for om den er tom, og kastes med en gang. Alle nøkkelnavn samles i ett funn.

### Nettverk

- Etablerte TCP-forbindelser med eierprosess (`GetExtendedTcpTable`, `TCP_TABLE_OWNER_PID_CONNECTIONS`, IPv4 og IPv6).
- Vertsnavn fra Windows' DNS-buffer (`DnsGetCacheDataTable` og `DnsQuery_W` med `DNS_QUERY_NO_WIRE_QUERY`, samme
  kilde som `ipconfig /displaydns`). Ingen omvendte oppslag. Skannerens egne oppslag (se under) går utenom Windows og
  havner ikke i bufferen. Står de fleste kjente AI-navnene i bufferen samtidig (rester etter en eldre versjon), brukes
  bufferen ikke som bevis i det søket.
- Land fra en innebygd tabell (IP to Country Lite fra DB-IP.com, CC BY 4.0).
- Eier (ASN og firma) fra en innebygd tabell (DB-IP og RouteViews via ip-location-db, CC BY 4.0). Merket «OSINT»: registrerte data, ikke målt. Ingen IP sendes ut.
- Kartet i resultatet er innebygd (Natural Earth, fri bruk, via world-atlas, ISC). Det viser land, ikke by, og henter
  ingenting fra nettet. IP-adressene vises i vinduet, men lagres ikke.
- IP-adresser bak en CDN får ikke land, fordi adressen bare er nærmeste kantserver. Cloudflare, Fastly og Amazon
  CloudFront kjennes på innebygde adresseblokker. Akamai, Azure Front Door og Google kjennes på navnene i CNAME-kjeden i
  DNS-bufferen (`DNS_QUERY_NO_WIRE_QUERY`, ingen nye oppslag).
- Nettleserprosesser vises bare med forbindelser til kjente AI-tjenester. Annen surfing vises ikke.

### Språk

Vinduet og rapporten finnes på norsk og engelsk. Språket følger Windows (`CurrentUICulture`) til brukeren trykker på
et flagg. Valget lagres ikke. Funnene oversettes i programmet med ordlista `engelsk.txt`, uten nett.

### Ukjente AI-spor

Oppsett og logger med ukjent opphav. Alle blir «Ukjent AI-spor» (rødt), også når IT har godkjent navnet. Bare
metadata kommer ut: filsti, tid, antall og kategori. Ved hver tid står kilden («tid i logglinje», «endringstid på
fil»), fordi endringstider kan forfalskes.

| Hva | Filer | Hva som leses |
|---|---|---|
| MCP-servere | `%APPDATA%\Claude\claude_desktop_config.json` (også Store-utgaven under `%LOCALAPPDATA%\Packages\*Claude*`), Windsurf `.codeium\windsurf\mcp_config.json`, LM Studio `.lmstudio\mcp.json`, Cline og Roo Code i `globalStorage`, VS Code Insiders, `%USERPROFILE%\.claude.json`, `.cursor\mcp.json`, `%APPDATA%\Code\User\mcp.json`, `.gemini\settings.json`, `.codex\config.toml`, Visual Studio `%USERPROFILE%\.mcp.json`, Zed `%APPDATA%\Zed\settings.json` (`context_servers`), Continue `.continue\config.json`, og `.mcp.json`, `.vscode\mcp.json`, `.cursor\mcp.json` i prosjektmapper | Navn, kommando, første argument og vert. Aldri `env`. Kode etter `-enc`/`-c` og alt som ligner en nøkkel vises som «[skjult]». Tilgangskart: hva hver server kan nå (filer, skall, nettleser, nett, database, e-post, sky …), tolket fra navn og kommando. |
| «Godkjenn alt» | `.claude\settings*.json`, `.codex\config.toml`, VS Code og Cursor `settings.json` | Bare `permissions.defaultMode`, `permissions.allow`, `approval_policy`, `sandbox_mode`, `chat.tools.autoApprove` |
| Lokale AI-servere | `%LOCALAPPDATA%\Ollama\server*.log`, `%USERPROFILE%\.lmstudio\server-logs` | Klientadresse, tid og endepunkt per linje. Ikke forespørslene. |
| Agentøkter | `.claude\projects\*.jsonl`, `.codex\sessions\rollout-*.jsonl`, `.gemini\tmp`, VS Code `chatSessions` | Tidsstempler, antall meldinger fra mennesket og treff per kategori. Teksten beholdes aldri. Maks 500 filer per program og 20 sekunder totalt. Av med `--uten-agentlogger`. |
| Skript med AI-nøkkel | `.vbs .js .ps1 .py .bat .cmd` i Oppstart, `%TEMP%` og `%ProgramData%` (ett nivå) | Om fila nevner en AI-tjeneste og har noe som ligner en nøkkel. Nøkkelen vises aldri. |
| Dårlige pakkeversjoner | `%APPDATA%\npm\node_modules\*\package.json`, `%LOCALAPPDATA%\npm-cache\_logs`, `.vscode\extensions` | Navn og versjon mot `daarligeVersjoner` i `regler.json` |
| Kommandolinjer | Tolkere (python, pythonw, node, bun, deno, powershell, pwsh, java, uv, uvx) og programmer som allerede er AI-funn, med `ProcessCommandLineInformation` | Sammenlignes med reglene i minnet og kastes. Vises: skriptfila, modul eller pakke, modellfil og flagg som `--host 0.0.0.0`, `--share`, `--dangerously-skip-permissions`. Aldri resten av argumentene. Kode etter `-enc` pakkes ut i minnet og vises aldri. |
| Skriptet en tolk kjører | Skriptfila fra kommandolinjen (`.py .js .mjs .ts .ps1` …, maks 2 MB) | `import`/`require` av AI-biblioteker, navn på AI-tjenester, om noe ligner en nøkkel. Teksten beholdes aldri. |
| Prefetch (admin) | `C:\Windows\Prefetch\*.pf` | Programnavn, de siste kjøretidene og filnavnene programmet åpnet (AI-biblioteker i `site-packages`/`node_modules`, `.gguf`/`.safetensors`) |
| BAM (admin) | `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings` | Programsti og siste kjøretid per konto, for AI-programmer |
| Amcache (admin) | `C:\Windows\appcompat\Programs\Amcache.hve`, lest rett fra disken og tolket i minnet | Sti, navn, versjon, utgiver og SHA-1 for AI-programmer, også avinstallerte. Transaksjonsloggene leses ikke. |
| Planlagte oppgaver (admin) | `TaskCache` i registeret, `System32\Tasks` | Siste kjøretid for oppgaver som starter AI. Starter oppgaven en tolk eller et skript, leses argumentene i minnet som en kommandolinje, og skriptet sjekkes for AI. |
| Oppstart som er slått av | `Explorer\StartupApproved\Run` og `Run32` (HKCU og HKLM) | Om en oppstart med AI er slått av i Oppgavebehandling, og når |
| Skript i oppstart | Skriptet en Run-oppføring eller oppgave starter (`.ps1 .vbs .js .py .bat .cmd` …, maks 2 MB) | AI-biblioteker, navn på AI-tjenester, om noe ligner en nøkkel. Teksten beholdes aldri. |
| Hvem og hvordan | Tilgangsbilletten til AI-prosesser (`TOKEN_QUERY`), Toolhelp-lista, programfila | Konto, om den kjører som administrator, hvem som startet den, SHA-256 av programfila (maks 512 MB), og hvilke programmer en AI-agent har startet nå (bare programnavn) |
| Hendelseslogger (admin) | Security 4688, Sysmon 1 og 22, `Microsoft-Windows-DNS-Client/Operational` 3008, siste 30 dager | Programnavn, tid, konto og AI-navn som ble slått opp. Kommandolinjen i 4688 og Sysmon behandles som over. Loggene slås aldri på av programmet. |

| Hooks og oppgaver | `hooks` i `.claude\settings*.json`, `.vscode\tasks.json` med `runOn: folderOpen`, skript rett i `.claude\` og `.vscode\` | Hendelse og første ord i kommandoen, filsti, tid |
| MCP som starter selv, uttak | `.claude\settings*.json` | `enableAllProjectMcpServers`, `enabledMcpjsonServers`, `WebFetch` i `permissions.allow` |
| Lenker inn i agentoppsett | Symlinker og junctions i prosjektmapper | Bare målet (FSCTL_GET_REPARSE_POINT). Lenken følges aldri. |
| Skjulte tegn | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.cursor\rules\*.mdc`, `.github\copilot-instructions.md` (maks 1 MB) | Antall usynlige tegn. Teksten beholdes aldri. |
| Agent-.env | `.gemini\.env` i prosjektmapper | Om fila finnes, og (som alle `.env`-filer) navnene på AI-nøkler som har en verdi. Verdiene leses aldri ut. |
| Ferdigheter og tillegg | `.claude\skills`, `.claude\plugins`, `.codex\skills`, `.openclaw`, `.clawdbot` og `.claude\skills` i prosjekter (maks 100 filer per ferdighet) | Om teksten har nedlasting og kjøring, lange base64-blokker, passord-zip eller uttakstjenester |
| Hugging Face og Ollama | `.cache\huggingface\modules\transformers_modules`, `.py` i `hub\models--*\snapshots`, `.ollama\models\manifests` | Mappenavn og tid; om modellkoden importerer nettverks- eller kommandobiblioteker; registernavn |
| Autostart med farlige flagg | HKCU `Run`/`RunOnce`, Oppstart-mappa, PowerShell-profiler, `.bashrc` | Bare agent og flagg. Ikke resten av kommandoen. |
| Lokale klienter | TCP-tabellen: forbindelser til 127.0.0.1:11434 og :1234 | Program og port |
| Nettleserbroer | `NativeMessagingHosts` for Chrome, Edge, Brave, Chromium og Firefox (HKCU og HKLM) og manifestet nøkkelen peker på | `name`, `description`, `path`, `allowed_origins`. Programmet startes aldri. |
| Tvungne utvidelser | `SOFTWARE\Policies\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave}\ExtensionInstallForcelist` | Bare utvidelses-ID-ene |
| Nettapper | `.lnk` i Start-menyen (maks 64 KB) | Om snarveien starter `*_proxy.exe --app-id`, og navnet |
| Office-tillegg | `SOFTWARE\Microsoft\Office\<app>\Addins` (HKCU, HKLM, WOW6432Node), `%LOCALAPPDATA%\Microsoft\Office\16.0\Wef` (maks 500 filer, 512 KB) | `FriendlyName`, `Description`, `LoadBehavior`; i manifestene bare `DisplayName` og `Description`. Dokumenter røres aldri. |
| Vektordatabaser | Filnavn i filgjennomgangen: `chroma.sqlite3`, `*.faiss`, `*.lance`, Qdrant `collections\*\collection.json`, LlamaIndex `docstore.json`, `*.usearch` | Bare sti, størrelse og endringstid. Innholdet leses aldri. |
| Brannmurlogg (admin) | `pfirewall.log` (standard sti og `LogFilePath` fra brannmurregler), siste 16 MB | Bare linjer til adressene kjente AI-tjenester har nå: tid, protokoll, port, PID |
| GPU/NPU | Ytelsestellere «GPU Engine» (Compute, Cuda), bare for PID-er som er AI-funn | Prosent beregning over ett sekund |
| Docker | `\\.\pipe\docker_engine`, bare når Docker kjører: `GET /images/json` og `/containers/json` | Bildenavn, størrelse, om beholderen kjører og åpne porter. `~/.docker/config.json` åpnes aldri. |
| WSL | `Lxss` i registeret; `\\wsl.localhost\<distro>\home\*` bare når Linux kjører | Navn på distribusjoner; antall filer i `.ollama\models\manifests`, `.cache\huggingface\hub`, `.cache\lm-studio\models` |
| Utvidelsers kode | `*.js` i utvidelsens mappe (maks 200 filer, 2 MB per fil, 4 MB per utvidelse) | Bare adresser til AI-tjenester fra `regler.json`. Teksten beholdes aldri. |
| Electron-apper | `resources\app.asar` i leverandørmappene | Innholdslista øverst i fila og `package.json`: navn på AI-biblioteker. Koden leses ikke. |
| Utvidelser | `manifest.json` (leses fra før) | Tilgang til AI-chatsider, og ID mot `daarligeUtvidelser` |
| Kjente filer og domener | `iocFiler` (finnes fila?), `iocDomener` mot DNS-bufferen, `site-packages\*.dist-info` | Navn og versjon |
| npx-cachen | `%LOCALAPPDATA%\npm-cache\_npx\*\node_modules\*mcp*` (maks 200 filer, 20 s) | Antall skjulte tegn og `<IMPORTANT>`-blokker |

Ikke dekket ennå: SRUM, MFT og filene inne i WSL. Er WSL installert, står det som blindsone i rapporten.

### Kommandolinjer

Kommandolinjer leses bare for tolkere, for programmer som allerede er AI-funn, og (i Vakt) for programmer en AI-agent starter. Python.exe sier ingenting om hva som
kjører; skriptet gjør det. Linjen leses fra Windows (ikke fra prosessminnet), sammenlignes med reglene og kastes. Det som
vises, er regelen som slo til og skriptfila. IT kan slå det av med `"lesKommandolinjer": false` i `regler.json`, eller
med `HKLM\SOFTWARE\Policies\AISkanner` `LesKommandolinjer` = 0 (DWORD, kan rulles ut med Intune). Da står det som
«blokkert av IT» i datagrunnlaget, og hendelsesloggene leses uten kommandolinjen.
Agentøkter kan inneholde personopplysninger. Bare tider og treff leses, men på jobb-PC bør bruken avklares
(e-postforskriften kan gjelde når agenten har lest e-post). Slå av med `--uten-agentlogger`.

### Angrep på AI-agenter

Ferdigheter (`SKILL.md` under `.claude`, `.agents`, `.gemini`, `.warp`, `.hermes` m.fl.), instruksjonsfiler og
MCP-pakker i npx-bufferen, globale npm-pakker og uv-verktøy sammenlignes med mønstre fra ATR (for eksempel skjulte
beskjeder i HTML-kommentarer, «send data til», «ikke si det til brukeren», kryptomining). Bare regelnavnet og fila
vises. Installerte AI-verktøy sammenlignes med kjente sikkerhetshull (`saarbareVersjoner` i `regler.json`).
Adresser for AI-trafikk (`*_BASE_URL` i miljøet, `env` i Claude Codes `settings.json`, `base_url` i Codex
`config.toml`) som peker til en ukjent vert, vises med vertsnavnet alene, aldri sti eller nøkkel. Windows' egne
MCP-koblinger (ODR) sjekkes som skrivebeskyttet lesing og står som ikke bekreftet på Windows 26H2.

### Lyttevindu og «Følg med»

Under søket leses TCP-tabellen (`GetExtendedTcpTable`) hvert 250. ms og DNS-bufferen hvert 2. sekund i minst 20
sekunder (`--lytt 0-60`, 0 = ett øyeblikksbilde). Ingen pakker fanges og ingenting sendes. Navn som ikke er AI,
forkastes i minnet. Som administrator slås Windows' tellere per forbindelse (EStats) på for nye forbindelser og av
igjen etterpå. I vinduet vises resultatet når sjekkene er ferdige; lyttevinduet går videre i bakgrunnen, og funnene og
revisjonsloggen oppdateres når det er gått. En teller slås av først når ingen (lyttingen, Nettverk, Følg med) bruker den.

«Følg med» leser de samme tabellene hvert sekund for ett funn mens vinduet er åpent, og viser datamengden i et
diagram. Det lagres ikke, logges ikke og forsvinner når haken tas bort eller vinduet lukkes. Bare TCP: UDP og QUIC
(HTTP/3) vises ikke.

### Nettverk (live)

Knappen «Nettverk» øverst til høyre i resultatet viser hvilke programmer som snakker med AI-tjenester akkurat nå: program,
AI-tjeneste og vertsnavn, land eller CDN, antall forbindelser, og som administrator sendt og mottatt per sekund i et
diagram for alle eller for ett valgt program. Program som ikke er kjent fra søket eller er en nettleser, merkes
«Ukjent program» i rødt. Den leser TCP-tabellen hvert sekund og DNS-bufferen hvert 2. sekund, bare mens visningen er
åpen. Kjente AI-programmer fra søket, og programmer som snakker med en AI-tjeneste, vises med alle forbindelsene sine;
der navnet ikke er i DNS-bufferen står «Kan ikke avgjøre». Andre forbindelser telles (med hvor mange som er fra
nettlesere) men vises ikke. Antall åpne UDP-porter hos nettlesere og AI-programmer vises som hint om QUIC (UDP-tabellen
sier ikke hvor det sendes). WebView2 (msedgewebview2) regnes som nettleser og merkes med programmet den kjører i. AI-skanneren
selv og alt den har startet, tas aldri med.

Trykk på en rad for å se prosessen: PID, starttid, signatur (WinVerifyTrust, uten nettoppslag), filinfo, full sti og
hvem som startet den (foreldrekjeden fra Toolhelp-lista, med sjekk for gjenbrukte PID-er). «Vis» åpner mappa i
Utforsker; bare stier som er vist, kan åpnes. Prosesser åpnes med `PROCESS_QUERY_LIMITED_INFORMATION`, sikkerhets- og
systemprosesser røres ikke, og kommandolinjer leses bare for tolkere og AI-funn (se Kommandolinjer). Ingen pakkefangst, ingen driver, ingen
innhold. Ingenting lagres og ingenting kommer i rapporten. Bare TCP: UDP og QUIC (HTTP/3) vises ikke, og det står i
visningen. `AISkanner.Cli --nettverk` skriver tre avlesninger som JSON.

### Kontroll av alarmene

`AISkanner.exe --kontroll` (eller `Kontroller-alarmene.cmd`) viser om alarmene virker på denne PC-en. Programmet
lager ufarlige falske spor i `%TEMP%\AISkanner-kontroll-xxxxxxxx`, peker sjekkene dit i stedet for brukerens mapper,
viser OK eller FEIL for hver alarm og sletter mappa. Ingen ekte mapper leses, ingenting lagres, ingenting sendes.
Antivirus kan reagere på de falske sporene (for eksempel en fil som ser ut som en kjent skadevare-fil). Nettverksreglene
kontrolleres med et kunstig nettbilde, så kontrollen viser at reglene virker, ikke at Windows ga nettverksdata.
Kommandolinjene kontrolleres med lagde linjer. Symlinker, Prefetch, BAM, hendelsesloggene og Run-nøkkelen kontrolleres ikke.

Kontrollen sjekker også reglene for kinesisk AI: vertsnavn for kinesiske AI-nettsteder og API-er skal treffe en tjeneste
i Kina med høy risiko, vanlige kinesiske nettsteder som ikke er AI (baidu.com, qq.com, aliyun.com, tiktok.com …) skal
ikke treffe, kinesiske AI-programmer og VS Code-utvidelser skal kjennes igjen, og modellarkitekturer skal peke entydig
på en kinesisk familie. Alt skal være OK; i 2.19.7 er det 104 av 104.

### Vakt (AI-agenter live)

Nettverk → «AI-agenter» følger AI-agentene (Claude Code, Codex, Gemini CLI, Cursor og andre i kategorien
«Skygge-AI (agent)») og alle programmene de starter, fra første søk til vinduet lukkes. Som administrator brukes én
sanntidsøkt mot Windows' egne hendelseskilder (`AISkanner-Vakt`: Kernel-Process, Kernel-File, Kernel-Network og
DNS-Client), uten fil og uten driver. Uten administrator leses bare prosesslista hvert halve sekund, og filer og nett
står som ikke sett.

Vakt ser når agenten eller noe den startet: lager planlagt oppgave, autostart eller bruker, svekker brannmur eller
Defender, kjører skjult eller kodet PowerShell, laster ned med Windows-verktøy (certutil, bitsadmin, mshta, regsvr32),
henter passordlageret, sletter logger eller skyggekopier, sletter alt i en mappe, sender filer ut, kobler et skall til
nettet, åpner hemmelighetsfiler (SSH, AWS, Kubernetes, Docker, Git, nettleserinnlogging, lommebøker, agentinnlogging),
slår opp uttakstjenester eller kjente misbruksdomener, kobler et skall til en IP-adresse uten navn, starter minst 150
programmer på ett minutt, eller endrer agentoppsett og instruksjonsfiler (`settings.json`, `.mcp.json`, `CLAUDE.md`,
`AGENTS.md`, `SKILL.md` m.fl.). Hver regel har kilde fra ATR, SigmaHQ og MITRE ATLAS. Programmer som har lov å åpne en
hemmelighet (for eksempel `ssh` og `aws`), og agentens egen innlogging, gir ingen hendelse.

Røde hendelser blir funn («AI-agent gjør noe kjent fra angrep») med regel, program, PID og tid. Kommandolinjen til et
program agenten starter, leses mens det kjører, sammenlignes med reglene og kastes (samme bryter som Kommandolinjer).
For filer ses bare navnet på fila som åpnes, aldri innholdet. Ingenting lagres; alt forsvinner når vinduet lukkes.

## Hva den aldri leser

Passord (`Login Data`), informasjonskapsler (`Cookies`), `Web Data`, `Local State` (unntatt `--flagg` i
kommandolinjen og innstillingen for sikker DNS), krypteringsnøkler, lommebokdata i utvidelser (`Local Extension Settings`), verdien av API-nøkler,
e-post, dokumentinnhold, innholdet i AI-agentenes økter og minnet til andre prosesser.

Håndhevet i koden: `Skanner.LovligeFiler` er de eneste filnavnene som åpnes for å lese innholdet: `manifest.json`,
`messages.json`, `extensions.json`, `Preferences`, `History` og `places.sqlite`, og for nettverket `Network Persistent State`
og `dns_over_https` i `Local State` (bare om sikker DNS er på). I tillegg leses begrensede deler av
modellfiler som beskrevet over.

## Hva den sender ut

| Til | Hva | Når |
|---|---|---|
| `127.0.0.1` | Maks tre `GET` per lyttende port | Under søket |
| Vanlig DNS (PC-ens egen DNS-server) | Navnene på de kjente AI-tjenestene fra `regler.json` (for eksempel `chatgpt.com`, `api.openai.com`), slått opp én gang per søk, sendt rett til DNS-serveren (UDP 53) utenom Windows' DNS-klient, så de ikke havner i DNS-bufferen | Under søket, bare på Windows |
| `services.nvd.nist.gov` (HTTPS) | Bare produktordet fra `regler.json` for kjente produkter som ble funnet, for eksempel `ollama` | Etter at resultatet vises. Av med `--uten-nvd`. |

PC-navn, brukernavn, stier og funn sendes aldri. DNS-oppslagene er de samme som når en nettside åpnes, og inneholder
bare navnet på tjenesten. De brukes til å kjenne igjen forbindelser nettleseren har slått opp selv (egen DNS eller
sikker DNS, DoH), som derfor mangler i Windows' DNS-buffer. Et slikt IP-treff regnes bare når nettleseren selv har
tjenesten i nettverkslageret sitt (`Network Persistent State`, bare vertsnavn; alt som ikke er AI, forkastes), fordi
mange tjenester deler IP-adresser på samme CDN. For andre programmer regnes IP-treff aldri. Ingen IP-oppslag på nett.

## Hva den skriver

| Hva | Hvor | Hvor lenge |
|---|---|---|
| WebView2-data | `%LOCALAPPDATA%\AISkanner\Vindu-<pid>` | Slettes når programmet lukkes. Rester etter avbrutte kjøringer slettes ved neste start. |
| Rapport | Der brukeren velger, som `AI-rapport_<PC>_<dato>_<tid>.txt`. Skriver aldri over en fil som finnes. | Bare når brukeren trykker «Lagre rapport» |
| Revisjonslogg | `Dokumenter\AI-skanner\AI-revisjon_<PC>_<dato>_<tid>.txt`. Ny fil per søk, aldri over en gammel. | Bare når brukeren har valgt Ja under «Hva søkes?» på startskjermen. Blir liggende til noen sletter den. |

Programmet har ingen cache, ingen hasher fra før og ingen historikk over søk. Nettleserdata lagres aldri av seg selv.
Rapporten brukeren selv laster ned (tekst og JSON), viser hvor AI brukes i nettleseren: AI-domene, nettleser og
profil, antall besøk og første og siste gang. Aldri hele adresser eller sidetitler. Revisjonsloggen har bare navn, type
og sted for slike funn.

## Datagrunnlag og revisjonslogg

**Datagrunnlag** (knappen øverst til høyre i resultatet) viser alt søket prøvde å lese: hvilken sjekk, hva (fil, mappe,
register, database, port, prosess, nettverk, hendelseslogg), hvor, og utfallet:

| Utfall | Betyr |
|---|---|
| lest | Lest uten feil |
| finnes ikke | Stedet finnes ikke på denne PC-en (vanlig: de fleste AI-programmer er ikke installert) |
| nektet tilgang | Windows sa nei (feil 5). Ofte mapper som krever administrator |
| låst | Et annet program holder fila (feil 32/33), for eksempel nettleserhistorikk mens nettleseren er åpen |
| stoppet av antivirus | Windows-feil 225/226, eller en Defender-hendelse (1116–1123) for dette programmet under søket |
| hoppet over | Med vilje: skyfiler (OneDrive), systemmapper, dybdegrense eller sikkerhetsprosesser |
| tidsgrense | Disken (45 s) eller AppData (40 s) tok for lang tid. Resten ble ikke gått gjennom |
| feil | Annen feil, eller en sjekk som stoppet |

Hvert tall kan trykkes på og åpner stedene bak det, med sjekk og grunn. Mapper i gjennomgangen, prosesser og
leverandørmapper står med sti; filer som leses inne i en mappe, telles per mappe. Alt som feiler, listes enkeltvis. Vinduet viser opptil 3000 oppføringer, revisjonsloggen opptil 20 000. Tellingene er alltid komplette.

**Kart** (fane i Datagrunnlag) viser de samme stedene som et klikkbart kart, etter samme prinsipp som SpaceSniffer:
Disk, Registeret, Nettverk og Annet øverst, og hver mappe eller nøkkel som en flis så stor som antall ting søket så
på der (eller samlet filstørrelse, med «Størrelse»). Farge viser høyeste risiko blant funn på stedet eller under det.
Stiplet kant betyr at noe ikke ble lest (nektet, låst, stoppet av antivirus, tidsgrense eller feil). Klikk på en flis
for å gå inn. «Om dette stedet», eller en flis uten noe under, åpner et infovindu med full sti, antall, filstørrelse,
utfall, hvilke sjekker som leste der, merknader fra søket og funnene der og under. Klikk på et funn for å åpne det.
Kartet bygges mens søket går, ligger bare i minnet og forsvinner med søket. Det kommer aldri i rapporten eller
revisjonsloggen. Det har bare stier, navn, antall og filstørrelser, aldri innhold. Mappenavn i brukerprofilen vises,
så skjermbilder av kartet kan avsløre prosjekt- og filnavn. Store mapper viser de 150 største stedene og samler resten.

Defenders logg (`Microsoft-Windows-Windows Defender/Operational`) krever som regel administrator. Som vanlig
bruker står det at den ikke ble lest, men feil 225/226 på selve fila vises uansett. Andre antivirusprogrammer har egne
logger som ikke leses.

**Revisjonslogg** er av som standard. Med Ja skrives én tekstfil per søk med `FileMode.CreateNew` (skriver aldri
over). Fila har versjon, PC og bruker, modus, språk, start og slutt, SHA-256 av programmet, kjernen, `regler.json`,
`ai-modeller.yar` og `godkjent-ai.txt`, tid og utfall per sjekk, Defender, funnene (risiko, navn, type, sted) og hver
tilgang. Siste linje er SHA-256 av alt over, så endringer kan oppdages. NVD-oppslag kommer etter søket og legges til
sist med ny kontrollsum over hele fila. Kontrollsummen beviser ikke hvem som skrev fila: den som kan endre fila, kan
også regne ut en ny sum. Vil dere ha sporbarhet, send fila til et sted brukeren ikke kan skrive.

Revisjonsloggen inneholder aldri nettadresser fra nettleseren, innhold i filer eller verdier av nøkler. Private funn
(nettleserhistorikk og DNS) står bare med navn, type og sted, som i JSON-rapporten.

## Søk som administrator (valgfritt)

Uten administrator viser skanneren hvor AI-programmene er koblet, men ikke hvor mye de sender. Windows gir ikke
vanlige brukere tilgang til tellerne.

Startskjermen har to valg: knappen i midten søker som bruker, og ringen rundt søker som administrator. Velger brukeren
administrator, eller trykker «Mål datamengde» etter et søk, startes programmet på nytt med vanlig UAC-spørsmål
(`runas`, argument `--sok`). Sier brukeren nei, skjer ingenting annet enn en melding. Resultatet og rapporten viser
«Søkt som bruker» eller «Søkt som admin». Som administrator ser skanneren også filstien til programmer som kjører som administrator.

**Hvilken bruker søket gjelder.** Godkjennes UAC med en annen konto (f.eks. IT-kontoen), kjører programmet som den
kontoen. Søket gjelder likevel brukeren som er logget inn på skjermen: programmet spør Windows hvem som eier økta
(`WTSQuerySessionInformation`), finner SID-en og leser stier fra `HKEY_USERS\<SID>\Volatile Environment` og
`ProfileList`. Profil, AppData, nettlesere og HKCU-sjekker gjelder da `HKEY_USERS\<SID>`. Navn på AI-nøkler telles bare
fra brukerens register, ikke fra IT-kontoens miljø. Bunnlinjen, rapporten og revisjonsloggen viser «Kjørt av» med
IT-kontoen. Kjøres CLI-en som SYSTEM (Intune), brukes den som er logget inn på skjermen; er ingen logget inn, gjelder søket
kontoen som kjører.
Som administrator slår skanneren på Windows' egne TCP-tellere (`SetPerTcpConnectionEStats`, `TcpConnectionEstatsData`,
samme som Ressursovervåking) for forbindelsene som er åpne når søket starter. Den leser dem når søket er ferdig
(`GetPerTcpConnectionEStats`) og slår dem av igjen.

Tallene er byte faktisk sendt og mottatt i måleperioden (typisk 10–30 sekunder, minst 5), ikke anslag.
Forbindelser som åpnes underveis, måles ikke. QUIC og UDP vises ikke.

**Lesing for sikkerhetskopi.** Som administrator slår skanneren på `SeBackupPrivilege` i sin egen prosess (rettigheten
finnes allerede i administratorens token, men er av). Mapper som er låst for alle, kan da listes, og filer som nekter
vanlig lesing, åpnes med `FILE_FLAG_BACKUP_SEMANTICS` bare for lesing. Ingen rettigheter, eiere eller filer endres.
Lista over det som aldri leses (under), gjelder fortsatt. Datagrunnlaget viser at retten var på, og hvilke filer som
ble lest slik. `SeDebugPrivilege` brukes ikke.

**Skjulte datastrømmer.** Fullt søk lister navngitte datastrømmer i hver fil (`FindFirstStreamW`) og sjekker filhodet
i strømmer på minst 50 MB.

Ikke testet på Windows ennå.

## Risiko og godkjentliste

- **Ukjent AI og skygge-AI er alltid røde.** Skygge-AI er AI som ikke er lagt inn av Windows, en signert leverandør
  eller IT: AI-nettsteder, nettleserutvidelser, agenter, kodeverktøy, AI-apper, modeller brukeren har lagt inn selv
  og AI-nøkler.
- **Godkjent AI blir grønn.** Legg `godkjent-ai.txt` ved siden av programmet, med ett navn eller domene per linje,
  eller bruk `godkjentAi` i `regler.json`. Bruk eksakte produktnavn og offisielle domener (se
  [SECURITY.md](SECURITY.md#kjente-svakheter)).
- **Godkjenning overstyrer aldri faresignaler.** En godkjent AI som er åpen mot nettverket eller sender til et
  høyrisikoland, blir rød. En godkjent AI som kjører fra nedlastinger eller en midlertidig mappe, kan kjøre skjult kode
  eller er blokkert av IT, blir gul. Grunnen står som «Godkjent av IT, men: …».
- Ukjent AI, farlige modellfiler og data til høyrisikoland (`hoyrisikoLand`, standard CN, RU, IR, KP og BY) er
  røde uansett hva som står på lista.
- **Blokkert AI blir rød.** Legg `blokkert-ai.txt` ved siden av programmet (samme format), eller bruk `blokkertAi` i
  `regler.json`. Finnes AI-en likevel, står det «Blokkert av IT, men finnes på PC-en», også om den er godkjent.
- Hvert funn viser status (Kjører nå, Brukt før, Satt opp, Finnes), treffsikkerhet (Høy, Middels, Lav, med antall
  uavhengige spor) og godkjenning (Godkjent av IT, Blokkert av IT, Ikke vurdert). Se [docs/REGELFILER.md](docs/REGELFILER.md).
- På en jobb-PC uten godkjentliste blir de fleste funn røde.

Format og eksempler: [docs/REGELFILER.md](docs/REGELFILER.md).

## Kommandolinje og utrulling

```
AISkanner.exe [--uten-nvd] [--uten-historikk] [--uten-agentlogger] [--lytt 0-60]
AISkanner.exe --kontroll [--en]
AISkanner.Cli [--nvd] [--uten-historikk] [--uten-agentlogger] [--lytt 0-60] [--regler sti\regler.json] [--txt] [--flagg]
AISkanner.Cli --nettverk
AISkanner.Cli --kontroll [--en]
```

`AISkanner.Cli` skriver JSON (eller tekst med `--txt`) til standard ut. Exit-kode: `0` = ingen funn,
`1` = bare gule eller grønne funn, `2` = minst ett rødt funn. Den passer for Intune eller andre verktøy for utrulling.
NVD er av som standard i kommandolinjen.

## Personvern på jobb-PC

Historikksøket er innsyn i elektronisk lagret materiale. En arbeidsgiver som bruker skanneren på ansattes PC-er, må
følge e-postforskriften og arbeidsmiljølovens regler om kontrolltiltak, eller slå av historikksøket med `--uten-historikk`.

## Kan EDR reagere?

Ja, det kan skje. Lesing av nettleserhistorikk, DNS-bufferen og nettverkstabellen, og gjennomgang av filer, kan ligne
rekognosering. Versjon 0.3 ble stoppet av Defender og Sentinel fordi den åpnet `lsass` med lesetilgang. Det ble rettet
i 0.4. Senere versjoner er kjørt på en jobb-PC med godkjenning fra IT.

Det som gjenstår, er at programmet er ukjent og usignert. Det løses med signerte utgivelser, eller med godkjenning på hash.

## Godkjenning (allowlist)

- Når utgivelsene er signert: godkjenn på signatur.
- Inntil da: godkjenn på SHA-256 av `AISkanner.exe` og DLL-ene. Hashene står i `SHA256.txt`, som byggeløypa lager.
- Legg programmet i en mappe vanlige brukere ikke kan skrive til, for eksempel under Program Files. Da kan ingen
  legge falske DLL-er eller regelfiler ved siden av det.
