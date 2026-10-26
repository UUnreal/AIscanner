# AI-skanner: informasjon til IT og sikkerhet

## Formål
Kartlegger AI-verktøy på én Windows-PC (lokal AI, skygge-AI, nettleser-AI) og viser dem sortert etter risiko.
Kjøres manuelt av innlogget bruker. Ingen installasjon, ingen tjeneste, ingen persistens, ingen admin-rettigheter.

## Hvordan den kjører
`AISkanner.exe` er et frittstående .NET 8-program (mappe med exe og noen få DLL-er). Det pakker ikke ut noe til `%TEMP%`,
er ikke komprimert, starter ingen skript eller kommandolinjer, og kjører som vanlig bruker (`asInvoker`).
Vinduet vises med Microsoft Edge WebView2 (som nye Outlook og Teams). WebView2 starter sine egne `msedgewebview2.exe`-prosesser
og lagrer sin vanlige profil i `%LOCALAPPDATA%\AISkanner\WebView2`. Siden er bygd inn i programmet, laster ingenting fra nett og kan ikke navigere bort.

## Hva den leser (kun lesing, ingenting endres)
- Prosessliste og filsti for prosesser (`PROCESS_QUERY_LIMITED_INFORMATION` + `QueryFullProcessImageName`).
  Minnet til andre prosesser leses aldri. lsass, csrss, winlogon og Defender-prosesser åpnes ikke.
- Filnavn i mappa til programmer som kjører, for å se etter AI-motorer (onnxruntime, ggml/llama, torch, OpenVINO, DirectML m.fl.)
- Installerte programmer (Uninstall-nøkler), Store-apper (nøkkelnavn), tjenester, Run-nøkler, Oppstart-mapper, navn på planlagte oppgaver
- Lyttende TCP-porter med eierprosess (`GetExtendedTcpTable`). For porter på localhost/0.0.0.0 eid av vanlige brukerprosesser
  sendes maks tre lesende `GET`-kall til `127.0.0.1` (`/api/tags`, `/v1/models`, `/sdapi/v1/sd-models`) for å se om programmet er en AI-server.
- Navn (aldri verdier) på miljøvariabler som `OPENAI_API_KEY`, og om `%USERPROFILE%\.cache\huggingface\token` finnes (åpnes ikke)
- Gjennomgang av brukerprofilen og andre faste disker (ikke Windows, Program Files eller ProgramData):
  - for filer over 20 MB leses de første 64 bytene for å kjenne igjen AI-modellformater (GGUF, safetensors, PyTorch, ONNX, TFLite, Keras).
    For GGUF og safetensors leses også metadata-hodet (modellnavn, arkitektur, antall parametre). Selve modellvektene leses ikke.
  - mappenavn i `site-packages` og `node_modules` for å finne AI-biblioteker
  - OneDrive-filer som bare ligger i skyen hoppes over, så ingenting lastes ned.
- Nettlesere (Chrome, Edge, Brave, Vivaldi, Opera, Firefox):
  - `manifest.json` og `messages.json` for utvidelser, `extensions.json` i Firefox
  - `Preferences` (bare nettstedenes bruksscore, `site_engagement`)
  - mappenavn og størrelse under `IndexedDB` og Firefox `storage\default`
  - **historikk** (`History` og `places.sqlite`), hvis brukeren lar bryteren stå på. Filen åpnes direkte, skrivebeskyttet og uten låser.
    Den kopieres aldri. Bare vertsnavn som matcher AI-tjenester beholdes i minnet. Fulle adresser og titler beholdes ikke.
    Ingenting fra nettleserdata lagres i rapporten.
- Policyverdien `GenAILocalFoundationalModelSettings` for Chrome og Edge

## Hva den aldri leser
Passord (`Login Data`), informasjonskapsler (`Cookies`), `Web Data`, `Local State`, krypteringsnøkler, lommebokdata i utvidelser
(`Local Extension Settings`), verdien av API-nøkler, e-post eller dokumentinnhold.
Håndhevet i koden: `Skanner.LovligeFiler` er de eneste filnavnene som åpnes for lesing av innhold (i tillegg til de første bytene av store filer).

## Nettverk
Til `127.0.0.1` som beskrevet over. Ellers ingenting som standard. Hvis brukeren selv slår på sårbarhetssjekk, sendes bare et produktord
(f.eks. `ollama`) til `services.nvd.nist.gov`.

## Personvern på jobb-PC
Historikksøket er innsyn i elektronisk lagret materiale. En arbeidsgiver som bruker skanneren på ansattes PC-er må følge e-postforskriften
og arbeidsmiljølovens regler om kontrolltiltak, eller slå av historikksøket (kommandolinje: `--uten-historikk`).

## Kan EDR reagere?
Lesing av nettleserhistorikk og gjennomgang av filer kan ligne rekognosering. Signerte utgivelser og godkjenning på signatur eller hash løser det.

## Godkjenning (allowlist)
Godkjenn på signatur når utgivelsene er signert, ellers på SHA256-hash av `AISkanner.exe` (står i `SHA256.txt`).
