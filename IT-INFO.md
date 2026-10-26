# AI-skanner: informasjon til IT og sikkerhet

## Formål
Kartlegger AI-verktøy på én Windows-PC (lokal AI, skygge-AI, nettleser-AI) og viser dem sortert etter risiko.
Kjøres manuelt av innlogget bruker. Ingen installasjon, ingen tjeneste, ingen persistens, ingen admin-rettigheter.

## Hvordan den kjører
`AISkanner.exe` er ett frittstående .NET 8-program. Det pakker ikke ut noe til `%TEMP%` og er ikke komprimert. Det starter ingen andre prosesser (ingen PowerShell,
cmd eller skript) og kjører som vanlig bruker (`asInvoker` i manifestet). Ingen kode lastes ned.

## Hva den leser (kun lesing, ingenting endres)
- Prosessliste og prosessenes filsti. Filstien hentes med `PROCESS_QUERY_LIMITED_INFORMATION` og
  `QueryFullProcessImageName`. Minnet til andre prosesser leses aldri, og systemprosesser som lsass,
  csrss, winlogon og Defender-prosessene åpnes ikke i det hele tatt.
- Installerte programmer: Uninstall-nøkler i HKLM/HKCU, og Store-apper for innlogget bruker
  (`HKCU\Software\Classes\Local Settings\...\AppModel\Repository\Packages`, bare nøkkelnavn)
- Tjenester: `HKLM\SYSTEM\CurrentControlSet\Services` (DisplayName, ImagePath, Start)
- Run-nøkler, Oppstart-mapper, navn på planlagte oppgaver (`...\Schedule\TaskCache\Tree`)
- Lyttende TCP-porter med eierprosess (`GetExtendedTcpTable` i iphlpapi.dll)
- Om kjente mapper finnes, f.eks. `%USERPROFILE%\.ollama`, `.claude`, `.codex`, `.cursor`
- Mappenavn i `%APPDATA%\npm\node_modules` og `%USERPROFILE%\.vscode\extensions`
- Filnavn og filstørrelse (aldri innhold) for `.gguf`, `.safetensors`, `.onnx`, `.ggml` over 200 MB i
  Downloads, Documents, Desktop, `.cache`, `.ollama`, `.lmstudio`, `nomic.ai`
- Nettleserutvidelser: KUN `manifest.json` og `_locales\*\messages.json` under
  `...\User Data\<profil>\Extensions\` (Chrome, Edge, Brave, Vivaldi, Opera), og `extensions.json` i Firefox-profilen
- Navn og størrelse på mapper for nettleserens innebygde AI-modell (f.eks. `Chrome\User Data\OptimizationGuideOnDeviceModel`)
- Policyverdien `GenAILocalFoundationalModelSettings` under `HKLM/HKCU\SOFTWARE\Policies\Google\Chrome` og `\Microsoft\Edge`

## Hva den aldri leser
Passord (Login Data), informasjonskapsler (Cookies), historikk (History), Web Data, Local State,
krypteringsnøkler, lommebokdata i utvidelser (Local Extension Settings), e-post eller dokumentinnhold.
Håndhevet i koden: `Skanner.LesJson` nekter å åpne andre filer enn `manifest.json`, `messages.json` og `extensions.json`.

## Nettverk
Ingen nettverkstrafikk som standard. Hvis brukeren selv huker av for sårbarhetssjekk, gjøres HTTPS-oppslag mot
`services.nvd.nist.gov` med bare et produktord (f.eks. `ollama`). PC-navn, brukernavn og filstier sendes aldri.

## Kan EDR reagere?
Et program som lister mapper under nettleserens `User Data` kan ligne på rekognosering. Signerte utgivelser og
godkjenning på signatur eller hash løser det. Kildekoden og byggeløypen er åpen, så IT kan bygge og kontrollere selv.

## Godkjenning (allowlist)
Godkjenn på signatur når utgivelsene er signert, ellers på SHA256-hash av `AISkanner.exe`.
Hashen for hver utgivelse står i `SHA256.txt` fra byggejobben.
