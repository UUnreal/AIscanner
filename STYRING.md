# Styring av AI-skanner (FindHiddenAI)

Dette dokumentet styrer alt arbeid med prosjektet. Her står det som gjelder nå. Fulle tekster er Jørunds «AIscanner – Permanent Project Instructions» (18.11.2026) og «FindHiddenAI – Masterprompt 1.0» (20.11.2026), kortet ned nedenfor. Der de to sier noe annet enn **Vedtak**, gjelder vedtaket.

## 1. Faste regler

- **Bare lesing.** PC-en endres aldri. Ingenting lagres, lastes opp eller sendes ut. Ingen telemetri. Ingen nye nettverkskall (bare localhost for Vakt).
- **Aldri les** passord, informasjonskapsler, skjemadata, tokens eller nøkkelverdier, prosessminne eller lsass, prompter eller chat, e-post, lyd eller innhold i dokumenter.
- **Ingen AI i skanneren.** Bare faste regler med kilde: filformat, YARA, regelfil og kjente adresser.
- **Bevis før navn.** Bekreftet betyr innhold eller målt oppførsel. Sannsynlig betyr to uavhengige spor, eller treff på en verifisert regel. Mulig spor betyr bare navn, sti eller ett spor; det telles ikke og blir aldri rødt. Ukjent forblir ukjent: identitet, opphav og leverandør diktes aldri opp. Er produktet kjent men ikke bekreftet, står det «Ikke bekreftet», ikke «Ukjent».
- **Ekte navn** når de kan bestemmes (fra modellfila, signaturen eller produktets offisielle navn). Ellers «Navn: ukjent».
- **Hver regel** har ID, kilde, en positiv test, en negativ test og en merknad om falske funn (`regler.json`, `--kontroll`).
- **Hver sjekk** synes i grensesnittet (Tilgangslogg). Null funn betyr aldri null AI. Det som ikke er målt, står som «ikke bekreftet». Ble det bare gjort et DNS-oppslag, står det «Bare slått opp».
- **Kina, Russland, Iran og Nord-Korea:** modellfamilier herfra blir røde, men bare med bekreftet innhold. Et godkjent produkt overstyrer aldri en alvorlig fare.
- **Minst mulig kode og færrest mulig tokens**, men aldri på bekostning av sikkerhet, korrekthet eller sjekker.
- **Sikkerhet ved hver endring:** Semgrep, gitleaks og avhengigheter, i tillegg til egen gjennomgang.
- **Påstå aldri at noe er testet på Windows** når det ikke er det. CHANGELOG skiller «testet på virtuell Windows» fra «ikke testet».
- Ingen AISkanner.exe.config. Antall funn nevnes aldri i repoet. Grensesnittet er rolig og enkelt, uten forstørrelsesglass og gnister.
- Nettsiden følger WCAG 2.1 AA og har automatisk mørk modus.

## 2. Vedtak (med dato)

- 2026-11-18: Merge til main når CI er grønn. Dette overstyrer «ingen commit, push eller release» i begge dokumentene.
- 2026-11-18: Deepfake og stemmekloning blir røde. Navn på avhengigheter i prosjektfiler kan leses. Vakt følger Ollama, LM Studio og llama.cpp, bare med lesing. Agentkommandoer vises maskert, med en «Vis kommando»-knapp. En agent som kjører kommandoer uten å spørre, blir rød.
- 2026-11-18: Testlaben er en virtuell Windows-maskin i CI, i tillegg til en rask sjekk på Jørunds PC før store versjoner.
- 2026-11-20: Ingen lesing av prosessminne eller innlastede DLL-er i andre prosesser. Skann lagres aldri, så det blir ingen sammenligning over tid. Dette er avvist fra masterprompten.
- 2026-11-20: Avvist for godt: prompter i sanntid og avlytting av HTTPS.
- 2026-11-20: PowerShell-historikk kan leses, men bare navnet på kjente AI-verktøy vises, aldri kommandoen.
- 2026-11-20: Ukjente funn får en Opphav-blokk: navn, hvem som laget det, nedlastingskilde, hvor data sendes (målt, med innebygd IP-database) og SHA-256.
- 2026-11-20: Microsoft Store er satt på pause.

## 3. Utgivelse

1. PR med grønn CI: bygg, sikkerhet, ytelse og laben. Kjør `--kontroll` og `--selvtest` før push.
2. Squash-merge. Etter en squash av en commit med falske testnøkler legges squash-SHA-en til i `.gitleaksignore` før det bes om tag.
3. Vent til bygg og sikkerhet er grønne på main.
4. «Lag vX.Y.Z nå» med lenken `releases/new?tag=vX.Y.Z&target=main&title=vX.Y.Z`. Jørund publiserer. Claude kan ikke lage tagger eller endre releaser.
5. Hak av for «Set as the latest release». Byggejobben gjør også releasen til siste etter at fila er lastet opp.
6. Bare exe-fila: AISkanner.exe og SHA256.txt. Sjekk SHA-256 og lever som `AISkanner-X.Y.Z.exe`.

## 4. Arbeidsmåte (kortet ned fra masterprompten)

- Roller: Windows-sikkerhetsforsker, forsker på omvendt utvikling av AI, deteksjonsingeniør, arkitekt og uavhengig revisor. Utfordre egne antakelser, og si fra når en metode ikke virker.
- Finn AI-funksjon, ikke bare AI-navn. Det gjelder også AI som er innebygd, skjult, lokal, i skyen, i skript, i Office, i nettleseren, i agenter og MCP, i WSL og Docker, og AI som lastes ned midlertidig.
- Bruk primærkilder: Microsoft Learn, MITRE ATT&CK, NIST, OWASP, leverandørenes dokumentasjon, GitHub og MCP-spesifikasjonen. Dikt aldri opp stier, nøkler eller porter. Det som ikke kan bekreftes, merkes «ikke bekreftet».
- Dekningskart A–T med status per kategori (`Kategoristatus.cs`) og kapabilitetsmatrisen (`ai-skanner/dekning/kapabiliteter.md`). Sjekk hver ny idé mot dem før noe bygges.
- Selvrevisjon før store valg: Hva overser vi? Kan AI kjøre uten disse sporene? Skiller vi evne fra bruk? Samler vi mer enn nødvendig? Finnes det en enklere løsning?
