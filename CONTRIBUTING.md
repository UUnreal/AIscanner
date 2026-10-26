# Bidra til AI-skanner

Takk for at du vil hjelpe til. Les [docs/ARKITEKTUR.md](docs/ARKITEKTUR.md) først. Prinsippene der gjelder for
alle endringer: bare lesing, innhold før navn, ukjent er rødt, ingenting lagres og lite og raskt.

## Hva vi gjerne vil ha hjelp med

- **Testing på ekte Windows**, særlig 2.8–2.11. Send rapporten (.txt) og et skjermbilde.
- **Bekrefte mappenavn** for oppføringer i `leverandorAi` med `bekreftet: false` og for Edges lokale modell.
- **Nye regler** i `regler.json` (AI-nettsteder, AI-tjenester, modellfamilier) og i `ai-modeller.yar`.
- **Feilrapporter** med versjon, Windows-versjon og hva du forventet.

Sårbarheter meldes **ikke** som vanlige saker. Se [SECURITY.md](SECURITY.md).

## Utviklingsmiljø

- .NET 8 SDK. Den bygger både `net48` og `net8.0`, også på Linux og macOS.
- Windows 10 eller 11 for å kjøre vinduet.
- Valgfritt: Python 3 med `yara-python` for YARA-testene.

```
dotnet build AISkanner.sln -c Release
dotnet publish src/AISkanner -c Release -o publish
```

## Teste

Prosjektet har ennå ingen enhetstester. Dette er det som finnes:

| Test | Kommando | Hvor |
|---|---|---|
| Røyktest: skanner maskinen og sjekker at JSON er gyldig og exit-kode ≤ 2 | `dotnet run --project src/AISkanner.Cli -c Release` | Byggeløypa (Windows) |
| YARA-motoren mot ekte YARA | `python3 verktoy/sammenlign-yara.py tests/yara/test.yar tests/yara/filer` | Lokalt |
| `ai-modeller.yar` kompilerer i ekte YARA | `python3 verktoy/test-yara.py fil …` | Lokalt |
| Trafikklogikk uten Windows | `AISkanner.Cli --test-nett nett.json` | Lokalt |
| Én lokal port | `AISkanner.Cli --test-server 11434` | Lokalt |
| Brukerflaten | Åpne `src/AISkanner/ui/index.html` i en nettleser. Den bruker eksempeldata. | Lokalt |
| Størrelse ≤ 10 MB | Automatisk | Byggeløypa |

`sammenlign-yara.py` kaller `src/AISkanner.Cli/bin/Release/net8.0/AISkanner.Cli.dll`, så bygg i Release først.

**Skanneren kan ikke testes ferdig på Linux.** P/Invoke mot Windows (TCP-tabeller, DNS-bufferen, EStats,
`WinVerifyTrust`, registeret) og WebView2 virker bare på Windows. Skriv i pull requesten hva du har testet på Windows,
og hva du bare har testet på Linux.

## Kodestil

- **Norsk** i navn, kommentarer og tekst til brukeren (`Funn`, `Skanner`, `LeggTil`). Engelsk bare der API-er krever det.
- Følg stilen i fila du endrer: korte metoder, `/// <summary>` på offentlige typer, og kommentarer som forklarer *hvorfor*.
- `AISkanner.Core` må bygge for både `net48` og `net8.0`. Bruk `Polyfills.cs` og `Plattform.cs` ved behov.
- Tekst til brukeren skal være kort, konkret og uten fagord. Ingen råd («Gjør …») på skjerm eller i rapport.
- Risikoregler skrives i `regler.json` når det går, ikke i koden.

## Regler som ikke kan brytes

En pull request som bryter disse, blir ikke tatt inn uten en god begrunnelse og oppdatert [SECURITY.md](SECURITY.md).

1. **Ingen skriving** utenfor WebView2-mappen per kjøring og rapporten brukeren selv lagrer.
2. **Ingen nye filer i lesesperren.** Endringer i `Skanner.LovligeFiler` krever at [IT-INFO.md](IT-INFO.md) og
   [SECURITY.md](SECURITY.md) oppdateres i samme pull request.
3. **Aldri** passord, informasjonskapsler, `Web Data`, lommebøker, verdien av nøkler eller minnet til andre prosesser.
4. **Ingen nye nettverkskall** uten at IT-INFO sier nøyaktig hva som sendes, og at brukeren får vite det.
5. **Ingen nye avhengigheter** som legger til en innebygd DLL eller kjøretid. Programmet skal holde seg under 10 MB.
6. **Ingen kodekjøring** fra filer som skannes: ingen unpickling, ingen lasting av modeller, ingen skript.
7. **Ingen lagring** mellom søk. Data fra nettleseren skal aldri skrives til disk utenom rapporten brukeren lagrer selv,
   og der bare som nettleser, profil og domenenavn.

## Pull requests

1. Lag en gren fra `main`.
2. Gjør én ting per pull request.
3. Oppdater dokumentasjonen i samme pull request:
   - [CHANGELOG.md](CHANGELOG.md) under `[Ikke utgitt]`, i riktig kategori
   - [IT-INFO.md](IT-INFO.md) hvis noe nytt leses, eller noe sendes ut
   - [docs/REGELFILER.md](docs/REGELFILER.md) hvis formatet i en regelfil endres
   - [docs/ARKITEKTUR.md](docs/ARKITEKTUR.md) hvis flyten eller risikomodellen endres
4. Byggeløypa må være grønn.
5. Skriv hva som er testet på Windows, og hva som ikke er det.

## Versjoner

Fra første offentlige utgivelse følger prosjektet [Semantisk versjonering](https://semver.org/lang/no/):

| Del | Økes når |
|---|---|
| **Hoved** (X.0.0) | Risikomodellen endres slik at samme PC gir andre farger, formatet i en regelfil eller i JSON-rapporten endres på en måte som ikke er bakoverkompatibel, eller kommandolinjevalg fjernes |
| **Minor** (0.X.0) | Nye sjekker, nye felt, nye regler eller nye kommandolinjevalg |
| **Patch** (0.0.X) | Feilrettinger og sikkerhetsrettinger uten nye funksjoner |

Endringer bare i `regler.json` eller `ai-modeller.yar` (nye produkter, nettsteder, regler) er minor. Feltet
`versjon` i `regler.json` oppdateres hver gang reglene endres.

## Lage en utgivelse

1. Flytt alt under `[Ikke utgitt]` i [CHANGELOG.md](CHANGELOG.md) til en ny versjon med dato, og oppdater lenkene nederst.
2. Oppdater `<Version>` i `src/AISkanner/AISkanner.csproj` og `assemblyIdentity version` i `src/AISkanner/app.manifest`.
   (Manifestet står på `2.1.0.0` og er ikke fulgt med siden 2.1.)
3. Oppdater versjonen og [Status](README.md#status)-tabellen i [README.md](README.md).
4. Merk utgivelsen: `git tag v2.11.0 && git push origin v2.11.0`.
5. Byggeløypa bygger, sjekker størrelsen og laster opp `AISkanner-usignert` med `SHA256.txt`.
6. Når SignPath er godkjent, signeres utgivelsen etter manuell godkjenning, se [CODE_SIGNING.md](CODE_SIGNING.md).
7. Legg ved zip-fila og innholdet i `SHA256.txt` i GitHub-utgivelsen.

## Lisens

Ved å bidra godtar du at bidraget ditt lisensieres under [MIT](LICENSE), som resten av prosjektet.
