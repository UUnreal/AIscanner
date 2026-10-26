# Regelfiler

AI-skanner har tre filer som IT kan endre uten å bygge programmet på nytt. Alle tre er bygget inn i programmet.
Legger du en fil med samme navn ved siden av `AISkanner.exe`, brukes den i stedet.

| Fil | Innebygd kilde | Hva den styrer |
|---|---|---|
| `godkjent-ai.txt` | `src/AISkanner/godkjent-ai.txt` (følger med, tom) | AI bedriften har godkjent. Blir grønt. |
| `regler.json` | `src/AISkanner.Core/regler.json` | Navn, risiko og land for kjente produkter, nettsteder, tjenester og modellfamilier |
| `ai-modeller.yar` | `src/AISkanner.Core/ai-modeller.yar` | YARA-regler for modellfiler |

> **Sikkerhet:** Filene er ikke signert. Den som kan skrive i programmappa, kan endre hva som blir rødt og grønt.
> Legg programmet i en mappe vanlige brukere ikke kan skrive til. Se [SECURITY.md](../SECURITY.md#kjente-svakheter).

Rapporten viser om YARA-reglene var innebygde eller kom fra en fil. Den viser ennå ikke hvilken `regler.json` eller
godkjentliste som ble brukt (`Regelsett.Kilde` og `GodkjentKilde` blir satt, men ikke skrevet ut).

## godkjent-ai.txt

Én oppføring per linje. Linjer som starter med `#`, er kommentarer. Store og små bokstaver spiller ingen rolle.

```
# AI bedriften har avtale med
Microsoft 365 Copilot
m365.cloud.microsoft
GitHub Copilot
```

En oppføring kan være:

- **Et navn**, skrevet slik det står i skanneren eller rapporten. Både fullt navn og kort navn virker. For
  nettleserutvidelser er kortnavnet uten «(Chrome-utvidelse)».
- **Et domene**, for eksempel `copilot.microsoft.com`. Det treffer også underdomener, men bare i målte forbindelser og nettstedsfunn, ikke i filstier. En oppføring regnes som domene
  når den inneholder punktum og ikke mellomrom.

Regler:

- AI på lista blir 🟢 grønn med typen «Godkjent av IT», så lenge den ikke har faresignaler.
- Godkjent AI som er åpen mot nettverket, blir 🔴 rød. Godkjent AI som kjører fra nedlastinger, kan kjøre skjult kode
  eller er blokkert av IT, blir 🟡 gul. Godkjenning fjerner bare risikoen ved at AI-en ikke er godkjent.
- Ukjent AI, farlige modellfiler og AI som sender data til høyrisikoland blir 🔴 røde uansett.
- Oppføringene legges sammen med `godkjentAi` i `regler.json`.

**Bruk eksakte produktnavn og offisielle domener.** Fra 2.13.1 godkjennes et navn bare når funnet er gjenkjent fra
`regler.json` eller er et kjent nettsted. En ukjent utvidelse eller mappe som kaller seg det samme som en godkjent AI,
blir ikke grønn. Et domene godkjennes bare mot forbindelser skanneren har målt, og mot nettstedsfunn.

## regler.json

JSON med kommentarer (`//`) og komma etter siste element tillatt. Nøkler som starter med `_`, er forklaringer og
leses ikke.

> **Viktig:** en `regler.json` ved siden av programmet **erstatter** hele den innebygde fila. Den blir ikke slått sammen
> med den. Start alltid med en kopi av [den innebygde fila](../src/AISkanner.Core/regler.json) og endre i den.
> Bare `godkjent-ai.txt` legges i tillegg.

Kommandolinjen kan peke på en annen fil: `AISkanner.Cli --regler sti\regler.json`.

### Toppnivå

| Felt | Type | Bruk |
|---|---|---|
| `versjon` | tekst | Versjonen av reglene, vises i rapporten. |
| `produkter` | liste | Kjente AI-produkter (se under). |
| `aiNettsteder` | liste | AI-nettsteder som kjennes igjen i nettleserdata. |
| `aiTjenester` | liste | AI-API-er som programmer snakker med i bakgrunnen, kjent på vertsnavn. |
| `hoyrisikoLand` | liste med landkoder | Data hit gir alltid rødt. Standard: `CN`, `RU`, `IR`, `KP`, `BY`. |
| `godkjentAi` | liste med tekst | Som `godkjent-ai.txt`. |
| `selskapsland` | objekt | Selskap eller produkt → land, for «Kommer fra». Verdien er `"US"` eller `"US:Anthropic"` (land og selskap). |
| `modellfamilier` | liste | Modellfamilier som kjennes igjen på innholdet. |
| `leverandorAi` | liste | Navn på AI som leverandører legger inn. |
| `nettleserInnebygd` | liste | Innebygd AI i nettlesere (Gemini Nano, Edge). |
| `ukjentUtvidelseOrd` | liste med tekst | Ord i navn eller beskrivelse som gjør en ukjent utvidelse til et AI-funn, for eksempel `gpt` og `copilot`. |
| `modellfilEndelser` | liste | Filendelser for modellfiler (`.gguf`, `.safetensors` …). |
| `modellfilMinMB` | tall | Minste størrelse for modellfiler med kjent endelse. Standard 200. |
| `innebygdMappeOrd` | liste | Ord i mappenavn som peker på innebygde nettlesermodeller. |

### produkter

```json
{
  "navn": "Ollama",
  "kategori": "Lokal AI",
  "risiko": "gul",
  "treff": ["ollama"],
  "mapper": ["%USERPROFILE%\\.ollama"],
  "porter": [11434],
  "kommandoer": [],
  "nvd": "ollama",
  "hvorfor": "Kjører språkmodeller lokalt …",
  "enkelt": "Kjører AI lokalt på PC-en",
  "hvorforEnkelt": "Kjører AI-modeller på selve PC-en …"
}
```

| Felt | Bruk |
|---|---|
| `navn` | Navnet som vises. |
| `kategori` | Bestemmer gruppe og type. Starter den med `Lokal`, havner funnet i *Lokal AI*. Starter den med `Nettleser`, havner det i *Nettleser*. Ellers havner det i *Skjult på PC*. Se [ARKITEKTUR.md](ARKITEKTUR.md#kategori-og-gruppe). |
| `risiko` | `rod`, `gul` eller `gronn`. Dette er risikoen fra søket. Skygge-AI blir likevel rød, se [Risikomodell](ARKITEKTUR.md#risikomodell). |
| `treff` | Ord som søkes etter i navn på prosesser, programmer, tjenester, oppstart og utvidelser. Hele ord, uten forskjell på store og små bokstaver. |
| `mapper` | Mapper som avslører produktet. Miljøvariabler som `%USERPROFILE%` er lov. |
| `porter` | Porter produktet lytter på. |
| `kommandoer` | Kommandoer i `PATH` (`.exe`, `.cmd`, `.bat`, `.ps1`). Bare om fila finnes. Ingenting kjøres. |
| `kunUtvidelse` | `true` når regelen bare skal treffe nettleserutvidelser. |
| `nvd` | Ordet som sendes til NVD for å telle kjente sårbarheter. Bruk et produktord, aldri noe som kan identifisere en person eller bedrift. |
| `hvorfor`, `hvorforEnkelt`, `enkelt` | Forklaringer i rapport og detaljvisning. |
| `rad` | Brukes ikke lenger. Råd ble fjernet fra skjerm og rapport i 2.8. |

### aiNettsteder og aiTjenester

```json
{ "navn": "OpenAI API", "domener": ["api.openai.com"], "risiko": "gul", "land": "US",
  "enkelt": "AI fra OpenAI (ChatGPT) brukt av et program", "hvorfor": "…" }
```

`domener` treffer domenet og alle underdomener. Når flere passer, vinner det lengste domenet. `land` er landet
selskapet hører hjemme i, og brukes i «Sender data til».

### modellfamilier

```json
{ "navn": "Llama 3", "utgiver": "Meta", "land": "US", "arkitekturer": ["llama"],
  "vokab": [128256, 128257], "ord": ["llama-3", "llama3"] }
```

| Felt | Bruk |
|---|---|
| `arkitekturer` | Verdien av `general.architecture` i GGUF, eller `model_type` i `config.json`. |
| `vokab` | Størrelsen på ordforrådet. Den følger familien selv om fila får nytt navn eller blir finjustert. |
| `deltVokab` | `true` når mange familier har samme størrelse. Da teller den mindre. |
| `ord` | Tekst i modellnavnet som peker på familien. |
| `type` | Valgfri. Hva slags modell, for eksempel bilde eller tale. |

### leverandorAi

```json
{ "ord": ["microsoftwindows.client.aix"], "navn": "Windows AI: Recall og Click to Do",
  "utgiver": "Microsoft", "hva": "Recall, Click to Do og AI-søk i Windows", "bekreftet": false }
```

Denne lista gir **bare navn**. Selve funnet gjøres på innholdet (modellfiler og AI-motorer), og leverandøren bekreftes
med signatur. `ord` er biter av mappestien med små bokstaver. `bekreftet: false` betyr at mappenavnet ikke er sjekket
på en ekte PC ennå.

### nettleserInnebygd

Beskriver innebygd AI i en nettleser: `brukerdata` (mappen med brukerdata), `policyNokkel` og `policyVerdi` (policyen
som slår den av) og forklaringstekster.

## ai-modeller.yar

Vanlig YARA 4-syntaks. Fila kan også kjøres med `yara.exe`:

```
yara ai-modeller.yar C:\Users\navn\Downloads\modell.pt
```

AI-skanner leser de første 8 MB og siste 1 MB av hver modell den finner, og den første MB-en av små
pickle-, PyTorch-, Keras- og NumPy-filer. Se [ARKITEKTUR.md](ARKITEKTUR.md#yara-motor) for hva motoren støtter.

### Konvensjoner

| Del | Bruk |
|---|---|
| `meta: beskrivelse` | Teksten som vises i resultatet. |
| `meta: risiko` | `rod`, `gul` eller `gronn`. `rod` gjør funnet rødt. |
| Tagg `format` | Hvilken type modell fila er. |
| Tagg `ondsinnet` | Tegn på at modellen kan kjøre kode eller gjemmer noe. Disse sjekkes også på små filer. |

### Innebygde regler

| Regel | Tagg | Finner |
|---|---|---|
| `AI_GGUF` | format | GGUF (llama.cpp, Ollama, LM Studio, GPT4All) |
| `AI_Safetensors` | format | safetensors |
| `AI_PyTorch` | format | PyTorch (zip med pickle) |
| `AI_Pickle` | format | Rå pickle |
| `AI_Keras_HDF5`, `AI_Keras_v3` | format | Keras |
| `AI_TFLite` | format | TensorFlow Lite |
| `AI_OpenVINO` | format | OpenVINO |
| `AI_Pickle_kjorer_kommando` | ondsinnet | Pickle som kaller `os.system`, `subprocess`, `exec` eller `eval` |
| `AI_Pickle_nettverk` | ondsinnet | Pickle med nettverkskall |
| `AI_Keras_Lambda` | ondsinnet | Keras-modell med Lambda-lag (vilkårlig Python-kode) |
| `AI_GGUF_mal_med_kode` | ondsinnet | GGUF-chatmal med Python-internals (CVE-2024-34359) |
| `AI_Modell_med_program` | ondsinnet | Windows-program (MZ/PE) gjemt i en modellfil |
| `AI_Modell_med_skall` | ondsinnet | Skallkommandoer gjemt i en modellfil |

### Legge til en regel

1. Skriv regelen i `src/AISkanner.Core/ai-modeller.yar`, eller i en kopi ved siden av programmet.
2. Sjekk at den kompilerer med ekte YARA: `python3 verktoy/test-yara.py fil …` (krever `pip install yara-python`).
3. Sjekk at motoren vår gir samme svar: `python3 verktoy/sammenlign-yara.py ai-modeller.yar testmappe/`.
4. Hvis fila ved siden av programmet har en feil, brukes de innebygde reglene, og rapporten sier hvorfor.
