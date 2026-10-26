# Kodesigneringspolicy

Målet er at alle utgivelser av AISkanner.exe signeres gjennom [SignPath Foundation](https://signpath.org),
med gratis sertifikat fra [SignPath.io](https://signpath.io). Til det er godkjent, er utgivelsene usignerte.

- Alle exe-filer bygges automatisk av GitHub Actions fra kildekoden i dette repoet (`.github/workflows/bygg.yml`).
- Hver utgivelse må godkjennes manuelt før signering.
- Roller: Forfattere, Gjennomgåere og Godkjennere: Jørund (vedlikeholder).
- Alle med skrivetilgang må ha tofaktorinnlogging på GitHub.

## Personvern
Programmet sender ingen data om brukeren eller PC-en noe sted. Etter hvert søk sendes bare et produktord fra
regelfila (for eksempel `ollama`) for kjente produkter som ble funnet, til
[NVD](https://nvd.nist.gov) (US National Vulnerability Database). Det kan slås av med `--uten-nvd`.
PC-navn, brukernavn og filstier sendes aldri. Rapporter lagres bare lokalt når brukeren ber om det.
Se [IT-INFO.md](IT-INFO.md) og [SECURITY.md](SECURITY.md).

## Installasjon og avinstallasjon
Programmet installeres ikke og endrer ingenting på maskinen. Slett mappa med AISkanner.exe for å fjerne det.
