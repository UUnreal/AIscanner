# Kodesigneringspolicy

Målet er at alle utgivelser av AISkanner.exe signeres gjennom [SignPath Foundation](https://signpath.org),
med gratis sertifikat fra [SignPath.io](https://signpath.io). Til det er godkjent, er utgivelsene usignerte.

- Alle exe-filer bygges automatisk av GitHub Actions fra kildekoden i dette repoet (`.github/workflows/bygg.yml`).
- Hver utgivelse må godkjennes manuelt før signering.
- Roller: Forfattere, Gjennomgåere og Godkjennere: Jørund (vedlikeholder).
- Alle med skrivetilgang må ha tofaktorinnlogging på GitHub.

## Personvern
Programmet sender ingen data noe sted. Hvis brukeren selv slår på «Sjekk kjente sårbarheter på nett»,
sendes bare et produktord fra regelfilen (for eksempel `ollama`) til
[NVD](https://nvd.nist.gov) (US National Vulnerability Database). PC-navn, brukernavn og filstier sendes aldri.
Rapporter lagres bare lokalt når brukeren ber om det.

## Installasjon og avinstallasjon
Programmet installeres ikke og endrer ingenting på maskinen. Slett AISkanner.exe for å fjerne det.
