@echo off
rem Kontrollerer at alarmene i AI-skanner virker: lager falske spor i en midlertidig mappe, sjekker dem og sletter mappa.
start "" "%~dp0AISkanner.exe" --kontroll %*
