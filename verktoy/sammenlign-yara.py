"""Kjører samme regler med ekte YARA (yara-python) og AISkanner.Cli --yara, og viser forskjeller.
Bruk: python3 verktoy/sammenlign-yara.py regler.yar fil-eller-mappe ..."""
import subprocess, sys, yara
import os
regler, filer = sys.argv[1], []
for a in sys.argv[2:]:
    if os.path.isdir(a):
        filer += [os.path.join(d, n) for d, _, ns in os.walk(a) for n in ns if os.path.isfile(os.path.join(d, n))]
    else:
        filer.append(a)
r = yara.compile(filepath=regler)
ekte = {f: " ".join(sorted(m.rule for m in r.match(f))) for f in filer}
ut = subprocess.run(["dotnet", "src/AISkanner.Cli/bin/Release/net8.0/AISkanner.Cli.dll", "--yara", regler, *filer],
                    capture_output=True, text=True, check=True).stdout.splitlines()
var = {l.split(": ", 1)[0]: (l.split(": ", 1)[1] if ": " in l else "") for l in ut}
feil = 0
for f in filer:
    if ekte[f] != var.get(f, "").strip():
        feil += 1
        print(f"ULIKT {f}\n  yara: {ekte[f]}\n  vår:  {var.get(f)}")
print(f"{len(filer)} filer, {sum(1 for v in ekte.values() if v)} med treff, {feil} ulike")
sys.exit(1 if feil else 0)
