"""Sjekker at ai-modeller.yar kompilerer med ekte YARA (pip install yara-python) og viser treff på filene som gis."""
import sys, yara
r = yara.compile(filepath="src/AISkanner.Core/ai-modeller.yar")
for f in sys.argv[1:]:
    print(f, [m.rule for m in r.match(f)])
