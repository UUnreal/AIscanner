# Lager trygge «ondsinnede» testmodeller for testlaben. Filene åpnes ALDRI med pickle/torch/keras:
# de er bare byte på disk, så kommandoen inni («echo testlab») kjøres aldri. Brukes til å se om skanneren slår ut.
import json, os, struct, sys, zipfile

ut = sys.argv[1]
os.makedirs(ut, exist_ok=True)
fasit = []

def skriv(navn, data, forventet, hva):
    p = os.path.join(ut, navn)
    with open(p, "wb") as f: f.write(data)
    fasit.append({"navn": navn, "sti": p, "forventet": forventet, "hva": hva})

def bu(s):  # BINUNICODE (X + 4 byte lengde)
    b = s.encode(); return b"X" + struct.pack("<I", len(b)) + b
def sbu(s):  # SHORT_BINUNICODE
    b = s.encode(); return b"\x8c" + bytes([len(b)]) + b

kall = bu("echo testlab") + b"\x85R."
glob = lambda m, n: b"c" + m.encode() + b"\n" + n.encode() + b"\n"
skriv("os-system-p2.pkl", b"\x80\x02" + glob("os", "system") + kall, "rod", "pickle protokoll 2, os.system")
skriv("nt-system-p0.pkl", glob("nt", "system") + b"(Vecho testlab\ntR.", "rod", "pickle protokoll 0, nt.system")
skriv("subprocess-p2.pkl", b"\x80\x02" + glob("subprocess", "Popen") + kall, "rod", "pickle, subprocess.Popen")
skriv("builtins-exec-p4.pkl", b"\x80\x04" + sbu("builtins") + b"\x94" + sbu("exec") + b"\x94\x93" + bu("print(1)") + b"\x85R.", "rod", "pickle protokoll 4, builtins.exec")
# Unnvikelser: samme angrep skrevet litt annerledes (viser om reglene har hull)
skriv("unnvik-binunicode-p4.pkl", b"\x80\x04" + bu("os") + bu("system") + b"\x93" + kall, "rod", "unnvikelse: STACK_GLOBAL med BINUNICODE")
skriv("unnvik-webbrowser.pkl", b"\x80\x02" + glob("webbrowser", "open") + bu("http://example.invalid") + b"\x85R.", "rod", "unnvikelse: webbrowser.open")
skriv("unnvik-importlib.pkl", b"\x80\x02" + glob("importlib", "import_module") + bu("os") + b"\x85R.", "rod", "unnvikelse: importlib.import_module")
# PyTorch-format: zip med archive/data.pkl
for navn in ("pytorch_model.bin", "ondsinnet.pt", "ondsinnet.ckpt"):
    p = os.path.join(ut, navn)
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("archive/data.pkl", b"\x80\x02" + glob("os", "system") + kall)
        z.writestr("archive/version", "3\n")
    fasit.append({"navn": navn, "sti": p, "forventet": "rod", "hva": "PyTorch-zip med os.system i data.pkl"})
# Keras v3 med Lambda-lag
p = os.path.join(ut, "lambda.keras")
with zipfile.ZipFile(p, "w") as z:
    z.writestr("config.json", json.dumps({"module": "keras.layers", "class_name": "Lambda", "config": {"function": {"class_name": "__lambda__", "config": {"code": "4wEAAAAAAAAAAAAAAAEAAAADAAAAQwAAAHMEAAAAfABTACkBTqkAKQHaAXhyAQAAAHIBAAAA"}}}}))
    z.writestr("metadata.json", json.dumps({"keras_version": "3.6.0"}))
fasit.append({"navn": "lambda.keras", "sti": p, "forventet": "rod", "hva": "Keras med Lambda-lag (CVE-2024-3660)"})
# GGUF med chat-mal som når Python-internals (CVE-2024-34359)
def gstr(s):
    b = s.encode(); return struct.pack("<Q", len(b)) + b
mal = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
kv = [("general.architecture", "llama"), ("general.name", "testlab-ondsinnet-mal"), ("tokenizer.chat_template", mal)]
data = b"GGUF" + struct.pack("<IQQ", 3, 0, len(kv)) + b"".join(gstr(k) + struct.pack("<I", 8) + gstr(v) for k, v in kv)
# Ekte angrepsmodeller er hele modeller: fyll ut til 25 MB så fila ser ut som en modell, ikke en testbit
skriv("ondsinnet-mal.gguf", data + b"\0" * (25 * 1024 * 1024), "rod", "GGUF-chat-mal med __subclasses__ (CVE-2024-34359)")
# Kontroller: ufarlig pickle skal IKKE være «farlig»
skriv("ufarlig-ordereddict.pkl", b"\x80\x02" + glob("collections", "OrderedDict") + b")R.", "ikke-farlig", "ufarlig pickle (kontroll)")
json.dump(fasit, open(os.path.join(ut, "..", "farlige-fasit.json"), "w"), indent=1)
print(f"{len(fasit)} testfiler i {ut}")
