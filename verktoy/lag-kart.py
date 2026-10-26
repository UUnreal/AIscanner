"""Lager et lite verdenskart (SVG-stier per land, ISO alpha-2) fra world-atlas countries-110m.json (TopoJSON, bare data)."""
import json, sys
topo = json.load(open(sys.argv[1])); codes = json.load(open(sys.argv[2]))
num2 = {c[2]: c[0] for c in codes}
sx, sy = topo["transform"]["scale"]; tx, ty = topo["transform"]["translate"]
arcs = []
for a in topo["arcs"]:
    x = y = 0; pts = []
    for dx, dy in a:
        x += dx; y += dy; pts.append((x * sx + tx, y * sy + ty))
    arcs.append(pts)
def ring(idx):
    out = []
    for i in idx:
        a = arcs[i] if i >= 0 else arcs[~i][::-1]
        out.extend(a if not out else a[1:])
    # Russland og Fiji krysser datolinjen: gjør ringen sammenhengende (ellers blir det en stripe over hele kartet)
    for i in range(1, len(out)):
        d = out[i][0] - out[i-1][0]
        if abs(d) > 180: out[i:] = [(x - 360 if d > 0 else x + 360, y) for x, y in out[i:]]
    return out
W, LATMAX, LATMIN = 1000, 84, -58
H = round(W * (LATMAX - LATMIN) / 360)
px = lambda p: ((p[0] + 180) / 360 * W, (LATMAX - p[1]) / (LATMAX - LATMIN) * H)
land, senter = {}, {}
for g in topo["objects"]["countries"]["geometries"]:
    navn = g.get("properties", {}).get("name")
    id_ = num2.get(g.get("id")) or {"Kosovo": "XK", "N. Cyprus": "CY", "Somaliland": "SO"}.get(navn)
    if not id_ or id_ == "AQ" or g["type"] not in ("Polygon", "MultiPolygon"): continue
    polys = [g["arcs"]] if g["type"] == "Polygon" else g["arcs"]
    d = ""; best = (0, None)
    for poly in polys:
        for k, r in enumerate(poly):
            rr = ring(r)
            # Delen som havner utenfor ±180 tegnes også på motsatt side; kartet klipper resten
            skift = [0] + ([-360] if max(x for x, _ in rr) > 180 else []) + ([360] if min(x for x, _ in rr) < -180 else [])
            for sk in skift:
                s = ""; last = None
                for x, y in (px((x + sk, y)) for x, y in rr):
                    p = (round(x), round(y))
                    if p == last: continue
                    s += ("L" if s else "M") + f"{p[0]} {p[1]}"; last = p
                d += s + "Z"
            pts = [px(p) for p in rr]
            if k == 0 and len(pts) > 2:
                a = cx = cy = 0
                for i in range(len(pts) - 1):
                    c = pts[i][0] * pts[i+1][1] - pts[i+1][0] * pts[i][1]
                    a += c; cx += (pts[i][0] + pts[i+1][0]) * c; cy += (pts[i][1] + pts[i+1][1]) * c
                if a and abs(a) > best[0]: best = (abs(a), [round(cx / (3 * a)), round(cy / (3 * a))])
    land[id_] = land.get(id_, "") + d
    senter.setdefault(id_, best[1])
ekstra = {"SG": (103.8, 1.35), "HK": (114.17, 22.3), "MT": (14.4, 35.9), "LU": (6.1, 49.6), "BH": (50.5, 26), "MC": (7.4, 43.7),
          "LI": (9.55, 47.15), "AD": (1.5, 42.5), "MU": (57.5, -20.2), "MV": (73.5, 4.2), "BB": (-59.5, 13.2)}
for k, v in ekstra.items():
    if not senter.get(k): senter[k] = [round(c) for c in px(v)]
# Kjente skjevheter: USA-senter i Alaska-polygonen? bruk fastland
fast = {"US": (-98, 39), "FR": (2.5, 46.5), "NO": (9, 61), "RU": (90, 61), "CA": (-100, 57), "GB": (-2, 53), "NL": (5.3, 52.2), "IE": (-8, 53.2)}
for k, v in fast.items(): senter[k] = [round(c) for c in px(v)]
js = "const KART={w:%d,h:%d,land:%s,senter:%s};" % (W, H, json.dumps(land, separators=(",", ":")), json.dumps(senter, separators=(",", ":")))
open(sys.argv[3], "w").write(js)
print(len(land), "land", len(js), "bytes", W, H)
