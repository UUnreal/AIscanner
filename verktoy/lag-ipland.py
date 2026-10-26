import csv,struct,zlib,ipaddress,sys
def les(fn,v6):
    rader=[]
    for a,b,c in csv.reader(open(fn)):
        a=int(a);b=int(b)
        if v6: a>>=64;b>>=64
        rader.append((a,b,c))
    rader.sort()
    ut=[];prev_end=-1
    for a,b,c in rader:
        if a>prev_end+1: ut.append((prev_end+1,'--'))
        if ut and ut[-1][1]==c: pass
        else: ut.append((a,c))
        prev_end=max(prev_end,b)
    ut.append((prev_end+1,'--'))
    return ut
v4=les('package/dbip-country-ipv4-num.csv',False)
v6=les('package/dbip-country-ipv6-num.csv',True)
v4=[(a,c) for a,c in v4 if a<=0xFFFFFFFF]
land=sorted(set(c for _,c in v4+v6))
idx={c:i for i,c in enumerate(land)}
b=bytearray(b'IPL1')
b+=struct.pack('<H',len(land))
for c in land:b+=c.encode()
b+=struct.pack('<I',len(v4))
for a,c in v4:
    if a>0xFFFFFFFF: continue
    b+=struct.pack('<I',a)
for a,c in v4:
    if a>0xFFFFFFFF: continue
    b.append(idx[c])
v6=[(a,c) for a,c in v6 if a<=0xFFFFFFFFFFFFFFFF]
b+=struct.pack('<I',len(v6))
for a,c in v6:b+=struct.pack('<Q',a)
for a,c in v6:b.append(idx[c])
z=zlib.compressobj(9,zlib.DEFLATED,-15)
d=z.compress(bytes(b))+z.flush()
open('ipland.bin','wb').write(d)
print(len(v4),len(v6),len(land),len(b),len(d))
