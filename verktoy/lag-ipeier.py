# Lager ipeier.bin (IP -> ASN og eier) fra ip-location-db/asn (DB-IP + RouteViews, CC BY 4.0).
# Bruk: python3 lag-ipeier.py asn-ipv4-num.csv asn-ipv6-num.csv  -> ipeier.bin i gjeldende mappe
import csv,struct,zlib,sys
navn={}
def les(fn,v6):
    rader=[]
    for r in csv.reader(open(fn,encoding='utf-8')):
        a,b,asn=int(r[0]),int(r[1]),int(r[2])
        if v6: a>>=64;b>>=64
        navn.setdefault(asn,r[3])
        rader.append((a,b,asn))
    rader.sort()
    ut=[];slutt=-1
    for a,b,asn in rader:
        if a<=slutt and ut and ut[-1][1]==asn: slutt=max(slutt,b);continue
        if a>slutt+1: ut.append((slutt+1,0))
        if not(ut and ut[-1][1]==asn): ut.append((max(a,slutt+1),asn))
        slutt=max(slutt,b)
    ut.append((slutt+1,0))
    return ut
v4=les(sys.argv[1],False);v6=les(sys.argv[2],True)
asner=sorted(navn);idx={a:i+1 for i,a in enumerate(asner)}
d=bytearray(b'ASN1')
d+=struct.pack('<i',len(asner))
for a in asner:
    n=navn[a].encode('utf-8')[:200];d+=struct.pack('<IB',a,len(n))+n
for tab,fmt in ((v4,'<I'),(v6,'<Q')):
    d+=struct.pack('<i',len(tab))
    for s,_ in tab: d+=struct.pack(fmt,s)
    for _,a in tab: i=idx.get(a,0);d+=bytes((i&255,(i>>8)&255,(i>>16)&255))
c=zlib.compressobj(9,zlib.DEFLATED,-15);z=c.compress(bytes(d))+c.flush()
open('ipeier.bin','wb').write(z)
print(len(asner),'eiere',len(v4),'v4',len(v6),'v6',len(z),'byte')
