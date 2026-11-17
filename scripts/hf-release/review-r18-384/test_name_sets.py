import subprocess,re,sys
def names(c):
    out=subprocess.run(['git','grep','-n','-A4','-E',r'^[[:space:]]*#\[(tokio::)?test',c,'--','crates','tools'],capture_output=True,text=True).stdout
    s=set()
    for line in out.splitlines():
        m=re.match(r'^[^:]+:(.+?)[-:]\d+[-:].*?\bfn ([a-z_0-9]+)\s*\(',line)
        if m: s.add((m.group(1),m.group(2)))
    return s
a,b,m=names(sys.argv[1]),names(sys.argv[2]),names(sys.argv[3])
print(len(a),len(b),len(m))
mn={n for _,n in m}
for tag,x in (('L2',a),('main',b)):
    miss=sorted(x-m)
    print(tag,'missing(file,name):',len(miss))
    for f,n in miss: print('  ',f,n,'(name elsewhere)' if n in mn else '(NAME GONE)')
