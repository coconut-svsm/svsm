import os
import sys
import pandas as pd
l = []
for line in sys.stdin:
    l.append(line)

cargopath = "/home/patrick/.cargo/registry/src/index.crates.io-6f17d22bba15001f"
deps = os.listdir(cargopath)
#print(deps)
lines = []

#fix names:
ll = []
for line in l:
    if "label" in line:
      t = line.split("\"")
      t = t[0] + " " + "\"" + ("-".join(t[1].split(" "))) + "\" "+ " ".join(t[2:len(t)])
      ll.append(t)
    else:
      ll.append(line)
l = ll

local = ["svsm","svsm-fuzz","packit","test","bootlib", "elf","syscall","libmstpm","cpuarch","igvmbuilder","igvmmeasure"]
local_path = ["kernel","fuzz","../../../../home/patrick/.cargo/git/checkouts/packit-b3e2ba428e3d4383/f31283d/src"] + local[3:len(local)] 
for line in l: 
    if "label" in line:
        if not any(n in line for n in local):
            s = line.split("\"")
            dep = s[1]
            dep_org = dep
            if not dep in deps:
                for d in deps:
                    if dep in d:
                        dep = d
            #print(dep)  

            infostream = os.popen(f"cloc --csv {cargopath}/{dep}")
            #info = infostream.read()
            info = pd.read_csv(infostream)
            loc = info[info["language"].isin(["Rust", "C"])]["code"].sum()
            r = s[0] + "\"" + (dep+" "+str(loc))+"\"" + "".join(s[2:len(s)])
            print(r)
        else:
            s = line.split("\"")
            dep = s[1]
            
    
            infostream = os.popen(f"cloc --csv ./{local_path[local.index(dep)]}")
            #info = infostream.read()
            info = pd.read_csv(infostream)
            loc = info[info["language"].isin(["Rust", "C"])]["code"].sum()
            r = s[0] + "\"" + (dep+" "+str(loc))+"\"" + "".join(s[2:len(s)])
            print(r)            
    else:
        print(line)
        pass 

#--exclude igvmmeasure,igvmbuilder,svsm-fuzz