import sys
import json

f = open(sys.argv[1])
data = json.load(f)
f.close()

v = []
for el in data:
	if ("/external/" in el['file']) or (".pb.cc" in el['file']):
		continue
	v.append(el)

f = open(sys.argv[1], 'w')
json.dump(v, f, indent=2)
f.close()
