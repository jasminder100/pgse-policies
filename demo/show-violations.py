import json, urllib.request, urllib.parse
q = urllib.parse.quote("pgse_violation")
r = json.load(urllib.request.urlopen(f"http://localhost:9090/api/v1/query?query={q}"))["data"]["result"]
print(f"{len(r)} non-compliant item(s)")
for x in sorted(r, key=lambda x: (x["metric"]["rule"], x["metric"]["name"])):
    m = x["metric"]
    print(f'  {m["rule"]} {m["action"]:5} {m["namespace"]}/{m["name"]}: {m["message"][:70]}')
