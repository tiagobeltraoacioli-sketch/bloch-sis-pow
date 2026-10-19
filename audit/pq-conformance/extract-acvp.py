import json, sys, os
src, wt = sys.argv[1], sys.argv[2]
C = "975de31eb83d87039ec88934fdc47d8c312b892d"
def load(n): return json.load(open(os.path.join(src, n + ".json")))
def lo(t, keys):
    out = {}
    for k in keys:
        v = t.get(k)
        out[k] = v.lower() if isinstance(v, str) else v
    return out
def groups(d, ps, **cond):
    for g in d["testGroups"]:
        if g.get("parameterSet") == ps and all(g.get(k) == v for k, v in cond.items()):
            yield g
# ML-DSA-65
kg = load("ML-DSA-keyGen-FIPS204"); sg = load("ML-DSA-sigGen-FIPS204"); sv = load("ML-DSA-sigVer-FIPS204")
ml = {"source": "usnistgov/ACVP-Server@" + C + " gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json",
      "parameterSet": "ML-DSA-65",
      "keyGen": [lo(t, ["tcId", "seed", "pk", "sk"]) for g in groups(kg, "ML-DSA-65") for t in g["tests"]],
      "sigGen": [dict(lo(t, ["tcId", "pk", "sk", "message", "context", "signature", "rnd"]), tgId=g["tgId"], deterministic=g["deterministic"])
                 for g in groups(sg, "ML-DSA-65", signatureInterface="external", preHash="pure") for t in g["tests"]],
      "sigVer": [dict(lo(t, ["tcId", "pk", "message", "context", "signature", "testPassed", "reason"]), tgId=g["tgId"])
                 for g in groups(sv, "ML-DSA-65", signatureInterface="external", preHash="pure") for t in g["tests"]]}
json.dump(ml, open(os.path.join(wt, "crates/bloch-crypto/tests/vectors/acvp-fips204-mldsa65-full.json"), "w"), indent=1); 
# SLH-DSA-SHAKE-128s
kg = load("SLH-DSA-keyGen-FIPS205"); sg = load("SLH-DSA-sigGen-FIPS205"); sv = load("SLH-DSA-sigVer-FIPS205")
P = "SLH-DSA-SHAKE-128s"
slh = {"source": "usnistgov/ACVP-Server@" + C + " gen-val/json-files/SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205/internalProjection.json",
       "parameterSet": P,
       "keyGen": [lo(t, ["tcId", "skSeed", "skPrf", "pkSeed", "sk", "pk"]) for g in groups(kg, P) for t in g["tests"]],
       "sigGen": [dict(lo(t, ["tcId", "sk", "pk", "message", "context", "additionalRandomness", "signature"]), tgId=g["tgId"], deterministic=g["deterministic"], signatureInterface=g["signatureInterface"])
                  for g in groups(sg, P) if g["preHash"] in ("pure", "none") for t in g["tests"]],
       "sigVer": [dict(lo(t, ["tcId", "pk", "message", "context", "signature", "testPassed", "reason"]), tgId=g["tgId"], signatureInterface=g["signatureInterface"])
                  for g in groups(sv, P) if g["preHash"] in ("pure", "none") for t in g["tests"]]}
os.makedirs(os.path.join(wt, "audit/pq-conformance/vectors"), exist_ok=True)
json.dump(slh, open(os.path.join(wt, "audit/pq-conformance/vectors/acvp-fips205-slhdsa-shake128s.json"), "w"), indent=1)
print({k: len(v) for k, v in ml.items() if isinstance(v, list)}, {k: len(v) for k, v in slh.items() if isinstance(v, list)})
print(sorted(set(t["reason"] for t in ml["sigVer"])), sorted(set(t["reason"] for t in slh["sigVer"])))
print("empty-ctx mldsa siggen:", sum(1 for t in ml["sigGen"] if not t["context"]))
