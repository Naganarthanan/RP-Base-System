import json, os, random, time
from urllib.parse import urlparse
from flask import Flask, jsonify, redirect, render_template, request, send_file, abort
from config import *
from chain import Network, sha
from certs import build_certificate, decode_qr, ensure_assets

app = Flask(__name__)
for p in ("certs", "ipfs"): os.makedirs(os.path.join(DATA, p), exist_ok=True)
net, LOG = Network(), os.path.join(DATA, "verify_log.jsonl")
ensure_assets()
FIELDS = ["name", "programme", "grade", "issue_date"]
# BASELINE DESIGN: only these structured fields are hashed. Logo, seal, signature, QR and file metadata are NOT covered.
canon = lambda r: json.dumps({k: r.get(k, "").strip() for k in ["cert_id"] + FIELDS}, sort_keys=True)

def issue_record(d):
    n = sum(1 for b in net.nodes[0].chain if "cert_id" in b["data"]) + 1
    r = {"cert_id": d.get("cert_id") or f"ST{n:04d}", "name": d["name"].strip(), "programme": d["programme"].strip(),
         "grade": d["grade"].strip(), "issue_date": d.get("issue_date") or time.strftime("%Y-%m-%d")}
    png = build_certificate(r, f"{PUBLIC_URL}/verify/{r['cert_id']}")
    cid = "Qm" + sha(png)[:44]                                           # IPFS-style content address (simulated)
    open(os.path.join(DATA, "ipfs", cid + ".png"), "wb").write(png)
    open(os.path.join(DATA, "certs", r["cert_id"] + ".png"), "wb").write(png)
    data = {"cert_id": r["cert_id"], "record_hash": sha(canon(r)), "ipfs_cid": cid, "issuer": INSTITUTION,
            "field_hashes": {k: sha(r[k]) for k in FIELDS}}               # unsalted per-field hashes (weak on purpose, for C3)
    return r, net.add(data)

@app.get("/")
def index(): return render_template("index.html", mode=DEFENSE_MODE, inst=INSTITUTION)

@app.get("/verify/<cid>")                                                # target of the QR code
def portal(cid): return redirect(f"/#verify={cid}")

@app.get("/certs/<cid>.png")
def cert_img(cid):
    p = os.path.join(DATA, "certs", os.path.basename(cid) + ".png")
    return send_file(p, mimetype="image/png") if os.path.exists(p) else abort(404)

@app.post("/api/issue")
def api_issue():
    d = request.get_json(force=True)
    if not all(d.get(k) for k in ("name", "programme", "grade")): return jsonify(error="name, programme and grade are required"), 400
    r, blk = issue_record(d)
    return jsonify(record=r, block=blk, cert_url=f"/certs/{r['cert_id']}.png", qr_url=f"{PUBLIC_URL}/verify/{r['cert_id']}")

@app.post("/api/seed")
def api_seed():
    names = ["P. Vathany", "A. Kumaran", "S. Nirmala", "R. Dineshkumar", "M. Aaliya"]
    out = [issue_record({"name": n, "programme": "BSc (Hons) Information Technology", "grade": random.choice(["A", "A-", "B+", "B"])})[0] for n in names]
    return jsonify(issued=out)

@app.post("/api/verify")
def api_verify():
    """Baseline verifier. Decision uses ONLY the structured-field hash + chain consensus.
    Optional upload -> QR decoded for the id; file hash / QR domain are reported but NOT enforced (research gap)."""
    t0 = time.perf_counter()
    f = request.form.to_dict() if request.form else (request.get_json(silent=True) or {})
    up = request.files.get("file"); raw = up.read() if up else None
    cid, info = (f.get("cert_id") or "").strip(), {}
    if raw:
        qr = decode_qr(raw); info["qr_url"] = qr
        if qr:
            info["qr_domain_official"] = urlparse(qr).hostname == OFFICIAL_DOMAIN
            cid = cid or qr.rstrip("/").split("/")[-1]
    blk, agree = net.find(cid)
    status = net.status(); valid_nodes = sum(s["valid"] for s in status)
    checks = {"record_found": blk is not None, "node_consensus": f"{agree}/{len(net.nodes)}", "chain_integrity": valid_nodes > len(net.nodes) // 2}
    verdict = "INVALID"
    if blk:
        d = blk["data"]
        checks["field_match"] = {k: sha(f.get(k, "").strip()) == d["field_hashes"][k] for k in FIELDS}   # leaks which field differs (baseline)
        checks["record_hash_match"] = sha(canon({**f, "cert_id": cid})) == d["record_hash"]
        if raw: info["file_hash_matches_ipfs"] = ("Qm" + sha(raw)[:44]) == d["ipfs_cid"]; info["note"] = "file/QR checks are informational only in baseline"
        if checks["record_hash_match"] and checks["chain_integrity"]: verdict = "VALID"
    lat = round((time.perf_counter() - t0) * 1000, 2)
    entry = {"ts": time.time(), "cert_id": cid, "verdict": verdict, "latency_ms": lat, "label": f.get("label", "unlabelled"),
             "attack_type": f.get("attack_type", "none"), "testbed": f.get("testbed", "python-chain"), "mode": DEFENSE_MODE}
    open(LOG, "a").write(json.dumps(entry) + "\n")
    return jsonify(verdict=verdict, checks=checks, info=info, latency_ms=lat, mode=DEFENSE_MODE)

def logs(): return [json.loads(l) for l in open(LOG)] if os.path.exists(LOG) else []

@app.get("/api/stats")
def api_stats():
    L = logs(); T = [l for l in L if l["label"] == "tampered"]; acc = [l for l in T if l["verdict"] == "VALID"]
    by = {}
    for l in T: by.setdefault(l["attack_type"], [0, 0]); by[l["attack_type"]][0] += 1; by[l["attack_type"]][1] += l["verdict"] == "VALID"
    return jsonify(issued=sum(1 for b in net.nodes[0].chain if "cert_id" in b["data"]), verifications=len(L),
                   accepted=sum(l["verdict"] == "VALID" for l in L), avg_latency_ms=round(sum(l["latency_ms"] for l in L) / len(L), 2) if L else 0,
                   tampered_attempts=len(T), asr=round(100 * len(acc) / len(T), 1) if T else None,
                   asr_by_attack={k: {"attempts": v[0], "asr": round(100 * v[1] / v[0], 1)} for k, v in by.items()}, nodes=net.status(), mode=DEFENSE_MODE)

@app.get("/api/chain")
def api_chain(): return jsonify([{"node": n.name, "chain": n.chain, "valid": n.valid()[0]} for n in net.nodes])

@app.get("/api/logs")
def api_logs(): return jsonify(logs())

@app.post("/api/dev/tamper")   # LAB ONLY: simulate a compromised organisation editing its own copy of a record
def api_tamper():
    d = request.get_json(force=True); n = net.nodes[int(d.get("node", 0))]
    for b in n.chain:
        if b["data"].get("cert_id") == d["cert_id"]: b["data"]["record_hash"] = sha("forged"); n.save(); return jsonify(ok=True, node=n.name)
    return jsonify(ok=False), 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)
