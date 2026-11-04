import os, sys, io
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app
c = app.test_client()
r = c.post("/api/issue", json={"name": "Test Student", "programme": "BSc IT", "grade": "B"}).get_json()["record"]
cid = r["cert_id"]; print("issued", cid)
v = lambda **k: c.post("/api/verify", json={**r, **k}).get_json()["verdict"]
print("genuine          ->", v(label="genuine"))
print("grade B->A       ->", v(grade="A", label="tampered", attack_type="content"))
png = c.get(f"/certs/{cid}.png").data
res = c.post("/api/verify", data={**r, "label": "tampered", "attack_type": "visual", "file": (io.BytesIO(png), "c.png")}, content_type="multipart/form-data").get_json()
print("visual-only edit ->", res["verdict"], "(baseline blind spot) QR:", res["info"].get("qr_url"))
c.post("/api/dev/tamper", json={"node": 0, "cert_id": cid}); print("node0 tampered   ->", v(label="genuine"), "(majority still holds)")
print(c.get("/api/stats").get_json()["asr_by_attack"])
