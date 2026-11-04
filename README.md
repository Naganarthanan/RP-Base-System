<<<<<<< HEAD
# CertChain Registry – Baseline System (J26-NU-SE-002)
Python 3.10+ · Flask · vanilla JS (no build step).

## Run
    python -m venv venv && venv\Scripts\activate      # Windows  (Linux/Mac: source venv/bin/activate)
    pip install -r requirements.txt
    python app.py                                      # http://127.0.0.1:5000
    python tests/smoke.py                              # optional quick check

## Where each component plugs in
- C1 Manipulation attack: edit `data/assets/{logo,seal,signature}.png`, regenerate QR/metadata on `data/certs/<id>.png`,
  then POST to `/api/verify` (multipart: cert_id,name,programme,grade,issue_date,file,label=tampered,attack_type,testbed). Latency + verdict go to `data/verify_log.jsonl`; ASR shows on the Overview tab.
- C2 Manipulation defense: change `Network.add/find` in chain.py (vertical partitioning) and add OCR/forensics checks inside `api_verify`.
- C3 Inference attack: `/api/verify` leaks per-field match + on-chain `field_hashes` are unsalted (dictionary attack target).
- C4 Inference defense: replace `field_hashes` with Bloom filter / salted / HMAC + horizontal partitioning.
- `DEFENSE_MODE` env var labels each log entry (baseline | vertical | horizontal) so baseline vs defended ASR can be compared.

## Known baseline weaknesses (intentional)
Only structured fields are hashed; logo/seal/signature/QR/metadata are not. QR domain and file hash are reported, not enforced.
`/api/dev/tamper` simulates a compromised organisation – lab use only.
=======
# RP-Base-System
CertChain Registry: Baseline System  CertChain is a baseline prototype of a student certificate verification system built on a simulated permissioned blockchain. It is the common testbed for a security research project, where attacks and defenses are evaluated against the same system.
>>>>>>> 2ea5583ed6e7c4674fbdeb248482750b35903a8d
