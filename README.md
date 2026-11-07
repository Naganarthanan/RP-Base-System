# CertChain Academic Registry

A university records system on a simulated permissioned blockchain, built in **two designs**
so they can be compared under the same attacks:

- **Conventional system** — each record is anchored on-chain with plain, unsalted SHA-256 hashing.
- **Bloom filter system** — each record is anchored with a **keyed Bloom filter** (HMAC-SHA256)
  as well as hashing.

The full record is held off-chain in the registry database; the chain stores only the anchor
that proves the record has not changed. A **security check** runs the manipulation and inference
attacks against both systems side by side and reports the difference.

The earlier encrypted single-system registry remains on the `main` branch history; the original
hash-only baseline testbed remains at commit `be3c166`.

## Run

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe app.py        # http://127.0.0.1:5000
venv\Scripts\python.exe -m pytest     # tests
```

Open `http://127.0.0.1:5000/`. The landing page has three buttons:

| Button | Goes to | Needs sign-in |
|---|---|---|
| Conventional system | `/conventional/` | yes |
| Bloom filter system | `/bloom/` | yes |
| Security check | `/security` | no |

## Development logins

Quick-login buttons appear on each system's sign-in page in development mode, for localhost only.
Each system has its own set of accounts and its own database.

| Role | Username | Password |
|---|---|---|
| Admin | `admin.dev` | `Admin@123` |
| Faculty | `faculty.dev` | `Faculty@123` |
| Student | `student.dev` | `Student@123` |

Demo data is fictional and is loaded only into an empty development database.
To start fresh, stop the server and delete the `data/` folder.

## The two systems

Both systems share the same application, access rules and consensus. They differ only in the
**anchor** each block stores for a transaction (`certchain/anchors.py`):

| | Conventional | Bloom filter |
|---|---|---|
| On-chain anchor | SHA-256 of the whole record, plus one SHA-256 per field | A keyed Bloom filter over the same items |
| Keyed? | No — anyone holding the chain can recompute a hash | Yes — bit positions come from HMAC under a secret key |
| Forging a record's anchor | Possible without any secret | Needs the Bloom key |
| Confirming a guessed field from the chain | Possible offline (unsalted hash → dictionary attack) | Not possible without the key |

The security check demonstrates both differences. It runs only against the systems' own fictional
demo data and does not reconstruct anyone's personal details.

## Where the data lives

Each system keeps its own data under `data/<system>/`:

| Data | Location | Form |
|---|---|---|
| Full transactions (students, faculty, courses, marks, reports, certificates) | `records` table in `data/<system>/registry.db` | Plaintext JSON, held off-chain |
| Per-transaction anchor, hashes, block links | `blocks` table | SHA-256 hash links; anchor is hashes or a keyed Bloom filter |
| Username, password hash, role, linked ID | `users` table | Off-chain, so credentials can change or be removed |
| Session secret and Bloom key | `data/<system>/keys.json` | Plain file |

At startup the registry is rebuilt in memory from the off-chain records, and **each record is
checked against its on-chain anchor** — a record that does not match is left out and reported.

## Access rules

- **Admin:** all records and the blockchain page.
- **Faculty:** assigned courses, plus name, ID, email and programme of enrolled students. No NIC, date of birth, address or phone.
- **Student:** their own record only.
- **Public:** certificate verification, using the ID and verification code together.

## Before real use

- **Confidentiality at rest:** records are stored off-chain as **plaintext**, not encrypted. The
  anchors protect against tampering, not disclosure. Protect `registry.db` with database and
  disk-level controls, or add field encryption, before storing real personal data.
- **Network:** the three nodes are copies in one database, so this has no real decentralisation. A real deployment needs nodes run by separate organisations, for example on Hyperledger Fabric.
- **Keys:** move `data/<system>/keys.json` to a secrets manager or KMS and back it up separately. Anyone holding the Bloom key can test guesses against the Bloom filters.
- **Data deletion:** blocks cannot be deleted, so erasing one person's data is not supported. Check this against data protection law (Sri Lanka's PDPA, for example) before storing real personal data.
- **Grades:** `GRADE_SCALE` and the 40/60 weighting in `certchain/state.py` are placeholders. Replace them with the official rules.
- **Production mode:** set `APP_ENV=production`, serve over HTTPS and run one process only. Create the first admin with `python app.py create-admin <username>` (created on both systems). This turns off quick login, demo data and the tamper button.
