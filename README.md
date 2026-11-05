# CertChain Academic Registry

A centralised university records system. Student and faculty details, marks, reports and
certificates are all stored on a simulated permissioned blockchain, encrypted.

This replaces the original CertChain baseline testbed. The baseline's hash-only chain, `/api/verify`,
`DEFENSE_MODE`, verification log and the intentional weaknesses used for C1-C4 are no longer here.
The baseline remains on the `main` branch at commit `be3c166`.

## Run

```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe app.py        # http://127.0.0.1:5000
venv\Scripts\python.exe -m pytest     # tests
```

## Development logins

Quick-login buttons appear on the sign-in page in development mode, for localhost only.

| Role | Username | Password |
|---|---|---|
| Admin | `admin.dev` | `Admin@123` |
| Faculty | `faculty.dev` | `Faculty@123` |
| Student | `student.dev` | `Student@123` |

Demo data is fictional and is loaded only into an empty development database.
To start fresh, stop the server and delete the `data/` folder.

## Where the data lives

| Data | Location | Form |
|---|---|---|
| Students, faculty, courses, enrolments, marks, reports, certificates | `blocks` table in `data/certchain.db` | AES-256-GCM ciphertext, signed and hash-linked |
| Block index, timestamp, hashes, signature | `blocks` table | Plain (needed to validate the chain) |
| Username, password hash, role, linked ID | `users` table in `data/certchain.db` | Off-chain, so credentials can change or be removed |
| Encryption and signing keys | `data/keys.json` | Plain file |

Academic data has no tables of its own. It is rebuilt in memory by replaying the chain at startup.

## Access rules

- **Admin:** all records and the blockchain page.
- **Faculty:** assigned courses, plus name, ID, email and programme of enrolled students. No NIC, date of birth, address or phone.
- **Student:** their own record only.
- **Public:** certificate verification, using the ID and verification code together.

## Before real use

- **Network:** the three nodes are copies in one database, so this has no real decentralisation. A real deployment needs nodes run by separate organisations, for example on Hyperledger Fabric.
- **Keys:** move `data/keys.json` to a secrets manager or KMS and back it up separately. Anyone holding it can read the chain, and losing it makes all records unrecoverable.
- **Data deletion:** blocks cannot be deleted, so erasing one person's data is not supported. Check this against data protection law (Sri Lanka's PDPA, for example) before storing real personal data. Separate per-person keys would allow erasure by destroying a key.
- **Grades:** `GRADE_SCALE` and the 40/60 weighting in `certchain/state.py` are placeholders. Replace them with the official rules.
- **Production mode:** set `APP_ENV=production`, serve over HTTPS and run one process only. Create the first admin with `python app.py create-admin <username>`. This turns off quick login, demo data and the tamper button.
