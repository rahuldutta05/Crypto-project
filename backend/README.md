# Cryptographic Backend

A Flask backend implementing three cryptographic privacy guarantees:

1. **Anonymous but Verifiable Submission** — PoW + commitment scheme prevents spam and duplicate submissions without revealing identity
2. **Proof-of-Existence** — SHA-256 hash + Merkle tree + RSA-PSS signature proves *what* was submitted *when*, without storing plaintext
3. **Cryptographic Data Expiry** — AES-EAX DEKs are destroyed after a deadline, making data permanently unrecoverable

---

## Project Structure

```
backend/
├── run.py                   Entry point
├── app.py                   Flask app factory
├── config.py                All settings + KEK bootstrap
├── requirements.txt
│
├── core/
│   ├── storage.py           Central file I/O with locking (used everywhere)
│   ├── scheduler.py         Background DEK expiry thread
│   └── crypto/
│       ├── aes.py           AES-EAX encrypt / decrypt / wrap / unwrap
│       ├── merkle.py        Merkle tree, root, inclusion proof
│       ├── pow.py           Proof-of-Work verification
│       ├── signatures.py    RSA-PSS sign / verify (persistent key)
│       └── zkp.py           ZKP-style identity commitment chain
│
├── api/
│   ├── auth.py              /auth  — anonymous submit + read
│   ├── chat.py              /chat  — encrypted messaging
│   ├── keys.py              /keys  — public key registry
│   ├── verify.py            /verify — proof verification
│   └── admin.py             /admin — protected diagnostics
│
└── storage/
    ├── messages.json        Encrypted messages + wrapped DEKs
    ├── commitments.json     Used identity commitments (dedup set)
    ├── proofs.json          Hashes + timestamps + signatures
    └── vault/
        ├── kek.json         Master Key Encryption Key (persistent)
        ├── signing_key.pem  RSA private key for signatures (persistent)
        └── public_keys.json User public key registry
```

---

## Setup

```bash
pip install -r requirements.txt

export ADMIN_TOKEN="your-secret-admin-token"
export KEY_EXPIRY_MINUTES=60    # optional, default 60
export POW_DIFFICULTY=6          # optional, default 6

python run.py
```

For production:
```bash
gunicorn "run:app" --workers 4 --bind 0.0.0.0:5000
```

---

## API Reference

### Anonymous Submission  (`/auth`)

#### `POST /auth/identity`
Generate a fresh identity for a new submitter.

```json
// Response
{
  "identity_secret": "abc123...",   // KEEP PRIVATE — never send to server
  "nullifier": "def456...",         // intermediate (also keep private)
  "commitment": "xyz789..."         // send this to /auth/submit
}
```

#### `POST /auth/submit`
Submit data anonymously.

```json
// Request
{
  "data": "My whistleblower report...",
  "commitment": "xyz789...",
  "nonce": "00042abc"      // nonce satisfying PoW: SHA256(commitment+nonce).startsWith("000000")
}

// Response 201
{
  "status": "accepted",
  "msg_id": "7",
  "expiry": "2024-01-01T13:00:00+00:00"
}
```

#### `GET /auth/read/<msg_id>`
Decrypt and read a submission (only works before expiry).

```json
// Response 200 (before expiry)
{ "msg_id": "7", "data": "My whistleblower report...", "expiry": "..." }

// Response 410 (after expiry — key destroyed)
{ "error": "Content expired", "detail": "The encryption key has been destroyed..." }
```

---

### Encrypted Chat  (`/chat`)

#### `POST /chat/send`
Send an encrypted message (sender encrypts with recipient's public key client-side).

```json
// Request
{
  "encrypted_message": "<base64 ciphertext>",
  "encrypted_key": "<base64 encrypted symmetric key>",
  "receiver": "alice"
}

// Response 201
{ "message_id": "uuid-...", "expiry": "..." }
```

#### `GET /chat/inbox/<user_id>`
Retrieve all messages for a user.

---

### Public Key Registry  (`/keys`)

#### `POST /keys/register`
```json
{ "user_id": "alice", "public_key": "-----BEGIN PUBLIC KEY-----\n..." }
```

#### `GET /keys/<user_id>`
Returns `{ "user_id": "alice", "public_key": "..." }`

#### `GET /keys/server/pubkey`
Returns the server's RSA public key PEM for independent signature verification.

---

### Proof Verification  (`/verify`)

#### `GET /verify/root`
Current Merkle root of all submissions.

#### `POST /verify/hash`
```json
// Request
{ "data": "My whistleblower report..." }

// Response
{ "data_hash": "sha256hex...", "merkle_root": "sha256hex...", "found": true }
```

#### `GET /verify/proof/<msg_id>`
Full Merkle inclusion proof — lets any verifier independently reconstruct the root.

```json
{
  "msg_id": "7",
  "leaf_hash": "abc...",
  "merkle_root": "xyz...",
  "proof_path": [
    { "sibling": "def...", "position": "right" },
    { "sibling": "ghi...", "position": "left" }
  ]
}
```

#### `POST /verify/signature`
Verify the RSA-PSS proof-of-existence signature for a chat message.
```json
{ "msg_id": "uuid-..." }
```

---

### Admin  (`/admin`)
All endpoints require `Authorization: Bearer <ADMIN_TOKEN>`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/messages` | All messages (with encrypted content) |
| GET | `/admin/proofs` | All proof records |
| GET | `/admin/commitments` | All used commitments |
| GET | `/admin/stats` | Active/expired counts |
| POST | `/admin/expire` | Trigger immediate expiry sweep |

---

## Cryptographic Design

### Key Hierarchy
```
KEK (256-bit AES, persistent in vault/kek.json)
 └── wraps per-message DEK (256-bit AES, AES-EAX)
       └── encrypts plaintext submission
```

### Identity Commitment Chain (ZKP-style)
```
identity_secret  →SHA-256→  nullifier  →SHA-256→  commitment
(client private)             (client private)       (submitted to server)
```

### Proof-of-Existence
```
plaintext  →SHA-256→  leaf_hash  →Merkle tree→  root
                          └→RSA-PSS signature (chat only)
```

### Data Death
The background scheduler runs every 60 seconds and sets `wrapped_dek = null`
for all expired messages. Without the DEK, the AES-EAX ciphertext is
computationally indistinguishable from random noise.
