# 🔐 CryptoChat — *From Trust Me to Prove It*

> **A cryptographic messaging backend that replaces server promises with mathematical proof.**
>
> *"We don't log who you are"* → **Ring signature: provably unlinkable**
> *"This message existed at time T"* → **Merkle proof: mathematically verifiable**
> *"We deleted the key"* → **Commitment + ZKP: cryptographically demonstrated**
> *"Past messages are safe if we're hacked"* → **Double Ratchet: forward secrecy by construction**

Traditional security asks users to *trust* the server. This framework **eliminates trust as a requirement** — every security property is mathematically verifiable by anyone, at any time, with no faith in any party required.

---

## 📖 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [The Three Pillars](#the-three-pillars)
  - [Pillar 1 — The Phantom Sender](#pillar-1--the-phantom-sender-anonymous-authentication)
  - [Pillar 2 — The Witness Protocol](#pillar-2--the-witness-protocol-verifiable-data-existence)
  - [Pillar 3 — Cryptographic Amnesia](#pillar-3--cryptographic-amnesia-enforced-data-expiry)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Security Monitoring](#security-monitoring)
- [Tech Stack](#tech-stack)

---

## Overview

CryptoChat is a Flask + WebSocket backend for anonymous, end-to-end encrypted messaging. It is built around three cryptographic pillars that each transform a verbal privacy claim into a mathematical guarantee.

Every feature here is a real, production-grade cryptographic primitive — the same ones used in Signal, Monero, Bitcoin, and anonymous e-cash systems — implemented in Python and wired into a REST + WebSocket API.

---

## Architecture

```
backend/
├── app.py                    # Flask app, SocketIO events, blueprint registration
├── config.py                 # Settings: key sizes, expiry windows, rate limits
├── requirements.txt
│
├── routes/
│   ├── auth_routes.py        # Registration, ZKP challenge/verify, blind signatures
│   ├── chat_routes.py        # REST send / receive / decrypt / history
│   ├── pairing_routes.py     # QR code pairing + Diffie-Hellman key exchange
│   ├── verify_routes.py      # Merkle proofs, proof-of-deletion, integrity checks
│   └── admin_routes.py       # Security dashboard, attack reports, event exports
│
├── crypto/
│   ├── signature_utils.py    # RSA keypair generation, sign, verify, encrypt/decrypt
│   ├── hash_utils.py         # SHA-256, proof-of-existence, temporal commitments
│   ├── blind_signatures.py   # Chaum blind signatures — server signs without seeing
│   ├── diffie_hellman.py     # RFC 3526 2048-bit DH + PBKDF2 session key derivation
│   ├── double_ratchet.py     # Signal-style ratchet — per-message HKDF keys
│   ├── key_expiry.py         # AES-256-GCM, TimeLockCipher, key destruction
│   ├── merkle_proofs.py      # Full Merkle tree, path generation, path verification
│   ├── proof_of_deletion.py  # Commitment + HMAC attestation of key deletion
│   ├── ring_signatures.py    # Monero-style ring signatures — unlinkable sender
│   └── time_lock_puzzle.py   # VDF-style sequential SHA256 — time-enforced decryption
│
├── monitoring/
│   └── security_monitor.py   # Event logging, brute-force detection, attack analysis
│
├── scheduler/
│   └── expiry_scheduler.py   # APScheduler: destroys expired keys every 60 seconds
│
└── storage/                  # JSON flat-file persistence (no external DB required)
    ├── messages.json
    ├── keys.json
    ├── tokens.json
    ├── proof.json
    ├── devices.json
    ├── nonces.json
    ├── merkle_state.json
    ├── blind_signing_key.json
    ├── deleted_commitments.json
    └── security_events.json
```

---

## The Three Pillars

### Pillar 1 — The Phantom Sender *(Anonymous Authentication)*

#### Zero-Knowledge Registration
Devices register with no username or password. An RSA keypair is generated, and the anonymous device ID is derived as `SHA256(public_key)[:16]`. Authentication works by signing a random server-issued challenge — proving ownership of the private key without revealing any identity.

#### Ring Signatures
When a message is sent, the sender can attach a ring signature that proves the message came from *one of N registered users* — but mathematically, nobody can determine which one. Not even the server.

```
Ring = {User A, User B, User C, User D, You}
Signature proves: "one of these five sent this"
Nobody can determine: which one
```

This is the same primitive used in **Monero** (the privacy cryptocurrency). Implemented in `crypto/ring_signatures.py`.

#### Blind Signatures (Chaum's Scheme)
Like a carbon-paper envelope. The server signs your authentication token without ever seeing what's inside. You later reveal the token; the server can verify it's genuine — but has **zero record of having issued it to you specifically**.

```
Client:  blind(token) → sends blinded_token to server
Server:  signs blinded_token → returns blind_signature  (never sees token)
Client:  unblind(blind_signature) → gets valid signature on original token
Anyone:  verify(token, signature, server_public_key) → TRUE
Server:  cannot link this verification back to the original issuance
```

This is how **anonymous e-cash** works. Implemented in `crypto/blind_signatures.py`.

---

### Pillar 2 — The Witness Protocol *(Verifiable Data Existence)*

#### Proof of Existence
Every message generates a cryptographic proof at send time:

```
proof_hash = SHA256( SHA256(content) + ":" + timestamp )
```

The server stores only the proof hash and timestamp — never the message content. Anyone can later verify a message existed at a specific time by re-hashing the content and comparing.

#### Merkle Proof Trees
Every message hash becomes a leaf in a Merkle tree. Only the 32-byte root hash is published. To prove any single message existed, a tiny "Merkle path" is provided — without revealing any other messages in the tree.

```
          RootHash
         /        \
     H(A+B)      H(C+D)
     /    \      /    \
  H(A)  H(B)  H(C)  H(D)
```

*"I can prove this one specific message existed, while keeping every other message completely hidden. A proof the size of a tweet, covering a database of millions."*

This is exactly how **Bitcoin transaction proofs** (SPV) work. Implemented in `crypto/merkle_proofs.py`.

#### Temporal Commitment with Reveal
Before sending a message, a commitment (hash of message + random salt) is published. The message is revealed later. Anyone can verify the content was not changed after the fact — proving temporal integrity.

```
Commit:  commitment = SHA256(message + salt)   ← published first
Reveal:  (message, salt)                        ← published later
Verify:  SHA256(message + salt) == commitment   ← proves no retroactive edits
```

Implemented in `crypto/hash_utils.py` (`create_temporal_commitment`, `verify_temporal_reveal`).

---

### Pillar 3 — Cryptographic Amnesia *(Enforced Data Expiry)*

#### Double Ratchet (Signal Protocol)
Every single message gets a fresh derived key, computed from the previous chain key using HKDF. Once the ratchet advances, the old key is mathematically gone — not deleted, but **underivable**.

```
chain_key_0 → HKDF → (msg_key_1, chain_key_1)
chain_key_1 → HKDF → (msg_key_2, chain_key_2)
chain_key_2 → HKDF → (msg_key_3, chain_key_3)
...
```

Even if someone records all traffic and later steals the device, past messages are provably unreadable. *Forward secrecy by construction.*

Implemented in `crypto/double_ratchet.py`.

#### Time-Lock Puzzles / VDFs
Encrypt a message so it cannot be decrypted until a specific time — not because of a policy, but because the math requires N sequential SHA256 operations that take exactly X seconds regardless of compute power. Cannot be parallelized.

```python
# Cannot decrypt faster than N sequential hashes — not policy, math
key = SHA256(SHA256(SHA256(...(seed)...)))   # N iterations
```

Implemented in `crypto/time_lock_puzzle.py`.

#### Proof of Deletion
Can you *prove* you deleted something? Using a commitment scheme, the server commits to a key at creation time. When the key is destroyed, it publishes a cryptographically-attested proof:

```
At creation:   commitment = SHA256(key + nonce)      ← stored
At deletion:   attestation = HMAC(key_id + "DELETED" + timestamp)
Anyone:        verify attestation is binding to original commitment
```

*Not "trust me, I deleted it." Cryptographically demonstrated.*

Implemented in `crypto/proof_of_deletion.py`.

#### Automatic Key Expiry Scheduler
A background APScheduler job runs every 60 seconds. It iterates all active keys and messages, and for anything past its `expires_at` timestamp:
- Sets `status = "expired"`
- Nulls out `session_key` — **permanent, irreversible key destruction**
- Records the expiry timestamp

Implemented in `scheduler/expiry_scheduler.py`.

---

## API Reference

### Authentication — `/api/auth`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/register` | Anonymous registration — generates RSA keypair, returns anonymous ID |
| `POST` | `/challenge` | Request ZKP authentication challenge |
| `POST` | `/verify` | Submit signed challenge — proves key ownership without revealing identity |
| `POST` | `/validate` | Validate an active session token |
| `GET`  | `/blind-public-key` | Get server's RSA public key for blind signing |
| `POST` | `/blind-sign` | Submit blinded token — server signs without seeing content |
| `POST` | `/verify-blind-token` | Verify a token + signature pair (server has no issuance record) |

### Chat — `/api/chat`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/send` | Send E2E encrypted message with time-locked key (REST flow) |
| `GET`  | `/receive/<recipient_id>` | Retrieve active encrypted messages for recipient |
| `POST` | `/decrypt` | Decrypt message using recipient private key (demo endpoint) |
| `GET`  | `/history/<user_id>` | Get message metadata — no content, proof hashes only |

### Verification — `/api/verify`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/proof/<message_id>` | Get proof-of-existence for a message |
| `POST` | `/verify` | Verify message content against its proof |
| `POST` | `/integrity/<message_id>` | Check if a message matches its stored proof |
| `GET`  | `/merkle/root` | Get current Merkle root hash (covers all messages) |
| `GET`  | `/merkle/proof/<message_id>` | Get Merkle path for a single message |
| `POST` | `/merkle/verify` | Verify a Merkle path proof |
| `POST` | `/proof-of-deletion` | Submit a cryptographic proof of key deletion |
| `POST` | `/proof-of-deletion/verify` | Verify a deletion proof |

### Device Pairing — `/api/pairing`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/initiate` | Generate QR code for device pairing (DH key exchange) |
| `POST` | `/scan` | Second device scans QR — performs DH, derives session key |
| `POST` | `/complete` | First device completes DH exchange with peer's public key |
| `POST` | `/verify-safety-number` | Verify Signal-style safety numbers (MITM detection) |
| `GET`  | `/list-devices` | List all registered devices |

### Admin — `/api/admin`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/security-events` | Query security events with filters (type, severity, IP, time) |
| `GET`  | `/attack-summary` | Aggregate attack counts, success rate, top IPs |
| `GET`  | `/attack-timeline` | Hourly breakdown of events over last N hours |
| `GET`  | `/penetration-test-report` | Full pen-test analysis with strengths and vulnerabilities |
| `GET`  | `/export-events` | Export events as JSON or CSV |
| `GET`  | `/attack-types` | Count events by attack category |
| `GET`  | `/system-stats` | Message counts, device stats, key destruction metrics |
| `GET`  | `/threat-assessment` | Current threat level (LOW / ELEVATED / HIGH / CRITICAL) |
| `POST` | `/clear-old-events` | Clear events older than N days |

### WebSocket Events

| Direction | Event | Description |
|-----------|-------|-------------|
| Server → Client | `connected` | Emitted on connection with session ID |
| Client → Server | `verify_device` | Authenticate device via ZKP signature |
| Server → Client | `verified` / `verification_failed` | Authentication result |
| Client → Server | `send_message` | Send encrypted message with anti-replay nonce |
| Server → Client | `receive_message` | Real-time delivery to recipient (never stored to disk) |
| Server → Client | `message_sent` | Confirmation with proof hash and expiry |
| Client → Server | `check_message_validity` | Check if a message key is still active |
| Server → Client | `message_status` | Key status with seconds remaining |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/health` | Health check with pillar status |
| `GET`  | `/api/server-info` | Server URL and WebSocket URL for QR generation |

---

## Getting Started

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/your-username/cryptochat-backend.git
cd cryptochat-backend/backend

pip install -r requirements.txt
```

### Running

```bash
python app.py
```

The server starts on `http://0.0.0.0:5000`.

On startup you'll see:

```
============================================================
🔐 CRYPTOGRAPHIC CHAT FRAMEWORK v2.0
   "From Trust Me to Prove It"
============================================================

📋 OLD CLAIM → NEW PROOF:
  "We don't log who you are"     → Ring signature: provably unlinkable
  "This message existed at T"    → Merkle proof: mathematically verifiable
  "We deleted the key"           → Commitment + ZKP: cryptographically demonstrated
  "Past messages safe if hacked" → Double Ratchet: forward secrecy by construction

🟣 PILLARS:
  1. The Phantom Sender (Ring + Blind Signatures)
  2. The Witness Protocol (Merkle + Commitment with Reveal)
  3. Cryptographic Amnesia (Double Ratchet + Time-Lock + Proof of Deletion)

🌐 SERVER STARTING...
  • WebSocket: Enabled
  • Security Monitoring: Active
  • Key Expiry Scheduler: Running
```

### Quick Test

```bash
# Health check
curl http://localhost:5000/api/health

# Register anonymously
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" -d '{}'

# Get server info
curl http://localhost:5000/api/server-info
```

---

## Configuration

All settings are in `config.py`:

```python
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-CHANGE-IN-PRODUCTION'

    KEY_SIZE = 2048                              # RSA key size (bits)
    HASH_ALGORITHM = 'sha256'

    DEFAULT_MESSAGE_EXPIRY = timedelta(minutes=60)  # Keys destroyed after 1 hour
    MAX_MESSAGE_EXPIRY     = timedelta(hours=24)
    MIN_MESSAGE_EXPIRY     = timedelta(minutes=5)

    CHALLENGE_EXPIRY       = timedelta(minutes=5)   # ZKP challenge window
    SESSION_EXPIRY         = timedelta(hours=12)

    SECURITY_LOG_RETENTION_DAYS = 90
    RATE_LIMIT_PER_IP           = 100               # Requests per hour per IP
    BRUTE_FORCE_THRESHOLD       = 5                 # Auth failures before alert
```

For production, set the `SECRET_KEY` environment variable and uncomment the SSL/cookie settings at the bottom of `config.py`.

---

## Security Monitoring

The `SecurityMonitor` class in `monitoring/security_monitor.py` tracks every security-relevant event and detects attack patterns in real time.

### Tracked Event Types

| Event | Severity | Description |
|-------|----------|-------------|
| `connection` | info | New device connected |
| `auth_success` | info | Successful ZKP authentication |
| `auth_failure` | warning | Failed authentication attempt |
| `replay_attack_detected` | critical | Duplicate nonce detected — replay blocked |
| `brute_force_detected` | critical | 5+ auth failures from same IP in 5 minutes |
| `mitm_detected` | critical | Safety number mismatch — MITM suspected |
| `unauthorized_attempt` | high | Action attempted without device verification |
| `timing_anomaly` | warning | Unusual response time pattern |
| `suspicious_pattern` | high | 3+ replay attacks within 10 minutes |
| `key_expired` | info | Message key destroyed by scheduler |
| `message_sent` | info | Message transmitted |

### Viewing the Dashboard

```bash
# All events
GET /api/admin/security-events

# Only critical events
GET /api/admin/security-events?severity=critical

# Events from last hour
GET /api/admin/security-events?hours=1

# Filter by IP
GET /api/admin/security-events?ip=192.168.1.1

# Full penetration test report
GET /api/admin/penetration-test-report

# Current threat level
GET /api/admin/threat-assessment

# Export as CSV
GET /api/admin/export-events?format=csv
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Web Framework | Flask 3.0 |
| WebSockets | Flask-SocketIO 5.3 + python-socketio |
| Cryptography | PyCryptodome (RSA, AES-256-GCM, SHA-256, HKDF, PBKDF2) |
| Key Scheduling | APScheduler 3.10 |
| QR Code Generation | qrcode + Pillow |
| CORS | flask-cors |
| DH Group | RFC 3526 2048-bit MODP Group 14 |
| Persistence | JSON flat files (no external database) |

---

## Cryptographic Primitives Summary

| Primitive | Used For | Location |
|-----------|----------|----------|
| RSA-2048 + PKCS1v15 | Device signatures, ZKP authentication | `signature_utils.py` |
| RSA-OAEP | Session key encryption | `signature_utils.py` |
| Chaum Blind Signatures | Anonymous token issuance | `blind_signatures.py` |
| Ring Signatures (RSA toy) | Unlinkable sender in message groups | `ring_signatures.py` |
| AES-256-GCM | Message encryption | `key_expiry.py`, `double_ratchet.py` |
| HKDF (SHA-256) | Double Ratchet key derivation | `double_ratchet.py` |
| PBKDF2 (SHA-256, 100k rounds) | DH shared secret → session key | `diffie_hellman.py` |
| Merkle Trees (SHA-256) | Proof-of-existence without content disclosure | `merkle_proofs.py` |
| SHA-256 Commitment | Temporal integrity, proof of deletion | `hash_utils.py`, `proof_of_deletion.py` |
| HMAC-SHA-256 | Deletion attestation binding | `proof_of_deletion.py` |
| Sequential SHA-256 VDF | Time-lock puzzles | `time_lock_puzzle.py` |
| DH (RFC 3526 Group 14) | Device pairing key exchange | `diffie_hellman.py` |

---

## Security Notice

> All connection attempts, authentication failures, replay attacks, and anomalous patterns are logged to `storage/security_events.json` and accessible via the admin dashboard at `/api/admin/security-events`.

> The `SECRET_KEY` in `config.py` is a development placeholder. **Always set a strong secret via environment variable before any public deployment.**

---

## License

MIT License. See `LICENSE` for details.