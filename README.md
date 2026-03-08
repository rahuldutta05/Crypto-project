# 🔐 CryptoChat — *From Trust Me to Prove It*

> **A full-stack cryptographic messaging application that replaces server promises with mathematical proof.**
>
> *"We don't log who you are"* → **Ring signature: provably unlinkable**
> *"This message existed at time T"* → **Merkle proof: mathematically verifiable**
> *"We deleted the key"* → **Commitment + ZKP: cryptographically demonstrated**
> *"Past messages are safe if we're hacked"* → **Double Ratchet: forward secrecy by construction**

Traditional security asks users to *trust* the server. This framework **eliminates trust as a requirement** — every security property is mathematically verifiable by anyone, at any time, with no faith in any party required.

---

## 📖 Table of Contents

- [Overview](#overview)
- [Full-Stack Architecture](#full-stack-architecture)
- [Frontend](#frontend)
  - [Pages & Components](#pages--components)
  - [Client-Side Cryptography](#client-side-cryptography)
  - [Frontend Setup](#frontend-setup)
- [Backend](#backend)
  - [The Three Pillars](#the-three-pillars)
  - [Backend Structure](#backend-structure)
  - [Backend Setup](#backend-setup)
- [Running the Full Stack](#running-the-full-stack)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Security Monitoring](#security-monitoring)
- [Tech Stack](#tech-stack)

---

## Overview

CryptoChat is a React + Flask application for anonymous, end-to-end encrypted real-time messaging. It is built around three cryptographic pillars that each transform a verbal privacy claim into a mathematical guarantee.

Every feature is a real, production-grade cryptographic primitive — the same ones used in Signal, Monero, Bitcoin, and anonymous e-cash systems — implemented end-to-end from browser to server.

```
┌─────────────────────────────────┐       ┌──────────────────────────────────┐
│         React Frontend          │       │         Flask Backend             │
│  ─────────────────────────────  │       │  ──────────────────────────────  │
│  • Cyberpunk dark UI            │◄─────►│  • REST API + WebSocket          │
│  • Device pairing via QR code   │  WS   │  • Ring & Blind Signatures       │
│  • AES-GCM encryption in-browser│  +    │  • Merkle Proof Trees            │
│  • Live expiry countdown        │  REST │  • Double Ratchet (Signal-style) │
│  • Safety number verification   │       │  • Proof of Deletion             │
│  • Security dashboard           │       │  • APScheduler key destruction   │
└─────────────────────────────────┘       └──────────────────────────────────┘
```

---

## Full-Stack Architecture

```
cryptochat/
├── frontend/                        # React + Vite application
│   ├── index.html
│   ├── vite.config.js               # Dev proxy → localhost:5000
│   ├── package.json
│   └── src/
│       ├── App.jsx                  # Router, top bar, WebSocket connection status
│       ├── main.jsx
│       ├── index.css                # Cyberpunk dark theme, full design system
│       ├── pages/
│       │   ├── ChatApp.jsx          # Pairing gate → Chat interface
│       │   └── AdminDashboard.jsx   # Live security monitoring dashboard
│       ├── components/
│       │   ├── DevicePairing.jsx    # QR code generation + DH key exchange UI
│       │   ├── ChatInterface.jsx    # Real-time E2E encrypted chat
│       │   └── SafetyNumber.jsx     # Signal-style MITM detection display
│       └── utils/
│           ├── cryptoUtils.js       # Browser WebCrypto AES-GCM encrypt/decrypt
│           └── socketManager.js     # Singleton Socket.IO client wrapper
│
└── backend/                         # Flask + SocketIO application
    ├── app.py                       # App factory, blueprints, WebSocket events
    ├── config.py                    # Expiry windows, rate limits, key sizes
    ├── requirements.txt
    ├── routes/
    │   ├── auth_routes.py           # ZKP auth, blind signatures
    │   ├── chat_routes.py           # REST send/receive/decrypt/history
    │   ├── pairing_routes.py        # QR pairing, Diffie-Hellman exchange
    │   ├── verify_routes.py         # Merkle proofs, proof-of-deletion
    │   └── admin_routes.py          # Security dashboard endpoints
    ├── crypto/
    │   ├── signature_utils.py       # RSA keypair, sign, verify, encrypt/decrypt
    │   ├── hash_utils.py            # SHA-256, proof-of-existence, temporal commitments
    │   ├── blind_signatures.py      # Chaum blind signatures
    │   ├── diffie_hellman.py        # RFC 3526 2048-bit DH + PBKDF2
    │   ├── double_ratchet.py        # Signal-style HKDF ratchet
    │   ├── key_expiry.py            # AES-256-GCM, TimeLockCipher, key destruction
    │   ├── merkle_proofs.py         # Full Merkle tree, path proofs
    │   ├── proof_of_deletion.py     # Commitment + HMAC deletion attestation
    │   ├── ring_signatures.py       # Monero-style ring signatures
    │   └── time_lock_puzzle.py      # VDF-style sequential SHA256
    ├── monitoring/
    │   └── security_monitor.py      # Event logging, pattern detection, alerts
    ├── scheduler/
    │   └── expiry_scheduler.py      # APScheduler: destroys expired keys every 60s
    └── storage/                     # JSON flat-file persistence (no external DB)
        ├── messages.json, keys.json, tokens.json, proof.json
        ├── devices.json, nonces.json, merkle_state.json
        ├── blind_signing_key.json, deleted_commitments.json
        └── security_events.json
```

---

## Frontend

### Pages & Components

#### `ChatApp.jsx` — Pairing Gate
The entry point for users. Before the chat is accessible, devices must be paired via Diffie-Hellman key exchange. Once pairing is complete, the chat interface is unlocked and the derived session key is passed down.

#### `DevicePairing.jsx` — QR Code Pairing
Implements a full Signal-style device pairing flow with three modes:

- **Device A — Generate:** Calls `/api/pairing/initiate`, receives a QR code and displays it for Device B to scan. After Device B responds, Device A pastes the DH public key to complete the exchange.
- **Device B — Scan:** Accepts the QR JSON payload, calls `/api/pairing/scan`, and receives a derived AES-256 session key.
- **Completion:** Both sides finalize the Diffie-Hellman exchange and arrive at an identical session key — never transmitted in plaintext.

```
Device A                              Server                              Device B
   │── POST /pairing/initiate ────────►│                                    │
   │◄── QR data + DH public key ───────│                                    │
   │                                   │◄──── POST /pairing/scan ───────────│
   │                                   │───── session_key + safety_num ────►│
   │── POST /pairing/complete ─────────►│                                    │
   │◄── session_key + safety_num ──────│                                    │
   │                                   │                                    │
   │◄══════════ Shared AES-256 Session Key (never sent in plaintext) ══════►│
```

#### `SafetyNumber.jsx` — MITM Detection
Displays the 6-digit Signal-style safety number derived from both devices' public keys. Users compare this number verbally — if the numbers differ, a man-in-the-middle intercepted the key exchange.

#### `ChatInterface.jsx` — Encrypted Real-Time Chat
The main chat view. Key behaviours:

- **Device verification** via WebSocket `verify_device` event (ZKP challenge-response)
- **Optimistic message sending** — message appears immediately, updated with proof hash on server confirmation
- **Live expiry countdown** — every message shows a real-time `Xm Ys` countdown to key destruction
- **Automatic expiry display** — when a key is destroyed, the message content is replaced with `[key destroyed — permanently unrecoverable]`
- **Per-message metadata** — each bubble shows its truncated proof hash (`🔒 a3f9c1b2…`) and encryption label (`AES-256-GCM`)
- **Configurable expiry** — sender selects message lifetime (1 min → 24 hr) before sending
- **Enter to send**, Shift+Enter for newline

#### `AdminDashboard.jsx` — Security Monitoring Dashboard
A live security operations panel. Features:

- **Threat level banner** — colour-coded LOW / ELEVATED / HIGH / CRITICAL with event counts for the past hour
- **8-metric stats grid** — total events, attacks detected, successful attacks, attack success rate, devices registered, proofs created, expired keys, nonces tracked
- **Attack breakdown chart** — horizontal bar chart per attack type (replay, brute force, MITM, unauthorized, timing, suspicious pattern)
- **Security strengths panel** — which protections have activated (e.g. "✓ 3 replay attacks blocked by nonce tracking")
- **Core principles status** — live status of all 3 pillars with per-metric detail
- **Events table** — latest 50 security events with timestamp, type, severity badge, and detail payload
- **Recommendations feed** — colour-coded action items from the pen-test report
- **Auto-refresh** — optional 5-second polling toggle
- **JSON export** — one-click download of all security events

---

### Client-Side Cryptography

All encryption and decryption happens **in the browser** using the native [WebCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto). The backend never receives plaintext.

#### `cryptoUtils.js`

```javascript
// Encrypt a message with the DH-derived session key
encryptMessage(plaintext, sessionKeyB64)
// → { ciphertext: base64, iv: base64 }

// Decrypt a received message
decryptMessage({ ciphertext, iv }, sessionKeyB64)
// → plaintext string

// Generate a cryptographically random 16-byte nonce (anti-replay)
generateNonce()
// → 32-char hex string
```

The session key (AES-256, derived server-side via PBKDF2 from the DH shared secret, returned as base64) is imported into the browser's non-extractable key store. Encryption uses AES-GCM with a fresh random 12-byte IV per message.

#### `socketManager.js`
Singleton wrapper around `socket.io-client`. Ensures a single WebSocket connection is shared across all components. The Vite dev proxy transparently forwards `/socket.io` traffic to `localhost:5000`.

---

### Frontend Setup

**Prerequisites:** Node.js 18+

```bash
cd frontend
npm install
npm run dev
```

The dev server starts at `http://localhost:5173` and proxies all `/api` and `/socket.io` traffic to the backend at `http://localhost:5000`.

**Build for production:**

```bash
npm run build       # outputs to dist/
npm run preview     # preview production build locally
```

---

## Backend

### The Three Pillars

#### Pillar 1 — The Phantom Sender *(Anonymous Authentication)*

**Zero-Knowledge Registration** — Devices register with no username or password. An RSA keypair is generated and the anonymous device ID is `SHA256(public_key)[:16]`. Authentication works by signing a random server-issued challenge — proving key ownership without revealing identity.

**Ring Signatures** — When a message is sent, the sender can attach a ring signature proving the message came from *one of N registered users* — but mathematically nobody can tell which one. Not even the server.

```
Ring = {User A, User B, User C, User D, You}
Signature proves: "one of these five sent this"
Nobody can determine: which one
```

Same primitive used in **Monero**. Implemented in `crypto/ring_signatures.py`.

**Blind Signatures (Chaum's Scheme)** — Like a carbon-paper envelope. The server signs your authentication token without ever seeing what's inside. You later reveal the token and the server can verify it's genuine — but has zero record of having issued it to you specifically.

```
Client:  blind(token) → sends blinded_token to server
Server:  signs blinded_token → returns blind_signature  (never sees token)
Client:  unblind(blind_signature) → gets valid signature on original token
Anyone:  verify(token, signature, server_public_key) → TRUE
Server:  cannot link this verification back to the original issuance
```

How **anonymous e-cash** works. Implemented in `crypto/blind_signatures.py`.

---

#### Pillar 2 — The Witness Protocol *(Verifiable Data Existence)*

**Proof of Existence** — Every message generates a cryptographic proof at send time:
```
proof_hash = SHA256( SHA256(content) + ":" + timestamp )
```
The server stores only this proof hash and timestamp — never the message content.

**Merkle Proof Trees** — Every message hash becomes a leaf in a Merkle tree. Only the 32-byte root hash is published. To prove any single message existed, a tiny Merkle path is provided — without revealing any other messages in the tree.

```
          RootHash
         /        \
     H(A+B)      H(C+D)
     /    \      /    \
  H(A)  H(B)  H(C)  H(D)
```

*"A proof the size of a tweet, covering a database of millions."* This is exactly how **Bitcoin SPV proofs** work. Implemented in `crypto/merkle_proofs.py`.

**Temporal Commitment with Reveal** — Commit to a message before sending. Later reveal it. Anyone can verify you didn't change it after the fact. Implemented in `crypto/hash_utils.py`.

---

#### Pillar 3 — Cryptographic Amnesia *(Enforced Data Expiry)*

**Double Ratchet (Signal Protocol)** — Every message gets a fresh HKDF-derived key. Once the ratchet advances, the old key is mathematically gone — not just deleted, but underivable. Forward secrecy by construction. Implemented in `crypto/double_ratchet.py`.

**Time-Lock Puzzles / VDFs** — Encrypt a message so it cannot be decrypted until a specific time — not because of policy, but because the math requires N sequential SHA256 operations that cannot be parallelized. Implemented in `crypto/time_lock_puzzle.py`.

**Proof of Deletion** — The server commits to a key at creation time. When the key is destroyed, it publishes a cryptographically-attested HMAC proof. *Not "trust me, I deleted it." Cryptographically demonstrated.* Implemented in `crypto/proof_of_deletion.py`.

**Automatic Key Expiry Scheduler** — APScheduler runs every 60 seconds, iterates all active keys, nulls out any `session_key` past its `expires_at` — permanent, irreversible destruction. Implemented in `scheduler/expiry_scheduler.py`.

---

### Backend Setup

**Prerequisites:** Python 3.10+

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Server starts on `http://0.0.0.0:5000`. Quick test:

```bash
curl http://localhost:5000/api/health
curl -X POST http://localhost:5000/api/auth/register -H "Content-Type: application/json" -d '{}'
curl http://localhost:5000/api/admin/threat-assessment
```

---

## Running the Full Stack

```bash
# Terminal 1 — Backend
cd backend && pip install -r requirements.txt && python app.py

# Terminal 2 — Frontend
cd frontend && npm install && npm run dev
```

Open `http://localhost:5173` in **two browser tabs** to simulate two devices pairing and chatting with each other.

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
| `GET`  | `/history/<user_id>` | Get message metadata — proof hashes only, no content |

### Verification — `/api/verify`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/proof/<message_id>` | Get proof-of-existence for a message |
| `POST` | `/verify` | Verify message content against its proof |
| `POST` | `/integrity/<message_id>` | Check if message matches its stored proof |
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
| `GET`  | `/security-events` | Query events with filters (type, severity, IP, time range) |
| `GET`  | `/attack-summary` | Aggregate counts, success rate, top attacking IPs |
| `GET`  | `/attack-timeline` | Hourly breakdown of events over last N hours |
| `GET`  | `/penetration-test-report` | Full pen-test analysis with strengths and vulnerabilities |
| `GET`  | `/export-events` | Export as JSON or CSV |
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
| Server → Client | `message_sent` | Confirmation with proof hash and expiry timestamp |
| Client → Server | `check_message_validity` | Check if a message key is still active |
| Server → Client | `message_status` | Key status with seconds remaining |

### Utility

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/health` | Health check with pillar status |
| `GET`  | `/api/server-info` | Server URL and WebSocket URL (for QR generation) |

---

## Configuration

All backend settings live in `config.py`:

```python
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-CHANGE-IN-PRODUCTION'

    KEY_SIZE = 2048                              # RSA key size (bits)

    DEFAULT_MESSAGE_EXPIRY = timedelta(minutes=60)   # Keys destroyed after 1 hour
    MAX_MESSAGE_EXPIRY     = timedelta(hours=24)
    MIN_MESSAGE_EXPIRY     = timedelta(minutes=5)

    CHALLENGE_EXPIRY       = timedelta(minutes=5)    # ZKP challenge window
    SESSION_EXPIRY         = timedelta(hours=12)

    SECURITY_LOG_RETENTION_DAYS = 90
    RATE_LIMIT_PER_IP           = 100                # Max requests per hour per IP
    BRUTE_FORCE_THRESHOLD       = 5                  # Auth failures before alert
```

For production, set `SECRET_KEY` as an environment variable and uncomment the SSL/cookie hardening settings at the bottom of `config.py`.

---

## Security Monitoring

The `SecurityMonitor` tracks every security-relevant event and detects attack patterns in real time. All events are visible in the frontend Admin Dashboard and via `/api/admin/security-events`.

### Tracked Event Types

| Event | Severity | Description |
|-------|----------|-------------|
| `connection` | info | New device connected |
| `auth_success` | info | Successful ZKP authentication |
| `auth_failure` | warning | Failed authentication attempt |
| `replay_attack_detected` | critical | Duplicate nonce — replay blocked |
| `brute_force_detected` | critical | 5+ auth failures from same IP in 5 minutes |
| `mitm_detected` | critical | Safety number mismatch — MITM suspected |
| `unauthorized_attempt` | high | Action attempted without device verification |
| `timing_anomaly` | warning | Unusual response time pattern |
| `suspicious_pattern` | high | 3+ replay attacks within 10 minutes |
| `key_expired` | info | Message key destroyed by scheduler |
| `message_sent` | info | Message transmitted |

---

## Tech Stack

### Frontend

| | Technology |
|---|---|
| Framework | React 19 + Vite 7 |
| Routing | React Router v7 |
| WebSocket Client | Socket.IO Client v4 |
| Encryption | WebCrypto API — AES-GCM, native browser, zero dependencies |
| QR Codes | qrcode.react |
| Icons | Lucide React |
| Fonts | Inter + JetBrains Mono |
| Theme | Cyberpunk dark — neon cyan / green / purple accents |

### Backend

| | Technology |
|---|---|
| Web Framework | Flask 3.0 |
| WebSockets | Flask-SocketIO 5.3 + python-socketio |
| Cryptography | PyCryptodome — RSA, AES-256-GCM, SHA-256, HKDF, PBKDF2 |
| Key Scheduling | APScheduler 3.10 |
| QR Generation | qrcode + Pillow |
| CORS | flask-cors |
| DH Group | RFC 3526 2048-bit MODP Group 14 |
| Persistence | JSON flat files — no external database required |

### Cryptographic Primitives

| Primitive | Used For | Location |
|-----------|----------|----------|
| RSA-2048 + PKCS1v15 | Device signatures, ZKP auth | `signature_utils.py` |
| RSA-OAEP | Session key encryption | `signature_utils.py` |
| Chaum Blind Signatures | Anonymous token issuance | `blind_signatures.py` |
| Ring Signatures (RSA) | Unlinkable sender in groups | `ring_signatures.py` |
| AES-256-GCM (server) | Message encryption | `key_expiry.py`, `double_ratchet.py` |
| AES-256-GCM (browser) | Client-side encryption | `cryptoUtils.js` |
| HKDF (SHA-256) | Double Ratchet key derivation | `double_ratchet.py` |
| PBKDF2 (SHA-256, 100k) | DH shared secret → session key | `diffie_hellman.py` |
| Merkle Trees (SHA-256) | Proof-of-existence, no content disclosure | `merkle_proofs.py` |
| SHA-256 Commitment | Temporal integrity, proof of deletion | `hash_utils.py` |
| HMAC-SHA-256 | Deletion attestation binding | `proof_of_deletion.py` |
| Sequential SHA-256 VDF | Time-lock puzzles | `time_lock_puzzle.py` |
| DH RFC 3526 Group 14 | Device pairing key exchange | `diffie_hellman.py` |

---

## Security Notice

> All connection attempts, authentication failures, replay attacks, and anomalous patterns are logged to `storage/security_events.json` and visible in the Admin Dashboard at `/admin`.

> The `SECRET_KEY` in `config.py` is a development placeholder. **Always set a strong secret via environment variable before any public deployment.**

> The `storage/` directory contains sensitive cryptographic material. Exclude it from version control in production deployments.

---

## License

MIT License. See `LICENSE` for details.