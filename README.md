# 🔐 CryptoChat v3 — *From Trust Me to Prove It*

**A cryptographically verifiable, end-to-end encrypted chat system where every security property is mathematically provable — not just claimed.**

[Live Demo](https://crypto-chat-sepia.vercel.app) · [Backend API](https://cryptochat-production-e2fe.up.railway.app/api/health) · [Report Bug](../../issues) · [Request Feature](../../issues)

---

## 📖 The Philosophy

Traditional secure messaging asks you to **trust the server**. CryptoChat v3 eliminates trust as a requirement entirely.

| Old Claim | New Proof |
|-----------|-----------|
| *"We don't log who you are"* | **Ring Signature** — provably unlinkable sender |
| *"This message existed at time T"* | **Merkle Proof** — mathematically verifiable |
| *"We deleted the encryption key"* | **Proof of Deletion** — cryptographically demonstrated |
| *"Past messages are safe if we're hacked"* | **Double Ratchet** — forward secrecy by construction |

Every claim is a **mathematical proof**. No faith in any party required.

---

## 🏛️ Three Cryptographic Pillars

### 🔵 Pillar 1 — The Phantom Sender *(Anonymous Authentication)*

> *"We don't just hide your identity. We give you 4 innocent alibis."*

**Ring Signatures** — When a message is sent, the signature mathematically proves it came from *one of N registered users* — but it is impossible, even for the server, to determine which one. The sender is hidden inside a crowd. This is the same primitive used by **Monero**, the privacy cryptocurrency.

**Blind Signatures (Chaum's Scheme)** — Like signing a document inside a carbon-paper envelope. The server signs your authentication token *without ever seeing it*. You later reveal the token; the server can verify it's genuine but has **zero record** of having issued it to you specifically. This is how anonymous e-cash works.

**Zero-Knowledge Device Pairing** — No username. No password. No phone number. Two devices exchange keys via Diffie-Hellman over QR code or a 6-digit code. Both parties compute a **Safety Number** (Signal-style) — a short fingerprint you compare verbally to detect any man-in-the-middle.

---

### 🟣 Pillar 2 — The Witness Protocol *(Verifiable Data Existence)*

> *"A proof the size of a tweet, covering a database of millions."*

**Merkle Proof Trees** — Every message becomes a leaf in a Merkle tree. Only the 32-byte root hash is published. Any single message can be proven to have existed at time T using a tiny Merkle path — without revealing any other message in the tree. This is exactly how **Bitcoin transaction proofs** work.

```
         RootHash
        /         \
    H(A+B)        H(C+D)
    /    \        /    \
  H(A)  H(B)  H(C)  H(D)
```

**Commitment Schemes with Reveal** — Before sending, a commitment (hash of message + random salt) is published. The message is revealed later. Anyone can verify you didn't retroactively change it. **Temporal integrity**: you said what you said, when you said it.

**Proof-of-Existence** — The backend never stores message content — only a SHA-256 chain hash and a timestamp. The existence of a conversation is verifiable; its contents are not accessible to anyone but the participants.

---

### 🔴 Pillar 3 — Cryptographic Amnesia *(Enforced Data Expiry)*

> *"We don't just forget. We make it mathematically impossible to remember."*

**Signal Double Ratchet** — Every single message gets a fresh derived key via **HKDF-SHA-256**. Once you advance the ratchet, the old key is not just deleted — it is *underivable*. Even if an attacker records all network traffic today and steals your device tomorrow, every past message is provably unreadable. Implemented in full on both the Python backend and the React frontend (WebCrypto API).

**Time-Lock Cipher** — Messages are encrypted with keys that carry an expiry timestamp. A background scheduler (APScheduler) checks every 60 seconds and **nullifies** expired keys — setting them to `null` in storage. Recovery after expiry is not a policy decision; it is a mathematical impossibility.

**Proof of Deletion** — The most provocative primitive: *Can you prove you deleted something?* Using a commitment scheme, a key's existence is committed to at creation. Upon expiry, an HMAC-signed attestation is published that proves: *"I held this key, and I have now overwritten it with zeros."* No trust required — the proof is publicly verifiable.

**Burn on Read** — A message can be flagged to self-destruct immediately upon delivery. The recipient's client emits `destroy_message` over WebSocket; the server nullifies the proof hash and notifies both parties.

---

## 🚀 Features at a Glance

- 🔑 **No login required** — anonymous device pairing via QR code or 6-digit code
- 🔒 **End-to-end encryption** — AES-256-GCM; server never sees plaintext
- 🔁 **Double Ratchet** — forward secrecy, every message has a unique key
- 🌳 **Merkle tree** — every message is a leaf; root hash published on every send
- 👁 **Ring signatures** — sender hidden in a cryptographic crowd of users
- 🪙 **Blind signatures** — Chaum's anonymous e-cash scheme for auth tokens
- 🗑️ **Burn on Read** — messages self-destruct after delivery
- ⏱️ **Configurable expiry** — 1 min to 24 hr; keys auto-nullified by scheduler
- 🛡️ **Safety Numbers** — Signal-style MITM detection via verbal fingerprint comparison
- 📊 **Security Dashboard** — real-time threat monitoring, attack simulation, pentest reports
- 🔄 **Persistent storage** — GitHub API-backed JSON storage survives server restarts
- 🌐 **Deployed** — Frontend on Vercel, Backend on Railway

---

## 🗂️ Project Structure

```
crypto-chat-v3/
│
├── frontend/                        # React 19 + Vite 7
│   ├── src/
│   │   ├── App.jsx                  # Root layout, nav, WS status
│   │   ├── index.css                # Cyberpunk dark theme (825 lines)
│   │   ├── components/
│   │   │   ├── ChatInterface.jsx    # Double Ratchet encrypt/decrypt, burn-on-read
│   │   │   ├── DevicePairing.jsx    # QR + 6-digit code pairing flow
│   │   │   └── SafetyNumber.jsx     # MITM detection fingerprint display
│   │   ├── pages/
│   │   │   ├── ChatApp.jsx          # Pairing → Chat orchestrator
│   │   │   └── AdminDashboard.jsx   # Security monitoring UI
│   │   └── utils/
│   │       ├── cryptoUtils.js       # Full Double Ratchet (WebCrypto API)
│   │       ├── socketManager.js     # Singleton Socket.IO client
│   │       └── api.js               # Cross-domain URL builder
│   ├── .env.production              # VITE_BACKEND_URL
│   ├── vercel.json                  # SPA rewrites + COOP/COEP headers
│   └── vite.config.js               # Dev proxy to localhost:5000
│
└── backend/                         # Flask 3 + Flask-SocketIO
    ├── app.py                       # Main app, all WebSocket handlers
    ├── config.py                    # All tunable constants
    ├── github_storage.py            # Dual-layer local + GitHub API storage
    │
    ├── crypto/                      # Cryptographic primitives
    │   ├── diffie_hellman.py        # RFC 3526 2048-bit DH + PBKDF2 session key
    │   ├── double_ratchet.py        # Signal-style Double Ratchet (HKDF-SHA256)
    │   ├── hash_utils.py            # SHA-256, Merkle root, proof-of-existence, commitments
    │   ├── key_expiry.py            # AES-256-GCM, TimeLockCipher, key nullification
    │   ├── merkle_proofs.py         # Full Merkle tree: build, path, verify
    │   ├── blind_signatures.py      # Chaum's blind signature scheme
    │   ├── ring_signatures.py       # Monero-style ring signatures
    │   ├── signature_utils.py       # RSA-2048 keypair, PKCS1v15 sign/verify
    │   ├── proof_of_deletion.py     # HMAC-bound deletion attestation
    │   └── time_lock_puzzle.py      # Time-lock puzzle primitives
    │
    ├── routes/
    │   ├── pairing_routes.py        # /api/pairing/* — DH key exchange, QR, safety numbers
    │   ├── auth_routes.py           # /api/auth/* — ZKP, blind signing, session tokens
    │   ├── chat_routes.py           # /api/chat/* — REST send/receive (fallback)
    │   ├── admin_routes.py          # /api/admin/* — stats, threat level, attack simulation
    │   └── verify_routes.py         # /api/verify/* — Merkle, proof-of-existence, deletion
    │
    ├── monitoring/
    │   └── security_monitor.py      # Real-time event logging, brute-force detection
    │
    ├── scheduler/
    │   └── expiry_scheduler.py      # APScheduler — key expiry every 60s
    │
    ├── storage/                     # JSON flat-file database
    │   ├── devices.json             # Device registry (public keys, pairing status)
    │   ├── messages.json            # Proof metadata only — NO content
    │   ├── proof.json               # Proof-of-existence records
    │   ├── merkle_state.json        # Live Merkle tree state
    │   ├── nonces.json              # Anti-replay nonce registry
    │   ├── security_events.json     # Full security event log
    │   └── ...                      # keys, tokens, blind signing key, etc.
    │
    ├── requirements.txt
    ├── Procfile                     # gunicorn --worker-class eventlet
    └── railway.json                 # Railway deployment config
```

---

## ⚡ Quick Start

### Prerequisites

- Node.js 18+ and npm
- Python 3.11+
- Git

---

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/crypto-chat-v3.git
cd crypto-chat-v3
```

---

### 2. Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

The backend starts on **http://localhost:5000**

> **Optional:** For persistent storage across restarts, set the GitHub environment variables (see [Environment Variables](#environment-variables)).

---

### 3. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend starts on **http://localhost:5173** and proxies API/WebSocket calls to `localhost:5000` automatically.

---

### 4. Start Chatting

1. Open **http://localhost:5173** in **two separate browser windows** (or two devices on the same network)
2. In Window 1 — click **"Generate Link + Code (Device A)"**
3. In Window 2 — click **"Scan QR Code (Device B)"** → enter the 6-digit code
4. Back in Window 1 — click **"Complete Pairing"**
5. Both windows now share a cryptographically secured channel — **compare Safety Numbers** verbally to confirm no MITM

---

## 🌐 Deployment

### Frontend — Vercel

```bash
cd frontend
npm run build
# Deploy the dist/ folder to Vercel, or connect your GitHub repo
```

Set environment variable in Vercel:
```
VITE_BACKEND_URL=https://your-railway-backend.up.railway.app
```

The included `vercel.json` handles SPA routing rewrites and sets required `Cross-Origin-Opener-Policy` / `Cross-Origin-Embedder-Policy` headers for WebCrypto API support.

---

### Backend — Railway

1. Connect your GitHub repo to Railway
2. Set the root directory to `backend/`
3. Railway auto-detects `railway.json` and uses Nixpacks builder
4. Set environment variables (see below)
5. Deploy — the `Procfile` runs `gunicorn --worker-class eventlet`

---

## 🔧 Environment Variables

### Backend

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask secret key — generate a random 32-byte hex string |
| `FRONTEND_URL` | Yes | Full URL of deployed frontend (e.g. `https://your-app.vercel.app`) |
| `GITHUB_TOKEN` | Optional | GitHub PAT with `repo` write scope — enables persistent storage |
| `GITHUB_REPO` | Optional | Repo for storage (e.g. `username/repo-name`) |
| `GITHUB_BRANCH` | Optional | Branch to read/write (default: `main`) |
| `GITHUB_STORAGE_PATH` | Optional | Path inside repo (default: `backend/storage`) |

### Frontend

| Variable | Description |
|----------|-------------|
| `VITE_BACKEND_URL` | Full URL of deployed backend |

---

## 📡 API Reference

### Pairing

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/pairing/initiate` | Device A: generate DH keypair, QR data, 6-digit code |
| `GET` | `/api/pairing/lookup?code=XXXXXX` | Resolve 6-digit code to QR payload |
| `POST` | `/api/pairing/scan` | Device B: compute DH shared secret, derive session key |
| `POST` | `/api/pairing/complete-auto` | Device A: auto-complete once Device B has joined |
| `POST` | `/api/pairing/verify-safety-number` | Confirm MITM-free connection |

### Authentication (ZKP + Blind Signatures)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Anonymous registration — no identity required |
| `POST` | `/api/auth/challenge` | Get ZKP challenge |
| `POST` | `/api/auth/verify` | Prove key ownership without revealing identity |
| `GET` | `/api/auth/blind-public-key` | Fetch server's blind-signing public key |
| `POST` | `/api/auth/blind-sign` | Server signs blinded token — never sees content |
| `POST` | `/api/auth/verify-blind-token` | Verify token authenticity with no issuance record |

### Verification

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/verify/proof/<message_id>` | Get proof-of-existence for a message |
| `GET` | `/api/verify/merkle/root` | Current Merkle tree root hash |
| `GET` | `/api/verify/merkle/proof/<message_id>` | Merkle path for a single message |
| `POST` | `/api/verify/merkle/verify` | Verify a Merkle path independently |
| `POST` | `/api/verify/proof-of-deletion` | Submit key deletion attestation |

### Admin / Security Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/admin/system-stats` | Devices, messages, proofs, nonce counts |
| `GET` | `/api/admin/attack-summary` | All attack types, success rates, top IPs |
| `GET` | `/api/admin/threat-assessment` | Current threat level (LOW/ELEVATED/HIGH/CRITICAL) |
| `GET` | `/api/admin/security-events` | Full filterable security event log |
| `GET` | `/api/admin/penetration-test-report` | Strengths, vulnerabilities, recommendations |
| `POST` | `/api/admin/simulate-attack` | Fire a simulated attack event for testing |
| `GET` | `/api/admin/export-events` | Export events as JSON or CSV |

### WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `verify_device` | Client → Server | Authenticate via DH-paired status |
| `send_message` | Client → Server | Nonce check → proof-of-existence → Merkle leaf → forward |
| `receive_message` | Server → Client | Encrypted blob forwarded in-memory only — never written to disk |
| `destroy_message` | Client → Server | Burn-on-read: nullify proof, notify both parties |
| `message_sent` | Server → Client | Confirmation with proof hash and expiry timestamp |
| `message_destroyed` | Server → Client | Burn-on-read destruction confirmed |
| `join_admin` | Client → Server | Subscribe to real-time security alert stream |
| `security_event` | Server → Client | Real-time push of new security events to admin dashboard |

---

## 🔬 Cryptographic Primitives Deep Dive

### Diffie-Hellman Key Exchange
Uses **RFC 3526 2048-bit MODP Group 14** (the same well-known safe prime used by SSH and TLS). Private keys are 256-bit random integers. Session keys are derived from the shared secret using **PBKDF2-SHA256** with 100,000 iterations and a random 32-byte salt — ensuring both sides arrive at the identical AES-256 key.

### Double Ratchet (Signal Protocol)
```
SharedSecret ──HKDF──► SendChain   RecvChain
                           │              │
              Step 1:  HKDF(SendChain) → MsgKey₁ + NewSendChain
              Step 2:  HKDF(NewSendChain) → MsgKey₂ + ...
```
Every message advances the chain. `MsgKeyN` encrypts exactly one message with AES-256-GCM, then is discarded. The previous chain state is gone — it cannot be recomputed from the new state. Fully implemented in Python (backend) and JavaScript WebCrypto API (frontend) with matching HKDF parameters.

### Ring Signatures
```
Ring = {User₁, User₂, User₃, User₄, User₅}
Signer = User₃ (unknown to verifier)

Verify(Ring, Message, Signature) → TRUE
Who signed? → MATHEMATICALLY UNKNOWABLE
```
The implementation uses a shared-modulus RSA construction. The verifier can confirm the signature is valid for the ring, but the signer's index is computationally hidden.

### Merkle Tree
```
New message arrives → SHA-256(proof_hash) → appended as leaf
Tree rebuilt → new root_hash stored
Any message can be proven with O(log n) hashes
Root hash published — proving all messages without revealing any
```

### Blind Signatures (Chaum)
```
Client:  m' = H(token) * r^e mod n    (blind with random r)
Server:  s' = (m')^d mod n            (sign without seeing token)
Client:  s  = s' * r⁻¹ mod n         (unblind — now has valid sig on token)
Verify:  s^e mod n == H(token)        ✓ — but server has no record of r
```

---

## 🛡️ Security Dashboard

The admin dashboard at `/admin` provides:

- **Threat Level Banner** — AUTO/ELEVATED/HIGH/CRITICAL based on recent event density
- **Attack Type Breakdown** — bar chart of replay attacks, brute force, MITM, unauthorized access, timing anomalies
- **Core Principles Status** — live counters for anonymous devices, proofs created, keys destroyed
- **Recent Security Events** — scrollable table with timestamp, type, severity, details
- **Attacker Simulation Panel** — fire test events to verify the monitoring pipeline
- **Penetration Test Report** — auto-generated security strengths and vulnerability list
- **Export** — download all events as JSON or CSV for external analysis

---

## 🧪 Running the Pentest Simulation

The admin dashboard includes a built-in attack simulator. To test the full pipeline:

1. Navigate to `/admin`
2. Use the **Attacker Simulation** panel to fire events:
   - 🔁 **Replay Attack** — tests nonce deduplication
   - 💥 **Brute Force** — tests pattern detection (5 failures → alert)
   - 🕵 **MITM Attempt** — tests safety number mismatch detection
   - 🚫 **Unauthorized Access** — tests unverified device rejection
3. Watch the **Recent Security Events** table update in real-time via WebSocket
4. Check **Threat Level** — it escalates automatically based on event volume
5. View the **Penetration Test Report** for a structured security analysis

---

## 🧰 Tech Stack

### Frontend
| Technology | Version | Purpose |
|------------|---------|---------|
| React | 19 | UI framework |
| Vite | 7 | Build tool + dev server |
| React Router | 7 | SPA routing |
| Socket.IO Client | 4.8 | Real-time WebSocket |
| qrcode.react | 4.2 | QR code generation |
| lucide-react | 0.577 | Icons |
| WebCrypto API | Native | AES-GCM, HKDF (no library) |

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| Flask | 3.0 | HTTP framework |
| Flask-SocketIO | 5.3 | WebSocket server |
| eventlet | 0.35 | Async worker |
| PyCryptodome | Latest | All cryptographic ops |
| APScheduler | 3.10 | Key expiry scheduler |
| gunicorn | 21.2 | Production WSGI server |
| requests | 2.31 | GitHub storage API |

---

## 🤝 Contributing

Contributions are welcome! Here are some areas for improvement:

- [ ] Actual VDF (Verifiable Delay Function) implementation — true time-lock puzzles
- [ ] ECDH key exchange (replace DH for better performance)
- [ ] Multi-party ring signature with dynamic ring assembly
- [ ] WebRTC peer-to-peer mode (remove server from message path entirely)
- [ ] Mobile app (React Native)
- [ ] Threshold signatures for group chats

### Steps

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 🙏 Acknowledgements

- [Signal Protocol](https://signal.org/docs/) — Double Ratchet specification
- [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf) — Merkle tree transaction proofs
- [Monero](https://www.getmonero.org/) — Ring signature implementation inspiration
- [David Chaum](https://en.wikipedia.org/wiki/David_Chaum) — Blind signature scheme (1982)
- [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526) — 2048-bit MODP Group 14 for Diffie-Hellman

---

**Built with the conviction that security should be provable, not promised.**

*"From Trust Me to Prove It"*