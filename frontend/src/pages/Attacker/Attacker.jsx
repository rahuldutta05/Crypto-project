/**
 * pages/Attacker/Attacker.jsx — Attacker simulation dashboard
 *
 * Demonstrates what an attacker can and cannot observe/do given the
 * backend_v2 security model:
 *
 * ✅ Attacker CAN see: encrypted ciphertext, commitment (hash), expiry, proof hashes
 * ❌ Attacker CANNOT: decrypt (no KEK), link commitment to identity, extend expiry,
 *    read data after expiry (DEK destroyed), forge Merkle/RSA proofs
 */

import React, { useState } from "react";
import { adminGetMessages, adminGetProofs } from "../../services/api";

const SCENARIOS = [
  {
    id: "replay",
    label: "Replay Commitment",
    description:
      "Attacker captures a commitment and nonce and tries to replay the same submission.",
    result:
      "❌ BLOCKED — backend rejects: 'Commitment already used — duplicate submission rejected' (HTTP 409). Each commitment can only be used once.",
  },
  {
    id: "extend",
    label: "Extend Expiry",
    description: "Attacker intercepts the submission and tries to set a longer expiry.",
    result:
      "❌ BLOCKED — expiry is set server-side (config.KEY_EXPIRY_MINUTES). Client-supplied expiry fields are ignored.",
  },
  {
    id: "decrypt",
    label: "Decrypt Ciphertext",
    description: "Attacker reads stored ciphertext from the database and tries to decrypt it.",
    result:
      "❌ BLOCKED — ciphertext is AES-EAX encrypted with a DEK, which is itself AES-EAX wrapped with the server KEK. Without the KEK (stored only in /storage/vault/kek.json), decryption is computationally infeasible.",
  },
  {
    id: "postexpiry",
    label: "Read After Expiry",
    description: "Attacker waits for data to expire and then reads the message.",
    result:
      "❌ BLOCKED — after expiry the scheduler sets wrapped_dek = null. GET /auth/read returns HTTP 410 Gone. The DEK is gone; even the server cannot recover it.",
  },
  {
    id: "pow_skip",
    label: "Skip Proof-of-Work",
    description: "Attacker submits without solving PoW to spam the server.",
    result:
      "❌ BLOCKED — server verifies SHA-256(commitment+nonce) must start with 000000 (difficulty 6). Missing or invalid nonce returns HTTP 400.",
  },
  {
    id: "link",
    label: "Link Commitment to Identity",
    description: "Attacker sees commitment on the wire and tries to derive the identity_secret.",
    result:
      "❌ BLOCKED — commitment = SHA-256(SHA-256(identity_secret)). Reversing requires breaking SHA-256 (computationally infeasible). Only the commitment is ever sent to the server.",
  },
];

export default function Attacker() {
  const [activeScenario, setActiveScenario] = useState(null);
  const [sniffed, setSniffed] = useState(null);
  const [loading, setLoading] = useState(false);
  const [adminToken, setAdminToken] = useState("");

  async function sniffMessages() {
    if (!adminToken) { alert("Enter admin token to simulate database read."); return; }
    setLoading(true);
    try {
      const msgs = await adminGetMessages(adminToken);
      const proofs = await adminGetProofs(adminToken);
      setSniffed({ messages: msgs, proofs });
    } catch (e) {
      setSniffed({ error: e.message });
    } finally { setLoading(false); }
  }

  return (
    <div className="page-attacker">
      <div className="card">
        <h2>🔴 Attacker Simulation</h2>
        <p className="subtitle">
          Educational view of what an attacker can observe and what the
          cryptographic design prevents.
        </p>

        <div className="scenario-grid">
          {SCENARIOS.map((s) => (
            <div key={s.id}
              className={`scenario-card ${activeScenario?.id === s.id ? "open" : ""}`}
              onClick={() => setActiveScenario(activeScenario?.id === s.id ? null : s)}>
              <div className="scenario-label">🎯 {s.label}</div>
              {activeScenario?.id === s.id && (
                <div className="scenario-detail">
                  <p className="scenario-desc">{s.description}</p>
                  <div className="scenario-result">{s.result}</div>
                </div>
              )}
            </div>
          ))}
        </div>

        <hr />

        <h3>📡 Raw Database Dump</h3>
        <p className="hint">
          Simulate attacker with DB access. Even with full read access, all
          messages are encrypted. (Requires admin token.)
        </p>
        <div className="row">
          <input className="input-field" type="password" placeholder="Admin token"
            value={adminToken} onChange={(e) => setAdminToken(e.target.value)} />
          <button className="btn-danger" onClick={sniffMessages} disabled={loading}>
            {loading ? "Reading…" : "Read DB"}
          </button>
        </div>

        {sniffed && (
          <div className="sniff-result">
            {sniffed.error ? (
              <div className="error-banner">{sniffed.error}</div>
            ) : (
              <>
                <p>Messages in DB: <strong>{Object.keys(sniffed.messages).length}</strong></p>
                <p className="hint">All ciphertext is encrypted. DEKs are wrapped with KEK.</p>
                <pre className="json-dump">{JSON.stringify(sniffed.messages, null, 2)}</pre>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
