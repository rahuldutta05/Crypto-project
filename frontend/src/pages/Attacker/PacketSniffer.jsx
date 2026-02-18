/**
 * pages/Attacker/PacketSniffer.jsx — Intercepted packet viewer
 *
 * Shows what an attacker sees intercepting network traffic between client and
 * backend_v2. All sensitive data is either hashed (commitment) or encrypted
 * (ciphertext). Demonstrates the "what can you see on the wire?" question.
 */

import React, { useState } from "react";

const EXAMPLE_PACKETS = [
  {
    id: 1,
    direction: "→ Client → Server",
    endpoint: "POST /auth/submit",
    payload: {
      data: "⚠️ NOT VISIBLE — sent plaintext but immediately encrypted by server",
      commitment: "a7f3d2e1b9c8... (SHA-256 of SHA-256 of identity_secret)",
      nonce: "84712",
    },
    analysis:
      "Attacker sees: commitment (opaque hash) + nonce (only useful for this PoW). Cannot derive identity_secret from commitment. Cannot reuse (409 on replay).",
  },
  {
    id: 2,
    direction: "← Server → Client",
    endpoint: "POST /auth/submit response",
    payload: {
      status: "accepted",
      msg_id: "3",
      expiry: "2026-02-18T07:00:00+00:00",
    },
    analysis:
      "Attacker learns: msg_id + expiry. They can try GET /auth/read before expiry but still can't decrypt without the KEK (server-side).",
  },
  {
    id: 3,
    direction: "→ Client → Server",
    endpoint: "POST /chat/send",
    payload: {
      encrypted_message: "base64(AES-GCM(plaintext))... [opaque ciphertext]",
      encrypted_key: "base64(RSA-OAEP(DEK))... [opaque, only recipient can decrypt]",
      receiver: "alice",
    },
    analysis:
      "Attacker sees: two opaque blobs. Cannot decrypt encrypted_key without Alice's private key. Cannot decrypt encrypted_message without the DEK.",
  },
  {
    id: 4,
    direction: "← Server → Client",
    endpoint: "GET /verify/proof/:msg_id",
    payload: {
      leaf_hash: "f3a2d1... (SHA-256 of original data)",
      merkle_root: "b9c8e7...",
      proof_path: "[{ sibling, position }, ...]",
    },
    analysis:
      "Attacker can verify Merkle proof (it's public) but cannot recover original data from hash (SHA-256 is one-way).",
  },
];

export default function PacketSniffer() {
  const [selected, setSelected] = useState(null);

  return (
    <div className="page-sniffer">
      <div className="card">
        <h2>📡 Packet Sniffer</h2>
        <p className="subtitle">
          Simulated network interception. Click a packet to inspect what an
          attacker would observe at the network layer.
        </p>

        <div className="packet-list">
          {EXAMPLE_PACKETS.map((pkt) => (
            <div key={pkt.id}
              className={`packet-row ${selected?.id === pkt.id ? "selected" : ""}`}
              onClick={() => setSelected(selected?.id === pkt.id ? null : pkt)}>
              <span className="pkt-dir">{pkt.direction}</span>
              <code className="pkt-endpoint">{pkt.endpoint}</code>
            </div>
          ))}
        </div>

        {selected && (
          <div className="packet-detail">
            <h3>{selected.endpoint}</h3>
            <div className="pkt-direction-badge">{selected.direction}</div>

            <h4>Intercepted payload:</h4>
            <pre className="json-dump">{JSON.stringify(selected.payload, null, 2)}</pre>

            <h4>Attacker analysis:</h4>
            <div className="analysis-box">{selected.analysis}</div>
          </div>
        )}
      </div>
    </div>
  );
}
