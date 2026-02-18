/**
 * pages/Verify.jsx — Proof-of-existence verification
 *
 * Covers: /verify/root, /verify/hash, /verify/proof/:msgId, /verify/signature
 */

import React, { useState } from "react";
import {
  getMerkleRoot,
  verifyHash,
  getInclusionProof,
  verifySignature,
} from "../services/api";
import { verifyMerkleProof } from "../crypto/merkle";

export default function Verify() {
  const [tab, setTab] = useState("root");
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [clientVerified, setClientVerified] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  async function handleVerify() {
    setLoading(true); setResult(null); setClientVerified(null); setErrorMsg("");
    try {
      let data;
      if (tab === "root") {
        data = await getMerkleRoot();
      } else if (tab === "hash") {
        data = await verifyHash({ data: input });
      } else if (tab === "proof") {
        data = await getInclusionProof(input.trim());
        // Client-side Merkle verification
        if (data.proof_path && data.leaf_hash && data.merkle_root) {
          const valid = await verifyMerkleProof(data.leaf_hash, data.proof_path, data.merkle_root);
          setClientVerified(valid);
        }
      } else if (tab === "signature") {
        data = await verifySignature({ msg_id: input.trim() });
      }
      setResult(data);
    } catch (e) {
      setErrorMsg(e.message || "Verification failed.");
    } finally {
      setLoading(false);
    }
  }

  const tabs = [
    { id: "root", label: "Merkle Root" },
    { id: "hash", label: "Hash Check" },
    { id: "proof", label: "Inclusion Proof" },
    { id: "signature", label: "Signature" },
  ];

  return (
    <div className="page-verify">
      <div className="card">
        <h2>Proof-of-Existence Verification</h2>

        <div className="tab-bar">
          {tabs.map((t) => (
            <button key={t.id}
              className={`tab ${tab === t.id ? "active" : ""}`}
              onClick={() => { setTab(t.id); setResult(null); setInput(""); setErrorMsg(""); }}>
              {t.label}
            </button>
          ))}
        </div>

        {tab === "root" && (
          <p className="hint">Fetch the current Merkle root of all submissions.</p>
        )}
        {tab === "hash" && (
          <textarea className="message-input" rows={3} value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter original plaintext data to hash and check…" />
        )}
        {tab === "proof" && (
          <input className="input-field" type="text" value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Message ID (msg_id or message_id)" />
        )}
        {tab === "signature" && (
          <input className="input-field" type="text" value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Chat message_id to verify signature" />
        )}

        {errorMsg && <div className="error-banner">{errorMsg}</div>}

        <button className="btn-primary" onClick={handleVerify} disabled={loading}>
          {loading ? "Verifying…" : "Verify"}
        </button>

        {result && (
          <div className="result-box">
            {tab === "root" && (
              <>
                <div>Merkle Root: <code className="hash">{result.merkle_root}</code></div>
                <div>Total submissions: <strong>{result.total_submissions}</strong></div>
              </>
            )}
            {tab === "hash" && (
              <>
                <div>Hash: <code className="hash">{result.data_hash}</code></div>
                <div>Found in tree: <strong className={result.found ? "ok" : "no"}>{result.found ? "✅ Yes" : "❌ No"}</strong></div>
                <div>Current root: <code className="hash">{result.merkle_root}</code></div>
              </>
            )}
            {tab === "proof" && (
              <>
                <div>Leaf hash: <code className="hash">{result.leaf_hash}</code></div>
                <div>Merkle root: <code className="hash">{result.merkle_root}</code></div>
                <div>Proof steps: <strong>{result.proof_path?.length ?? 0}</strong></div>
                {clientVerified !== null && (
                  <div>Client verification: <strong className={clientVerified ? "ok" : "no"}>
                    {clientVerified ? "✅ Valid — root matches" : "❌ Invalid — root mismatch"}
                  </strong></div>
                )}
              </>
            )}
            {tab === "signature" && (
              <>
                {"valid" in result ? (
                  <div>Signature: <strong className={result.valid ? "ok" : "no"}>
                    {result.valid ? "✅ Valid" : "❌ Invalid"}
                  </strong></div>
                ) : (
                  <div>Note: {result.note}</div>
                )}
                <div>Hash: <code className="hash">{result.hash}</code></div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
