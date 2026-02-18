/**
 * pages/Send.jsx — Anonymous submission with PoW + ZKP commitment
 *
 * Backend endpoint: POST /auth/submit
 * Required fields:  { data, commitment, nonce }
 *
 * Flow:
 *   1. Load or create identity_secret from localStorage
 *   2. Derive commitment (secret→nullifier→commitment) — never sends secret to server
 *   3. Solve PoW: SHA-256(commitment + nonce) must start with 000000
 *   4. POST { data, commitment, nonce } to /auth/submit
 *   5. Server returns { msg_id, expiry, status }
 */

import React, { useState, useEffect, useCallback } from "react";
import { getOrCreateSecret, commitmentFromSecret } from "../crypto/identity";
import { solvePoW, POW_DIFFICULTY } from "../crypto/pow";
import { submitAnonymous } from "../services/api";

export default function Send() {
  const [message, setMessage] = useState("");
  const [commitment, setCommitment] = useState(null);
  const [nonce, setNonce] = useState(null);
  const [powProgress, setPowProgress] = useState(0);
  const [status, setStatus] = useState("idle"); // idle | preparing | solving | sending | done | error
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  // Derive commitment on mount (never sends identity_secret to server)
  const prepareIdentity = useCallback(async () => {
    setStatus("preparing");
    try {
      const secret = getOrCreateSecret();
      const comm = await commitmentFromSecret(secret);
      setCommitment(comm);

      setStatus("solving");
      const n = await solvePoW(comm, POW_DIFFICULTY, (iter) => setPowProgress(iter));
      setNonce(n);
      setStatus("idle");
    } catch (e) {
      setErrorMsg("Failed to prepare identity: " + e.message);
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    prepareIdentity();
  }, [prepareIdentity]);

  async function handleSend() {
    if (!commitment || !nonce) return;
    if (!message.trim()) {
      setErrorMsg("Message cannot be empty.");
      return;
    }

    setStatus("sending");
    setErrorMsg("");
    try {
      const data = await submitAnonymous({ data: message, commitment, nonce });
      setResult(data);
      setStatus("done");
      setMessage("");

      // Re-solve PoW for next message (commitment is consumed — one per identity)
      // To send again, user needs a fresh identity or the same commitment won't be accepted.
      // The backend rejects duplicate commitments, so regenerate.
    } catch (e) {
      if (e.status === 409) {
        setErrorMsg(
          "This identity's commitment was already used. Refresh to generate a new one."
        );
      } else {
        setErrorMsg(e.message || "Submission failed.");
      }
      setStatus("error");
    }
  }

  const isReady = status === "idle" && commitment && nonce;

  return (
    <div className="page-send">
      <div className="card">
        <h2>Anonymous Submission</h2>
        <p className="subtitle">
          Your identity secret never leaves your device. Only a cryptographic
          commitment is sent to the server.
        </p>

        {/* Identity status */}
        <div className={`identity-status ${isReady ? "ready" : "pending"}`}>
          {status === "preparing" && "⏳ Deriving identity commitment…"}
          {status === "solving" && (
            <>
              ⚙️ Solving Proof-of-Work (difficulty {POW_DIFFICULTY})…
              {powProgress > 0 && (
                <span className="pow-progress"> {powProgress.toLocaleString()} hashes</span>
              )}
            </>
          )}
          {isReady && (
            <>
              ✅ Identity ready
              <span className="commitment-preview" title={commitment}>
                {" "}
                ({commitment.slice(0, 12)}…)
              </span>
            </>
          )}
          {status === "error" && "❌ Identity error"}
        </div>

        {/* Message input */}
        <textarea
          className="message-input"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Type your anonymous message here…"
          rows={5}
          disabled={!isReady || status === "sending"}
        />

        {errorMsg && <div className="error-banner">{errorMsg}</div>}

        <button
          className="btn-primary"
          onClick={handleSend}
          disabled={!isReady || status === "sending" || !message.trim()}
        >
          {status === "sending" ? "Submitting…" : "Submit Anonymously"}
        </button>

        {/* Result */}
        {status === "done" && result && (
          <div className="result-box success">
            <strong>✅ Submitted</strong>
            <div>
              Message ID: <code>{result.msg_id}</code>
            </div>
            <div>
              Expires: <code>{new Date(result.expiry).toLocaleString()}</code>
            </div>
            <div className="hint">
              After expiry the encryption key is destroyed — data is
              permanently unrecoverable, even by the server.
            </div>
            <button className="btn-secondary" onClick={prepareIdentity}>
              Send another (new identity)
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
