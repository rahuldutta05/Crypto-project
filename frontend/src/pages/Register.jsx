/**
 * pages/Register.jsx — RSA key pair registration (POST /keys/register)
 *
 * Generates an RSA-OAEP key pair, saves it locally, and registers
 * the public key PEM with the server so other users can send encrypted messages.
 */

import React, { useState, useEffect } from "react";
import { generateKeyPair, exportPublicKeyPem, saveKeyPair, loadKeyPair } from "../crypto/rsa";
import { registerKey } from "../services/api";

export default function Register() {
  const [userId, setUserId] = useState(localStorage.getItem("user_id") || "");
  const [hasKeys, setHasKeys] = useState(false);
  const [status, setStatus] = useState("idle");
  const [errorMsg, setErrorMsg] = useState("");
  const [pubKeyPreview, setPubKeyPreview] = useState("");

  useEffect(() => {
    loadKeyPair().then((kp) => {
      setHasKeys(!!kp);
      if (kp) exportPublicKeyPem(kp.publicKey).then(setPubKeyPreview);
    });
  }, []);

  async function handleRegister() {
    if (!userId.trim()) { setErrorMsg("User ID is required."); return; }
    setStatus("generating"); setErrorMsg("");

    try {
      const keyPair = await generateKeyPair();
      await saveKeyPair(keyPair);
      const pubKeyPem = await exportPublicKeyPem(keyPair.publicKey);

      await registerKey({ user_id: userId.trim(), public_key: pubKeyPem });

      localStorage.setItem("user_id", userId.trim());
      setHasKeys(true);
      setPubKeyPreview(pubKeyPem);
      setStatus("done");
    } catch (e) {
      setErrorMsg(e.message || "Registration failed.");
      setStatus("error");
    }
  }

  return (
    <div className="page-register">
      <div className="card">
        <h2>Key Registration</h2>
        <p className="subtitle">
          Generate an RSA key pair to receive encrypted messages. Your private key
          stays in your browser — the server only stores your public key.
        </p>

        {hasKeys && (
          <div className="result-box success">
            <strong>✅ Keys registered</strong>
            <div>User ID: <code>{localStorage.getItem("user_id")}</code></div>
            <details>
              <summary>View public key</summary>
              <pre className="key-preview">{pubKeyPreview}</pre>
            </details>
          </div>
        )}

        <div className="form-group">
          <label>User ID</label>
          <input className="input-field" type="text" placeholder="e.g. alice"
            value={userId} onChange={(e) => setUserId(e.target.value)} />
        </div>

        {errorMsg && <div className="error-banner">{errorMsg}</div>}

        <button className="btn-primary" onClick={handleRegister}
          disabled={status === "generating"}>
          {status === "generating" ? "Generating keys…" :
           hasKeys ? "Re-generate & Re-register" : "Generate & Register"}
        </button>

        {hasKeys && (
          <p className="hint">
            ⚠️ Re-generating will replace your current key pair. Any messages
            encrypted with the old key will become unreadable.
          </p>
        )}
      </div>
    </div>
  );
}
