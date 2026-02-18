/**
 * pages/ChatPortal.jsx — E2E encrypted message sender (POST /chat/send)
 *
 * Flow:
 *   1. Fetch recipient's public key from GET /keys/:userId
 *   2. Generate ephemeral AES-GCM DEK
 *   3. AES-GCM encrypt message with DEK → encrypted_message
 *   4. RSA-OAEP encrypt DEK with recipient pubkey → encrypted_key
 *   5. POST { encrypted_message, encrypted_key, receiver } to /chat/send
 *   6. Server returns { message_id, expiry }
 */

import React, { useState } from "react";
import { getPublicKey, sendMessage } from "../services/api";
import { importPublicKeyPem, rsaEncrypt } from "../crypto/rsa";
import { generateDek, exportDekRaw, encryptMessage } from "../crypto/aes";

export default function ChatPortal() {
  const [receiver, setReceiver] = useState("");
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("idle");
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  async function handleSend() {
    if (!receiver.trim() || !message.trim()) {
      setErrorMsg("Recipient and message are required.");
      return;
    }

    setStatus("sending"); setErrorMsg("");

    try {
      // 1. Fetch recipient public key
      const keyData = await getPublicKey(receiver.trim());
      const recipientPubKey = await importPublicKeyPem(keyData.public_key);

      // 2. Generate ephemeral DEK
      const dek = await generateDek();

      // 3. Encrypt message with AES-GCM
      const encryptedMessage = await encryptMessage(message, dek);

      // 4. Encrypt DEK with recipient's RSA public key
      const rawDek = await exportDekRaw(dek);
      const encryptedKey = await rsaEncrypt(recipientPubKey, rawDek);

      // 5. POST to /chat/send
      const data = await sendMessage({
        encrypted_message: encryptedMessage,
        encrypted_key: encryptedKey,
        receiver: receiver.trim(),
      });

      setResult(data);
      setStatus("done");
      setMessage("");
    } catch (e) {
      if (e.status === 404) {
        setErrorMsg(`User "${receiver}" has no registered public key. They must register first.`);
      } else {
        setErrorMsg(e.message || "Send failed.");
      }
      setStatus("error");
    }
  }

  return (
    <div className="page-chat">
      <div className="card">
        <h2>Send Encrypted Message</h2>
        <p className="subtitle">
          Messages are encrypted client-side with the recipient's public key.
          The server never sees plaintext.
        </p>

        <div className="form-group">
          <label>To (user ID)</label>
          <input className="input-field" type="text" placeholder="e.g. alice"
            value={receiver} onChange={(e) => setReceiver(e.target.value)} />
        </div>

        <div className="form-group">
          <label>Message</label>
          <textarea className="message-input" rows={5} value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Your encrypted message…"
            disabled={status === "sending"} />
        </div>

        {errorMsg && <div className="error-banner">{errorMsg}</div>}

        <button className="btn-primary" onClick={handleSend}
          disabled={status === "sending" || !receiver.trim() || !message.trim()}>
          {status === "sending" ? "Encrypting & Sending…" : "Send Encrypted"}
        </button>

        {status === "done" && result && (
          <div className="result-box success">
            <strong>✅ Message sent</strong>
            <div>Message ID: <code>{result.message_id}</code></div>
            <div>Expires: <code>{new Date(result.expiry).toLocaleString()}</code></div>
          </div>
        )}
      </div>
    </div>
  );
}
