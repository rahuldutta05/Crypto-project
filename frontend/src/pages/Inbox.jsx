/**
 * pages/Inbox.jsx — Encrypted message inbox (GET /chat/inbox/:userId)
 */

import React, { useState } from "react";
import { getInbox } from "../services/api";
import { loadKeyPair, rsaDecrypt } from "../crypto/rsa";
import { decryptMessage, importDekRaw } from "../crypto/aes";
import StatusBadge from "../components/StatusBadge";

export default function Inbox() {
  const [userId, setUserId] = useState(localStorage.getItem("user_id") || "");
  const [messages, setMessages] = useState([]);
  const [decrypted, setDecrypted] = useState({});
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  async function loadMessages() {
    if (!userId.trim()) { setErrorMsg("Enter your user ID first."); return; }
    setLoading(true); setErrorMsg("");
    try {
      const data = await getInbox(userId.trim());
      setMessages(Object.entries(data));
    } catch (e) {
      setErrorMsg(e.message || "Failed to load inbox.");
    } finally { setLoading(false); }
  }

  async function decryptMsg(msgId, encMsg, encKey) {
    try {
      const keyPair = await loadKeyPair();
      if (!keyPair) { setDecrypted(p => ({ ...p, [msgId]: "❌ No private key. Register first." })); return; }
      const dekBytes = await rsaDecrypt(keyPair.privateKey, encKey);
      const dek = await importDekRaw(dekBytes);
      const plaintext = await decryptMessage(encMsg, dek);
      setDecrypted(p => ({ ...p, [msgId]: plaintext }));
    } catch (e) {
      setDecrypted(p => ({ ...p, [msgId]: "❌ Decryption failed: " + e.message }));
    }
  }

  return (
    <div className="page-inbox">
      <div className="card">
        <h2>Inbox</h2>
        <div className="inbox-controls">
          <input className="input-field" type="text" placeholder="Your user ID"
            value={userId} onChange={(e) => setUserId(e.target.value)} />
          <button className="btn-primary" onClick={loadMessages} disabled={loading}>
            {loading ? "Loading…" : "Load Inbox"}
          </button>
        </div>
        {errorMsg && <div className="error-banner">{errorMsg}</div>}
        {messages.length === 0 && !loading && !errorMsg && (
          <div className="empty-state">No messages. Load inbox or send a message first.</div>
        )}
        <div className="message-list">
          {messages.map(([msgId, msg]) => (
            <div key={msgId} className={`message-card ${msg.expired ? "expired" : "active"}`}>
              <div className="message-header">
                <code className="msg-id">{msgId.slice(0, 8)}…</code>
                <StatusBadge expired={msg.expired} />
                <span className="expiry">
                  {msg.expired ? "Expired" : "Expires"}: {new Date(msg.expiry).toLocaleString()}
                </span>
              </div>
              {msg.expired ? (
                <div className="expired-notice">🔑 Key destroyed — data permanently gone.</div>
              ) : decrypted[msgId] ? (
                <div className="decrypted-content">{decrypted[msgId]}</div>
              ) : (
                <button className="btn-secondary"
                  onClick={() => decryptMsg(msgId, msg.encrypted_message, msg.encrypted_key)}>
                  🔓 Decrypt
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
