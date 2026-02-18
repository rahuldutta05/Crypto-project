/**
 * services/api.js — HTTP client for backend_v2
 *
 * Covers all backend_v2 API endpoints:
 *   /auth      — anonymous submission (identity, submit, read)
 *   /chat      — E2E encrypted messaging (send, inbox)
 *   /keys      — public key registry (register, lookup, server pubkey)
 *   /verify    — proof-of-existence (root, hash, proof, signature)
 *   /admin     — protected admin endpoints (requires Bearer token)
 */

const BASE_URL = "http://localhost:5000";

async function request(method, path, body = null, headers = {}) {
  const opts = {
    method,
    headers: { "Content-Type": "application/json", ...headers },
  };
  if (body !== null) {
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(`${BASE_URL}${path}`, opts);
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }

  return data;
}

// ─── /auth ───────────────────────────────────────────────────────────────────

export const generateIdentity = () => request("POST", "/auth/identity");
export const submitAnonymous = (body) => request("POST", "/auth/submit", body);
export const readSubmission = (msgId) => request("GET", `/auth/read/${msgId}`);

// ─── /chat ───────────────────────────────────────────────────────────────────

export const sendMessage = (body) => request("POST", "/chat/send", body);
export const getInbox = (userId) => request("GET", `/chat/inbox/${userId}`);

// ─── /keys ───────────────────────────────────────────────────────────────────

export const registerKey = (body) => request("POST", "/keys/register", body);
export const getPublicKey = (userId) => request("GET", `/keys/${userId}`);
export const getServerPublicKey = () => request("GET", "/keys/server/pubkey");

// ─── /verify ─────────────────────────────────────────────────────────────────

export const getMerkleRoot = () => request("GET", "/verify/root");
export const verifyHash = (body) => request("POST", "/verify/hash", body);
export const getInclusionProof = (msgId) => request("GET", `/verify/proof/${msgId}`);
export const verifySignature = (body) => request("POST", "/verify/signature", body);

// ─── /admin ──────────────────────────────────────────────────────────────────

function adminHeaders(token) {
  return { Authorization: `Bearer ${token}` };
}

export const adminGetMessages = (token) =>
  request("GET", "/admin/messages", null, adminHeaders(token));
export const adminGetProofs = (token) =>
  request("GET", "/admin/proofs", null, adminHeaders(token));
export const adminGetCommitments = (token) =>
  request("GET", "/admin/commitments", null, adminHeaders(token));
export const adminGetStats = (token) =>
  request("GET", "/admin/stats", null, adminHeaders(token));
export const adminForceExpire = (token) =>
  request("POST", "/admin/expire", null, adminHeaders(token));
