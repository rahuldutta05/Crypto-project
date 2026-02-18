/**
 * crypto/identity.js — ZKP-style identity chain (mirrors backend core/crypto/zkp.py)
 *
 * Chain: identity_secret → nullifier → commitment
 *   identity_secret  = 256-bit random hex (keep private, stored in localStorage)
 *   nullifier        = SHA-256(identity_secret)       (keep private)
 *   commitment       = SHA-256(nullifier)             (submit to server)
 *
 * The server only sees the commitment. It cannot reverse-derive the secret.
 */

export async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function generateIdentitySecret() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function deriveNullifier(identitySecret) {
  return sha256(identitySecret);
}

export async function deriveCommitment(nullifier) {
  return sha256(nullifier);
}

export async function commitmentFromSecret(identitySecret) {
  const nullifier = await deriveNullifier(identitySecret);
  return deriveCommitment(nullifier);
}

/** Persist identity secret in localStorage. Returns existing or new secret. */
export function getOrCreateSecret() {
  let secret = localStorage.getItem("identity_secret");
  if (!secret) {
    secret = generateIdentitySecret();
    localStorage.setItem("identity_secret", secret);
  }
  return secret;
}
