/**
 * crypto/aes.js — Client-side AES-GCM encryption for E2E chat messages.
 *
 * The backend uses AES-EAX for server-side DEK wrapping, but for the
 * client-side E2E layer (chat messages), we use WebCrypto AES-GCM since
 * AES-EAX is not available natively in the browser.
 *
 * Flow for sending:
 *   1. Generate random 256-bit AES key (DEK)
 *   2. Encrypt message with AES-GCM(DEK) → encrypted_message (base64)
 *   3. RSA-OAEP encrypt DEK with recipient pubkey → encrypted_key (base64)
 *   4. POST { encrypted_message, encrypted_key, receiver } to /chat/send
 *
 * Flow for reading:
 *   1. RSA-OAEP decrypt encrypted_key with your private key → DEK bytes
 *   2. AES-GCM decrypt encrypted_message → plaintext
 */

/** Generate a fresh 256-bit AES-GCM key. */
export async function generateDek() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

/** Export a CryptoKey to raw bytes (ArrayBuffer). */
export async function exportDekRaw(key) {
  return crypto.subtle.exportKey("raw", key);
}

/** Import raw bytes as AES-GCM CryptoKey. */
export async function importDekRaw(rawBytes) {
  return crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Encrypt plaintext string. Returns base64-encoded string of IV (12 bytes) + ciphertext.
 */
export async function encryptMessage(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

  // Prepend IV to ciphertext for transport
  const combined = new Uint8Array(12 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 12);
  return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypt base64-encoded IV+ciphertext string. Returns plaintext string.
 */
export async function decryptMessage(b64Combined, key) {
  const combined = Uint8Array.from(atob(b64Combined), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}
