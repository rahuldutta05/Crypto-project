/**
 * crypto/rsa.js — RSA key pair management for E2E messaging (aligned to backend api/keys.py)
 *
 * Generates RSA-OAEP key pairs. The public key PEM is registered with the server
 * via POST /keys/register. The private key stays local (localStorage).
 *
 * Sender:    fetch recipient public key → RSA-OAEP encrypt AES key → POST /chat/send
 * Recipient: use stored private key → RSA-OAEP decrypt AES key → AES decrypt message
 */

const RSA_PARAMS = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

/** Generate a fresh RSA-OAEP key pair. */
export async function generateKeyPair() {
  return crypto.subtle.generateKey(RSA_PARAMS, true, ["encrypt", "decrypt"]);
}

/** Export a CryptoKey public key to PEM string for server registration. */
export async function exportPublicKeyPem(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(spki)));
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

/** Import a PEM public key string back to a CryptoKey for encryption. */
export async function importPublicKeyPem(pem) {
  const b64 = pem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s/g, "");
  const binaryDer = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("spki", binaryDer, RSA_PARAMS, true, ["encrypt"]);
}

/** Encrypt bytes with a public key. Returns base64 string. */
export async function rsaEncrypt(publicKey, data) {
  const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, data);
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

/** Decrypt base64 ciphertext with a private key. Returns ArrayBuffer. */
export async function rsaDecrypt(privateKey, b64Ciphertext) {
  const ciphertext = Uint8Array.from(atob(b64Ciphertext), (c) => c.charCodeAt(0));
  return crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, ciphertext);
}

/**
 * Persist serialized key pair in localStorage.
 * Keys are exported as JWK format for reliable storage.
 */
export async function saveKeyPair(keyPair) {
  const pubJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  localStorage.setItem("rsa_public_key", JSON.stringify(pubJwk));
  localStorage.setItem("rsa_private_key", JSON.stringify(privJwk));
}

/** Load key pair from localStorage. Returns null if not found. */
export async function loadKeyPair() {
  const pubJwkStr = localStorage.getItem("rsa_public_key");
  const privJwkStr = localStorage.getItem("rsa_private_key");
  if (!pubJwkStr || !privJwkStr) return null;

  try {
    const pubJwk = JSON.parse(pubJwkStr);
    const privJwk = JSON.parse(privJwkStr);
    const publicKey = await crypto.subtle.importKey("jwk", pubJwk, RSA_PARAMS, true, ["encrypt"]);
    const privateKey = await crypto.subtle.importKey("jwk", privJwk, RSA_PARAMS, true, ["decrypt"]);
    return { publicKey, privateKey };
  } catch {
    return null;
  }
}
