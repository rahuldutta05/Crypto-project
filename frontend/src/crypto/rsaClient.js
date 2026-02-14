export async function generateKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportPublicKey(key) {
  const spki = await crypto.subtle.exportKey("spki", key);
  return btoa(String.fromCharCode(...new Uint8Array(spki)));
}

export async function encryptAESKey(aesKey, publicKey) {

  const rawKey = await crypto.subtle.exportKey("raw", aesKey);

  return await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    rawKey
  );
}

export async function exportPrivateKey(key) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", key);
  return btoa(
    String.fromCharCode(...new Uint8Array(pkcs8))
  );
}
