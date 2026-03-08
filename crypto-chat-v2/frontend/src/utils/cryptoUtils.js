/**
 * cryptoUtils.js
 * Client-side AES-GCM encryption / decryption using the WebCrypto API.
 * The backend NEVER sees plaintext — only encrypted blobs.
 */

// ─── AES-GCM key derivation ──────────────────────────────────────────────────

export async function importKeyFromSession(sessionKeyB64) {
    const raw = Uint8Array.from(atob(sessionKeyB64), c => c.charCodeAt(0))
    return window.crypto.subtle.importKey(
        'raw',
        raw,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    )
}

// ─── Encrypt ─────────────────────────────────────────────────────────────────

export async function encryptMessage(plaintext, sessionKeyB64) {
    const key = await importKeyFromSession(sessionKeyB64)
    const iv = window.crypto.getRandomValues(new Uint8Array(12))
    const encoded = new TextEncoder().encode(plaintext)

    const ciphertext = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoded
    )

    return {
        ciphertext: arrayBufferToBase64(ciphertext),
        iv: arrayBufferToBase64(iv.buffer)
    }
}

// ─── Decrypt ─────────────────────────────────────────────────────────────────

export async function decryptMessage(encryptedObj, sessionKeyB64) {
    const key = await importKeyFromSession(sessionKeyB64)
    const iv = base64ToArrayBuffer(encryptedObj.iv)
    const ciphertext = base64ToArrayBuffer(encryptedObj.ciphertext)

    const plaintext = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(iv) },
        key,
        ciphertext
    )

    return new TextDecoder().decode(plaintext)
}

// ─── Nonce ───────────────────────────────────────────────────────────────────

export function generateNonce() {
    const arr = window.crypto.getRandomValues(new Uint8Array(16))
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (const b of bytes) binary += String.fromCharCode(b)
    return btoa(binary)
}

export function base64ToArrayBuffer(base64) {
    const binary = atob(base64)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
    return bytes.buffer
}
