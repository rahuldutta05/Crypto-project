/**
 * cryptoUtils.js
 * Client-side AES-GCM encryption / decryption using the WebCrypto API.
 * Uses Signal-style Double Ratchet: every message gets a fresh HKDF-derived key.
 * The backend NEVER sees plaintext — only encrypted blobs.
 */

// ─── Double Ratchet (Signal-style forward secrecy) ───────────────────────────────

/**
 * Derive a new 32-byte key from keyBytes via HKDF-SHA-256.
 */
async function hkdf32(keyBytes, info) {
    const hkdfKey = await crypto.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
        hkdfKey,
        256
    )
    return new Uint8Array(bits)
}

/**
 * One ratchet step: (msgKey, nextChainKey) ← HKDF(chainKey, "double-ratchet-step").
 * The old chain key is never needed again — forward secrecy by construction.
 */
async function ratchetStep(chainKeyBytes) {
    const hkdfKey = await crypto.subtle.importKey('raw', chainKeyBytes, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('double-ratchet-step') },
        hkdfKey,
        512  // 64 bytes: first 32 = msg key, next 32 = next chain key
    )
    const arr = new Uint8Array(bits)
    return { msgKey: arr.slice(0, 32), nextChainKey: arr.slice(32) }
}

/**
 * Initialise both ratchet chains from the shared DH session key.
 * isInitiator=true  → Device A (called /complete):  send=”send-chain”, recv=”recv-chain”
 * isInitiator=false → Device B (called /scan):       send=”recv-chain”, recv=”send-chain”
 * This ensures A’s send chain always == B’s recv chain and vice-versa.
 */
export async function initDoubleRatchet(sessionKeyB64, isInitiator) {
    const secret = Uint8Array.from(atob(sessionKeyB64), c => c.charCodeAt(0))
    const sendChainRaw = await hkdf32(secret, 'send-chain')
    const recvChainRaw = await hkdf32(secret, 'recv-chain')
    return {
        sendChain: isInitiator ? sendChainRaw : recvChainRaw,
        recvChain:  isInitiator ? recvChainRaw  : sendChainRaw,
        sendStep: 0,
        recvStep: 0
    }
}

/**
 * Ratchet-encrypt plaintext. Returns { payload, newState }.
 * payload = { ciphertext, iv, step } — send this as encrypted_data.
 */
export async function ratchetEncrypt(plaintext, ratchetState) {
    const { msgKey, nextChainKey } = await ratchetStep(ratchetState.sendChain)
    const aesKey = await crypto.subtle.importKey('raw', msgKey, { name: 'AES-GCM' }, false, ['encrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        new TextEncoder().encode(plaintext)
    )
    const newState = { ...ratchetState, sendChain: nextChainKey, sendStep: ratchetState.sendStep + 1 }
    return {
        payload: {
            ciphertext: arrayBufferToBase64(ciphertext),
            iv: arrayBufferToBase64(iv.buffer),
            step: newState.sendStep
        },
        newState
    }
}

/**
 * Ratchet-decrypt a received payload. Returns { plaintext, newState }.
 * Throws if step is out of order (replay / skipped message).
 */
export async function ratchetDecrypt(payload, ratchetState) {
    if (payload.step !== ratchetState.recvStep + 1) {
        throw new Error(`Out-of-order ratchet step (got ${payload.step}, expected ${ratchetState.recvStep + 1})`)
    }
    const { msgKey, nextChainKey } = await ratchetStep(ratchetState.recvChain)
    const aesKey = await crypto.subtle.importKey('raw', msgKey, { name: 'AES-GCM' }, false, ['decrypt'])
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(base64ToArrayBuffer(payload.iv)) },
        aesKey,
        base64ToArrayBuffer(payload.ciphertext)
    )
    const newState = { ...ratchetState, recvChain: nextChainKey, recvStep: ratchetState.recvStep + 1 }
    return { plaintext: new TextDecoder().decode(plaintext), newState }
}

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
