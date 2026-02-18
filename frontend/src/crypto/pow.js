/**
 * crypto/pow.js — Proof-of-Work solver (mirrors backend core/crypto/pow.py)
 *
 * PoW challenge: find nonce such that SHA-256(commitment + nonce) starts with
 * POW_DIFFICULTY leading zero hex digits.
 *
 * Backend default: POW_DIFFICULTY = 6  (must match server config)
 */

import { sha256 } from "./identity";

export const POW_DIFFICULTY = 6;

/**
 * Solve PoW for a given commitment.
 * Returns nonce string that satisfies SHA-256(commitment+nonce).startsWith("000000")
 *
 * @param {string} commitment - hex commitment string
 * @param {number} difficulty - number of leading zero hex digits required
 * @param {function} onProgress - optional callback(nonce) called every 500 iterations
 * @returns {Promise<string>} nonce as string
 */
export async function solvePoW(commitment, difficulty = POW_DIFFICULTY, onProgress = null) {
  let nonce = 0;
  const prefix = "0".repeat(difficulty);

  while (true) {
    const hash = await sha256(commitment + nonce);
    if (hash.startsWith(prefix)) {
      return nonce.toString();
    }
    nonce++;

    // Yield to UI every 500 iterations to avoid blocking
    if (nonce % 500 === 0) {
      if (onProgress) onProgress(nonce);
      await new Promise((r) => setTimeout(r, 0));
    }
  }
}
