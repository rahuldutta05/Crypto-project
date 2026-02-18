/**
 * crypto/merkle.js — Client-side Merkle proof verification
 *
 * Mirrors the verification algorithm documented in backend api/verify.py:
 *
 *   current = leaf_hash
 *   for step in proof_path:
 *     if step.position == "left":
 *       current = SHA256(step.sibling + current)
 *     else:
 *       current = SHA256(current + step.sibling)
 *   assert current == merkle_root
 */

import { sha256 } from "./identity";

/**
 * Verify a Merkle inclusion proof returned by GET /verify/proof/<msg_id>
 *
 * @param {string} leafHash    - the leaf hash (from proof response)
 * @param {Array}  proofPath   - array of { sibling, position } steps
 * @param {string} merkleRoot  - expected root
 * @returns {Promise<boolean>}
 */
export async function verifyMerkleProof(leafHash, proofPath, merkleRoot) {
  let current = leafHash;

  for (const step of proofPath) {
    if (step.position === "left") {
      current = await sha256(step.sibling + current);
    } else {
      current = await sha256(current + step.sibling);
    }
  }

  return current === merkleRoot;
}
