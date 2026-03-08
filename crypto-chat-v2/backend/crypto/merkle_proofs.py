"""
Merkle Proof Trees — "The Witness Protocol"
Every message is a leaf in a Merkle tree. Publish only the root hash (32 bytes).
Prove any single message existed at time T with a tiny Merkle path — without revealing others.
How Bitcoin transaction proofs work.
"""
from .hash_utils import hash_data


def _hash_pair(left, right):
    """Hash two nodes in order (left < right for determinism)."""
    if left < right:
        combined = left + right
    else:
        combined = right + left
    return hash_data(combined)


def build_merkle_tree(leaf_hashes):
    """
    Build full Merkle tree from leaf hashes.
    Returns (root_hash, tree_layers). tree_layers[0] = leaves, tree_layers[-1] = [root].
    """
    if not leaf_hashes:
        return None, []
    leaves = list(leaf_hashes)
    if len(leaves) == 1:
        return leaves[0], [leaves]
    layers = [leaves]
    while len(layers[-1]) > 1:
        level = layers[-1]
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                next_level.append(_hash_pair(level[i], level[i + 1]))
            else:
                next_level.append(_hash_pair(level[i], level[i]))
        layers.append(next_level)
    return layers[-1][0], layers


def get_merkle_path(leaf_index, tree_layers):
    """
    Get the Merkle path (sibling hashes and positions) for a leaf at leaf_index.
    Returns list of (sibling_hash, is_right) where is_right means sibling is on the right.
    """
    if not tree_layers or leaf_index >= len(tree_layers[0]):
        return []
    path = []
    idx = leaf_index
    for layer in tree_layers[:-1]:
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        if sibling_idx < len(layer):
            path.append((layer[sibling_idx], sibling_idx > idx))
        idx = idx // 2
    return path


def verify_merkle_path(leaf_hash, path, root_hash):
    """
    Verify that leaf_hash is in the tree with given root by recomputing from path.
    path = list of (sibling_hash, is_right). Returns True if valid.
    """
    current = leaf_hash
    for sibling_hash, is_right in path:
        if is_right:
            current = _hash_pair(current, sibling_hash)
        else:
            current = _hash_pair(sibling_hash, current)
    return current == root_hash


def create_merkle_proof(leaf_hashes, leaf_index):
    """
    One-shot: from list of leaf hashes and an index, return (root_hash, path)
    so that anyone can verify leaf_hashes[leaf_index] existed in the tree.
    """
    root, layers = build_merkle_tree(leaf_hashes)
    path = get_merkle_path(leaf_index, layers)
    leaf_hash = leaf_hashes[leaf_index]
    return {
        'root_hash': root,
        'leaf_index': leaf_index,
        'leaf_hash': leaf_hash,
        'path': path,
        'tree_size': len(leaf_hashes),
    }


def verify_merkle_proof(proof):
    """Verify a proof dict from create_merkle_proof."""
    return verify_merkle_path(
        proof['leaf_hash'],
        proof['path'],
        proof['root_hash'],
    )
