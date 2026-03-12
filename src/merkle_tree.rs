#![allow(dead_code)]
use {
    super::Error, solana_hash::Hash, solana_sha256_hasher::hashv,
    static_assertions::const_assert_eq, std::iter::successors,
};

pub(crate) const SIZE_OF_MERKLE_ROOT: usize = std::mem::size_of::<Hash>();
const_assert_eq!(SIZE_OF_MERKLE_ROOT, 32);
const_assert_eq!(SIZE_OF_MERKLE_PROOF_ENTRY, 20);
pub(crate) const SIZE_OF_MERKLE_PROOF_ENTRY: usize = std::mem::size_of::<MerkleProofEntry>();
// Number of proof entries for the standard 64 shred batch.
pub const PROOF_ENTRIES_FOR_32_32_BATCH: u8 = 6;

// Defense against second preimage attack:
pub(crate) const MERKLE_HASH_PREFIX_LEAF: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
pub(crate) const MERKLE_HASH_PREFIX_NODE: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

pub(crate) type MerkleProofEntry = [u8; 20];

/// A struct to track a given Merkle tree.
pub(crate) struct MerkleTree {
    nodes: Vec<Hash>,
}

impl MerkleTree {
    pub(crate) fn try_new(
        shreds: impl ExactSizeIterator<Item = Result<Hash, Error>>,
    ) -> Result<MerkleTree, Error> {
        if shreds.len() == 0 {
            return Err(Error::EmptyIterator);
        }
        let num_shreds = shreds.len();
        let capacity = get_merkle_tree_size(num_shreds);
        let mut nodes = Vec::with_capacity(capacity);
        for shred in shreds {
            nodes.push(shred?);
        }
        let init = (num_shreds > 1).then_some(num_shreds);
        for size in successors(init, |&k| (k > 2).then_some((k + 1) >> 1)) {
            let offset = nodes.len() - size;
            for index in (offset..offset + size).step_by(2) {
                let node = &nodes[index];
                let other = &nodes[(index + 1).min(offset + size - 1)];
                let parent = join_nodes(node, other);
                nodes.push(parent);
            }
        }
        debug_assert_eq!(nodes.len(), capacity);
        Ok(MerkleTree { nodes })
    }

    pub(crate) fn root(&self) -> &Hash {
        self.nodes.last().unwrap()
    }

    pub(crate) fn make_merkle_proof(
        &self,
        mut index: usize,
        mut size: usize,
    ) -> impl Iterator<Item = Result<&MerkleProofEntry, Error>> {
        let mut offset = 0;
        if index >= size {
            (size, offset) = (0, self.nodes.len());
        }
        std::iter::from_fn(move || {
            if size > 1 {
                let Some(node) = self.nodes.get(offset + (index ^ 1).min(size - 1)) else {
                    return Some(Err(Error::InvalidMerkleProof));
                };
                offset += size;
                size = (size + 1) >> 1;
                index >>= 1;
                let entry = &node.as_ref()[..SIZE_OF_MERKLE_PROOF_ENTRY];
                let entry = <&MerkleProofEntry>::try_from(entry).unwrap();
                Some(Ok(entry))
            } else if offset + 1 == self.nodes.len() {
                None
            } else {
                Some(Err(Error::InvalidMerkleProof))
            }
        })
    }
}

fn join_nodes<S: AsRef<[u8]>, T: AsRef<[u8]>>(node: S, other: T) -> Hash {
    let node = &node.as_ref()[..SIZE_OF_MERKLE_PROOF_ENTRY];
    let other = &other.as_ref()[..SIZE_OF_MERKLE_PROOF_ENTRY];
    hashv(&[MERKLE_HASH_PREFIX_NODE, node, other])
}

pub fn get_merkle_root<'a, I>(index: usize, node: Hash, proof: I) -> Result<Hash, Error>
where
    I: IntoIterator<Item = &'a MerkleProofEntry>,
{
    let (index, root) = proof
        .into_iter()
        .fold((index, node), |(index, node), other| {
            let parent = if index % 2 == 0 {
                join_nodes(node, other)
            } else {
                join_nodes(other, node)
            };
            (index >> 1, parent)
        });
    (index == 0)
        .then_some(root)
        .ok_or(Error::InvalidMerkleProof)
}

pub fn get_merkle_tree_size(num_shreds: usize) -> usize {
    successors(Some(num_shreds), |&k| (k > 1).then_some((k + 1) >> 1)).sum()
}
