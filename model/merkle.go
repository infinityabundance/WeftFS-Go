package model

import "github.com/infinityabundance/WeftCodec-Go/hash"

// Merkle content identity (`WEFT-MODEL.md` §2.3.2).
//
// These constructors are the Go reference for `weft.manifest.v3`. They are
// byte-for-byte identical to the Rust `identity::merkle_*` functions: the
// domain-separated hash is `BLAKE3(u32le(|domain|) || domain || data)` and the
// preimages are fixed-width little-endian fields.
const (
	// DomainMerkleLeaf is the per-chunk leaf domain.
	DomainMerkleLeaf = "weft/merkle/leaf/v1"
	// DomainMerkleNode is the internal-node domain.
	DomainMerkleNode = "weft/merkle/node/v1"
	// DomainMerkleEmpty is the empty-tree domain.
	DomainMerkleEmpty = "weft/merkle/empty/v1"
)

// MerkleLeaf returns H("weft/merkle/leaf/v1", u64le(chunkLen) || chunkHash).
func MerkleLeaf(chunkLen uint64, chunkHash Hash32) Hash32 {
	preimage := make([]byte, 40)
	putU64LE(preimage[0:8], chunkLen)
	copy(preimage[8:], chunkHash[:])
	return hash.Domain(DomainMerkleLeaf, preimage)
}

// MerkleNode returns H("weft/merkle/node/v1", left || right).
func MerkleNode(left, right Hash32) Hash32 {
	preimage := make([]byte, 64)
	copy(preimage[0:32], left[:])
	copy(preimage[32:], right[:])
	return hash.Domain(DomainMerkleNode, preimage)
}

// MerkleEmptyRoot returns H("weft/merkle/empty/v1", empty).
func MerkleEmptyRoot() Hash32 {
	return hash.Domain(DomainMerkleEmpty, nil)
}

// MerkleRootChunks folds the chunk table into a root.
//
// An odd trailing node at any level is promoted unchanged; it is never
// duplicated. The chunk size and the final chunk length are part of each leaf
// preimage, so the root is deliberately chunk-size dependent and the chunk size
// is recorded in the manifest.
func MerkleRootChunks(chunks []ChunkRef) Hash32 {
	if len(chunks) == 0 {
		return MerkleEmptyRoot()
	}
	level := make([]Hash32, len(chunks))
	for i, chunk := range chunks {
		level[i] = MerkleLeaf(chunk.Len, chunk.Hash)
	}
	for len(level) > 1 {
		next := make([]Hash32, 0, (len(level)+1)/2)
		i := 0
		for i+1 < len(level) {
			next = append(next, MerkleNode(level[i], level[i+1]))
			i += 2
		}
		if i < len(level) {
			next = append(next, level[i])
		}
		level = next
	}
	return level[0]
}

func putU64LE(dst []byte, value uint64) {
	for i := 0; i < 8; i++ {
		dst[i] = byte(value >> (8 * uint(i)))
	}
}
