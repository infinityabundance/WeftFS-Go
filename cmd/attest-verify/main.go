// Command attest-verify verifies a signed `weft.load-attestation.v1` record.
//
// It is a deliberately independent implementation of the verification an
// operator needs before believing a load receipt:
//
//  1. the record must be canonical WCB (decode -> re-encode must be identical);
//  2. the schema, key sets and value types must be exactly the v1 shape;
//  3. the Ed25519 signature must verify over the canonical bytes of the record
//     with the `signature` key removed (the same construction Rust uses);
//  4. a trust set, when supplied, must contain the signing key.
//
// What it cannot do is re-read tensor bytes: this repository has no
// `weft.checkpoint.v1` reader, so byte-level replay stays in Rust. The command
// says so in its output rather than implying more.
//
// Usage:
//
//	attest-verify <receipt.wcb> [--trust HEX[,HEX...]] [--require-signature]
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
)

const schema = "weft.load-attestation.v1"

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "attest-verify: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: attest-verify <receipt.wcb> [--trust HEX[,HEX...]] [--require-signature]")
	}
	path := os.Args[1]
	var trust []string
	requireSignature := false
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--trust":
			if i+1 >= len(os.Args) {
				fail("--trust needs a value")
			}
			trust = strings.Split(os.Args[i+1], ",")
			i++
		case "--require-signature":
			requireSignature = true
		default:
			fail("unknown argument %q", os.Args[i])
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		fail("read %s: %v", path, err)
	}
	value, err := wcb.DecodeDefault(raw)
	if err != nil {
		fail("decode: %v", err)
	}
	canonical, err := wcb.EncodeDefault(value)
	if err != nil {
		fail("re-encode: %v", err)
	}
	if string(canonical) != string(raw) {
		fail("record is not canonical WCB (%d bytes in, %d bytes out)", len(raw), len(canonical))
	}
	record, ok := mapOf(value)
	if !ok {
		fail("record is not a map")
	}
	if got := text(record, "schema"); got != schema {
		fail("schema %q is not %q", got, schema)
	}
	if err := checkKeys(record, []string{
		"schema", "checkpoint", "checkpoint_root", "manifest_root", "snapshot",
		"replica", "verifier", "issued_at", "tensors", "totals",
		"load_receipt_root", "signature",
	}); err != nil {
		fail("record keys: %v", err)
	}
	verifier, ok := mapOf(record["verifier"])
	if !ok {
		fail("verifier is not a map")
	}
	if err := checkKeys(verifier, []string{"principal", "public_key"}); err != nil {
		fail("verifier keys: %v", err)
	}
	verifierKey, err := hashBytes(verifier["public_key"])
	if err != nil {
		fail("verifier.public_key: %v", err)
	}

	// Recompute the signing bytes: the record without its `signature` key.
	unsigned := make(map[string]wcb.Value, len(record))
	for key, v := range record {
		if key == "signature" {
			continue
		}
		unsigned[key] = v
	}
	signingBytes, err := wcb.EncodeDefault(wcb.MapValue(unsigned))
	if err != nil {
		fail("encode signing bytes: %v", err)
	}

	signatureValue, present := record["signature"]
	signed := false
	if present && signatureValue.Kind != wcb.Null {
		sigMap, ok := mapOf(signatureValue)
		if !ok {
			fail("signature is not a map")
		}
		if err := checkKeys(sigMap, []string{"algorithm", "public_key", "signature"}); err != nil {
			fail("signature keys: %v", err)
		}
		if got := text(sigMap, "algorithm"); got != "ed25519" {
			fail("signature algorithm %q is not ed25519", got)
		}
		publicKey, err := hashBytes(sigMap["public_key"])
		if err != nil {
			fail("signature.public_key: %v", err)
		}
		sigBytes, err := hashBytes(sigMap["signature"])
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			fail("signature is not %d bytes", ed25519.SignatureSize)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			fail("signature public key is not %d bytes", ed25519.PublicKeySize)
		}
		if hex.EncodeToString(publicKey) != hex.EncodeToString(verifierKey) {
			fail("signature key does not match the verifier identity")
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), signingBytes, sigBytes) {
			fail("Ed25519 signature does not verify")
		}
		signed = true
		if len(trust) > 0 {
			trusted := false
			for _, candidate := range trust {
				if strings.EqualFold(strings.TrimSpace(candidate), hex.EncodeToString(publicKey)) {
					trusted = true
					break
				}
			}
			if !trusted {
				fail("signing key is not in the trust set")
			}
		}
	}
	if !signed && requireSignature {
		fail("record is unsigned and --require-signature was given")
	}

	tensors, ok := arrayOf(record["tensors"])
	if !ok {
		fail("tensors is not an array")
	}
	loaded, unverified, ranges, groups := 0, 0, 0, 0
	previous := ""
	for _, item := range tensors {
		entry, ok := mapOf(item)
		if !ok {
			fail("tensor entry is not a map")
		}
		if err := checkKeys(entry, []string{
			"name", "dtype", "shape", "logical_root", "element_bytes", "status",
			"bytes_loaded", "ranges", "groups", "units_verified",
			"full_root_verified", "reason",
		}); err != nil {
			fail("tensor entry keys: %v", err)
		}
		name := text(entry, "name")
		if name <= previous {
			fail("tensor entries are not strictly sorted by name (%q after %q)", name, previous)
		}
		previous = name
		switch text(entry, "status") {
		case "loaded":
			loaded++
			entryRanges, ok := arrayOf(entry["ranges"])
			if !ok || len(entryRanges) == 0 {
				fail("loaded tensor %q has no ranges", name)
			}
			entryGroups, ok := arrayOf(entry["groups"])
			if !ok || len(entryGroups) == 0 {
				fail("loaded tensor %q has no groups", name)
			}
			ranges += len(entryRanges)
			groups += len(entryGroups)
		case "unverified":
			unverified++
			if entry["reason"].Kind == wcb.Null {
				fail("unverified tensor %q has no reason", name)
			}
		default:
			fail("tensor %q has status %q", name, text(entry, "status"))
		}
	}
	if _, ok := mapOf(record["totals"]); !ok {
		fail("totals is not a map")
	}

	fmt.Printf("schema=%s\n", schema)
	fmt.Printf("checkpoint=%s\n", text(record, "checkpoint"))
	fmt.Printf("checkpoint_root=%s\n", hexOf(record, "checkpoint_root"))
	fmt.Printf("manifest_root=%s\n", hexOf(record, "manifest_root"))
	fmt.Printf("verifier_principal=%s\n", text(verifier, "principal"))
	fmt.Printf("verifier_public_key=%s\n", hex.EncodeToString(verifierKey))
	fmt.Printf("signed=%t\n", signed)
	fmt.Printf("tensors=%d loaded=%d unverified=%d ranges=%d groups=%d\n",
		len(tensors), loaded, unverified, ranges, groups)
	fmt.Printf("byte_replay=not_performed (this repository has no weft.checkpoint.v1 reader)\n")
}
