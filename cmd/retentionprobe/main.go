// Command retentionprobe is the Go side of the R6 cross-language parity court.
// It is a test/court probe, not a product surface.
//
//	go run ./cmd/retentionprobe write-file  PATH
//	go run ./cmd/retentionprobe read-file   PATH
//	go run ./cmd/retentionprobe read-store  DIR DESCRIPTOR_HEX
//	go run ./cmd/retentionprobe rebind-store DIR DESCRIPTOR_HEX
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/store"
)

const issuedAtNS int64 = 1_800_000_000_000_000_000

func descriptor() hash.Hash32 {
	var bytes [32]byte
	for i := range bytes {
		bytes[i] = 0x42
	}
	return hash.FromBytes(bytes)
}

func probeBinding() (*store.RetentionBinding, error) {
	return store.NewRetentionBinding(
		descriptor(), store.RetentionVolatile, 180_000, "cross-rust", 1, issuedAtNS, nil,
	)
}

func report(binding *store.RetentionBinding) error {
	bytes, err := binding.Encode()
	if err != nil {
		return err
	}
	id, err := binding.ID()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(bytes)
	fmt.Printf("descriptor_root=%s\n", binding.DescriptorRoot.Hex())
	fmt.Printf("binding=%s\n", id.Hex())
	fmt.Printf("binding_sha256=%s\n", hex.EncodeToString(digest[:]))
	fmt.Printf("binding_bytes=%d\n", len(bytes))
	fmt.Printf("class=%s\n", binding.Class)
	fmt.Printf("producer=%s\n", binding.Producer)
	fmt.Printf("policy_epoch=%d\n", binding.PolicyEpoch)
	fmt.Printf("issued_at_ns=%d\n", binding.IssuedAtNS)
	fmt.Printf("canonical_hex=%s\n", hex.EncodeToString(bytes))
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "retentionprobe: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: retentionprobe write-file|read-file|read-store|rebind-store PATH [DESCRIPTOR_HEX]")
	}
	switch args[0] {
	case "write-file":
		binding, err := probeBinding()
		if err != nil {
			return err
		}
		bytes, err := binding.Encode()
		if err != nil {
			return err
		}
		if err := os.WriteFile(args[1], bytes, 0o644); err != nil {
			return err
		}
		return report(binding)
	case "read-file":
		bytes, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		binding, err := store.DecodeRetentionBinding(bytes)
		if err != nil {
			return err
		}
		reencoded, err := binding.Encode()
		if err != nil {
			return err
		}
		if string(reencoded) != string(bytes) {
			return fmt.Errorf("%s is not canonical retention bytes", args[1])
		}
		return report(binding)
	case "read-store":
		if len(args) < 3 {
			return fmt.Errorf("read-store needs DIR DESCRIPTOR_HEX")
		}
		root, err := hash.FromHex(args[2])
		if err != nil {
			return err
		}
		s, err := store.Open(args[1], store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		binding, err := s.RetentionOf(root)
		if err != nil {
			return err
		}
		if binding == nil {
			return fmt.Errorf("no retention binding for %s", args[2])
		}
		return report(binding)
	case "rebind-store":
		if len(args) < 3 {
			return fmt.Errorf("rebind-store needs DIR DESCRIPTOR_HEX")
		}
		root, err := hash.FromHex(args[2])
		if err != nil {
			return err
		}
		s, err := store.Open(args[1], store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		pointer, err := s.RetentionPointer(root)
		if err != nil {
			return err
		}
		if pointer == nil {
			return fmt.Errorf("no retention pointer for %s", args[2])
		}
		artifact := pointer.Artifact
		issued := issuedAtNS
		id, err := s.SetRetention(store.RetentionRequest{
			DescriptorRoot:     root,
			Class:              store.RetentionEphemeral,
			DeclaredLifetimeMS: 21_600_000,
			Producer:           "cross-go",
			PolicyEpoch:        2,
			IssuedAtNS:         &issued,
			Artifact:           &artifact,
		})
		if err != nil {
			return err
		}
		binding, err := s.RetentionBindingByID(id)
		if err != nil {
			return err
		}
		return report(binding)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
