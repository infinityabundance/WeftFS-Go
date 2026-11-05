package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/store"
)

func resetRepresentationPolicy(t *testing.T) {
	t.Helper()
	previousMode := representationMode
	previousMin := codecMinBytes
	t.Cleanup(func() {
		representationMode = previousMode
		codecMinBytes = previousMin
	})
	representationMode = store.RepresentationModeRaw
	codecMinBytes = store.DefaultCodecMinBytes
}

func TestGlobalsRepresentationPolicy(t *testing.T) {
	resetRepresentationPolicy(t)

	rest, dir, jsonOut, err := globals([]string{
		"--store", "/tmp/store", "--representation", "codec-auto",
		"--codec-min-bytes", "8192", "info",
	})
	if err != nil {
		t.Fatalf("globals: %v", err)
	}
	if dir != "/tmp/store" || jsonOut || len(rest) != 1 || rest[0] != "info" {
		t.Fatalf("globals rest=%v dir=%s json=%v", rest, dir, jsonOut)
	}
	if representationMode != store.RepresentationModeCodecAuto || codecMinBytes != 8192 {
		t.Fatalf("policy not applied: %s/%d", representationMode, codecMinBytes)
	}

	if _, _, _, err := globals([]string{"--representation", "bogus", "cat", "/x"}); err == nil {
		t.Fatal("invalid --representation was accepted")
	}
	if _, _, _, err := globals([]string{"--codec-min-bytes", "not-a-number", "cat", "/x"}); err == nil {
		t.Fatal("invalid --codec-min-bytes was accepted")
	}
	if _, _, _, err := globals([]string{"--representation=raw", "--codec-min-bytes=0", "cat", "/x"}); err != nil {
		t.Fatalf("valid policy form rejected: %v", err)
	}
	if representationMode != store.RepresentationModeRaw || codecMinBytes != 0 {
		t.Fatalf("equals-form policy not applied: %s/%d", representationMode, codecMinBytes)
	}
}

func TestGlobalsQuotaPolicy(t *testing.T) {
	previous := quotaBudgets
	t.Cleanup(func() { quotaBudgets = previous })
	quotaBudgets = nil
	rest, _, _, err := globals([]string{
		"--store", "/tmp/store", "--quota", "0:0:1024:10",
		"--quota", "tenant:acme:2048:20", "snapshot", "branch", "s1", "b1",
	})
	if err != nil {
		t.Fatalf("globals: %v", err)
	}
	if len(rest) != 4 || rest[0] != "snapshot" {
		t.Fatalf("rest = %v", rest)
	}
	if len(quotaBudgets) != 2 {
		t.Fatalf("budgets = %d", len(quotaBudgets))
	}
	if quotaBudgets[0].Principal != store.PosixPrincipal(0, 0) || quotaBudgets[0].MaxNewBytes != 1024 {
		t.Fatalf("posix budget = %+v", quotaBudgets[0])
	}
	if quotaBudgets[1].Principal != store.TenantPrincipal("acme") {
		t.Fatalf("tenant budget = %+v", quotaBudgets[1])
	}
	if _, _, _, err := globals([]string{"--quota", "nonsense", "info"}); err == nil {
		t.Fatal("invalid --quota was accepted")
	}
}

func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = writer
	runErr := fn()
	_ = writer.Close()
	os.Stdout = previous
	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if runErr != nil {
		t.Fatalf("command: %v", runErr)
	}
	if readErr != nil {
		t.Fatalf("read captured stdout: %v", readErr)
	}
	return string(output)
}

func cliSmoothBf16(elements int) []byte {
	out := make([]byte, 0, elements*2)
	state := uint64(0x11)
	for index := 0; index < elements; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		low := (uint16(index) * 37) & 0x3ff
		word := uint16(0x3f00|low) ^ (uint16(state) & 0x3f)
		out = append(out, byte(word), byte(word>>8))
	}
	return out
}

func TestTensorCLIWriteLogicalRootAndRegion(t *testing.T) {
	resetRepresentationPolicy(t)
	representationMode = store.RepresentationModeCodecAuto
	dir := t.TempDir()
	if err := run("init", nil, dir, false); err != nil {
		t.Fatalf("init: %v", err)
	}
	payload := cliSmoothBf16(64)
	payloadPath := t.TempDir() + "/tensor.bin"
	if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if err := run("write", []string{"/t.bin", "--tensor", "--dtype", "bf16",
		"--shape", "8,8", "--file", payloadPath}, dir, false); err != nil {
		t.Fatalf("write --tensor: %v", err)
	}

	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	id, err := s.ResolvePath("/t.bin")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	root, err := s.TensorLogicalRoot(id)
	if err != nil {
		t.Fatalf("logical root: %v", err)
	}
	_ = s.Close()

	output := captureStdout(t, func() error {
		return run("tensor", []string{"logical-root", "/t.bin"}, dir, false)
	})
	if output != root.Hex()+"\n" {
		t.Fatalf("tensor logical-root output = %q, want %q", output, root.Hex())
	}

	metaOutput := captureStdout(t, func() error {
		return run("tensor", []string{"meta", "/t.bin"}, dir, true)
	})
	var meta map[string]any
	if err := json.Unmarshal([]byte(metaOutput), &meta); err != nil {
		t.Fatalf("tensor meta JSON: %v\n%s", err, metaOutput)
	}
	if meta["dtype"] != "bf16" || meta["logical_root"] != root.Hex() {
		t.Fatalf("tensor meta = %+v", meta)
	}

	region := captureStdout(t, func() error {
		return run("cat", []string{"/t.bin", "--region", "0,0:2,8"}, dir, false)
	})
	if !bytes.Equal([]byte(region), payload[:2*8*2]) {
		t.Fatal("cat --region returned the wrong bytes")
	}
}

func TestInfoJSONReportsRepresentationPolicy(t *testing.T) {
	resetRepresentationPolicy(t)
	representationMode = store.RepresentationModeCodecAuto
	codecMinBytes = 8192
	dir := t.TempDir()
	if err := run("init", nil, dir, false); err != nil {
		t.Fatalf("init: %v", err)
	}
	payloadPath := t.TempDir() + "/payload.txt"
	payload := ""
	for len(payload) < 16*1024 {
		payload += "WeftFS CLI representation policy. "
	}
	if err := os.WriteFile(payloadPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if err := run("create", []string{"/big.txt", "--file", payloadPath}, dir, false); err != nil {
		t.Fatalf("create: %v", err)
	}
	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	id, err := s.ResolvePath("/big.txt")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	manifest, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.Representation == nil || manifest.Representation.Kind != "codec" {
		t.Fatalf("CLI codec-auto did not write a v2 codec representation: %+v", manifest.Representation)
	}
	_ = s.Close()
	output := captureStdout(t, func() error {
		return run("info", nil, dir, true)
	})
	var parsed map[string]any
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("info JSON: %v\n%s", err, output)
	}
	if parsed["representation"] != "codec-auto" {
		t.Fatalf("info representation = %v", parsed["representation"])
	}
	if parsed["codec_min_bytes"] != float64(8192) {
		t.Fatalf("info codec_min_bytes = %v", parsed["codec_min_bytes"])
	}
}
