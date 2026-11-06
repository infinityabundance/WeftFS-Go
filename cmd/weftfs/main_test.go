package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
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

func TestOverlayCompactCLIReportsUnchangedRoot(t *testing.T) {
	resetRepresentationPolicy(t)
	previousIdentity := contentIdentityMode
	previousExplicit := contentIdentityExplicit
	t.Cleanup(func() {
		contentIdentityMode = previousIdentity
		contentIdentityExplicit = previousExplicit
	})
	representationMode = store.RepresentationModeOverlay
	contentIdentityMode = model.ContentIdentityMerkleV1
	contentIdentityExplicit = true

	dir := t.TempDir()
	opts := store.DefaultOptions()
	opts.Representation = store.RepresentationModeOverlay
	opts.ContentIdentity = model.ContentIdentityMerkleV1
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	base := make([]byte, 8*1024)
	for i := range base {
		base[i] = byte(i % 251)
	}
	id, err := s.CreateFile(model.RootID, []byte("cli.bin"), base, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.WriteFile(id, 10, []byte("overlay-layer")); err != nil {
		t.Fatalf("write: %v", err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	before, err := store.ReadManifest(dir, record.Content)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if before.Representation == nil || before.Representation.Kind != model.RepresentationOverlay {
		t.Fatalf("setup is not an overlay representation")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	output := captureStdout(t, func() error {
		return run("compact", []string{"/cli.bin"}, dir, true)
	})
	var parsed map[string]any
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("compact JSON: %v\n%s", err, output)
	}
	if parsed["content_root"] != before.ContentHash.Hex() {
		t.Fatalf("compact reported content_root=%v, want %s", parsed["content_root"], before.ContentHash.Hex())
	}
	reader, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reader.Close()
	afterRecord, err := reader.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta after: %v", err)
	}
	after, err := store.ReadManifest(dir, afterRecord.Content)
	if err != nil {
		t.Fatalf("manifest after: %v", err)
	}
	if after.Representation != nil {
		t.Fatalf("compact left a representation: %+v", after.Representation)
	}
	if after.ContentHash != before.ContentHash {
		t.Fatalf("compact changed the content root")
	}
}

func resetPlanePolicy(t *testing.T) {
	t.Helper()
	previousBlob := blobBackend
	previousCommit := commitBackend
	previousRoot := blobRoot
	t.Cleanup(func() {
		blobBackend = previousBlob
		commitBackend = previousCommit
		blobRoot = previousRoot
	})
}

func TestGlobalsPlanePolicy(t *testing.T) {
	resetPlanePolicy(t)
	blobBackend = store.PlaneLocal
	commitBackend = store.PlaneLocal
	blobRoot = ""
	rest, dir, _, err := globals([]string{
		"--store", "/tmp/store",
		"--blob-backend", "object",
		"--commit-backend=local",
		"--blob-root", "/tmp/blobs",
		"info",
	})
	if err != nil {
		t.Fatalf("globals: %v", err)
	}
	if dir != "/tmp/store" || len(rest) != 1 || rest[0] != "info" {
		t.Fatalf("rest=%v dir=%s", rest, dir)
	}
	if blobBackend != store.PlaneObject || commitBackend != store.PlaneLocal || blobRoot != "/tmp/blobs" {
		t.Fatalf("plane policy not applied: %s/%s/%s", blobBackend, commitBackend, blobRoot)
	}
	opts := store.DefaultOptions()
	applyPlanePolicy(&opts)
	if opts.BlobBackend != store.PlaneObject || opts.CommitBackend != store.PlaneLocal || opts.BlobRoot != "/tmp/blobs" {
		t.Fatalf("options not routed: %+v", opts)
	}
	if _, _, _, err := globals([]string{"--blob-backend", "bogus", "info"}); err == nil {
		t.Fatal("invalid --blob-backend was accepted")
	}
}

func TestSplitCLIInfoReportsPlanes(t *testing.T) {
	resetPlanePolicy(t)
	dir := t.TempDir()
	blobDir := filepath.Join(t.TempDir(), "blobs")
	opts := store.DefaultOptions()
	opts.BlobBackend = store.PlaneObject
	opts.CommitBackend = store.PlaneLocal
	opts.BlobRoot = blobDir
	s, err := store.Init(dir, opts)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	s.Close()

	blobBackend = store.PlaneObject
	commitBackend = store.PlaneLocal
	blobRoot = blobDir
	output := captureStdout(t, func() error {
		return run("info", nil, dir, true)
	})
	var parsed map[string]any
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("info JSON: %v\n%s", err, output)
	}
	planes, ok := parsed["planes"].(map[string]any)
	if !ok {
		t.Fatalf("info JSON has no planes: %s", output)
	}
	blobs, _ := planes["blobs"].(map[string]any)
	commits, _ := planes["commits"].(map[string]any)
	if blobs["backend"] != "object" || commits["backend"] != "local" {
		t.Fatalf("planes report = %v", planes)
	}
	if planes["blob_root"] != blobDir || planes["commit_root"] != dir {
		t.Fatalf("plane roots = %v/%v", planes["blob_root"], planes["commit_root"])
	}
}

func TestPackCLIRoundTrip(t *testing.T) {
	resetPlanePolicy(t)
	previousPacking := packing
	previousTarget, previousMember := packTarget, packMember
	previousCatalog, previousSegments := packCatalog, packSegments
	t.Cleanup(func() {
		packing = previousPacking
		packTarget, packMember = previousTarget, previousMember
		packCatalog, packSegments = previousCatalog, previousSegments
	})
	packing = true
	packTarget = store.DefaultPackOptions().TargetBytes
	packMember = store.DefaultPackOptions().MemberThresholdBytes
	packCatalog = store.DefaultPackOptions().MaxCatalogBytes
	packSegments = store.DefaultPackOptions().CatalogSegments

	dir := t.TempDir()
	payloadPath := filepath.Join(t.TempDir(), "payload.bin")
	payload := make([]byte, 200000)
	for i := range payload {
		payload[i] = byte((i * 7) % 251)
	}
	if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if err := run("init", nil, dir, false); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := run("create", []string{"/packed.bin", "--file", payloadPath, "--seed", "cli-pack"}, dir, false); err != nil {
		t.Fatalf("create: %v", err)
	}
	output := captureStdout(t, func() error {
		return run("info", nil, dir, true)
	})
	var info map[string]any
	if err := json.Unmarshal([]byte(output), &info); err != nil {
		t.Fatalf("info: %v\n%s", err, output)
	}
	planes, _ := info["planes"].(map[string]any)
	if planes == nil || planes["packing"] != true {
		t.Fatalf("info planes does not report packing: %s", output)
	}
	packs, _ := info["packs"].(map[string]any)
	if packs == nil || packs["sealed_packs"].(float64) == 0 {
		t.Fatalf("info packs did not report sealed packs: %s", output)
	}
	if err := run("verify", []string{"--full"}, dir, false); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestCalibrationFlag(t *testing.T) {
	previousModel := plannerCostModel
	previousPath := calibrationPath
	previousRecord := calibration
	t.Cleanup(func() {
		plannerCostModel = previousModel
		calibrationPath = previousPath
		calibration = previousRecord
	})

	bin := rustBinaryCLI(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "calibration.json")
	runRustCLI(t, bin,
		"--store", filepath.Join(dir, "calibrate-store"),
		"calibrate", "--out", path,
		"--reps", "5", "--small-kib", "64", "--large-mib", "8", "--json",
	)

	plannerCostModel = store.DefaultCostModel
	calibrationPath = ""
	calibration = nil
	if _, _, _, err := globals([]string{
		"--planner-cost-model", "measured", "--calibration", path, "info",
	}); err != nil {
		t.Fatalf("valid calibration rejected: %v", err)
	}
	if calibration == nil {
		t.Fatal("--calibration did not load a calibration")
	}
	if table := activeCostTable(); table == nil {
		t.Fatal("active cost table is nil after loading")
	}

	// --calibration is only legal with the measured model.
	plannerCostModel = store.CostModelDeclared
	calibration = nil
	if _, _, _, err := globals([]string{
		"--planner-cost-model", "declared", "--calibration", path, "info",
	}); err == nil {
		t.Fatal("--calibration with the declared model was accepted")
	}

	// A missing file refuses the command.
	plannerCostModel = store.CostModelMeasured
	calibration = nil
	if _, _, _, err := globals([]string{
		"--planner-cost-model", "measured", "--calibration", filepath.Join(dir, "missing.json"), "info",
	}); err == nil {
		t.Fatal("a missing calibration file was accepted")
	}

	// A mutated document is refused, never replaced by the baked table.
	mutated := filepath.Join(dir, "mutated.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read calibration: %v", err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(mutated, raw, 0o644); err != nil {
		t.Fatalf("write mutated: %v", err)
	}
	calibration = nil
	if _, _, _, err := globals([]string{
		"--planner-cost-model", "measured", "--calibration", mutated, "info",
	}); err == nil {
		t.Fatal("a corrupted calibration document was accepted")
	}
}
