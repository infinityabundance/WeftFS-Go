package store_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	retentionNow  int64 = 1_800_000_000_000_000_000
	retentionHour int64 = 3_600_000_000_000
)

func retentionStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Init(filepath.Join(t.TempDir(), "store"), func() store.Options {
		opts := store.DefaultOptions()
		opts.GCGraceSecs = 0
		return opts
	}())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func descriptorRoot(byteValue byte) model.Hash32 {
	var out [32]byte
	for i := range out {
		out[i] = byteValue
	}
	return model.Hash32(out)
}

type retentionArtifact struct {
	name     string
	artifact model.Hash32
	content  []byte
}

func writeArtifact(t *testing.T, s *store.Store, name string, payload []byte) retentionArtifact {
	t.Helper()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	id, err := s.CreateFile(root, []byte(name), payload, 0o644, 0, 0, nil)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		t.Fatalf("meta %s: %v", name, err)
	}
	return retentionArtifact{name: name, artifact: record.Content, content: payload}
}

func bindArtifact(t *testing.T, s *store.Store, descriptor model.Hash32, artifact retentionArtifact, class store.RetentionClass, lifetimeMS uint64, issuedAt int64) model.Hash32 {
	t.Helper()
	anchor := artifact.artifact
	issued := issuedAt
	id, err := s.SetRetention(store.RetentionRequest{
		DescriptorRoot:     descriptor,
		Class:              class,
		DeclaredLifetimeMS: lifetimeMS,
		Producer:           "go-court",
		PolicyEpoch:        1,
		IssuedAtNS:         &issued,
		Artifact:           &anchor,
	})
	if err != nil {
		t.Fatalf("set retention: %v", err)
	}
	return id
}

func artifactPresent(t *testing.T, s *store.Store, artifact retentionArtifact) bool {
	t.Helper()
	bytes, err := s.ReadContent(artifact.artifact, 0, uint64(len(artifact.content)))
	if err != nil {
		return false
	}
	return string(bytes) == string(artifact.content)
}

func TestRetentionBindingRoundTripsAndHashesCanonically(t *testing.T) {
	binding, err := store.NewRetentionBinding(
		descriptorRoot(0x11), store.RetentionVolatile, 180_000, "run-1", 3, retentionNow, nil,
	)
	if err != nil {
		t.Fatalf("new binding: %v", err)
	}
	bytes, err := binding.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := store.DecodeRetentionBinding(bytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reencoded, err := decoded.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if string(reencoded) != string(bytes) {
		t.Fatal("re-encode changed the canonical bytes")
	}
	id, err := binding.ID()
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	decomputed, err := decoded.ID()
	if err != nil {
		t.Fatalf("decoded id: %v", err)
	}
	if id != decomputed {
		t.Fatal("decoded binding has a different id")
	}
	t.Logf("COURT binding=%s bytes=%d", id.Hex(), len(bytes))
}

func TestRetentionSignatureVerifiesAndTamperingFails(t *testing.T) {
	binding, err := store.NewRetentionBinding(
		descriptorRoot(0x12), store.RetentionSession, 3_600_000, "signed-run", 1, retentionNow, nil,
	)
	if err != nil {
		t.Fatalf("new binding: %v", err)
	}
	seed := [32]byte{9}
	if err := binding.Sign(seed); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := binding.VerifySignature(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	binding.Producer = "tampered"
	if err := binding.VerifySignature(); err == nil {
		t.Fatal("tampered binding verified")
	}
}

func TestRetentionRefusesDurableWithoutRoot(t *testing.T) {
	s := retentionStore(t)
	artifact := writeArtifact(t, s, "durable", []byte("durable-bytes"))
	anchor := artifact.artifact
	_, err := s.SetRetention(store.RetentionRequest{
		DescriptorRoot: descriptorRoot(0x21),
		Class:          store.RetentionDurable,
		Producer:       "go-court",
		IssuedAtNS:     ptrInt64(retentionNow),
		Artifact:       &anchor,
	})
	if err == nil || werr.ClassOf(err) != werr.InvalidArgument {
		t.Fatalf("durable without root: %v", err)
	}
	if _, err := s.SnapshotCreate("keep"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	id, err := s.SetRetention(store.RetentionRequest{
		DescriptorRoot: descriptorRoot(0x21),
		Class:          store.RetentionDurable,
		Producer:       "go-court",
		IssuedAtNS:     ptrInt64(retentionNow),
		Artifact:       &anchor,
	})
	if err != nil {
		t.Fatalf("durable with snapshot: %v", err)
	}
	binding, err := s.RetentionBindingByID(id)
	if err != nil {
		t.Fatalf("read binding: %v", err)
	}
	if binding.Class != store.RetentionDurable || binding.DeclaredLifetimeMS != 0 {
		t.Fatalf("durable binding = %+v", binding)
	}
}

func TestClassAwareGCNeverReclaimsReachable(t *testing.T) {
	s := retentionStore(t)
	kept := writeArtifact(t, s, "kept", []byte("kept-bytes"))
	bindArtifact(t, s, descriptorRoot(0x31), kept, store.RetentionVolatile, 1_000, retentionNow-2*retentionHour)
	if _, err := s.SnapshotCreate("keep"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := s.Unlink(mustRoot(t, s), []byte("kept")); err != nil {
		t.Fatalf("unlink kept: %v", err)
	}

	dropped := writeArtifact(t, s, "dropped", []byte("dropped-bytes"))
	bindArtifact(t, s, descriptorRoot(0x32), dropped, store.RetentionVolatile, 1_000, retentionNow-2*retentionHour)
	if err := s.Unlink(mustRoot(t, s), []byte("dropped")); err != nil {
		t.Fatalf("unlink dropped: %v", err)
	}

	plan, err := s.GCPlan(retentionNow, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, candidate := range plan.Candidates {
		if candidate.Path == "" {
			t.Fatalf("empty candidate path")
		}
	}
	reasons := ""
	for _, retained := range plan.Retained {
		if retained.DescriptorRoot == descriptorRoot(0x31) {
			reasons = retained.Reason
		}
	}
	if reasons == "" || !strings.HasPrefix(reasons, "reachable from ") {
		t.Fatalf("retained reason for the reachable artifact = %q", reasons)
	}
	applied, err := s.RetentionGC(true, retentionNow, nil)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied.ReclaimedBlobs == 0 {
		t.Fatal("nothing was reclaimed")
	}
	if !artifactPresent(t, s, kept) {
		t.Fatal("reachable artifact was reclaimed")
	}
	if artifactPresent(t, s, dropped) {
		t.Fatal("unreachable artifact was not reclaimed")
	}
	t.Logf("COURT reclaimed_blobs=%d retained=%d reason=%q", applied.ReclaimedBlobs, len(plan.Retained), reasons)
}

func TestExpiredVolatileIsOrderedBeforeExpiredEphemeral(t *testing.T) {
	s := retentionStore(t)
	volatile := writeArtifact(t, s, "volatile", []byte("volatile-bytes"))
	ephemeral := writeArtifact(t, s, "ephemeral", []byte("ephemeral-bytes"))
	bindArtifact(t, s, descriptorRoot(0x41), volatile, store.RetentionVolatile, 1_000, retentionNow-2*retentionHour)
	bindArtifact(t, s, descriptorRoot(0x42), ephemeral, store.RetentionEphemeral, 60_000, retentionNow-2*retentionHour)
	if err := s.Unlink(mustRoot(t, s), []byte("volatile")); err != nil {
		t.Fatalf("unlink volatile: %v", err)
	}
	if err := s.Unlink(mustRoot(t, s), []byte("ephemeral")); err != nil {
		t.Fatalf("unlink ephemeral: %v", err)
	}
	zero := uint64(0)
	plan, err := s.GCPlan(retentionNow, &zero)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Candidates) == 0 {
		t.Fatal("no candidates")
	}
	if plan.Candidates[0].Class != "volatile" {
		t.Fatalf("first candidate class = %s", plan.Candidates[0].Class)
	}
	if plan.PlannedBlobs != 1 {
		t.Fatalf("a zero budget must still make progress, got %d", plan.PlannedBlobs)
	}
}

func TestLiveBindingRetainsUnreachableBytes(t *testing.T) {
	s := retentionStore(t)
	artifact := writeArtifact(t, s, "live", []byte("live-bytes"))
	bindArtifact(t, s, descriptorRoot(0x51), artifact, store.RetentionEphemeral, 6*3_600_000, retentionNow-60_000)
	if err := s.Unlink(mustRoot(t, s), []byte("live")); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	plan, err := s.GCPlan(retentionNow, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Candidates) != 0 {
		t.Fatalf("live binding produced %d candidates", len(plan.Candidates))
	}
	if !artifactPresent(t, s, artifact) {
		t.Fatal("live binding did not retain its bytes")
	}
	later := retentionNow + 7*retentionHour
	plan, err = s.GCPlan(later, nil)
	if err != nil {
		t.Fatalf("later plan: %v", err)
	}
	if len(plan.Candidates) == 0 {
		t.Fatal("an expired binding must become reclaimable")
	}
}

func TestRebindingForksOnlyTheBindingIdentity(t *testing.T) {
	s := retentionStore(t)
	artifact := writeArtifact(t, s, "rebind", []byte("rebind-bytes"))
	descriptor := descriptorRoot(0x61)
	first := bindArtifact(t, s, descriptor, artifact, store.RetentionVolatile, 180_000, retentionNow)

	anchor := artifact.artifact
	issued := retentionNow
	second, err := s.SetRetention(store.RetentionRequest{
		DescriptorRoot:     descriptor,
		Class:              store.RetentionEphemeral,
		DeclaredLifetimeMS: 21_600_000,
		Producer:           "go-court",
		PolicyEpoch:        2,
		IssuedAtNS:         &issued,
		Artifact:           &anchor,
	})
	if err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if first == second {
		t.Fatal("rebind did not fork the retention identity")
	}
	history, err := s.RetentionHistory(descriptor, 8)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 2 || history[0].ID != second || history[1].ID != first {
		t.Fatalf("history = %+v", history)
	}
	if history[0].Binding.Supersedes == nil || *history[0].Binding.Supersedes != first {
		t.Fatal("supersedes does not point at the previous binding")
	}
	if history[1].Binding.Supersedes != nil {
		t.Fatal("first binding has a supersedes value")
	}
	if !artifactPresent(t, s, artifact) {
		t.Fatal("rebinding changed the artifact")
	}
	if record, err := s.ObjectMeta(mustLookup(t, s, "rebind")); err != nil || record.Content != artifact.artifact {
		t.Fatalf("artifact content changed: %v", err)
	}
}

func mustRoot(t *testing.T, s *store.Store) model.Hash32 {
	t.Helper()
	root, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	return root
}

func mustLookup(t *testing.T, s *store.Store, name string) model.Hash32 {
	t.Helper()
	id, err := s.Lookup(mustRoot(t, s), []byte(name))
	if err != nil {
		t.Fatalf("lookup %s: %v", name, err)
	}
	return id
}

func ptrInt64(value int64) *int64 { return &value }
