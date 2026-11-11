// Store-level parity court for provenance-bound KV pages (mode 19) and the
// plain mode-12 page, mirroring `tests/kv_provenance.rs` and the enforcement
// order of `docs/KV-CACHE-GOVERNANCE.md`.
//
// The claim is structural, not statistical: every pre-byte failure is the one
// denial text with class Unauthorized, a content id is not a credential, and a
// mode-19 page is refused by the mode-12 reader and vice versa.
package store_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/modes"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	kvNowNS     int64 = 1_700_000_000_000_000_000
	kvExpiresNS int64 = 2_000_000_000_000_000_000
	kvTenant          = "tenant-a"
)

// ---------------------------------------------------------------------------
// Fixtures (identical geometry to the Rust court)
// ---------------------------------------------------------------------------

func kvTestInput() modes.KvCacheInput {
	return modes.KvCacheInput{
		Model:     "qwen2.5-0.5b@060db649",
		Layer:     3,
		Session:   "session-42",
		PageIndex: 0,
		PageCount: 1,
		SeqStart:  0,
		SeqEnd:    8,
		Dtype:     modes.KvDtype{Name: "bf16", WordBytes: 2, Planes: 2},
		HeadCount: 4,
		HeadDim:   64,
	}
}

// kvTestElements is the deterministic BF16 word stream the Rust court uses.
func kvTestElements() []byte {
	const words = 8 * 4 * 64
	out := make([]byte, 0, words*2)
	state := uint64(0x9E3779B97F4A7C15)
	for index := 0; index < words; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		out = append(out, byte(state), byte(state>>8))
	}
	return out
}

func kvTestProvenance(adapters ...byte) modes.KvProvenanceInput {
	provenance := modes.KvProvenanceInput{
		ModelRoot:          kvRoot(0x11),
		TokenizerScheme:    "qwen-bpe",
		TokenizerVocabSize: 151_936,
		Attention: modes.KvAttention{
			HeadCount:     4,
			HeadDim:       64,
			SlidingWindow: 0,
			RopeThetaBits: math.Float64bits(10_000.0),
			RopeScaleBits: math.Float64bits(1.0),
		},
		Positional: modes.KvPositionalRope,
		Layout: modes.KvLayout{
			Dtype:      modes.KvDtype{Name: "bf16", WordBytes: 2, Planes: 2},
			PageRows:   8,
			LayerCount: 24,
		},
		Salt: kvRoot(0xA0),
	}
	for _, adapter := range adapters {
		provenance = provenance.WithAdapter(kvRoot(adapter))
	}
	return provenance
}

func kvRoot(byteValue byte) model.Hash32 {
	var value model.Hash32
	for index := range value {
		value[index] = byteValue
	}
	return value
}

func kvTestOptions() store.Options {
	stamp := kvNowNS
	options := store.DefaultOptions()
	options.FixedTimestampNS = &stamp
	return options
}

// kvTestGrant builds an unsigned capability scope naming exactly one descriptor
// id, the tenant principal, and the `kv.<tenant>` namespace.
func kvTestGrant(t *testing.T, principal, namespace string, expiresAt int64, roots ...model.Hash32) *auth.Capability {
	t.Helper()
	scope, err := weftcontext.NewCapabilityScope(
		principal, []string{namespace}, roots, nil, nil, &expiresAt,
	)
	if err != nil {
		t.Fatalf("capability scope: %v", err)
	}
	capability, err := auth.NewCapability(scope)
	if err != nil {
		t.Fatalf("capability: %v", err)
	}
	return capability
}

func kvTestReader(t *testing.T, uid, gid uint64, capability *auth.Capability) store.KvPrincipal {
	t.Helper()
	return store.NewKvPrincipal(auth.New(uid, gid, nil), capability)
}

// kvAssertDenied asserts the single non-disclosing denial: class Unauthorized
// and the exact Rust text.
func kvAssertDenied(t *testing.T, err error, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected a denial, got success", label)
	}
	var typed *werr.Error
	if !errors.As(err, &typed) {
		t.Fatalf("%s: expected a typed store error, got %T: %v", label, err, err)
	}
	if typed.Kind != werr.Unauthorized {
		t.Fatalf("%s: class = %s, want Unauthorized (%v)", label, typed.Kind, err)
	}
	if typed.Msg != store.KvDenied {
		t.Fatalf("%s: text = %q, want %q", label, typed.Msg, store.KvDenied)
	}
}

func kvAssertClass(t *testing.T, err error, want werr.Kind, label string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected %s, got success", label, want)
	}
	if got := werr.ClassOf(err); got != want {
		t.Fatalf("%s: class = %s, want %s (%v)", label, got, want, err)
	}
}

// ---------------------------------------------------------------------------
// Store scope matrix
// ---------------------------------------------------------------------------

func TestKvStoreScopeIsTheProvenanceDescriptorID(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, kvTestOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	rootID, err := s.ResolvePath("/")
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	elements := kvTestElements()
	written, err := s.WriteKvProvPage(
		rootID, []byte("prov-page.kv"), kvTenant, kvTestInput(), elements,
		kvTestProvenance(0x21), 1000, 1000,
	)
	if err != nil {
		t.Fatalf("write prov page: %v", err)
	}
	if written.PageBytes != uint64(len(elements)) {
		t.Fatalf("page_bytes = %d, want %d", written.PageBytes, len(elements))
	}
	mode, err := s.KvPageMode(written.ObjectID)
	if err != nil || mode != store.KvPageModeProvenance {
		t.Fatalf("kv_page_mode = %v, %v; want Provenance", mode, err)
	}
	stored, err := s.KvProvDescriptor(written.ObjectID)
	if err != nil {
		t.Fatalf("kv_prov_descriptor: %v", err)
	}
	if stored.ProvenanceRoot != written.ProvenanceRoot {
		t.Fatalf("stored provenance root %s != written %s",
			stored.ProvenanceRoot.Hex(), written.ProvenanceRoot.Hex())
	}
	if stored.Tenant != kvTenant || stored.Namespace() != "kv."+kvTenant {
		t.Fatalf("descriptor tenant/namespace = %q/%q", stored.Tenant, stored.Namespace())
	}
	t.Logf("COURT written object=%s descriptor_id=%s provenance_root=%s mode=19",
		written.ObjectID.Hex(), written.DescriptorID.Hex(), written.ProvenanceRoot.Hex())

	// 1. Correct scope: a capability naming the provenance-bound descriptor id.
	reader := kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, written.DescriptorID))
	page, err := s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	if err != nil {
		t.Fatalf("authorized read: %v", err)
	}
	if !bytes.Equal(page.Bytes, elements) {
		t.Fatalf("authorized read returned %d bytes that differ from the %d written",
			len(page.Bytes), len(elements))
	}
	if page.Root != written.ProvenanceRoot {
		t.Fatalf("decoded root %s != written %s", page.Root.Hex(), written.ProvenanceRoot.Hex())
	}
	t.Logf("COURT authorized_read bytes=%d exact=true", len(page.Bytes))

	// 2. The mode-12 reader must not silently decode a mode-19 page.
	_, err = s.ReadKvPage(written.ObjectID, reader, kvNowNS)
	kvAssertClass(t, err, werr.Corrupt, "mode-12 reader on a mode-19 page")
	if !strings.Contains(err.Error(), "use read_kv_prov_page") {
		t.Fatalf("cross-mode text = %v", err)
	}

	// 3. A capability naming the *plain* (mode-12) descriptor id over the same
	// page fields, without provenance, must be denied.
	plainDescriptor, err := store.NewKvDescriptor(kvTestInput(), kvTenant, uint64(len(elements)))
	if err != nil {
		t.Fatalf("plain descriptor: %v", err)
	}
	plainID, err := plainDescriptor.ID()
	if err != nil {
		t.Fatalf("plain descriptor id: %v", err)
	}
	if plainID == written.DescriptorID {
		t.Fatal("plain and provenance descriptor ids are equal")
	}
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, plainID))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "plain descriptor id grant")

	// 4. A capability naming the ContentId and the ObjectId, but not the
	// descriptor id: a content hash is not a credential.
	record, err := s.ObjectMeta(written.ObjectID)
	if err != nil {
		t.Fatalf("object meta: %v", err)
	}
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, record.Content, written.ObjectID))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "content+object id grant")

	// 5. Another page's provenance descriptor for the same tenant.
	other, err := s.WriteKvProvPage(
		rootID, []byte("prov-page-other.kv"), kvTenant, kvTestInput(), elements,
		kvTestProvenance(0x22), 1000, 1000,
	)
	if err != nil {
		t.Fatalf("write other page: %v", err)
	}
	if other.DescriptorID == written.DescriptorID {
		t.Fatal("two provenances produced one descriptor id")
	}
	if other.ProvenanceRoot == written.ProvenanceRoot {
		t.Fatal("two provenances produced one codec root")
	}
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, other.DescriptorID))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "other page's descriptor id")

	// 6. No capability at all.
	reader = store.NewKvPrincipal(auth.New(1000, 1000, nil), nil)
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "no capability")

	// 7. An expired capability.
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvNowNS-1, written.DescriptorID))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "expired capability")

	// 8. A foreign tenant in the scope.
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, "tenant-b", "kv.tenant-b", kvExpiresNS, written.DescriptorID))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "foreign tenant principal")

	// 9. The right principal but the wrong namespace.
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv.tenant-b", kvExpiresNS, written.DescriptorID))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "missing kv.<tenant> namespace")

	// 10. The right tenant and namespace but a root list that omits the
	// descriptor id.
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, kvRoot(0xFE)))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "descriptor id absent from roots")

	// 11. A POSIX denial: the page is 0600 and the reader is a different uid.
	ownerOnly := uint64(0o600)
	if _, err := s.Setattr(written.ObjectID, store.SetAttr{Mode: &ownerOnly}); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	reader = kvTestReader(t, 2000, 2000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, written.DescriptorID))
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "POSIX denial")
	// The owner still reads.
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, written.DescriptorID))
	if _, err := s.ReadKvProvPage(written.ObjectID, reader, kvNowNS); err != nil {
		t.Fatalf("owner read after chmod: %v", err)
	}

	// 12. An unknown object: the same denial, never NotFound.
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, written.DescriptorID))
	_, err = s.ReadKvProvPage(kvRoot(0x42), reader, kvNowNS)
	kvAssertDenied(t, err, "unknown object")

	// 13. The raw object is a frame, not plaintext.
	raw, err := s.ReadObject(written.ObjectID)
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if len(raw) < 4 || string(raw[:4]) != "WFT1" {
		t.Fatalf("stored object is not a frame: % x", raw[:4])
	}
	if bytes.Equal(raw, elements) {
		t.Fatal("stored object equals the plaintext page")
	}

	// 14. The store verifier accepts mode-19 objects as ordinary files.
	report, err := s.Verify(true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.OK {
		t.Fatalf("verify problems: %+v", report.Problems)
	}

	// 15. The provenance reader must not decode a plain mode-12 page.
	plainPage, err := s.WriteKvPage(rootID, []byte("plain-page.kv"), kvTenant, kvTestInput(), elements, 1000, 1000)
	if err != nil {
		t.Fatalf("write plain page: %v", err)
	}
	mode, err = s.KvPageMode(plainPage.ObjectID)
	if err != nil || mode != store.KvPageMode12 {
		t.Fatalf("plain kv_page_mode = %v, %v; want Page12", mode, err)
	}
	reader = kvTestReader(t, 1000, 1000,
		kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, plainPage.DescriptorID))
	_, err = s.ReadKvProvPage(plainPage.ObjectID, reader, kvNowNS)
	kvAssertClass(t, err, werr.Corrupt, "provenance reader on a mode-12 page")
	if !strings.Contains(err.Error(), "use read_kv_page") {
		t.Fatalf("cross-mode text = %v", err)
	}
	decoded, err := s.ReadKvPage(plainPage.ObjectID, reader, kvNowNS)
	if err != nil {
		t.Fatalf("mode-12 read: %v", err)
	}
	if !bytes.Equal(decoded.Bytes, elements) {
		t.Fatal("mode-12 read returned different bytes")
	}
	// The plain descriptor is parseable and its id matches the attribute.
	parsedPlain, err := s.KvDescriptor(plainPage.ObjectID)
	if err != nil {
		t.Fatalf("kv_descriptor on a plain page: %v", err)
	}
	derived, err := parsedPlain.ID()
	if err != nil || derived != plainPage.DescriptorID {
		t.Fatalf("plain descriptor id %s != written %s (%v)", derived.Hex(), plainPage.DescriptorID.Hex(), err)
	}

	// 16. A plain mode-12 write gains no mode-19 attributes, so every
	// pre-existing page stays readable.
	plainRecord, err := s.ObjectMeta(plainPage.ObjectID)
	if err != nil {
		t.Fatalf("plain meta: %v", err)
	}
	provRecord, err := s.ObjectMeta(written.ObjectID)
	if err != nil {
		t.Fatalf("prov meta: %v", err)
	}
	if _, present := plainRecord.Attrs[store.AttrKvMode]; present {
		t.Fatal("a plain page carries weft.kv.mode")
	}
	if _, present := provRecord.Attrs[store.AttrKvMode]; !present {
		t.Fatal("a provenance page is missing weft.kv.mode")
	}
	if _, present := plainRecord.Attrs[store.AttrKVProvRoot]; present {
		t.Fatal("a plain page carries weft.kv.provenance_root")
	}
	if len(provRecord.Attrs) != len(plainRecord.Attrs)+2 {
		t.Fatalf("prov attrs = %d, plain attrs = %d; want exactly two more",
			len(provRecord.Attrs), len(plainRecord.Attrs))
	}
	t.Logf("COURT denials all class=Unauthorized text=%q plain_attrs=%d prov_attrs=%d",
		store.KvDenied, len(plainRecord.Attrs), len(provRecord.Attrs))
}

// ---------------------------------------------------------------------------
// Forgery: descriptor attributes and frame/payload disagreement
// ---------------------------------------------------------------------------

func TestKvProvForgeryIsRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Init(dir, kvTestOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer s.Close()

	rootID, _ := s.ResolvePath("/")
	elements := kvTestElements()
	written, err := s.WriteKvProvPage(
		rootID, []byte("page.kv"), kvTenant, kvTestInput(), elements,
		kvTestProvenance(0x21), 1000, 1000,
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	original, err := s.ObjectMeta(written.ObjectID)
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	goodAttrs := model.CloneAttrs(original.Attrs)
	grant := kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, written.DescriptorID)
	reader := kvTestReader(t, 1000, 1000, grant)

	// (a) A descriptor attribute that is not hex.
	corrupt := model.CloneAttrs(goodAttrs)
	corrupt[store.AttrKvDescriptor] = wcb.TextValue("zz")
	if _, err := s.Setattr(written.ObjectID, store.SetAttr{Attrs: corrupt}); err != nil {
		t.Fatalf("setattr descriptor: %v", err)
	}
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "non-hex descriptor attribute")

	// (b) A descriptor id that does not match its bytes.
	corrupt = model.CloneAttrs(goodAttrs)
	corrupt[store.AttrKvDescriptorID] = wcb.TextValue(kvRoot(0x33).Hex())
	if _, err := s.Setattr(written.ObjectID, store.SetAttr{Attrs: corrupt}); err != nil {
		t.Fatalf("setattr descriptor id: %v", err)
	}
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "descriptor id mismatch")

	// (c) A provenance-root attribute that disagrees with the descriptor.
	corrupt = model.CloneAttrs(goodAttrs)
	corrupt[store.AttrKVProvRoot] = wcb.TextValue(kvRoot(0x44).Hex())
	if _, err := s.Setattr(written.ObjectID, store.SetAttr{Attrs: corrupt}); err != nil {
		t.Fatalf("setattr provenance root: %v", err)
	}
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "provenance root attribute mismatch")

	// (d) A missing descriptor.
	corrupt = model.CloneAttrs(goodAttrs)
	delete(corrupt, store.AttrKvDescriptor)
	if _, err := s.Setattr(written.ObjectID, store.SetAttr{Attrs: corrupt}); err != nil {
		t.Fatalf("setattr missing descriptor: %v", err)
	}
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertDenied(t, err, "missing descriptor attribute")

	// Restore the good attributes.
	if _, err := s.Setattr(written.ObjectID, store.SetAttr{Attrs: model.CloneAttrs(goodAttrs)}); err != nil {
		t.Fatalf("restore attrs: %v", err)
	}
	if _, err := s.ReadKvProvPage(written.ObjectID, reader, kvNowNS); err != nil {
		t.Fatalf("read after restore: %v", err)
	}

	// (e) Post-authorization corruption: swap in another frame's payload while
	// the capability descriptor still names the original page. The reader is
	// authorized, so the mismatch is Corrupt, not a denial.
	other, err := s.WriteKvProvPage(
		rootID, []byte("other.kv"), kvTenant, kvTestInput(), elements,
		kvTestProvenance(0x22), 1000, 1000,
	)
	if err != nil {
		t.Fatalf("write other: %v", err)
	}
	otherFrame, err := s.ReadObject(other.ObjectID)
	if err != nil {
		t.Fatalf("read other frame: %v", err)
	}
	if _, err := s.WriteFile(written.ObjectID, 0, otherFrame); err != nil {
		t.Fatalf("swap frame: %v", err)
	}
	record, err := s.ObjectMeta(written.ObjectID)
	if err != nil {
		t.Fatalf("meta after swap: %v", err)
	}
	if record.Attrs[store.AttrKvDescriptorID].Str != written.DescriptorID.Hex() {
		t.Fatal("the write path dropped the KV descriptor attribute")
	}
	_, err = s.ReadKvProvPage(written.ObjectID, reader, kvNowNS)
	kvAssertClass(t, err, werr.Corrupt, "frame does not match the stored descriptor")
	if !strings.Contains(err.Error(), "kv provenance descriptor does not match its frame metadata") {
		t.Fatalf("post-authorization text = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Canonical descriptor forms
// ---------------------------------------------------------------------------

func TestKvDescriptorCanonicalForms(t *testing.T) {
	page, err := store.NewKvDescriptor(kvTestInput(), kvTenant, 4096)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	encoded, err := page.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	parsed, err := store.ParseKvDescriptor(encoded)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if id1, _ := page.ID(); id1.Hex() != mustID(t, parsed).Hex() {
		t.Fatal("descriptor id changed across a round trip")
	}

	providerived, err := store.NewKvProvDescriptor(kvTestInput(), kvTenant, 4096, kvRoot(0x11))
	if err != nil {
		t.Fatalf("prov descriptor: %v", err)
	}
	provBytes, err := providerived.CanonicalBytes()
	if err != nil {
		t.Fatalf("prov bytes: %v", err)
	}
	if _, err := store.ParseKvDescriptor(provBytes); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("mode-19 descriptor under the mode-12 parser: %v", err)
	}
	if _, err := store.ParseKvProvDescriptor(encoded); werr.ClassOf(err) != werr.Corrupt {
		t.Fatalf("mode-12 descriptor under the mode-19 parser: %v", err)
	}

	// A value with an extra key.
	withExtra := map[string]wcb.Value{}
	for key, value := range pageValue(t, page) {
		withExtra[key] = value
	}
	withExtra["extra"] = wcb.U64Value(1)
	extraBytes, err := wcb.EncodeDefault(wcb.MapValue(withExtra))
	if err != nil {
		t.Fatalf("encode extra: %v", err)
	}
	if _, err := store.ParseKvDescriptor(extraBytes); werr.ClassOf(err) != werr.Corrupt ||
		!strings.Contains(err.Error(), "unknown kv descriptor key") {
		t.Fatalf("extra key: %v", err)
	}

	// A missing key.
	missing := map[string]wcb.Value{}
	for key, value := range pageValue(t, page) {
		if key == "salt" || key == "tenant" {
			continue
		}
		missing[key] = value
	}
	missingBytes, err := wcb.EncodeDefault(wcb.MapValue(missing))
	if err != nil {
		t.Fatalf("encode missing: %v", err)
	}
	if _, err := store.ParseKvDescriptor(missingBytes); werr.ClassOf(err) != werr.Corrupt ||
		!strings.Contains(err.Error(), "missing a field") {
		t.Fatalf("missing key: %v", err)
	}

	// A foreign schema.
	otherSchema := map[string]wcb.Value{}
	for key, value := range pageValue(t, page) {
		otherSchema[key] = value
	}
	otherSchema["schema"] = wcb.TextValue("weft.kv.capability.v2")
	schemaBytes, err := wcb.EncodeDefault(wcb.MapValue(otherSchema))
	if err != nil {
		t.Fatalf("encode schema: %v", err)
	}
	if _, err := store.ParseKvDescriptor(schemaBytes); werr.ClassOf(err) != werr.Corrupt ||
		!strings.Contains(err.Error(), "unknown kv descriptor schema") {
		t.Fatalf("foreign schema: %v", err)
	}

	// A wrong WCB type.
	wrongType := map[string]wcb.Value{}
	for key, value := range pageValue(t, page) {
		wrongType[key] = value
	}
	wrongType["layer"] = wcb.TextValue("3")
	wrongBytes, err := wcb.EncodeDefault(wcb.MapValue(wrongType))
	if err != nil {
		t.Fatalf("encode type: %v", err)
	}
	if _, err := store.ParseKvDescriptor(wrongBytes); werr.ClassOf(err) != werr.Corrupt ||
		!strings.Contains(err.Error(), "is not u64") {
		t.Fatalf("wrong type: %v", err)
	}

	// A layer past u32.
	bigLayer := map[string]wcb.Value{}
	for key, value := range pageValue(t, page) {
		bigLayer[key] = value
	}
	bigLayer["layer"] = wcb.U64Value(1 << 32)
	bigBytes, err := wcb.EncodeDefault(wcb.MapValue(bigLayer))
	if err != nil {
		t.Fatalf("encode layer: %v", err)
	}
	if _, err := store.ParseKvDescriptor(bigBytes); werr.ClassOf(err) != werr.Corrupt ||
		!strings.Contains(err.Error(), "does not fit u32") {
		t.Fatalf("layer overflow: %v", err)
	}

	// Trailing bytes are not canonical.
	trailing := append(append([]byte(nil), encoded...), 0x00)
	_, trailingErr := store.ParseKvDescriptor(trailing)
	if trailingErr == nil {
		t.Fatal("trailing bytes were accepted")
	}
	class := werr.ClassOf(trailingErr)
	if class != werr.NonCanonical && class != werr.Malformed {
		t.Fatalf("trailing bytes class = %s (%v)", class, trailingErr)
	}

	// A provenance root that is not a hash.
	badRoot := map[string]wcb.Value{}
	for key, value := range provValue(t, providerived) {
		badRoot[key] = value
	}
	badRoot["provenance_root"] = wcb.TextValue("not-a-hash")
	badRootBytes, err := wcb.EncodeDefault(wcb.MapValue(badRoot))
	if err != nil {
		t.Fatalf("encode root: %v", err)
	}
	if _, err := store.ParseKvProvDescriptor(badRootBytes); werr.ClassOf(err) != werr.Corrupt ||
		!strings.Contains(err.Error(), "is not a hash") {
		t.Fatalf("bad provenance root: %v", err)
	}

	// The namespace is the grant namespace.
	if page.Namespace() != "kv."+kvTenant {
		t.Fatalf("namespace = %q", page.Namespace())
	}
	if providerived.Namespace() != "kv."+kvTenant {
		t.Fatalf("prov namespace = %q", providerived.Namespace())
	}
}

// pageValue rebuilds the canonical descriptor value through its bytes, so the
// test does not depend on an unexported encoder.
func pageValue(t *testing.T, descriptor store.KvDescriptor) map[string]wcb.Value {
	t.Helper()
	encoded, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	value, err := wcb.DecodeDefault(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return value.Map
}

func provValue(t *testing.T, descriptor store.KvProvDescriptor) map[string]wcb.Value {
	t.Helper()
	encoded, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	value, err := wcb.DecodeDefault(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return value.Map
}

func mustID(t *testing.T, descriptor store.KvDescriptor) model.Hash32 {
	t.Helper()
	id, err := descriptor.ID()
	if err != nil {
		t.Fatalf("descriptor id: %v", err)
	}
	return id
}

// ---------------------------------------------------------------------------
// Rust <-> Go handoff
// ---------------------------------------------------------------------------

// rustCodecBinary locates the Rust WeftCodec CLI (codec oracle only; no
// production package invokes it).
func rustCodecBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{
		os.Getenv("WEFTCODEC_RUST_BIN"),
		filepath.Join("..", "..", ".docker-cache", "target-rust", "release", "weftcodec"),
		"/work/.docker-cache/target-rust/release/weftcodec",
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			absolute, err := filepath.Abs(candidate)
			if err != nil {
				absolute = candidate
			}
			probe := exec.Command(absolute, "--help")
			if output, probeErr := probe.CombinedOutput(); probeErr != nil {
				t.Skipf("Rust codec oracle at %s is not runnable in this court: %v\n%s",
					absolute, probeErr, output)
			}
			return absolute
		}
	}
	t.Skip("Rust codec oracle not found; build it in the Rust court with: " +
		"scripts/docker-court.sh rust \"cargo build --release --locked --bin weftcodec\"")
	return ""
}

// TestKvProvHandoffGoThenRust writes a mode-19 page with Go, then makes Rust
// read it three ways: the store read path (`cat`), the store descriptor path
// (`retention history --object`, which parses the canonical capability
// descriptor, checks its id and the recorded provenance root), and the codec
// (`weftcodec decode`). Two pages with different provenance give different
// roots and ids on both sides.
func TestKvProvHandoffGoThenRust(t *testing.T) {
	bin := rustBinary(t)
	codec := rustCodecBinary(t)
	dir := t.TempDir()
	s, err := store.Init(dir, kvTestOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	rootID, _ := s.ResolvePath("/")
	elements := kvTestElements()
	first, err := s.WriteKvProvPage(
		rootID, []byte("prov-page.kv"), kvTenant, kvTestInput(), elements,
		kvTestProvenance(0x21), 1000, 1000,
	)
	if err != nil {
		t.Fatalf("write first: %v", err)
	}
	second, err := s.WriteKvProvPage(
		rootID, []byte("prov-page-b.kv"), kvTenant, kvTestInput(), elements,
		kvTestProvenance(0x22), 1000, 1000,
	)
	if err != nil {
		t.Fatalf("write second: %v", err)
	}
	storedFrame, err := s.ReadObject(first.ObjectID)
	if err != nil {
		t.Fatalf("read stored frame: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 1. Rust's store read returns exactly the frame Go stored.
	frame := runRustBytes(t, bin, "--store", dir, "cat", "/prov-page.kv")
	if !bytes.Equal(frame, storedFrame) {
		t.Fatalf("rust cat returned %d bytes, Go stored %d", len(frame), len(storedFrame))
	}
	t.Logf("COURT rust_cat bytes=%d equals_go_stored=true", len(frame))

	// 2. Rust's store descriptor path resolves the same provenance root.
	historyA := rustJSON(t, bin, dir, "retention", "history", "--object", first.ObjectID.Hex())
	historyB := rustJSON(t, bin, dir, "retention", "history", "--object", second.ObjectID.Hex())
	rootA, _ := historyA["descriptor_root"].(string)
	rootB, _ := historyB["descriptor_root"].(string)
	if rootA != first.ProvenanceRoot.Hex() {
		t.Fatalf("rust descriptor_root A = %q, Go = %q", rootA, first.ProvenanceRoot.Hex())
	}
	if rootB != second.ProvenanceRoot.Hex() {
		t.Fatalf("rust descriptor_root B = %q, Go = %q", rootB, second.ProvenanceRoot.Hex())
	}
	if rootA == rootB {
		t.Fatal("rust reported one provenance root for two provenance inputs")
	}
	if count, _ := historyA["count"].(float64); count != 0 {
		t.Fatalf("retention history count = %v, want 0 (no binding was published)", count)
	}
	t.Logf("COURT rust_descriptor_roots a=%s b=%s distinct=true", rootA, rootB)

	// 3. Rust's codec decodes the stored frame to exactly the page Go encoded.
	work := t.TempDir()
	framePath := filepath.Join(work, "frame.bin")
	if err := os.WriteFile(framePath, storedFrame, 0o644); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	pagePath := filepath.Join(work, "page.bin")
	cmd := exec.Command(codec, "decode", "--input", framePath, "--output", pagePath)
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rust codec decode: %v\n%s", err, output)
	}
	decoded, err := os.ReadFile(pagePath)
	if err != nil {
		t.Fatalf("read decoded page: %v", err)
	}
	if !bytes.Equal(decoded, elements) {
		t.Fatalf("rust decoded %d bytes that differ from the %d Go wrote",
			len(decoded), len(elements))
	}
	t.Logf("COURT rust_codec_decoded bytes=%d exact=true", len(decoded))

	// 4. Rust still verifies the Go store in full.
	report := rustJSON(t, bin, dir, "verify", "--full")
	if ok, _ := report["ok"].(bool); !ok {
		t.Fatalf("rust verify --full on a Go store: %+v", report)
	}
}

// TestKvPageHandoffRustThenGo has Rust write plain mode-12 pages with
// `weftfs kv put` (the shipped Rust writer for that tier) and reads them back
// through the Go store API.
func TestKvPageHandoffRustThenGo(t *testing.T) {
	bin := rustBinary(t)
	dir := t.TempDir()
	runRust(t, bin, "--store", dir, "init")
	runRust(t, bin, "--store", dir, "kv", "put",
		"--name", "p1",
		"--model", "qwen2.5-0.5b@060db649",
		"--tokens", "128",
		"--page-rows", "64",
		"--layers", "1",
		"--heads", "4",
		"--head-dim", "64",
		"--dtype", "bf16",
		"--payload-seed", "1",
	)

	s, err := store.Open(dir, store.ReadOnly)
	if err != nil {
		t.Fatalf("open rust store: %v", err)
	}
	defer s.Close()

	pagesID, err := s.ResolvePath("/kv/pages")
	if err != nil {
		t.Fatalf("resolve /kv/pages: %v", err)
	}
	entries, err := s.ListDir(pagesID)
	if err != nil {
		t.Fatalf("list /kv/pages: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("page objects = %d, want 2 (128 tokens at 64 rows)", len(entries))
	}
	t.Logf("COURT rust_written_pages=%d", len(entries))
	elements := 0
	for _, entry := range entries {
		mode, err := s.KvPageMode(entry.Target)
		if err != nil {
			t.Fatalf("kv_page_mode: %v", err)
		}
		if mode != store.KvPageMode12 {
			t.Fatalf("mode = %v, want Page12", mode)
		}
		descriptor, err := s.KvDescriptor(entry.Target)
		if err != nil {
			t.Fatalf("parse a Rust-written descriptor: %v", err)
		}
		if descriptor.Tenant != "default" || descriptor.Model != "qwen2.5-0.5b@060db649" {
			t.Fatalf("descriptor = %+v", descriptor)
		}
		if descriptor.HeadCount != 4 || descriptor.HeadDim != 64 || descriptor.Dtype != "bf16" {
			t.Fatalf("descriptor geometry = %+v", descriptor)
		}
		id, err := descriptor.ID()
		if err != nil {
			t.Fatalf("descriptor id: %v", err)
		}
		record, err := s.ObjectMeta(entry.Target)
		if err != nil {
			t.Fatalf("meta: %v", err)
		}
		if record.Attrs[store.AttrKvDescriptorID].Str != id.Hex() {
			t.Fatalf("rust descriptor id %q != recomputed %q",
				record.Attrs[store.AttrKvDescriptorID].Str, id.Hex())
		}
		capability := kvTestGrant(t, "default", "kv.default", kvExpiresNS, id)
		page, err := s.ReadKvPage(entry.Target, kvTestReader(t, 0, 0, capability), kvNowNS)
		if err != nil {
			t.Fatalf("read a Rust-written page: %v", err)
		}
		if uint64(len(page.Bytes)) != descriptor.PageBytes {
			t.Fatalf("decoded %d bytes, descriptor says %d", len(page.Bytes), descriptor.PageBytes)
		}
		// Rust names a page `p-<descriptor-id>-<chunk-hash>`, and that id comes
		// from Rust's own `KvDescriptor::from_input`. Rebuilding the descriptor
		// with Go from the same input must produce the same canonical bytes and
		// therefore the same id, which is a same-bytes check of the constructor
		// against Rust's derivation (not of Go against itself).
		input := modes.KvCacheInput{
			Model:     descriptor.Model,
			Layer:     descriptor.Layer,
			Session:   descriptor.Session,
			PageIndex: descriptor.PageIndex,
			PageCount: descriptor.PageCount,
			SeqStart:  descriptor.SeqStart,
			SeqEnd:    descriptor.SeqEnd,
			Dtype:     page.Meta.Dtype,
			HeadCount: descriptor.HeadCount,
			HeadDim:   descriptor.HeadDim,
		}
		expected, err := store.NewKvDescriptor(input, "default", descriptor.PageBytes)
		if err != nil {
			t.Fatalf("rebuild descriptor: %v", err)
		}
		expectedBytes, err := expected.CanonicalBytes()
		if err != nil {
			t.Fatalf("rebuild descriptor bytes: %v", err)
		}
		rustDescriptorBytes, err := hex.DecodeString(record.Attrs[store.AttrKvDescriptor].Str)
		if err != nil {
			t.Fatalf("rust descriptor hex: %v", err)
		}
		if !bytes.Equal(expectedBytes, rustDescriptorBytes) {
			t.Fatalf("Go descriptor bytes (%d) != Rust descriptor bytes (%d)",
				len(expectedBytes), len(rustDescriptorBytes))
		}
		if !strings.HasPrefix(string(entry.Name), "p-"+id.Hex()+"-") {
			t.Fatalf("page name %q does not start with Rust's descriptor id %s",
				entry.Name, id.Hex())
		}
		// Re-encoding the decoded page with Go must reproduce the Rust frame
		// byte for byte, which is the strongest exactness check available here.
		reencoded, err := modes.EncodeKvPage(input, page.Bytes, limits.Default())
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		rustFrame, err := s.ReadObject(entry.Target)
		if err != nil {
			t.Fatalf("read rust frame: %v", err)
		}
		if !bytes.Equal(reencoded, rustFrame) {
			t.Fatalf("Go re-encode (%d bytes) != Rust frame (%d bytes)",
				len(reencoded), len(rustFrame))
		}
		elements += len(page.Bytes)
	}
	if elements == 0 {
		t.Fatal("no page bytes were read")
	}
	t.Logf("COURT rust_written_page_bytes=%d descriptor_and_frame_match=true", elements)
}

// TestKvProvHandoffRustThenGo makes Rust the writer of a mode-19 page through the
// shipped CLI verb `kv prov-write`.
//
// Both languages encode the same page geometry and provenance inputs from the
// same element bytes. Because every identity is content-derived, Rust's own
// descriptor derivation must land on the same descriptor id, provenance root and
// frame bytes as Go's. Go then reads the Rust-written page back. This exercises
// Rust's writer rather than copying attribute values it printed from a
// Go-written object.
func TestKvProvHandoffRustThenGo(t *testing.T) {
	bin := rustBinary(t)
	first := t.TempDir()
	second := t.TempDir()

	// Go writes a reference page.
	s, err := store.Init(first, kvTestOptions())
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	rootID, _ := s.ResolvePath("/")
	elements := kvTestElements()
	written, err := s.WriteKvProvPage(
		rootID, []byte("prov-page.kv"), kvTenant, kvTestInput(), elements,
		kvTestProvenance(0x21), 1000, 1000,
	)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	goFrame, err := s.ReadObject(written.ObjectID)
	if err != nil {
		t.Fatalf("read the Go-written frame: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Rust writes the same page through the shipped CLI verb. Every identity is
	// content-derived, so agreeing on the descriptor id and provenance root is
	// the real cross-language claim.
	payloadPath := writePayload(t, t.TempDir(), "elements.bin", elements)
	hexRoot := func(value byte) string {
		return strings.Repeat(fmt.Sprintf("%02x", value), 32)
	}
	runRust(t, bin, "--store", second, "init")
	prov := rustJSON(t, bin, second, "kv", "prov-write",
		"--name", "rewritten.kv",
		"--tenant", kvTenant,
		"--model", "qwen2.5-0.5b@060db649",
		"--layer", "3",
		"--session", "session-42",
		"--page-index", "0",
		"--page-count", "1",
		"--seq-start", "0",
		"--seq-end", "8",
		"--dtype", "bf16",
		"--heads", "4",
		"--head-dim", "64",
		"--payload", payloadPath,
		"--model-root", hexRoot(0x11),
		"--adapter-root", hexRoot(0x21),
		"--tokenizer-scheme", "qwen-bpe",
		"--vocab-size", "151936",
		"--sliding-window", "0",
		"--rope-theta", "10000",
		"--rope-scale", "1",
		"--positional", "rope",
		"--page-rows", "8",
		"--layer-count", "24",
		"--salt", hexRoot(0xA0),
		"--uid", "1000",
		"--gid", "1000",
	)
	if got, _ := prov["descriptor_id"].(string); got != written.DescriptorID.Hex() {
		t.Fatalf("rust prov-write descriptor id = %v, Go = %s", prov["descriptor_id"], written.DescriptorID.Hex())
	}
	if got, _ := prov["provenance_root"].(string); got != written.ProvenanceRoot.Hex() {
		t.Fatalf("rust prov-write provenance root = %v, Go = %s", prov["provenance_root"], written.ProvenanceRoot.Hex())
	}
	if got, _ := prov["page_bytes"].(float64); got != float64(len(elements)) {
		t.Fatalf("rust prov-write page_bytes = %v, want %d", prov["page_bytes"], len(elements))
	}

	// Go reads the Rust-written page back.
	readOnly, err := store.Open(second, store.ReadOnly)
	if err != nil {
		t.Fatalf("open second store: %v", err)
	}
	defer readOnly.Close()
	id, err := readOnly.ResolvePath("/rewritten.kv")
	if err != nil {
		t.Fatalf("resolve rewritten page: %v", err)
	}
	mode, err := readOnly.KvPageMode(id)
	if err != nil || mode != store.KvPageModeProvenance {
		t.Fatalf("kv_page_mode = %v, %v; want Provenance", mode, err)
	}
	descriptor, err := readOnly.KvProvDescriptor(id)
	if err != nil {
		t.Fatalf("kv_prov_descriptor: %v", err)
	}
	if descriptor.ProvenanceRoot != written.ProvenanceRoot {
		t.Fatalf("rust-written provenance root %s != Go %s",
			descriptor.ProvenanceRoot.Hex(), written.ProvenanceRoot.Hex())
	}
	descriptorID, err := descriptor.ID()
	if err != nil || descriptorID != written.DescriptorID {
		t.Fatalf("rust-written descriptor id %s != Go %s (%v)",
			descriptorID.Hex(), written.DescriptorID.Hex(), err)
	}
	capability := kvTestGrant(t, kvTenant, "kv."+kvTenant, kvExpiresNS, descriptorID)
	page, err := readOnly.ReadKvProvPage(id, kvTestReader(t, 1000, 1000, capability), kvNowNS)
	if err != nil {
		t.Fatalf("read a Rust-written mode-19 page: %v", err)
	}
	if !bytes.Equal(page.Bytes, elements) {
		t.Fatalf("decoded %d bytes that differ from the %d Go wrote", len(page.Bytes), len(elements))
	}
	storedFrame, err := readOnly.ReadObject(id)
	if err != nil {
		t.Fatalf("read rewritten frame: %v", err)
	}
	if !bytes.Equal(storedFrame, goFrame) {
		t.Fatalf("rust-written frame (%d bytes) != Go-written frame (%d bytes)",
			len(storedFrame), len(goFrame))
	}
	t.Logf("COURT rust_verb_written descriptor_id=%s root=%s frame_bytes=%d exact=true",
		descriptorID.Hex(), descriptor.ProvenanceRoot.Hex(), len(storedFrame))
	report, err := readOnly.Verify(true)
	if err != nil || !report.OK {
		t.Fatalf("go verify of the Rust-written store: %v, problems=%+v", err, report.Problems)
	}
}
