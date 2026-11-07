package store

import (
	"strings"
	"testing"
	"time"
)

// sigV4Example is the "Example: GET Object" vector from the AWS Signature
// Version 4 documentation. It pins the canonical request, the string to sign,
// and the final signature, so a regression in any signing step fails here
// before it reaches an endpoint.
func TestSigV4MatchesThePublishedAWSVector(t *testing.T) {
	headers := map[string]string{
		"host":                 "examplebucket.s3.amazonaws.com",
		"range":                "bytes=0-9",
		"x-amz-content-sha256": s3EmptySHA256,
		"x-amz-date":           "20130524T000000Z",
	}
	signature := signS3Request(s3SignatureInput{
		Method:      "GET",
		Host:        "examplebucket.s3.amazonaws.com",
		Path:        "/test.txt",
		Headers:     headers,
		PayloadHash: s3EmptySHA256,
		AmzDate:     "20130524T000000Z",
		Date:        "20130524",
		Region:      "us-east-1",
		AccessKey:   "AKIAIOSFODNN7EXAMPLE",
		SecretKey:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	if signature.SignedHeaders != "host;range;x-amz-content-sha256;x-amz-date" {
		t.Fatalf("unexpected signed headers: %s", signature.SignedHeaders)
	}
	if !strings.Contains(signature.Authorization, "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Fatalf("signature does not match the published vector:\n%s", signature.Authorization)
	}
	if !strings.Contains(signature.Authorization, "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request") {
		t.Fatalf("unexpected credential scope: %s", signature.Authorization)
	}
}

func TestPayloadHashNeverUsesUnsignedPayload(t *testing.T) {
	if got := s3PayloadHash(nil); got != s3EmptySHA256 {
		t.Fatalf("empty body hash: %s", got)
	}
	if got := s3PayloadHash([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("body hash: %s", got)
	}
	if got := s3PayloadHash([]byte("abc")); got == "UNSIGNED-PAYLOAD" {
		t.Fatal("the client must never sign UNSIGNED-PAYLOAD")
	}
}

func TestCanonicalQueryEncodesAndSortsLikeAWS(t *testing.T) {
	query := []s3Query{
		{"prefix", "objects/ab/"},
		{"list-type", "2"},
		{"continuation-token", "a+b/c="},
		{"max-keys", "1000"},
	}
	got := canonicalS3Query(query)
	want := "continuation-token=a%2Bb%2Fc%3D&list-type=2&max-keys=1000&prefix=objects%2Fab%2F"
	if got != want {
		t.Fatalf("canonical query mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestPathAndComponentEncodingPreserveOnlyUnreservedBytes(t *testing.T) {
	if got := encodeS3Path("objects/ab/ff"); got != "objects/ab/ff" {
		t.Fatalf("path encoding changed slashes: %s", got)
	}
	if got := encodeS3Path("a b+c"); got != "a%20b%2Bc" {
		t.Fatalf("path encoding: %s", got)
	}
	if got := encodeS3Component("a/b c"); got != "a%2Fb%20c" {
		t.Fatalf("component encoding: %s", got)
	}
}

func TestIfMatchFormsEncodeETags(t *testing.T) {
	if got := stripETagQuotes(`"abc123"`); got != "abc123" {
		t.Fatalf("dequote: %s", got)
	}
	if got := stripETagQuotes("abc123"); got != "abc123" {
		t.Fatalf("dequote bare: %s", got)
	}
	if got := stripETagQuotes(`W/"abc"`); got != `W/"abc"` {
		t.Fatalf("weak etag must not be rewritten: %s", got)
	}
	if got := IfMatchAsReturned.Encode(`"abc123"`); got != `"abc123"` {
		t.Fatalf("as-returned: %s", got)
	}
	if got := IfMatchDequoted.Encode(`"abc123"`); got != "abc123" {
		t.Fatalf("dequoted: %s", got)
	}
	if IfMatchAsReturned.String() != "quoted-as-returned" || IfMatchDequoted.String() != "dequoted" {
		t.Fatal("unexpected form labels")
	}
}

func TestLockRecordRoundTripsLegacyAndTombstone(t *testing.T) {
	release := encodeS3Lock("owner-a", 3, 9, 1000, 900, 12, strings.Repeat("ab", 32), 4096)
	record, ok := parseS3Lock([]byte(release))
	if !ok {
		t.Fatal("v3 record must parse")
	}
	if record.schemaVersion != 3 || record.owner != "owner-a" || record.fence != 3 || record.sequence != 9 ||
		record.deadlineNS != 1000 || record.renewedNS != 900 ||
		record.pendingGeneration != 12 || record.pendingCommit != strings.Repeat("ab", 32) ||
		record.pendingCommitLen != 4096 {
		t.Fatalf("v3 round trip mismatch: %+v", record)
	}
	if record.released {
		t.Fatal("v3 record must not be released")
	}
	if !record.isLive(1000) || record.isLive(1001) {
		t.Fatal("lease liveness must be inclusive at the deadline")
	}
	if generation, _, ok := record.attestedHead(); !ok || generation != 12 {
		t.Fatalf("v3 record must attest its head: %+v", record)
	}

	idle := encodeS3Lock("owner-a", 3, 10, 1000, 950, 0, "", 0)
	idleRecord, ok := parseS3Lock([]byte(idle))
	if !ok || idleRecord.pendingGeneration != 0 || idleRecord.pendingCommit != "-" || idleRecord.pendingCommitLen != 0 {
		t.Fatalf("idle record: %+v ok=%t", idleRecord, ok)
	}
	if _, _, ok := idleRecord.attestedHead(); ok {
		t.Fatal("an idle record must not attest a head")
	}

	// A v2 record is still readable and reports an unknown head length.
	v2 := s3LockSchemaV2 + "\nowner=y\nfence=1\nsequence=1\nlease_deadline_ns=10\nrenewed_ns=9\npending_generation=4\npending_commit=" + strings.Repeat("cd", 32) + "\n"
	v2Record, ok := parseS3Lock([]byte(v2))
	if !ok || v2Record.schemaVersion != 2 || v2Record.pendingCommitLen != 0 {
		t.Fatalf("v2 record: %+v ok=%t", v2Record, ok)
	}
	if generation, _, ok := v2Record.attestedHead(); !ok || generation != 4 {
		t.Fatalf("v2 record must attest its head: %+v", v2Record)
	}

	legacy := s3LockSchemaV1 + "\nowner=x\nexpires_ns=42\n"
	legacyRecord, ok := parseS3Lock([]byte(legacy))
	if !ok || legacyRecord.schemaVersion != 1 || legacyRecord.fence != 0 || legacyRecord.deadlineNS != 42 || legacyRecord.sequence != 0 {
		t.Fatalf("legacy record: %+v ok=%t", legacyRecord, ok)
	}

	tombstone := encodeS3Released("owner-a", 4, 11, 5000, "deadbeef", 12, strings.Repeat("ab", 32), 4096)
	released, ok := parseS3Lock([]byte(tombstone))
	if !ok || !released.released || released.fence != 4 || released.sequence != 11 ||
		released.releasedFrom != "deadbeef" || released.pendingGeneration != 12 ||
		released.pendingCommitLen != 4096 {
		t.Fatalf("tombstone: %+v ok=%t", released, ok)
	}
	if released.isLive(0) || released.isLive(1<<62) {
		t.Fatal("a tombstone is never live")
	}

	legacyTombstone := s3ReleasedSchemaV1 + "\nowner=a\nfence=4\nsequence=11\nreleased_ns=5000\nreleased_from=deadbeef\n"
	legacyReleased, ok := parseS3Lock([]byte(legacyTombstone))
	if !ok || !legacyReleased.released || legacyReleased.pendingGeneration != 0 || legacyReleased.releasedFrom != "deadbeef" {
		t.Fatalf("legacy tombstone: %+v ok=%t", legacyReleased, ok)
	}

	for _, bad := range []string{
		"garbage",
		s3LockSchema + "\nowner=x\n",
		s3LockSchemaV2 + "\nowner=x\nfence=-1\nsequence=1\nlease_deadline_ns=1\nrenewed_ns=1\npending_generation=0\npending_commit=-\n",
		// v3 without the length field is not a v3 record.
		s3LockSchema + "\nowner=x\nfence=1\nsequence=1\nlease_deadline_ns=1\nrenewed_ns=1\npending_generation=0\npending_commit=-\n",
	} {
		if _, ok := parseS3Lock([]byte(bad)); ok {
			t.Fatalf("malformed record accepted: %q", bad)
		}
	}
}

func TestSchemasDoNotParseAcrossBackends(t *testing.T) {
	body := encodeS3Lock("o", 1, 1, 1, 1, 0, "", 0)
	if _, ok := parseS3Lock([]byte("weftfs-gcs-lock v3\nowner=o\nfence=1\nsequence=1\nlease_deadline_ns=1\nrenewed_ns=1\npending_generation=0\npending_commit=-\npending_commit_len=0\n")); ok {
		t.Fatal("a foreign schema must not parse; body=" + body)
	}
}

func TestS3ConfigResolutionAndValidation(t *testing.T) {
	saved := lookupEnv
	defer func() { lookupEnv = saved }()
	env := map[string]string{
		"WEFT_S3_ENDPOINT":   "http://127.0.0.1:9000",
		"WEFT_S3_BUCKET":     "weft-court",
		"WEFT_S3_ACCESS_KEY": "key",
		"WEFT_S3_SECRET_KEY": "secret",
	}
	lookupEnv = func(name string) (string, bool) {
		value, ok := env[name]
		return value, ok
	}
	config, err := ResolveS3("", "", "", "", "", "")
	if err != nil {
		t.Fatalf("environment resolution failed: %v", err)
	}
	if config.Region != "us-east-1" || config.Bucket != "weft-court" || !config.PathStyle {
		t.Fatalf("unexpected defaults: %+v", config)
	}
	if config.LockLease != 900*time.Second {
		t.Fatalf("default lease: %s", config.LockLease)
	}

	explicit, err := ResolveS3("http://example:9000", "other-bucket", "eu-west-1", "a", "b", "token")
	if err != nil {
		t.Fatalf("explicit resolution failed: %v", err)
	}
	if explicit.Bucket != "other-bucket" || explicit.Region != "eu-west-1" || explicit.SessionToken != "token" {
		t.Fatalf("explicit values did not win: %+v", explicit)
	}

	lookupEnv = func(name string) (string, bool) { return "", false }
	if _, err := ResolveS3("", "", "", "a", "b", ""); err == nil {
		t.Fatal("a missing endpoint must be refused")
	}
	bad := S3Config{Endpoint: "http://h:1", Bucket: "Upper", Region: "r", AccessKey: "a", SecretKey: "b"}
	if err := bad.Validate(); err == nil {
		t.Fatal("a non-DNS bucket name must be refused")
	}
	if _, err := parseS3Endpoint("ftp://h:1"); err == nil {
		t.Fatal("a non-http endpoint must be refused")
	}
	if endpoint, err := parseS3Endpoint("http://h:9000/base/"); err != nil || endpoint.BasePath != "/base" {
		t.Fatalf("base path parsing: %+v err=%v", endpoint, err)
	}
}
