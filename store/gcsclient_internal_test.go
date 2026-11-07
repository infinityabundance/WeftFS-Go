package store

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

func TestGCSPreconditionParameters(t *testing.T) {
	if got := gcsMissing().parameter(); got != "0" {
		t.Fatalf("create-once parameter = %q, want 0", got)
	}
	if got := gcsMatches(42).parameter(); got != "42" {
		t.Fatalf("matching parameter = %q, want 42", got)
	}
}

func TestGCSPctEncodesOnePathSegment(t *testing.T) {
	cases := map[string]string{
		"objects/ab/0123abcd": "objects%2Fab%2F0123abcd",
		"a b":                 "a%20b",
		"a+b":                 "a%2Bb",
		"a~b-c_d.e":           "a~b-c_d.e",
		"gcs://bucket":        "gcs%3A%2F%2Fbucket",
	}
	for input, want := range cases {
		if got := gcsPct(input); got != want {
			t.Fatalf("gcsPct(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGCSLockRecordIsSeparateFromS3(t *testing.T) {
	body := encodeGCSLock("owner-1", 7, 3, 1700000000000000000, 1699999999000000000, 11, strings.Repeat("ab", 32), 4096)
	record, ok := parseGCSLock([]byte(body))
	if !ok {
		t.Fatalf("GCS lock did not parse: %q", body)
	}
	if record.schemaVersion != 3 || record.owner != "owner-1" || record.fence != 7 ||
		record.sequence != 3 || record.pendingGeneration != 11 || record.pendingCommitLen != 4096 {
		t.Fatalf("GCS lock fields = %+v", record)
	}
	generation, commit, ok := record.attestedHead()
	if !ok || generation != 11 || commit.Hex() != strings.Repeat("ab", 32) {
		t.Fatalf("attested head = %d %s %t", generation, commit.Hex(), ok)
	}
	if _, ok := parseS3Lock([]byte(body)); ok {
		t.Fatal("an S3 parser accepted a GCS lock record")
	}
	s3Body := encodeS3Lock("owner-1", 7, 3, 1700000000000000000, 1699999999000000000, 11, strings.Repeat("ab", 32), 4096)
	if _, ok := parseGCSLock([]byte(s3Body)); ok {
		t.Fatal("a GCS parser accepted an S3 lock record")
	}
	if _, ok := parseGCSLock([]byte("weftfs-gcs-lock v3\nowner=o\n")); ok {
		t.Fatal("a truncated GCS lock record was accepted")
	}
}

func TestGCSConfigResolutionAndCredentialForms(t *testing.T) {
	restore := swapGCSEnv(map[string]string{
		"WEFT_GCS_ENDPOINT":              "",
		"WEFT_GCS_BUCKET":                "",
		"WEFT_GCS_ACCESS_TOKEN":          "",
		"GOOGLE_OAUTH_ACCESS_TOKEN":      "",
		"WEFT_GCS_CREDENTIALS":           "",
		"GOOGLE_APPLICATION_CREDENTIALS": "",
		"WEFT_GCS_PROJECT":               "",
		"GOOGLE_CLOUD_PROJECT":           "",
		"WEFT_GCS_ANONYMOUS":             "",
		"WEFT_GCS_SCOPE":                 "",
	})
	defer restore()

	anonymous := true
	config, err := ResolveGCS("http://127.0.0.1:4443", "weft-court", "", "project", &anonymous, "", "")
	if err != nil {
		t.Fatalf("anonymous resolve: %v", err)
	}
	if !config.Anonymous || config.Endpoint != "http://127.0.0.1:4443" || config.Bucket != "weft-court" {
		t.Fatalf("anonymous config = %+v", config)
	}

	if _, err := ResolveGCS("", "weft-court", "token-a", "", nil, "/tmp/key.json", ""); err == nil {
		t.Fatal("two credential forms were accepted")
	} else if werr.ClassOf(err) != werr.Unsupported {
		t.Fatalf("mixed forms class = %s, want Unsupported", werr.ClassOf(err))
	}
	if _, err := ResolveGCS("", "weft-court", "", "", nil, "", ""); err == nil {
		t.Fatal("no credential form was accepted")
	} else if werr.ClassOf(err) != werr.InvalidArgument {
		t.Fatalf("missing form class = %s, want InvalidArgument", werr.ClassOf(err))
	}
	if _, err := ResolveGCS("", "Weft-Court", "token-a", "", nil, "", ""); err == nil {
		t.Fatal("an invalid bucket name was accepted")
	}
	if _, err := ResolveGCS("ftp://example", "weft-court", "token-a", "", nil, "", ""); err == nil {
		t.Fatal("a non-http endpoint was accepted")
	}
}

// swapGCSEnv installs a deterministic environment for lookupEnv and returns a
// restore function. Unlisted variables are treated as absent.
func swapGCSEnv(values map[string]string) func() {
	previous := lookupEnv
	var mu sync.Mutex
	lookupEnv = func(name string) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		value, ok := values[name]
		if !ok || value == "" {
			return "", false
		}
		return value, true
	}
	return func() { lookupEnv = previous }
}

func testServiceAccountJSON(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	document := map[string]any{
		"type":           "service_account",
		"client_email":   "weft-court@example.iam.gserviceaccount.com",
		"private_key":    string(pemBytes),
		"private_key_id": "test-key-id",
		"token_uri":      "https://oauth2.example/token",
		"project_id":     "weft-court",
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return string(data), key
}

func TestGCSServiceAccountAssertionAndExchange(t *testing.T) {
	document, key := testServiceAccountJSON(t)

	var mu sync.Mutex
	exchanges := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("token exchange method = %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("grant_type = %q", got)
		}
		assertion := r.PostForm.Get("assertion")
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			t.Errorf("assertion is not a compact JWT: %q", assertion)
			return
		}
		signingInput := parts[0] + "." + parts[1]
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Errorf("signature decode: %v", err)
			return
		}
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
			t.Errorf("assertion signature: %v", err)
			return
		}
		var header map[string]any
		headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
		_ = json.Unmarshal(headerBytes, &header)
		if header["alg"] != "RS256" || header["typ"] != "JWT" {
			t.Errorf("header = %v", header)
		}
		var claims map[string]any
		claimsBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(claimsBytes, &claims)
		if claims["iss"] != "weft-court@example.iam.gserviceaccount.com" ||
			claims["scope"] != GCSScopeStorageReadWrite {
			t.Errorf("claims = %v", claims)
		}
		mu.Lock()
		exchanges++
		mu.Unlock()
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token-from-court","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer server.Close()

	// Point the key's token_uri at the test server without changing production
	// behaviour.
	document = strings.ReplaceAll(document, "https://oauth2.example/token", server.URL)
	parsed, err := parseGCSServiceAccountKey([]byte(document), "test")
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if parsed.projectID != "weft-court" || parsed.bits != 2048 || parsed.fingerprint == "" {
		t.Fatalf("parsed key = %+v", parsed)
	}
	auth := newGCSAuth(parsed, GCSScopeStorageReadWrite, server.Client())
	now := time.Now().UnixNano()
	first, err := auth.authorization(now)
	if err != nil {
		t.Fatalf("first authorization: %v", err)
	}
	second, err := auth.authorization(now + int64(time.Second))
	if err != nil || first != second {
		t.Fatalf("cached authorization = %q %q err=%v", first, second, err)
	}
	stats := auth.stats()
	if stats.Exchanges != 1 || stats.CacheHits != 1 {
		t.Fatalf("auth stats = %+v", stats)
	}
	if exchanges != 1 {
		t.Fatalf("token endpoint saw %d exchanges, want 1", exchanges)
	}
}

func TestGCSServiceAccountRejectsBadKeys(t *testing.T) {
	cases := map[string]string{
		"not json":   "{",
		"wrong type": `{"type":"authorized_user","client_email":"a@b","private_key":"x"}`,
		"no email":   `{"type":"service_account","private_key":"x"}`,
		"no key":     `{"type":"service_account","client_email":"a@b"}`,
		"bad pem":    `{"type":"service_account","client_email":"a@b","private_key":"not pem"}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseGCSServiceAccountKey([]byte(text), "test"); err == nil {
				t.Fatal("a malformed service-account key was accepted")
			}
		})
	}
}
