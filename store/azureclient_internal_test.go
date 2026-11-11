// Unit tests for the Azure client that need no network: configuration
// resolution, the exact SharedKey string-to-sign, canonical query handling,
// path encoding, and the strict base64 decoder.
package store

import (
	"strings"
	"testing"
	"time"
)

// TestAzureStringToSignIsExact pins the field order and the canonicalised
// resource. The account appears twice for a path-style endpoint, which is what
// Azurite recomputes.
func TestAzureStringToSignIsExact(t *testing.T) {
	headers := map[string]string{
		"x-ms-date":       "Mon, 02 Jan 2006 15:04:05 GMT",
		"x-ms-version":    "2021-12-02",
		"content-length":  "5",
		"content-type":    "application/octet-stream",
		"x-ms-blob-type":  "BlockBlob",
		"if-none-match":   "*",
		"x-ms-meta-empty": "  spaced  ",
	}
	got := azureStringToSign(azureFakeAccount, "PUT", headers, 5,
		"/devstoreaccount1/weft-court/objects/ab/aa", "")
	want := "PUT\n" + // method
		"\n" + // content-encoding
		"\n" + // content-language
		"5\n" + // content-length
		"\n" + // content-md5
		"application/octet-stream\n" + // content-type
		"\n" + // date
		"\n" + // if-modified-since
		"\n" + // if-match
		"*\n" + // if-none-match
		"\n" + // if-unmodified-since
		"\n" + // range
		"x-ms-blob-type:BlockBlob\n" +
		"x-ms-date:Mon, 02 Jan 2006 15:04:05 GMT\n" +
		"x-ms-meta-empty:spaced\n" +
		"x-ms-version:2021-12-02\n" +
		"/devstoreaccount1/devstoreaccount1/weft-court/objects/ab/aa"
	if got != want {
		t.Fatalf("string-to-sign mismatch\n got: %q\nwant: %q", got, want)
	}
}

// TestAzureStringToSignOmitsEmptyContentLength pins the documented rule: the
// header is sent as `0` but the signed value is empty.
func TestAzureStringToSignOmitsEmptyContentLength(t *testing.T) {
	headers := map[string]string{"content-length": "0"}
	got := azureStringToSign("acct", "PUT", headers, 0, "/acct/c/b", "")
	fields := strings.SplitN(got, "\n", 5)
	if len(fields) < 5 {
		t.Fatalf("unexpected string-to-sign shape: %q", got)
	}
	if fields[3] != "" {
		t.Fatalf("content-length field = %q, want empty", fields[3])
	}
}

// TestAzureCanonicalQueryAndResource covers the sorted, encoded query spelling
// and the decoded resource lines (the `objects/` prefix keeps its slash).
func TestAzureCanonicalQueryAndResource(t *testing.T) {
	query := []azureQuery{
		{"restype", "container"},
		{"comp", "list"},
		{"prefix", "objects/"},
		{"maxresults", "1000"},
	}
	canonical := canonicalAzureQuery(query)
	want := "comp=list&maxresults=1000&prefix=objects%2F&restype=container"
	if canonical != want {
		t.Fatalf("canonical query = %q, want %q", canonical, want)
	}
	sign := azureStringToSign("devstoreaccount1", "GET", map[string]string{}, 0,
		"/devstoreaccount1/weft-court", canonical)
	for _, want := range []string{
		"\ncomp:list", "\nmaxresults:1000", "\nprefix:objects/", "\nrestype:container",
	} {
		if !strings.Contains(sign, want) {
			t.Fatalf("string-to-sign is missing %q:\n%s", want, sign)
		}
	}
}

// TestAzurePathEncoding keeps `/` for logical keys and escapes everything else
// outside the unreserved set.
func TestAzurePathEncoding(t *testing.T) {
	if got := encodeAzurePath("objects/ab/deadbeef"); got != "objects/ab/deadbeef" {
		t.Fatalf("encodeAzurePath = %q", got)
	}
	if got := encodeAzurePath("refs/tags/a b+c"); got != "refs/tags/a%20b%2Bc" {
		t.Fatalf("encodeAzurePath = %q", got)
	}
	if got := encodeAzureComponent("objects/ab"); got != "objects%2Fab" {
		t.Fatalf("encodeAzureComponent = %q", got)
	}
	if got := percentDecode("objects%2Fab%20c"); got != "objects/ab c" {
		t.Fatalf("percentDecode = %q", got)
	}
	if got := percentDecode("no-escapes"); got != "no-escapes" {
		t.Fatalf("percentDecode = %q", got)
	}
}

// TestDecodeBase64AnyIsStrict mirrors the Rust decoder's acceptance rules.
func TestDecodeBase64AnyIsStrict(t *testing.T) {
	accepted := map[string]string{
		"":         "",
		"Zg==":     "f",
		"Zm8=":     "fo",
		"Zm9v":     "foo",
		"Zm9vYg==": "foob",
		"-_8":      "\xfb\xff",
	}
	for text, want := range accepted {
		got, err := decodeBase64Any(text)
		if err != nil {
			t.Fatalf("decodeBase64Any(%q) = %v", text, err)
		}
		if string(got) != want {
			t.Fatalf("decodeBase64Any(%q) = %q, want %q", text, got, want)
		}
	}
	for _, text := range []string{"a", "abcde", "Zm9v!", "Zm 9v", "Z===", "Zg=", "Zh==", "Zg==="} {
		if _, err := decodeBase64Any(text); err == nil {
			t.Fatalf("decodeBase64Any(%q) accepted a malformed value", text)
		}
	}
}

// TestAzureResolveRejectsAmbiguousCredentials proves the client refuses to
// guess which credential the endpoint should see.
func TestAzureResolveRejectsAmbiguousCredentials(t *testing.T) {
	anonymous := true
	cases := []struct {
		name string
		key  string
		sas  string
		anon *bool
	}{
		{"none", "", "", nil},
		{"key and sas", "a2V5LWtleS1rZXkta2V5LWtleQ==", "sv=2021-08-06&sp=r", nil},
		{"key and anonymous", "a2V5LWtleS1rZXkta2V5LWtleQ==", "", &anonymous},
	}
	for _, c := range cases {
		if _, err := ResolveAzure("http://127.0.0.1:10000/devstoreaccount1", "weft-court", "devstoreaccount1", c.key, c.sas, c.anon, 0); err == nil {
			t.Fatalf("%s: ambiguous credentials were accepted", c.name)
		}
	}
	config, err := ResolveAzure("http://127.0.0.1:10000/devstoreaccount1", "weft-court", "devstoreaccount1", azureFakeKey, "", nil, 60)
	if err != nil {
		t.Fatalf("single key form: %v", err)
	}
	if config.LockLease != 60*time.Second {
		t.Fatalf("lock lease = %v", config.LockLease)
	}
}

// TestAzureConfigValidation covers the field-level refusals.
func TestAzureConfigValidation(t *testing.T) {
	base := AzureConfig{
		Endpoint:  "http://127.0.0.1:10000/devstoreaccount1",
		Container: "weft-court",
		Account:   "devstoreaccount1",
		Key:       azureFakeKey,
		LockLease: time.Minute,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline config rejected: %v", err)
	}
	broken := []struct {
		name   string
		mutate func(*AzureConfig)
	}{
		{"empty endpoint", func(c *AzureConfig) { c.Endpoint = "" }},
		{"bad scheme", func(c *AzureConfig) { c.Endpoint = "ftp://host" }},
		{"empty account", func(c *AzureConfig) { c.Account = "" }},
		{"uppercase account", func(c *AzureConfig) { c.Account = "DevStoreAccount1" }},
		{"short container", func(c *AzureConfig) { c.Container = "ab" }},
		{"uppercase container", func(c *AzureConfig) { c.Container = "Weft-Court" }},
		{"leading hyphen", func(c *AzureConfig) { c.Container = "-weft" }},
		{"invalid key", func(c *AzureConfig) { c.Key = "not base64" }},
		{"short key", func(c *AzureConfig) { c.Key = "Zm9v" }},
		{"sas with question mark", func(c *AzureConfig) { c.SASToken = "?sv=1" }},
	}
	for _, c := range broken {
		config := base
		c.mutate(&config)
		if err := config.Validate(); err == nil {
			t.Fatalf("%s: config was accepted", c.name)
		}
	}
}

// TestAzureDevKeyDecodes pins the documented Azurite development key length.
func TestAzureDevKeyDecodes(t *testing.T) {
	key, err := decodeBase64Any(azureFakeKey)
	if err != nil {
		t.Fatalf("dev key: %v", err)
	}
	if len(key) != 64 {
		t.Fatalf("dev key decoded to %d bytes, want 64", len(key))
	}
}
