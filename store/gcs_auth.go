// Google service-account authentication (RS256 JWT bearer flow), standard
// library only.
//
// The key file is the JSON document Google Cloud issues
// (`type: service_account`): `client_email`, `private_key` (PEM), `token_uri`,
// and `project_id`. The backend mints an assertion
//
//	{"alg":"RS256","typ":"JWT"}.{"iss":<email>,"scope":<scope>,
//	 "aud":<token_uri>,"iat":<now>,"exp":<now+3600>}
//
// signs the SHA-256 digest with RSA PKCS#1 v1.5, and exchanges it at
// `token_uri` for an OAuth2 bearer token (`grant_type=urn:ietf:params:oauth:
// grant-type:jwt-bearer`). Tokens are cached until a bounded refresh window.
//
// No secret is ever rendered: errors name the field, diagnostics name the key
// fingerprint only. This is a real implementation, not a simulation; a live
// exchange against Google needs a real key, which is not present in the court.
package store

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

// GCS default scope and token endpoint.
const (
	GCSScopeStorageReadWrite = "https://www.googleapis.com/auth/devstorage.read_write"
	GCSScopeStorageReadOnly  = "https://www.googleapis.com/auth/devstorage.read_only"
	gcsDefaultTokenURI       = "https://oauth2.googleapis.com/token"
	gcsAssertionLifetimeSecs = 3600
	gcsMaxRefreshWindowNS    = int64(300 * time.Second)
	gcsMaxKeyFileBytes       = 1 << 20
	gcsMaxTokenReplyBytes    = 1 << 20
	gcsMinRSAKeyBits         = 2048
	gcsMaxRSAKeyBits         = 8192
)

// gcsServiceAccountKey is a parsed, validated service-account key.
type gcsServiceAccountKey struct {
	clientEmail string
	projectID   string
	tokenURI    string
	privateKey  *rsa.PrivateKey
	fingerprint string
	bits        int
}

// gcsServiceAccountFile is the JSON key document.
type gcsServiceAccountFile struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
	ProjectID    string `json:"project_id"`
}

// loadGCSServiceAccountKey reads and validates a service-account JSON file.
func loadGCSServiceAccountKey(path string) (*gcsServiceAccountKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "service-account key `%s`", path)
	}
	if uint64(info.Size()) > gcsMaxKeyFileBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"service-account key `%s` is %d bytes, above the %d-byte bound",
			path, info.Size(), gcsMaxKeyFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "service-account key `%s`", path)
	}
	return parseGCSServiceAccountKey(data, path)
}

func parseGCSServiceAccountKey(data []byte, label string) (*gcsServiceAccountKey, error) {
	var file gcsServiceAccountFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, werr.Newf(werr.InvalidArgument,
			"service-account key `%s` is not valid JSON: %s", label, err)
	}
	if file.Type != "service_account" {
		return nil, werr.Newf(werr.InvalidArgument,
			"service-account key `%s` has type `%s`, expected `service_account`",
			label, file.Type)
	}
	if strings.TrimSpace(file.ClientEmail) == "" {
		return nil, werr.Newf(werr.InvalidArgument,
			"service-account key `%s` has no `client_email`", label)
	}
	if strings.TrimSpace(file.PrivateKey) == "" {
		return nil, werr.Newf(werr.InvalidArgument,
			"service-account key `%s` has no `private_key`", label)
	}
	tokenURI := strings.TrimSpace(file.TokenURI)
	if tokenURI == "" {
		tokenURI = gcsDefaultTokenURI
	}
	if parsed, err := url.Parse(tokenURI); err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, werr.Newf(werr.InvalidArgument,
			"service-account key `%s` has an unusable `token_uri`", label)
	}
	key, err := parseRSAPrivateKeyPEM(file.PrivateKey)
	if err != nil {
		return nil, werr.Newf(werr.InvalidArgument,
			"service-account key `%s`: %s", label, err)
	}
	digest := sha256.Sum256(key.PublicKey.N.Bytes())
	return &gcsServiceAccountKey{
		clientEmail: strings.TrimSpace(file.ClientEmail),
		projectID:   strings.TrimSpace(file.ProjectID),
		tokenURI:    tokenURI,
		privateKey:  key,
		fingerprint: hex.EncodeToString(digest[:8]),
		bits:        key.N.BitLen(),
	}, nil
}

func parseRSAPrivateKeyPEM(text string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, fmt.Errorf("private_key is not PEM")
	}
	var parsed any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("private_key PEM type `%s` is not PKCS#8 or PKCS#1", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("private_key is not a valid RSA key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private_key is not an RSA key")
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("private_key failed validation: %w", err)
	}
	if key.N.BitLen() < gcsMinRSAKeyBits || key.N.BitLen() > gcsMaxRSAKeyBits {
		return nil, fmt.Errorf("private_key is %d bits; require %d..=%d",
			key.N.BitLen(), gcsMinRSAKeyBits, gcsMaxRSAKeyBits)
	}
	if key.E < 3 {
		return nil, fmt.Errorf("private_key has an unusable public exponent")
	}
	return key, nil
}

// assertion builds the signed JWT for one token exchange.
func (k *gcsServiceAccountKey) assertion(scope string, nowNS int64) (string, error) {
	if strings.TrimSpace(scope) == "" {
		return "", werr.Newf(werr.InvalidArgument, "GCS service-account scope must not be empty")
	}
	now := nowNS / int64(time.Second)
	header := struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: "RS256", Typ: "JWT"}
	claims := struct {
		Iss   string `json:"iss"`
		Scope string `json:"scope"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}{
		Iss: k.clientEmail, Scope: scope, Aud: k.tokenURI,
		Iat: now, Exp: now + gcsAssertionLifetimeSecs,
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", werr.Wrap(werr.Io, err, "GCS assertion header")
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", werr.Wrap(werr.Io, err, "GCS assertion claims")
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, k.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", werr.Wrap(werr.Io, err, "GCS assertion signature")
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// gcsTokenInfo is one exchanged bearer token.
type gcsTokenInfo struct {
	accessToken string
	expiresNS   int64
}

// gcsAuthStats is diagnostic evidence only.
type gcsAuthStats struct {
	Exchanges uint64
	CacheHits uint64
	Refusals  uint64
}

// gcsAuth mints and caches service-account tokens.
type gcsAuth struct {
	key    *gcsServiceAccountKey
	scope  string
	client *http.Client

	mu        sync.Mutex
	token     string
	expiresNS int64
	exchanges uint64
	cacheHits uint64
	refusals  uint64
}

func newGCSAuth(key *gcsServiceAccountKey, scope string, client *http.Client) *gcsAuth {
	return &gcsAuth{key: key, scope: scope, client: client}
}

func (a *gcsAuth) stats() gcsAuthStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return gcsAuthStats{Exchanges: a.exchanges, CacheHits: a.cacheHits, Refusals: a.refusals}
}

// authorization returns a bearer token, exchanging an assertion when the cache
// is empty or inside the refresh window.
func (a *gcsAuth) authorization(nowNS int64) (string, error) {
	a.mu.Lock()
	if a.token != "" && nowNS < a.expiresNS {
		token := a.token
		a.cacheHits++
		a.mu.Unlock()
		return token, nil
	}
	a.mu.Unlock()
	token, expiresNS, err := a.exchange(nowNS)
	if err != nil {
		a.mu.Lock()
		a.refusals++
		a.mu.Unlock()
		return "", err
	}
	a.mu.Lock()
	a.token = token
	a.expiresNS = expiresNS
	a.exchanges++
	a.mu.Unlock()
	return token, nil
}

func (a *gcsAuth) exchange(nowNS int64) (string, int64, error) {
	assertion, err := a.key.assertion(a.scope, nowNS)
	if err != nil {
		return "", 0, err
	}
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	request, err := http.NewRequest("POST", a.key.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, werr.Wrap(werr.Io, err, "GCS token exchange request")
	}
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	request.Header.Set("user-agent", "weftfs-gcs/1")
	response, err := a.client.Do(request)
	if err != nil {
		return "", 0, werr.Wrap(werr.Io, err, "GCS token exchange")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, gcsMaxTokenReplyBytes+1))
	if err != nil {
		return "", 0, werr.Wrap(werr.Io, err, "GCS token reply")
	}
	if len(body) > gcsMaxTokenReplyBytes {
		return "", 0, werr.Newf(werr.LimitExceeded,
			"GCS token reply exceeded the %d-byte bound", gcsMaxTokenReplyBytes)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return "", 0, werr.Newf(werr.Unauthorized,
			"GCS token exchange for %s was refused (HTTP %d)", a.key.clientEmail, response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return "", 0, werr.Newf(werr.Io,
			"GCS token exchange for %s returned HTTP %d", a.key.clientEmail, response.StatusCode)
	}
	var reply struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   any    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &reply); err != nil {
		return "", 0, werr.Newf(werr.Io,
			"GCS token exchange reply is not JSON: %s", err)
	}
	if strings.TrimSpace(reply.AccessToken) == "" {
		return "", 0, werr.Newf(werr.Io, "GCS token exchange reply carried no access_token")
	}
	expiresIn := int64(3600)
	switch value := reply.ExpiresIn.(type) {
	case float64:
		expiresIn = int64(value)
	case string:
		if parsed, err := time.ParseDuration(value + "s"); err == nil {
			expiresIn = int64(parsed / time.Second)
		}
	}
	if expiresIn <= 0 {
		return "", 0, werr.Newf(werr.Io, "GCS token reply carried a non-positive lifetime")
	}
	window := int64(expiresIn) * int64(time.Second) / 2
	if window > gcsMaxRefreshWindowNS {
		window = gcsMaxRefreshWindowNS
	}
	return reply.AccessToken, nowNS + window, nil
}
