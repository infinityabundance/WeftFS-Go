// S3-compatible HTTP client: SigV4 signing, conditional writes, ranged reads,
// and ListObjectsV2, implemented over the standard library only.
//
// This is the Go port of the request layer of Rust `src/s3.rs`. The logical key
// layout is unchanged from the local layout, so a store published through this
// client is byte-identical to one published on a POSIX filesystem:
//
//	objects/<ab>/<hash>
//	manifests/<ab>/<hash>
//	indexes/<ab>/<hash>.idx
//	packs/<ab>/<hash>
//	pack-catalog/<ab>/<hash>
//	commits/<generation>.commit
//	refs/snapshots/<name>
//	FORMAT, LOCK, superblock, quota, quota.migrated
//	access/counts.v1, access/journal.v1
//
// # Conditional-write forms
//
// A writable open *measures* how the endpoint compares `If-Match` against an
// entity tag. AWS S3 and MinIO compare the opaque value and accept the quoted
// form; Ceph RGW 19.2.0 compares the header bytes literally against its
// unquoted ETag. The probe requires a matching write in one form to succeed and
// a stale write in the *same* form to be refused with the winner's bytes
// intact. An endpoint that ignores `If-None-Match: *` or accepts a stale
// `If-Match` is refused with `UnsupportedVersion`; there is no fallback.
//
// # Scope
//
// One S3-compatible endpoint, one bucket, single writer under the fenced `LOCK`
// object. `durable_fsync` means "the provider acknowledged the write": S3 has
// no separate fsync primitive. No AWS, multi-node, fleet, media, or power-loss
// claim is made.
package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	// s3MaxObjectBytes bounds one GET or PUT. It matches the Rust backend's
	// MAX_OBJECT_BYTES (MAX_CHUNK_SIZE * 64).
	s3MaxObjectBytes = uint64(1) << 30
	// s3EmptySHA256 is the SHA-256 of an empty body, used for GET/HEAD/DELETE
	// and empty PUTs exactly like the Rust client.
	s3EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	s3LockSchema     = "weftfs-s3-lock v2"
	s3LockSchemaV1   = "weftfs-s3-lock v1"
	s3ReleasedSchema = "weftfs-s3-lock-released v1"
)

// S3Config is the endpoint, bucket, and credentials of one S3-compatible store.
type S3Config struct {
	// Endpoint is `http://host:port` or `https://host`, with an optional path
	// prefix (for example a gateway that serves buckets under `/s3`).
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	Region   string `json:"region"`
	// AccessKey and SecretKey are the SigV4 credential. SessionToken, when set,
	// is sent as `x-amz-security-token` and signed.
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"-"`
	// PathStyle selects `endpoint/bucket/key`. Default true, required by the
	// MinIO court. Virtual-hosted style is implemented by the signer as well.
	PathStyle bool `json:"path_style"`
	// LockLease bounds a writer lease. A crashed writer leaves a stale LOCK
	// that becomes reclaimable after this duration.
	LockLease time.Duration `json:"lock_lease"`
	// RequestTimeout bounds one HTTP request.
	RequestTimeout time.Duration `json:"request_timeout"`
}

// minLockLease is the shortest lease that can bound one publication.
const minLockLease = time.Second

// S3ConfigFromEnv builds a configuration from `WEFT_S3_*` first and the
// standard AWS names second. Explicit CLI values are applied by ResolveS3.
func S3ConfigFromEnv() S3Config {
	leaseSecs := uint64(900)
	if text := firstEnv("WEFT_S3_LOCK_LEASE_SECS"); text != "" {
		if value, err := strconv.ParseUint(text, 10, 64); err == nil {
			leaseSecs = value
		}
	}
	if leaseSecs < uint64(minLockLease/time.Second) {
		leaseSecs = uint64(minLockLease / time.Second)
	}
	return S3Config{
		Endpoint:       firstEnv("WEFT_S3_ENDPOINT", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL"),
		Bucket:         firstEnv("WEFT_S3_BUCKET", "AWS_S3_BUCKET"),
		Region:         firstEnvDefault("us-east-1", "WEFT_S3_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"),
		AccessKey:      firstEnv("WEFT_S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID"),
		SecretKey:      firstEnv("WEFT_S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"),
		SessionToken:   firstEnv("WEFT_S3_SESSION_TOKEN", "AWS_SESSION_TOKEN"),
		PathStyle:      true,
		LockLease:      time.Duration(leaseSecs) * time.Second,
		RequestTimeout: 60 * time.Second,
	}
}

// ResolveS3 merges explicit values over the environment. Every required field
// must be present; there is no implicit local fallback.
func ResolveS3(endpoint, bucket, region, accessKey, secretKey, sessionToken string) (S3Config, error) {
	config := S3ConfigFromEnv()
	if endpoint != "" {
		config.Endpoint = endpoint
	}
	if bucket != "" {
		config.Bucket = bucket
	}
	if region != "" {
		config.Region = region
	}
	if accessKey != "" {
		config.AccessKey = accessKey
	}
	if secretKey != "" {
		config.SecretKey = secretKey
	}
	if sessionToken != "" {
		config.SessionToken = sessionToken
	}
	if err := config.Validate(); err != nil {
		return S3Config{}, err
	}
	return config, nil
}

// Validate checks the configuration. It never guesses a missing field.
func (c S3Config) Validate() error {
	if c.Endpoint == "" {
		return werr.Newf(werr.InvalidArgument,
			"S3 backend needs an endpoint (`--s3-endpoint`, WEFT_S3_ENDPOINT, AWS_ENDPOINT_URL_S3, or AWS_ENDPOINT_URL)")
	}
	if c.Bucket == "" {
		return werr.Newf(werr.InvalidArgument, "S3 backend needs a bucket (`--s3-bucket` or WEFT_S3_BUCKET)")
	}
	if c.AccessKey == "" {
		return werr.Newf(werr.InvalidArgument, "S3 backend needs an access key (`--s3-access-key` or AWS_ACCESS_KEY_ID)")
	}
	if c.SecretKey == "" {
		return werr.Newf(werr.InvalidArgument, "S3 backend needs a secret key (`--s3-secret-key` or AWS_SECRET_ACCESS_KEY)")
	}
	for i := 0; i < len(c.Bucket); i++ {
		b := c.Bucket[i]
		if !(b >= 'a' && b <= 'z') && !(b >= '0' && b <= '9') && b != '-' && b != '.' {
			return werr.Newf(werr.InvalidArgument, "S3 bucket `%s` is not a valid DNS-style bucket name", c.Bucket)
		}
	}
	if _, err := parseS3Endpoint(c.Endpoint); err != nil {
		return err
	}
	if c.Region == "" {
		return werr.Newf(werr.InvalidArgument, "S3 region must not be empty")
	}
	return nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value, ok := lookupEnv(name); ok && value != "" {
			return value
		}
	}
	return ""
}

func firstEnvDefault(fallback string, names ...string) string {
	if value := firstEnv(names...); value != "" {
		return value
	}
	return fallback
}

// lookupEnv is a variable for tests; production reads the process environment.
var lookupEnv = os.LookupEnv

func defaultLookupEnv(name string) (string, bool) { return os.LookupEnv(name) }

// s3Endpoint is a parsed endpoint.
type s3Endpoint struct {
	Scheme    string
	Authority string
	BasePath  string
}

func parseS3Endpoint(text string) (s3Endpoint, error) {
	parsed, err := url.Parse(text)
	if err != nil {
		return s3Endpoint{}, werr.Newf(werr.InvalidArgument, "S3 endpoint `%s` is not a URL: %s", text, err.Error())
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return s3Endpoint{}, werr.Newf(werr.InvalidArgument, "S3 endpoint `%s` must be http:// or https://", text)
	}
	if parsed.Host == "" {
		return s3Endpoint{}, werr.Newf(werr.InvalidArgument, "S3 endpoint `%s` has no host", text)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return s3Endpoint{}, werr.Newf(werr.InvalidArgument, "S3 endpoint `%s` must not carry a query or fragment", text)
	}
	base := strings.TrimSuffix(parsed.EscapedPath(), "/")
	return s3Endpoint{Scheme: parsed.Scheme, Authority: parsed.Host, BasePath: base}, nil
}

// IfMatchForm is how the endpoint compares an `If-Match` header with its ETag.
type IfMatchForm int

const (
	// IfMatchAsReturned sends the ETag exactly as the endpoint returned it.
	IfMatchAsReturned IfMatchForm = iota
	// IfMatchDequoted strips the surrounding double quotes.
	IfMatchDequoted
)

// String is the label used in diagnostics and receipts.
func (f IfMatchForm) String() string {
	if f == IfMatchDequoted {
		return "dequoted"
	}
	return "quoted-as-returned"
}

// Encode applies the form to a raw ETag header value.
func (f IfMatchForm) Encode(etag string) string {
	if f == IfMatchDequoted {
		return stripETagQuotes(etag)
	}
	return etag
}

func stripETagQuotes(etag string) string {
	trimmed := strings.TrimSpace(etag)
	if len(trimmed) >= 2 && trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"' {
		return trimmed[1 : len(trimmed)-1]
	}
	return trimmed
}

// s3Query is one canonical query parameter.
type s3Query struct {
	Name  string
	Value string
}

// s3Header is one extra request header, signed like every other header.
type s3Header struct {
	Name  string
	Value string
}

// s3Response is one response with bounded body.
type s3Response struct {
	Status        int
	ETag          string
	ContentRange  string
	ContentLength int64
	LastModified  time.Time
	Body          []byte
}

type s3Stats struct {
	reads        atomic.Uint64
	rangeReads   atomic.Uint64
	bytesRead    atomic.Uint64
	writes       atomic.Uint64
	bytesWritten atomic.Uint64
	conflicts    atomic.Uint64
	requests     atomic.Uint64
}

// S3StatsSnapshot is a copy of the client counters for diagnostics.
type S3StatsSnapshot struct {
	Requests            uint64 `json:"requests"`
	Reads               uint64 `json:"reads"`
	RangeReads          uint64 `json:"range_reads"`
	BytesRead           uint64 `json:"bytes_read"`
	Writes              uint64 `json:"writes"`
	BytesWritten        uint64 `json:"bytes_written"`
	ConditionalConflict uint64 `json:"conditional_conflicts"`
}

// s3Client is one connection to one bucket. Blob and commit planes share the
// same client so the measured If-Match form and the LOCK lease are single.
type s3Client struct {
	config   S3Config
	endpoint s3Endpoint
	http     *http.Client

	mu       sync.Mutex
	probeMu  sync.Mutex
	notes    []string
	probed   bool
	probeErr error
	form     IfMatchForm

	lockMu  sync.Mutex
	lease   *s3LockLease
	stats   s3Stats
	counter atomic.Uint64
}

// s3LockLease is this handle's copy of the published LOCK record.
type s3LockLease struct {
	owner      string
	fence      uint64
	sequence   uint64
	deadlineNS int64
	renewedNS  int64
	etag       string
}

func newS3Client(config S3Config) (*s3Client, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	endpoint, err := parseS3Endpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}
	if config.LockLease < minLockLease {
		config.LockLease = minLockLease
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = 60 * time.Second
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: config.RequestTimeout,
		DisableCompression:    true,
	}
	return &s3Client{
		config:   config,
		endpoint: endpoint,
		http:     &http.Client{Timeout: config.RequestTimeout, Transport: transport},
	}, nil
}

func (c *s3Client) note(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.notes) < 32 {
		c.notes = append(c.notes, text)
	}
}

func (c *s3Client) diagnostics() []string {
	c.mu.Lock()
	out := append([]string(nil), c.notes...)
	probed := c.probed
	form := c.form
	c.mu.Unlock()
	if probed {
		out = append(out, "S3 If-Match form measured at open: "+form.String())
	}
	if conflicts := c.stats.conflicts.Load(); conflicts > 0 {
		out = append(out, fmt.Sprintf("S3 conditional writes observed %d lost/retried race(s)", conflicts))
	}
	return out
}

func (c *s3Client) headIfMatchForm() IfMatchForm {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.form
}

// host returns the Host header value for the configured addressing style.
func (c *s3Client) host() string {
	if c.config.PathStyle {
		return c.endpoint.Authority
	}
	return c.config.Bucket + "." + c.endpoint.Authority
}

// urlPath is the encoded request path, starting with `/`.
func (c *s3Client) urlPath(keyPath string) string {
	encoded := encodeS3Path(keyPath)
	if c.config.PathStyle {
		if encoded == "" {
			if c.endpoint.BasePath == "" {
				return "/" + c.config.Bucket
			}
			return c.endpoint.BasePath + "/" + c.config.Bucket
		}
		if c.endpoint.BasePath == "" {
			return "/" + c.config.Bucket + "/" + encoded
		}
		return c.endpoint.BasePath + "/" + c.config.Bucket + "/" + encoded
	}
	if encoded == "" {
		if c.endpoint.BasePath == "" {
			return "/"
		}
		return c.endpoint.BasePath
	}
	if c.endpoint.BasePath == "" {
		return "/" + encoded
	}
	return c.endpoint.BasePath + "/" + encoded
}

// do performs one signed request. HTTP status codes are returned, never
// converted to errors: the caller decides what each status means.
func (c *s3Client) do(method, keyPath string, query []s3Query, body []byte, extra []s3Header) (*s3Response, error) {
	host := c.host()
	path := c.urlPath(keyPath)
	payloadHash := s3EmptySHA256
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	headers := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
	}
	if c.config.SessionToken != "" {
		headers["x-amz-security-token"] = c.config.SessionToken
	}
	for _, header := range extra {
		headers[strings.ToLower(header.Name)] = header.Value
	}
	canonicalQuery := canonicalS3Query(query)
	signature := signS3Request(s3SignatureInput{
		Method: method, Host: host, Path: path, CanonicalQuery: canonicalQuery,
		Headers: headers, PayloadHash: payloadHash, AmzDate: amzDate, Date: date,
		Region: c.config.Region, AccessKey: c.config.AccessKey, SecretKey: c.config.SecretKey,
	})
	authorization := signature.Authorization

	rawURL := c.endpoint.Scheme + "://" + host + path
	if canonicalQuery != "" {
		rawURL += "?" + canonicalQuery
	}
	request, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot build S3 %s %s", method, c.describe(keyPath))
	}
	for name, value := range headers {
		// `host` is set from the URL; setting it again is harmless and keeps the
		// wire headers identical to the signed set.
		request.Header.Set(name, value)
	}
	request.Header.Set("Authorization", authorization)
	if len(body) > 0 {
		request.ContentLength = int64(len(body))
	}
	c.stats.requests.Add(1)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "S3 %s %s failed", method, c.describe(keyPath))
	}
	defer response.Body.Close()
	out := &s3Response{
		Status:        response.StatusCode,
		ETag:          response.Header.Get("ETag"),
		ContentRange:  response.Header.Get("Content-Range"),
		ContentLength: response.ContentLength,
	}
	if modified := response.Header.Get("Last-Modified"); modified != "" {
		if when, err := http.ParseTime(modified); err == nil {
			out.LastModified = when
		}
	}
	if method == "HEAD" {
		if out.ContentLength < 0 {
			out.ContentLength = 0
		}
		return out, nil
	}
	data, err := readS3Body(response.Body, out.ContentLength, keyPath)
	if err != nil {
		return nil, err
	}
	out.Body = data
	return out, nil
}

func (c *s3Client) describe(keyPath string) string {
	if keyPath == "" {
		return "bucket " + c.config.Bucket
	}
	return "s3://" + c.config.Bucket + "/" + keyPath
}

// s3SignatureInput is everything SigV4 signs. Keeping it a pure value lets a
// test compare the exact canonical request and signature with the published
// AWS example.
type s3SignatureInput struct {
	Method         string
	Host           string
	Path           string
	CanonicalQuery string
	Headers        map[string]string
	PayloadHash    string
	AmzDate        string
	Date           string
	Region         string
	AccessKey      string
	SecretKey      string
}

type s3Signature struct {
	Authorization    string
	CanonicalRequest string
	StringToSign     string
	SignedHeaders    string
}

func signS3Request(in s3SignatureInput) s3Signature {
	signedNames := make([]string, 0, len(in.Headers))
	for name := range in.Headers {
		signedNames = append(signedNames, name)
	}
	sortStrings(signedNames)
	var canonicalHeaders strings.Builder
	for _, name := range signedNames {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(in.Headers[name]))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(signedNames, ";")
	canonicalRequest := in.Method + "\n" + in.Path + "\n" + in.CanonicalQuery + "\n" +
		canonicalHeaders.String() + "\n" + signedHeaders + "\n" + in.PayloadHash
	scope := in.Date + "/" + in.Region + "/s3/aws4_request"
	requestHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := "AWS4-HMAC-SHA256\n" + in.AmzDate + "\n" + scope + "\n" + hex.EncodeToString(requestHash[:])
	signingKey := deriveSigningKey(in.SecretKey, in.Date, in.Region)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))
	authorization := "AWS4-HMAC-SHA256 Credential=" + in.AccessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	return s3Signature{
		Authorization: authorization, CanonicalRequest: canonicalRequest,
		StringToSign: stringToSign, SignedHeaders: signedHeaders,
	}
}

// readS3Body reads at most s3MaxObjectBytes and fails closed above it.
func readS3Body(reader io.Reader, contentLength int64, keyPath string) ([]byte, error) {
	if contentLength > 0 && uint64(contentLength) > s3MaxObjectBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"S3 object `%s` is %d bytes, above the backend's %d-byte bound", keyPath, contentLength, s3MaxObjectBytes)
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(s3MaxObjectBytes)+1))
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot read S3 response for %s", keyPath)
	}
	if uint64(len(data)) > s3MaxObjectBytes {
		return nil, werr.Newf(werr.LimitExceeded,
			"S3 object `%s` exceeded the backend's %d-byte bound", keyPath, s3MaxObjectBytes)
	}
	return data, nil
}

// get reads a whole key or a range. `length == 0` reads the whole object.
func (c *s3Client) get(keyPath string, offset, length uint64) (*s3Response, error) {
	var extra []s3Header
	if length > 0 {
		end := offset + length - 1
		if end < offset {
			return nil, werr.Newf(werr.LimitExceeded, "range end overflows u64")
		}
		extra = append(extra, s3Header{"range", fmt.Sprintf("bytes=%d-%d", offset, end)})
	}
	return c.do("GET", keyPath, nil, nil, extra)
}

func (c *s3Client) head(keyPath string) (*s3Response, error) {
	return c.do("HEAD", keyPath, nil, nil, nil)
}

func (c *s3Client) delete(keyPath string) (*s3Response, error) {
	return c.do("DELETE", keyPath, nil, nil, nil)
}

// putConditional publishes `body` under `keyPath`. When ifMatch is nil the
// write is create-once (`If-None-Match: *`); otherwise it is conditional on the
// endpoint's current ETag. `ok == false` means the precondition failed: an
// existing key for a create-once write, or a changed ETag for a conditional
// write.
func (c *s3Client) putConditional(keyPath string, body []byte, ifMatch *string, countConflict bool) (string, bool, error) {
	return c.putConditionalHeader(keyPath, body, c.conditionalHeader(ifMatch), countConflict)
}

func (c *s3Client) conditionalHeader(ifMatch *string) string {
	if ifMatch == nil {
		return ""
	}
	return c.headIfMatchForm().Encode(*ifMatch)
}

// putConditionalHeader sends the literal header value. Only the probe passes a
// value that was not encoded through IfMatchForm.
func (c *s3Client) putConditionalHeader(keyPath string, body []byte, ifMatchValue string, countConflict bool) (string, bool, error) {
	if uint64(len(body)) > s3MaxObjectBytes {
		return "", false, werr.Newf(werr.LimitExceeded,
			"object is %d bytes, above the backend's %d-byte bound", len(body), s3MaxObjectBytes)
	}
	extra := []s3Header{{"if-none-match", "*"}}
	if ifMatchValue != "" {
		extra = []s3Header{{"if-match", ifMatchValue}}
	}
	response, err := c.do("PUT", keyPath, nil, body, extra)
	if err != nil {
		return "", false, err
	}
	switch {
	case response.Status >= 200 && response.Status < 300:
		c.stats.writes.Add(1)
		c.stats.bytesWritten.Add(uint64(len(body)))
		return response.ETag, true, nil
	case response.Status == http.StatusPreconditionFailed, response.Status == http.StatusConflict:
		if countConflict {
			c.stats.conflicts.Add(1)
		}
		return "", false, nil
	case response.Status == http.StatusForbidden:
		return "", false, werr.Newf(werr.Unauthorized, "S3 denied PUT %s", c.describe(keyPath))
	default:
		return "", false, werr.Newf(werr.Io, "S3 PUT %s returned HTTP %d: %s",
			c.describe(keyPath), response.Status, responseSnippet(response.Body))
	}
}

// putReplace replaces a mutable record atomically. It reads the current ETag,
// writes with If-Match, and retries a lost race from a fresh read; when the key
// is absent it creates it once. It never issues an unconditional overwrite.
func (c *s3Client) putReplace(keyPath string, body []byte) error {
	for attempt := 0; attempt < 8; attempt++ {
		current, err := c.do("GET", keyPath, nil, nil, nil)
		if err != nil {
			return err
		}
		switch current.Status {
		case http.StatusOK:
			if current.ETag == "" {
				return werr.Newf(werr.Unsupported,
					"S3 endpoint did not return an ETag for %s; refusing an unconditional replacement", c.describe(keyPath))
			}
			etag := current.ETag
			if _, ok, err := c.putConditional(keyPath, body, &etag, true); err != nil {
				return err
			} else if ok {
				return nil
			}
		case http.StatusNotFound:
			if _, ok, err := c.putConditional(keyPath, body, nil, true); err != nil {
				return err
			} else if ok {
				return nil
			}
		case http.StatusForbidden:
			return werr.Newf(werr.Unauthorized, "S3 denied GET %s", c.describe(keyPath))
		default:
			return werr.Newf(werr.Io, "S3 replace %s returned HTTP %d", c.describe(keyPath), current.Status)
		}
	}
	return werr.Newf(werr.Busy, "conditional replacement of %s kept losing a race", c.describe(keyPath))
}

// listObject is one ListObjectsV2 entry.
type listObject struct {
	Key          string
	Size         uint64
	LastModified time.Time
}

type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key          string `xml:"Key"`
		Size         uint64 `xml:"Size"`
		LastModified string `xml:"LastModified"`
	} `xml:"Contents"`
}

// listPrefix enumerates every key under `prefix`, following continuation
// tokens. A missing bucket is an empty result, matching the Rust client.
func (c *s3Client) listPrefix(prefix string) ([]listObject, error) {
	var out []listObject
	token := ""
	for page := 0; page < 10000; page++ {
		query := []s3Query{
			{"list-type", "2"},
			{"prefix", prefix},
			{"max-keys", "1000"},
		}
		if token != "" {
			query = append(query, s3Query{"continuation-token", token})
		}
		response, err := c.do("GET", "", query, nil, nil)
		if err != nil {
			return nil, err
		}
		if response.Status == http.StatusNotFound {
			return out, nil
		}
		if response.Status != http.StatusOK {
			return nil, werr.Newf(werr.Io, "S3 ListObjectsV2 returned HTTP %d: %s",
				response.Status, responseSnippet(response.Body))
		}
		var parsed listBucketResult
		if err := xml.Unmarshal(response.Body, &parsed); err != nil {
			return nil, werr.Wrap(werr.Io, err, "cannot parse S3 ListObjectsV2 response")
		}
		for _, entry := range parsed.Contents {
			when, _ := time.Parse(time.RFC3339Nano, entry.LastModified)
			out = append(out, listObject{Key: entry.Key, Size: entry.Size, LastModified: when})
		}
		if !parsed.IsTruncated {
			return out, nil
		}
		if parsed.NextContinuationToken == "" {
			return nil, werr.Newf(werr.Io, "S3 ListObjectsV2 returned a truncated page with no continuation token")
		}
		token = parsed.NextContinuationToken
	}
	return nil, werr.Newf(werr.LimitExceeded, "S3 ListObjectsV2 exceeded its page bound")
}

// ensureBucket creates the bucket when it does not exist. Idempotent.
func (c *s3Client) ensureBucket() error {
	response, err := c.do("HEAD", "", nil, nil, nil)
	if err != nil {
		return err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		var body []byte
		if c.config.Region != "us-east-1" {
			body = []byte("<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
				"<LocationConstraint>" + xmlEscape(c.config.Region) + "</LocationConstraint></CreateBucketConfiguration>")
		}
		created, err := c.do("PUT", "", nil, body, nil)
		if err != nil {
			return err
		}
		switch created.Status {
		case http.StatusOK, http.StatusNoContent, http.StatusConflict:
			return nil
		default:
			return werr.Newf(werr.Io, "S3 CreateBucket %s returned HTTP %d: %s",
				c.config.Bucket, created.Status, responseSnippet(created.Body))
		}
	default:
		return werr.Newf(werr.Io, "S3 HEAD bucket %s returned HTTP %d", c.config.Bucket, response.Status)
	}
}

func responseSnippet(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 240 {
		text = text[:240]
	}
	if text == "" {
		return "(empty body)"
	}
	return text
}

// ---- signing primitives --------------------------------------------------

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func deriveSigningKey(secret, date, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	return hmacSHA256(kService, []byte("aws4_request"))
}

// encodeS3Path is RFC 3986 encoding with `/` preserved.
func encodeS3Path(path string) string {
	var out strings.Builder
	for i := 0; i < len(path); i++ {
		b := path[i]
		if isUnreserved(b) || b == '/' {
			out.WriteByte(b)
		} else {
			fmt.Fprintf(&out, "%%%02X", b)
		}
	}
	return out.String()
}

// encodeS3Component is RFC 3986 encoding of a single query component.
func encodeS3Component(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if isUnreserved(b) {
			out.WriteByte(b)
		} else {
			fmt.Fprintf(&out, "%%%02X", b)
		}
	}
	return out.String()
}

func isUnreserved(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.' || b == '~'
}

// canonicalS3Query encodes and sorts the query exactly once, so the signed and
// sent query strings cannot drift.
func canonicalS3Query(query []s3Query) string {
	encoded := make([]string, 0, len(query))
	for _, item := range query {
		encoded = append(encoded, encodeS3Component(item.Name)+"="+encodeS3Component(item.Value))
	}
	sortStrings(encoded)
	return strings.Join(encoded, "&")
}

func sortStrings(values []string) {
	// Small slices; insertion sort keeps the import surface minimal and stable.
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return replacer.Replace(value)
}

// ---- fenced LOCK record --------------------------------------------------

// publishedLock is a parsed LOCK object.
type publishedLock struct {
	owner             string
	fence             uint64
	sequence          uint64
	deadlineNS        int64
	renewedNS         int64
	pendingGeneration uint64
	pendingCommit     string
	released          bool
	releasedFrom      string
}

// isLive reports whether a writer still holds the lease at nowNS.
func (l publishedLock) isLive(nowNS int64) bool {
	return !l.released && nowNS <= l.deadlineNS
}

func encodeS3Lock(owner string, fence, sequence uint64, deadlineNS, renewedNS int64, pendingGeneration uint64, pendingCommit string) string {
	if pendingCommit == "" {
		pendingCommit = "-"
	}
	return fmt.Sprintf("%s\nowner=%s\nfence=%d\nsequence=%d\nlease_deadline_ns=%d\nrenewed_ns=%d\npending_generation=%d\npending_commit=%s\n",
		s3LockSchema, owner, fence, sequence, deadlineNS, renewedNS, pendingGeneration, pendingCommit)
}

func encodeS3Released(owner string, fence, sequence uint64, releasedNS int64, releasedFrom string) string {
	return fmt.Sprintf("%s\nowner=%s\nfence=%d\nsequence=%d\nreleased_ns=%d\nreleased_from=%s\n",
		s3ReleasedSchema, owner, fence, sequence, releasedNS, releasedFrom)
}

// parseS3Lock accepts the fenced v2 record, the legacy v1 record (fence 0), and
// the released tombstone. It is a direct port of Rust `writer_fence::parse_lock`.
func parseS3Lock(bytes []byte) (publishedLock, bool) {
	var out publishedLock
	text := string(bytes)
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return out, false
	}
	header := lines[0]
	fields := map[string]string{}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return out, false
		}
		fields[key] = value
	}
	number := func(key string) (int64, bool) {
		value, ok := fields[key]
		if !ok {
			return 0, false
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	unsigned := func(key string) (uint64, bool) {
		value, ok := fields[key]
		if !ok {
			return 0, false
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	switch header {
	case s3LockSchema:
		owner, ok := fields["owner"]
		if !ok {
			return out, false
		}
		fence, ok := unsigned("fence")
		if !ok {
			return out, false
		}
		sequence, ok := unsigned("sequence")
		if !ok {
			return out, false
		}
		deadline, ok := number("lease_deadline_ns")
		if !ok {
			return out, false
		}
		renewed, ok := number("renewed_ns")
		if !ok {
			return out, false
		}
		pending, ok := unsigned("pending_generation")
		if !ok {
			return out, false
		}
		commit, ok := fields["pending_commit"]
		if !ok {
			commit = "-"
		}
		return publishedLock{
			owner: owner, fence: fence, sequence: sequence, deadlineNS: deadline,
			renewedNS: renewed, pendingGeneration: pending, pendingCommit: commit,
		}, true
	case s3LockSchemaV1:
		owner, ok := fields["owner"]
		if !ok {
			return out, false
		}
		deadline, ok := number("expires_ns")
		if !ok {
			return out, false
		}
		return publishedLock{owner: owner, deadlineNS: deadline, pendingCommit: "-"}, true
	case s3ReleasedSchema:
		owner, ok := fields["owner"]
		if !ok {
			return out, false
		}
		fence, ok := unsigned("fence")
		if !ok {
			return out, false
		}
		sequence, ok := unsigned("sequence")
		if !ok {
			return out, false
		}
		released, ok := number("released_ns")
		if !ok {
			return out, false
		}
		return publishedLock{
			owner: owner, fence: fence, sequence: sequence, deadlineNS: released,
			renewedNS: released, pendingCommit: "-", released: true,
			releasedFrom: fields["released_from"],
		}, true
	default:
		return out, false
	}
}

// describeObserved is the non-deciding diagnostic sentence on a refused
// publication, identical to Rust `writer_fence::describe_observed`.
func describeObserved(observed *publishedLock, owner string, fence uint64) string {
	if observed == nil {
		return "; the LOCK is absent"
	}
	if observed.owner != owner || observed.fence != fence {
		return fmt.Sprintf("; the LOCK now names owner %s fence %d", observed.owner, observed.fence)
	}
	if observed.released {
		return "; the LOCK is a released tombstone"
	}
	return "; the LOCK still names this writer, but its own lease expired"
}

func sha256HexBytes(bytes []byte) string {
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

func nowNS() int64 {
	return time.Now().UnixNano()
}
