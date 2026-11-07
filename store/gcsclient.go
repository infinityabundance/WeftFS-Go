// GCS JSON API client: generation preconditions, ranged reads, listing with
// page tokens, simple and resumable uploads, standard library only.
//
// This is the Go port of Rust `src/gcs.rs`. The logical key layout is exactly
// the local layout, so a store published through this client can be read by the
// Rust implementation (and by the POSIX backend) without translation:
//
//	objects/<ab>/<hash>
//	manifests/<ab>/<hash>
//	indexes/<ab>/<commit>.idx
//	packs/<ab>/<hash>
//	pack-catalog/<ab>/<hash>
//	commits/<generation>.commit
//	refs/snapshots/<name>
//	FORMAT, LOCK, superblock, quota, quota.migrated
//	access/counts.v1, access/journal.v1
//
// # Conditional writes
//
// GCS has no ETags for compare-and-swap: the token is the object *generation*.
// `ifGenerationMatch=0` publishes only when the object does not exist;
// `ifGenerationMatch=<n>` replaces only when the object is still at generation
// `n`. A failed precondition is HTTP 412 and becomes `Busy` at the store. A
// writable open *measures* both forms and refuses (`UnsupportedVersion`) an
// endpoint that accepts a stale generation or ignores create-once.
//
// # Authentication
//
// Exactly one credential form: a bearer token (`--gcs-token`,
// WEFT_GCS_ACCESS_TOKEN, GOOGLE_OAUTH_ACCESS_TOKEN), a service-account key
// (`--gcs-credentials`, WEFT_GCS_CREDENTIALS, GOOGLE_APPLICATION_CREDENTIALS)
// exchanged through the RS256 JWT-bearer flow, or `--gcs-anonymous` for an
// emulator. Supplying two forms is refused.
//
// # Durability and scope
//
// `durable_fsync` means "the provider acknowledged the upload". GCS has no
// fsync. The court runs `fake-gcs-server` with a memory backend, so it proves
// protocol and generation-precondition behaviour, not media, power loss,
// multi-node consistency, or a cloud deployment.
package store

import (
	"bytes"
	"encoding/json"
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
	// gcsMaxObjectBytes bounds one GET or upload. It matches the S3 and Rust
	// backends so a store built on any of them has the same object bound.
	gcsMaxObjectBytes = uint64(1) << 30
	// gcsSimpleUploadMax is the JSON API's simple-media-upload bound. Above it
	// the provider requires a resumable upload; the client switches protocol and
	// never truncates.
	gcsSimpleUploadMax = uint64(5) * 1024 * 1024
	// gcsMaxJSONBytes bounds metadata, listing, token, and error bodies.
	gcsMaxJSONBytes = uint64(8) * 1024 * 1024
	// gcsDefaultEndpoint is the public JSON API origin.
	gcsDefaultEndpoint = "https://storage.googleapis.com"

	gcsLockSchema       = "weftfs-gcs-lock v3"
	gcsLockSchemaV2     = "weftfs-gcs-lock v2"
	gcsLockSchemaV1     = "weftfs-gcs-lock v1"
	gcsReleasedSchema   = "weftfs-gcs-lock-released v2"
	gcsReleasedSchemaV1 = "weftfs-gcs-lock-released v1"
)

const gcsMinLockLease = time.Second

// GCSConfig is the endpoint, bucket, and credential of one GCS-compatible
// store. Exactly one credential form must be set.
type GCSConfig struct {
	Endpoint string `json:"endpoint"`
	Bucket   string `json:"bucket"`
	// Token is an OAuth2 bearer token. Never logged.
	Token string `json:"-"`
	// ServiceAccountPath is the JSON key minted by RS256 JWT-bearer. Never
	// rendered; the parsed key carries only a fingerprint in diagnostics.
	ServiceAccountPath string `json:"-"`
	// Scope is the OAuth2 scope requested by the assertion.
	Scope string `json:"scope"`
	// Project creates the bucket when it does not exist.
	Project string `json:"project"`
	// Anonymous sends no Authorization header (emulator court).
	Anonymous bool `json:"anonymous"`
	// LockLease bounds a writer lease. A crashed writer leaves a stale LOCK
	// that becomes reclaimable after this duration.
	LockLease time.Duration `json:"lock_lease"`
	// RequestTimeout bounds one HTTP request.
	RequestTimeout time.Duration `json:"request_timeout"`
}

// GCSConfigFromEnv builds a configuration from WEFT_GCS_* and the standard
// Google variables. Explicit CLI values are applied by ResolveGCS.
func GCSConfigFromEnv() GCSConfig {
	leaseSecs := uint64(900)
	if text := firstEnv("WEFT_GCS_LOCK_LEASE_SECS"); text != "" {
		if value, err := strconv.ParseUint(text, 10, 64); err == nil {
			leaseSecs = value
		}
	}
	if leaseSecs < uint64(gcsMinLockLease/time.Second) {
		leaseSecs = uint64(gcsMinLockLease / time.Second)
	}
	return GCSConfig{
		Endpoint:           firstEnvDefault(gcsDefaultEndpoint, "WEFT_GCS_ENDPOINT"),
		Bucket:             firstEnv("WEFT_GCS_BUCKET"),
		Token:              firstEnv("WEFT_GCS_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"),
		ServiceAccountPath: firstEnv("WEFT_GCS_CREDENTIALS", "GOOGLE_APPLICATION_CREDENTIALS"),
		Scope:              firstEnvDefault(GCSScopeStorageReadWrite, "WEFT_GCS_SCOPE"),
		Project:            firstEnv("WEFT_GCS_PROJECT", "GOOGLE_CLOUD_PROJECT"),
		Anonymous:          envFlag("WEFT_GCS_ANONYMOUS"),
		LockLease:          time.Duration(leaseSecs) * time.Second,
		RequestTimeout:     60 * time.Second,
	}
}

func envFlag(name string) bool {
	value := firstEnv(name)
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ResolveGCS applies explicit values over the environment and refuses an
// ambiguous or missing credential form. `anonymous` only overrides when it is
// non-nil.
func ResolveGCS(endpoint, bucket, token, project string, anonymous *bool, credentials, scope string) (GCSConfig, error) {
	config := GCSConfigFromEnv()
	if endpoint != "" {
		config.Endpoint = endpoint
	}
	if bucket != "" {
		config.Bucket = bucket
	}
	if token != "" {
		config.Token = token
	}
	if project != "" {
		config.Project = project
	}
	if anonymous != nil {
		config.Anonymous = *anonymous
	}
	if credentials != "" {
		config.ServiceAccountPath = credentials
	}
	if scope != "" {
		config.Scope = scope
	}
	if config.Bucket == "" {
		return GCSConfig{}, werr.Newf(werr.InvalidArgument,
			"GCS backend needs a bucket (`--gcs-bucket` or WEFT_GCS_BUCKET)")
	}
	forms := 0
	if config.Token != "" {
		forms++
	}
	if config.ServiceAccountPath != "" {
		forms++
	}
	if config.Anonymous {
		forms++
	}
	if forms > 1 {
		return GCSConfig{}, werr.Newf(werr.Unsupported,
			"GCS backend was given more than one credential form (bearer token, service-account key, anonymous); refusing to guess which one the endpoint should see")
	}
	if forms == 0 {
		return GCSConfig{}, werr.Newf(werr.InvalidArgument,
			"GCS backend needs one credential form: a bearer token (`--gcs-token`, WEFT_GCS_ACCESS_TOKEN, GOOGLE_OAUTH_ACCESS_TOKEN), a service-account key (`--gcs-credentials`, WEFT_GCS_CREDENTIALS, GOOGLE_APPLICATION_CREDENTIALS), or `--gcs-anonymous` for an emulator")
	}
	if err := config.Validate(); err != nil {
		return GCSConfig{}, err
	}
	return config, nil
}

// Validate checks the endpoint and bucket spelling.
func (c GCSConfig) Validate() error {
	if c.Bucket == "" {
		return werr.Newf(werr.InvalidArgument, "GCS bucket must not be empty")
	}
	if len(c.Bucket) > 222 {
		return werr.Newf(werr.InvalidArgument,
			"GCS bucket name is longer than the 222-byte service limit")
	}
	for i := 0; i < len(c.Bucket); i++ {
		ch := c.Bucket[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return werr.Newf(werr.InvalidArgument, "GCS bucket `%s` is not a valid bucket name", c.Bucket)
	}
	if c.Endpoint == "" {
		return werr.Newf(werr.InvalidArgument, "GCS endpoint must not be empty")
	}
	if _, err := parseGCSEndpoint(c.Endpoint); err != nil {
		return err
	}
	return nil
}

// gcsEndpoint is a parsed endpoint.
type gcsEndpoint struct {
	Scheme    string
	Authority string
	BasePath  string
}

func parseGCSEndpoint(text string) (gcsEndpoint, error) {
	parsed, err := url.Parse(text)
	if err != nil {
		return gcsEndpoint{}, werr.Newf(werr.InvalidArgument, "GCS endpoint `%s` is not a URL: %s", text, err.Error())
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return gcsEndpoint{}, werr.Newf(werr.InvalidArgument,
			"GCS endpoint `%s` must be http:// or https://", text)
	}
	if parsed.Host == "" {
		return gcsEndpoint{}, werr.Newf(werr.InvalidArgument, "GCS endpoint `%s` has no host", text)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return gcsEndpoint{}, werr.Newf(werr.InvalidArgument,
			"GCS endpoint `%s` must not carry a query or fragment", text)
	}
	base := strings.TrimSuffix(parsed.EscapedPath(), "/")
	return gcsEndpoint{Scheme: scheme, Authority: parsed.Host, BasePath: base}, nil
}

// gcsQuery is one already-ordered query parameter.
type gcsQuery struct {
	Name  string
	Value string
}

// gcsHeader is one request header.
type gcsHeader struct {
	Name  string
	Value string
}

// gcsObject is one listed object.
type gcsObject struct {
	Name    string
	Size    uint64
	Updated time.Time
}

// gcsObjectMeta is the metadata the store depends on.
type gcsObjectMeta struct {
	Size       uint64
	Generation uint64
	Updated    time.Time
}

// gcsPrecondition is one generation precondition.
type gcsPrecondition struct {
	missing    bool
	generation uint64
}

func gcsMissing() gcsPrecondition { return gcsPrecondition{missing: true} }

func gcsMatches(generation uint64) gcsPrecondition {
	return gcsPrecondition{generation: generation}
}

func (p gcsPrecondition) parameter() string {
	if p.missing {
		return "0"
	}
	return strconv.FormatUint(p.generation, 10)
}

type gcsStats struct {
	reads        atomic.Uint64
	rangeReads   atomic.Uint64
	bytesRead    atomic.Uint64
	writes       atomic.Uint64
	bytesWritten atomic.Uint64
	conflicts    atomic.Uint64
	requests     atomic.Uint64
}

// GCSStatsSnapshot is a copy of the client counters for diagnostics.
type GCSStatsSnapshot struct {
	Requests            uint64 `json:"requests"`
	Reads               uint64 `json:"reads"`
	RangeReads          uint64 `json:"range_reads"`
	BytesRead           uint64 `json:"bytes_read"`
	Writes              uint64 `json:"writes"`
	BytesWritten        uint64 `json:"bytes_written"`
	ConditionalConflict uint64 `json:"conditional_conflicts"`
}

// gcsLockLease is this handle's copy of the published LOCK record.
type gcsLockLease struct {
	owner          string
	fence          uint64
	sequence       uint64
	deadlineNS     int64
	renewedNS      int64
	generation     uint64
	headGeneration uint64
	headCommit     string
	headCommitLen  uint64
}

// gcsResponse is one bounded response.
type gcsResponse struct {
	Status   int
	Location string
	Body     []byte
}

type gcsClient struct {
	config   GCSConfig
	endpoint gcsEndpoint
	http     *http.Client
	auth     *gcsAuth

	mu       sync.Mutex
	probeMu  sync.Mutex
	notes    []string
	probed   bool
	probeErr error

	lockMu  sync.Mutex
	lease   *gcsLockLease
	stats   gcsStats
	counter atomic.Uint64
	// pageSize overrides maxResults. It exists so the court can prove page-token
	// following against an emulator that honours a small page. 0 means 1000.
	pageSize int
}

func newGCSClient(config GCSConfig) (*gcsClient, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	endpoint, err := parseGCSEndpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}
	if config.LockLease < gcsMinLockLease {
		config.LockLease = gcsMinLockLease
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
	client := &http.Client{Timeout: config.RequestTimeout, Transport: transport}
	out := &gcsClient{config: config, endpoint: endpoint, http: client}
	if config.ServiceAccountPath != "" {
		key, err := loadGCSServiceAccountKey(config.ServiceAccountPath)
		if err != nil {
			return nil, err
		}
		if out.config.Project == "" {
			out.config.Project = key.projectID
		}
		out.auth = newGCSAuth(key, config.Scope, client)
	}
	return out, nil
}

func (c *gcsClient) note(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.notes) < 32 {
		c.notes = append(c.notes, text)
	}
}

func (c *gcsClient) diagnostics() []string {
	c.mu.Lock()
	out := append([]string(nil), c.notes...)
	probed := c.probed
	c.mu.Unlock()
	if probed {
		out = append(out, "GCS generation preconditions measured at open: ifGenerationMatch=0 create-once and ifGenerationMatch=<generation> compare-and-swap, stale refused")
	}
	if conflicts := c.stats.conflicts.Load(); conflicts > 0 {
		out = append(out, "GCS generation preconditions observed "+strconv.FormatUint(conflicts, 10)+" lost/retried race(s)")
	}
	if c.auth != nil {
		stats := c.auth.stats()
		out = append(out, "GCS service-account auth: "+strconv.FormatUint(stats.Exchanges, 10)+" token exchange(s), "+
			strconv.FormatUint(stats.CacheHits, 10)+" cache hit(s), "+
			strconv.FormatUint(stats.Refusals, 10)+" refusal(s); key "+c.auth.key.fingerprint+
			" ("+strconv.Itoa(c.auth.key.bits)+" bits)")
	}
	return out
}

func (c *gcsClient) origin() string {
	return c.endpoint.Scheme + "://" + c.endpoint.Authority + c.endpoint.BasePath
}

func (c *gcsClient) objectURL(name string) string {
	return c.origin() + "/storage/v1/b/" + gcsPct(c.config.Bucket) + "/o/" + gcsPct(name)
}

func (c *gcsClient) uploadURL(parameters []gcsQuery) string {
	return c.origin() + "/upload/storage/v1/b/" + gcsPct(c.config.Bucket) + "/o?" + gcsQueryString(parameters)
}

func (c *gcsClient) bucketURL() string {
	return c.origin() + "/storage/v1/b/" + gcsPct(c.config.Bucket)
}

func (c *gcsClient) bucketCollectionURL(parameters []gcsQuery) string {
	return c.origin() + "/storage/v1/b?" + gcsQueryString(parameters)
}

func (c *gcsClient) objectCollectionURL(parameters []gcsQuery) string {
	return c.origin() + "/storage/v1/b/" + gcsPct(c.config.Bucket) + "/o?" + gcsQueryString(parameters)
}

func (c *gcsClient) authorization() (string, error) {
	if c.config.Token != "" {
		return "Bearer " + c.config.Token, nil
	}
	if c.auth == nil {
		return "", nil
	}
	token, err := c.auth.authorization(nowNS())
	if err != nil {
		return "", err
	}
	return "Bearer " + token, nil
}

// do performs one request. HTTP status codes are returned, never converted to
// errors: the caller decides what each status means.
func (c *gcsClient) do(method, rawURL string, headers []gcsHeader, body []byte, cap uint64) (*gcsResponse, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot build GCS %s request", method)
	}
	if authorization, authErr := c.authorization(); authErr != nil {
		return nil, authErr
	} else if authorization != "" {
		request.Header.Set("authorization", authorization)
	}
	request.Header.Set("user-agent", "weftfs-gcs/1")
	for _, header := range headers {
		request.Header.Set(header.Name, header.Value)
	}
	if body != nil {
		request.ContentLength = int64(len(body))
	}
	c.stats.requests.Add(1)
	response, err := c.http.Do(request)
	if err != nil {
		// A transport failure stays `Io`: an unreachable endpoint is not a
		// damaged store.
		return nil, werr.Wrap(werr.Io, err, "GCS %s %s failed", method, rawURL)
	}
	defer response.Body.Close()
	out := &gcsResponse{Status: response.StatusCode, Location: response.Header.Get("Location")}
	if response.ContentLength > 0 && uint64(response.ContentLength) > cap {
		return nil, werr.Newf(werr.LimitExceeded,
			"GCS response is %d bytes, above the backend's %d-byte bound", response.ContentLength, cap)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(cap)+1))
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "GCS %s %s response read", method, rawURL)
	}
	if uint64(len(data)) > cap {
		return nil, werr.Newf(werr.LimitExceeded,
			"GCS response exceeded the backend's %d-byte bound", cap)
	}
	out.Body = data
	return out, nil
}

// metadata reads an object's size, generation, and update time.
func (c *gcsClient) metadata(name string) (*gcsObjectMeta, error) {
	response, err := c.do("GET", c.objectURL(name), nil, nil, gcsMaxJSONBytes)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		value, err := parseGCSJSON(response.Body)
		if err != nil {
			return nil, werr.Newf(werr.Corrupt, "GCS metadata for `%s`: %s", name, err)
		}
		generation, ok := jsonUint(value["generation"])
		if !ok {
			return nil, werr.Newf(werr.Unsupported,
				"GCS metadata for `%s` has no integer `generation`; refusing a writable store whose compare-and-swap would have no token", name)
		}
		size, _ := jsonUint(value["size"])
		updated := time.Time{}
		if text, ok := value["updated"].(string); ok {
			if when, err := time.Parse(time.RFC3339Nano, text); err == nil {
				updated = when
			}
		}
		return &gcsObjectMeta{Size: size, Generation: generation, Updated: updated}, nil
	case http.StatusNotFound:
		return nil, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "GCS denied metadata for `%s`", name)
	default:
		return nil, werr.Newf(werr.Io, "GCS metadata for `%s` returned HTTP %d: %s",
			name, response.Status, gcsBodySnippet(response.Body))
	}
}

// media reads an object's bytes, optionally one range.
func (c *gcsClient) media(name string, rangeSpec *gcsRange) (*gcsResponse, error) {
	var headers []gcsHeader
	if rangeSpec != nil && rangeSpec.length > 0 {
		end := rangeSpec.offset + rangeSpec.length - 1
		if end < rangeSpec.offset {
			return nil, werr.Newf(werr.LimitExceeded, "range end overflows u64")
		}
		headers = append(headers, gcsHeader{Name: "range", Value: "bytes=" +
			strconv.FormatUint(rangeSpec.offset, 10) + "-" + strconv.FormatUint(end, 10)})
	}
	rawURL := c.objectURL(name) + "?" + gcsQueryString([]gcsQuery{{Name: "alt", Value: "media"}})
	return c.do("GET", rawURL, headers, nil, gcsMaxObjectBytes)
}

type gcsRange struct {
	offset uint64
	length uint64
}

// readWithGeneration reads bytes and the generation they belong to. The
// generation is confirmed after the read so a concurrent replacement cannot be
// mistaken for the observed state.
func (c *gcsClient) readWithGeneration(name string) ([]byte, uint64, bool, error) {
	for attempt := 0; attempt < 4; attempt++ {
		before, err := c.metadata(name)
		if err != nil {
			return nil, 0, false, err
		}
		if before == nil {
			return nil, 0, false, nil
		}
		response, err := c.media(name, nil)
		if err != nil {
			return nil, 0, false, err
		}
		switch response.Status {
		case http.StatusOK:
		case http.StatusNotFound:
			return nil, 0, false, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, 0, false, werr.Newf(werr.Unauthorized, "GCS denied reading `%s`", name)
		default:
			return nil, 0, false, werr.Newf(werr.Io, "GCS read `%s` returned HTTP %d", name, response.Status)
		}
		if uint64(len(response.Body)) != before.Size {
			continue
		}
		after, err := c.metadata(name)
		if err != nil {
			return nil, 0, false, err
		}
		if after == nil {
			continue
		}
		if after.Generation == before.Generation {
			return response.Body, after.Generation, true, nil
		}
	}
	return nil, 0, false, werr.Newf(werr.Busy,
		"GCS object `%s` kept changing while it was being read", name)
}

// upload publishes bytes subject to a generation precondition. `nil` bytes with
// `published=false` means the precondition failed (HTTP 412).
func (c *gcsClient) upload(name string, data []byte, precondition gcsPrecondition) (uint64, bool, error) {
	if uint64(len(data)) > gcsMaxObjectBytes {
		return 0, false, werr.Newf(werr.LimitExceeded,
			"object is %d bytes, above the backend's %d-byte bound", len(data), gcsMaxObjectBytes)
	}
	response, err := c.uploadResponse(name, data, precondition)
	if err != nil {
		return 0, false, err
	}
	switch response.Status {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		c.stats.writes.Add(1)
		c.stats.bytesWritten.Add(uint64(len(data)))
		if generation, ok := gcsResponseGeneration(response.Body); ok {
			return generation, true, nil
		}
		// The reply carried no object resource. Confirm the generation by
		// re-reading, and require the bytes to be exactly ours: a successor's
		// replacement would differ, so its generation can never be mistaken for
		// this writer's token.
		observed, generation, present, err := c.readWithGeneration(name)
		if err != nil {
			return 0, false, err
		}
		if !present {
			return 0, false, werr.Newf(werr.Busy,
				"GCS object `%s` disappeared while its generation was being confirmed", name)
		}
		if !bytes.Equal(observed, data) {
			return 0, false, werr.Newf(werr.Busy,
				"GCS object `%s` was replaced while its generation was being confirmed", name)
		}
		return generation, true, nil
	case http.StatusPreconditionFailed:
		c.stats.conflicts.Add(1)
		return 0, false, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return 0, false, werr.Newf(werr.Unauthorized, "GCS denied writing `%s`", name)
	case http.StatusRequestEntityTooLarge:
		return 0, false, werr.Newf(werr.LimitExceeded,
			"GCS rejected the %d-byte object `%s` as too large for one request", len(data), name)
	default:
		return 0, false, werr.Newf(werr.Io, "GCS upload of `%s` returned HTTP %d: %s",
			name, response.Status, gcsBodySnippet(response.Body))
	}
}

func (c *gcsClient) uploadResponse(name string, data []byte, precondition gcsPrecondition) (*gcsResponse, error) {
	if uint64(len(data)) <= gcsSimpleUploadMax {
		parameters := []gcsQuery{
			{Name: "name", Value: name},
			{Name: "uploadType", Value: "media"},
			{Name: "ifGenerationMatch", Value: precondition.parameter()},
		}
		return c.do("POST", c.uploadURL(parameters),
			[]gcsHeader{{Name: "content-type", Value: "application/octet-stream"}},
			data, gcsMaxJSONBytes)
	}
	return c.resumableUpload(name, data, precondition)
}

// resumableUpload runs the documented two-step upload for payloads above the
// simple bound. The generation precondition travels on the session-initiation
// request, which is where the provider evaluates it.
func (c *gcsClient) resumableUpload(name string, data []byte, precondition gcsPrecondition) (*gcsResponse, error) {
	parameters := []gcsQuery{
		{Name: "name", Value: name},
		{Name: "uploadType", Value: "resumable"},
		{Name: "ifGenerationMatch", Value: precondition.parameter()},
	}
	init, err := c.do("POST", c.uploadURL(parameters), []gcsHeader{
		{Name: "content-type", Value: "application/octet-stream"},
		{Name: "x-upload-content-length", Value: strconv.FormatUint(uint64(len(data)), 10)},
	}, []byte{}, gcsMaxJSONBytes)
	if err != nil {
		return nil, err
	}
	switch init.Status {
	case http.StatusOK, http.StatusCreated:
	case http.StatusPreconditionFailed:
		c.stats.conflicts.Add(1)
		return init, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "GCS denied initiating an upload for `%s`", name)
	default:
		return nil, werr.Newf(werr.Io, "GCS resumable initiation for `%s` returned HTTP %d: %s",
			name, init.Status, gcsBodySnippet(init.Body))
	}
	if init.Location == "" {
		return nil, werr.Newf(werr.Unsupported,
			"GCS resumable initiation for `%s` returned no session URI; refusing to continue rather than guessing an upload endpoint", name)
	}
	response, err := c.do("PUT", init.Location,
		[]gcsHeader{{Name: "content-type", Value: "application/octet-stream"}},
		data, gcsMaxJSONBytes)
	if err != nil {
		return nil, err
	}
	if response.Status == 308 {
		return nil, werr.Newf(werr.Io,
			"GCS resumable upload for `%s` ended incomplete (HTTP 308); no partial object is treated as published", name)
	}
	return response, nil
}

func (c *gcsClient) deleteObject(name string) error {
	response, err := c.do("DELETE", c.objectURL(name), nil, nil, gcsMaxJSONBytes)
	if err != nil {
		return err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return werr.Newf(werr.NotFound, "key `%s` does not exist", name)
	case http.StatusUnauthorized, http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "GCS denied deleting `%s`", name)
	default:
		return werr.Newf(werr.Io, "GCS delete of `%s` returned HTTP %d: %s",
			name, response.Status, gcsBodySnippet(response.Body))
	}
}

// listObjects enumerates one prefix, following `nextPageToken` to exhaustion.
func (c *gcsClient) listObjects(prefix string) ([]gcsObject, error) {
	var out []gcsObject
	token := ""
	pageSize := c.pageSize
	if pageSize <= 0 {
		pageSize = 1000
	}
	for {
		parameters := []gcsQuery{
			{Name: "prefix", Value: prefix},
			{Name: "maxResults", Value: strconv.Itoa(pageSize)},
		}
		if token != "" {
			parameters = append(parameters, gcsQuery{Name: "pageToken", Value: token})
		}
		response, err := c.do("GET", c.objectCollectionURL(parameters), nil, nil, gcsMaxJSONBytes)
		if err != nil {
			return nil, err
		}
		switch response.Status {
		case http.StatusOK:
		case http.StatusNotFound:
			return out, nil
		case http.StatusUnauthorized, http.StatusForbidden:
			return nil, werr.Newf(werr.Unauthorized, "GCS denied listing `%s`", prefix)
		default:
			return nil, werr.Newf(werr.Io, "GCS list returned HTTP %d: %s",
				response.Status, gcsBodySnippet(response.Body))
		}
		value, err := parseGCSJSON(response.Body)
		if err != nil {
			return nil, werr.Newf(werr.Corrupt, "GCS listing `%s`: %s", prefix, err)
		}
		if items, ok := value["items"].([]any); ok {
			for _, item := range items {
				object, ok := item.(map[string]any)
				if !ok {
					continue
				}
				name, _ := object["name"].(string)
				if name == "" {
					continue
				}
				size, _ := jsonUint(object["size"])
				updated := time.Time{}
				if text, ok := object["updated"].(string); ok {
					if when, err := time.Parse(time.RFC3339Nano, text); err == nil {
						updated = when
					}
				}
				out = append(out, gcsObject{Name: name, Size: size, Updated: updated})
			}
		}
		next, _ := value["nextPageToken"].(string)
		if next == "" {
			break
		}
		if next == token {
			return nil, werr.Newf(werr.Corrupt,
				"GCS listing `%s` repeated page token `%s`", prefix, next)
		}
		token = next
	}
	return out, nil
}

// ensureBucket creates the bucket when it is absent and a project is
// configured. Idempotent.
func (c *gcsClient) ensureBucket() error {
	response, err := c.do("GET", c.bucketURL(), nil, nil, gcsMaxJSONBytes)
	if err != nil {
		return err
	}
	switch response.Status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
	case http.StatusUnauthorized, http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "GCS denied reading bucket `%s`", c.config.Bucket)
	default:
		return werr.Newf(werr.Io, "GCS bucket metadata returned HTTP %d: %s",
			response.Status, gcsBodySnippet(response.Body))
	}
	if c.config.Project == "" {
		return werr.Newf(werr.NotFound,
			"GCS bucket `%s` does not exist and no project was configured; set --gcs-project or create the bucket out of band", c.config.Bucket)
	}
	body := []byte(`{"name":"` + c.config.Bucket + `"}`)
	url := c.bucketCollectionURL([]gcsQuery{{Name: "project", Value: c.config.Project}})
	response, err = c.do("POST", url,
		[]gcsHeader{{Name: "content-type", Value: "application/json"}}, body, gcsMaxJSONBytes)
	if err != nil {
		return err
	}
	switch response.Status {
	case http.StatusOK, http.StatusCreated, http.StatusConflict:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "GCS denied creating bucket `%s`", c.config.Bucket)
	default:
		return werr.Newf(werr.Io, "GCS CreateBucket `%s` returned HTTP %d: %s",
			c.config.Bucket, response.Status, gcsBodySnippet(response.Body))
	}
}

// probeGenerationPreconditions proves the two forms and a stale-refusal. An
// endpoint that accepts a stale generation could silently lose a head
// publication, so it is refused rather than downgraded.
func (c *gcsClient) probeGenerationPreconditions() error {
	c.probeMu.Lock()
	defer c.probeMu.Unlock()
	if c.probed {
		return c.probeErr
	}
	err := c.runGenerationProbe()
	c.probed = true
	c.probeErr = err
	if err == nil {
		c.note("GCS generation-precondition probe passed: create-once, matching generation, and stale-generation refusal all observed")
	}
	return err
}

func (c *gcsClient) runGenerationProbe() error {
	name := "tmp/generation-probe-" + strconv.Itoa(os.Getpid()) + "-" +
		strconv.FormatUint(c.counter.Add(1), 10)
	cleanup := func() { _ = c.deleteObject(name) }

	if _, ok, err := c.upload(name, []byte("probe-one"), gcsMissing()); err != nil {
		cleanup()
		return err
	} else if !ok {
		cleanup()
		return werr.Newf(werr.Io, "GCS generation probe: a fresh key reported a failed precondition")
	}
	if _, ok, err := c.upload(name, []byte("probe-two"), gcsMissing()); err != nil {
		cleanup()
		return err
	} else if ok {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"GCS-compatible endpoint ignored `ifGenerationMatch=0`; refusing a writable store because create-once publication cannot be guaranteed")
	}
	bytesValue, generation, present, err := c.readWithGeneration(name)
	if err != nil {
		cleanup()
		return err
	}
	if !present {
		cleanup()
		return werr.Newf(werr.Io, "GCS generation probe: the first writer's object is not readable")
	}
	if string(bytesValue) != "probe-one" {
		cleanup()
		return werr.Newf(werr.Io,
			"GCS generation probe: the first writer's bytes were replaced by a rejected create")
	}
	if _, ok, err := c.upload(name, []byte("probe-three"), gcsMatches(generation)); err != nil {
		cleanup()
		return err
	} else if !ok {
		cleanup()
		return werr.Newf(werr.Io,
			"GCS generation probe: a matching `ifGenerationMatch` was unexpectedly rejected")
	}
	// The load-bearing check: the old generation is now stale.
	if _, ok, err := c.upload(name, []byte("probe-four"), gcsMatches(generation)); err != nil {
		cleanup()
		return err
	} else if ok {
		cleanup()
		return werr.Newf(werr.Unsupported,
			"GCS-compatible endpoint accepted a stale `ifGenerationMatch`; refusing a writable store because head publication could lose a race silently")
	}
	cleanup()
	return nil
}

// ---- small helpers -------------------------------------------------------

func gcsPct(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var out strings.Builder
	out.Grow(len(value))
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			out.WriteByte(ch)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(hexDigits[ch>>4])
		out.WriteByte(hexDigits[ch&0x0f])
	}
	return out.String()
}

func gcsQueryString(parameters []gcsQuery) string {
	parts := make([]string, 0, len(parameters))
	for _, parameter := range parameters {
		parts = append(parts, gcsPct(parameter.Name)+"="+gcsPct(parameter.Value))
	}
	return strings.Join(parts, "&")
}

func parseGCSJSON(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errNotJSONObject
	}
	return object, nil
}

var errNotJSONObject = &jsonError{"document is not a JSON object"}

type jsonError struct{ text string }

func (e *jsonError) Error() string { return e.text }

// jsonUint accepts the string and numeric spellings GCS uses for u64 fields.
func jsonUint(value any) (uint64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseUint(typed.String(), 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, false
		}
		return uint64(typed), true
	default:
		return 0, false
	}
}

// gcsResponseGeneration reads the `generation` field of an upload reply.
func gcsResponseGeneration(body []byte) (uint64, bool) {
	value, err := parseGCSJSON(body)
	if err != nil {
		return 0, false
	}
	return jsonUint(value["generation"])
}

func gcsBodySnippet(body []byte) string {
	text := string(body)
	if len(text) > 240 {
		text = text[:240]
	}
	return text
}
