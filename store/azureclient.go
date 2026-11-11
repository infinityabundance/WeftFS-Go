// Azure Blob Storage client (subphase R14).
//
// This is the independent Go implementation of the same Azure Blob REST
// contract the Rust backend (`src/azure.rs`) speaks. It is written from that
// contract and the Azure Blob documentation, not by calling Rust: a store built
// by this client and a store built by the Rust client publish byte-identical
// records, and either implementation reads the other's store.
//
// # Protocol mapping
//
//   - create-once publication: `Put Blob` with `x-ms-blob-type: BlockBlob` and
//     `If-None-Match: *`. A second create is `409 Conflict`
//     (`BlobAlreadyExists`).
//   - compare-and-swap: `Put Blob` with `If-Match: <ETag>`. A stale ETag is
//     `412 Precondition Failed`. The public control token stays the content
//     token of the bytes; the ETag is the transport token, held privately.
//   - ranged reads: `Get Blob` with `Range: bytes=offset-end` (`206`).
//   - length and existence: `Get Blob Properties` (`HEAD`).
//   - deletion: `Delete Blob` (`202`).
//   - listing: `List Blobs` (`GET /container?restype=container&comp=list`).
//
// # Authentication
//
// Three credential forms exist and the client refuses to guess when a caller
// supplies two: **SharedKey** (HMAC-SHA256 over the documented string-to-sign,
// computed here with the standard library only), **SAS** (a pre-signed query
// string appended verbatim), and **anonymous** (emulator only). Secrets are
// never written to diagnostics or error text.
//
// # Endpoint behaviour is measured, not assumed
//
// HTTP entity tags are quoted. Azure compares `If-Match` against the quoted
// ETag it returned; a proxy or emulator may compare it literally. Like the S3
// and Rust Azure backends, this client *measures* the form at a writable open:
// a matching value must be accepted **and** a stale value in the same form
// refused, with the winner's bytes surviving. An endpoint that passes neither
// form is refused `Unsupported`, never downgraded.
//
// Label: protocol behaviour against an Azure-compatible endpoint. Durability
// here means "the service acknowledged the write"; no media, power-loss,
// replication, or cloud claim is made.
package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

const (
	// azureAPIVersion is the pinned Blob service version. The signature rules
	// and conditional-header semantics used here are the documented ones for
	// every version from 2015-02-21 onward; a pinned value keeps the court
	// reproducible.
	azureAPIVersion = "2021-12-02"

	// azureMaxObjectBytes matches the Rust backend's MAX_OBJECT_BYTES so a
	// store built on any backend has the same per-object bound.
	azureMaxObjectBytes = s3MaxObjectBytes

	// azureMaxXMLBytes bounds a metadata, listing, or error body.
	azureMaxXMLBytes = uint64(8) << 20

	azureLockSchema       = "weftfs-azure-lock v3"
	azureLockSchemaV2     = "weftfs-azure-lock v2"
	azureLockSchemaV1     = "weftfs-azure-lock v1"
	azureReleasedSchema   = "weftfs-azure-lock-released v2"
	azureReleasedSchemaV1 = "weftfs-azure-lock-released v1"
)

var azureFenceSchemas = fenceSchemas{
	v3:         azureLockSchema,
	v2:         azureLockSchemaV2,
	v1:         azureLockSchemaV1,
	releasedV2: azureReleasedSchema,
	releasedV1: azureReleasedSchemaV1,
}

// AzureConfig is the endpoint, container, and credentials of one Azure Blob
// (or Azure-compatible) store.
type AzureConfig struct {
	// Endpoint is `https://<account>.blob.core.windows.net`, or an emulator
	// endpoint such as `http://127.0.0.1:10000/devstoreaccount1`. An optional
	// path prefix is preserved (Azurite puts the account in the path).
	Endpoint  string `json:"endpoint"`
	Container string `json:"container"`
	// Account is the storage account name used as the SharedKey scope.
	Account string `json:"account"`
	// Key is the base64 account key. Never logged.
	Key string `json:"-"`
	// SASToken is a pre-signed SAS query string with no leading `?`. Never
	// logged.
	SASToken string `json:"-"`
	// Anonymous sends no credential at all. An emulator court only.
	Anonymous bool `json:"anonymous"`
	// LockLease bounds a writer lease. A crashed writer leaves a stale LOCK
	// that becomes reclaimable after this duration.
	LockLease time.Duration `json:"lock_lease"`
	// RequestTimeout bounds one HTTP request.
	RequestTimeout time.Duration `json:"request_timeout"`
}

// AzureConfigFromEnv builds a configuration from `WEFT_AZURE_*` first and the
// standard Azure Storage names second. Explicit CLI values are applied by
// ResolveAzure.
func AzureConfigFromEnv() AzureConfig {
	leaseSecs := uint64(900)
	if text := firstEnv("WEFT_AZURE_LOCK_LEASE_SECS"); text != "" {
		if value, err := strconv.ParseUint(text, 10, 64); err == nil {
			leaseSecs = value
		}
	}
	if leaseSecs < uint64(minLockLease/time.Second) {
		leaseSecs = uint64(minLockLease / time.Second)
	}
	return AzureConfig{
		Endpoint:       firstEnv("WEFT_AZURE_ENDPOINT", "AZURE_STORAGE_BLOB_ENDPOINT"),
		Container:      firstEnv("WEFT_AZURE_CONTAINER", "AZURE_STORAGE_CONTAINER"),
		Account:        firstEnv("WEFT_AZURE_ACCOUNT", "AZURE_STORAGE_ACCOUNT"),
		Key:            firstEnv("WEFT_AZURE_KEY", "AZURE_STORAGE_KEY"),
		SASToken:       firstEnv("WEFT_AZURE_SAS", "AZURE_STORAGE_SAS_TOKEN"),
		Anonymous:      envFlagValue("WEFT_AZURE_ANONYMOUS"),
		LockLease:      time.Duration(leaseSecs) * time.Second,
		RequestTimeout: 60 * time.Second,
	}
}

// envFlagValue reads a boolean environment flag with the same spellings the
// Rust backends accept. Unlike GCS, anonymous is never inferred.
func envFlagValue(name string) bool {
	switch strings.ToLower(firstEnv(name)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ResolveAzure merges explicit values over the environment and refuses an
// ambiguous credential set. Every required field must be present; there is no
// implicit local fallback.
func ResolveAzure(endpoint, container, account, key, sasToken string, anonymous *bool, lockLeaseSecs uint64) (AzureConfig, error) {
	config := AzureConfigFromEnv()
	if endpoint != "" {
		config.Endpoint = endpoint
	}
	if container != "" {
		config.Container = container
	}
	if account != "" {
		config.Account = account
	}
	if key != "" {
		config.Key = key
	}
	if sasToken != "" {
		config.SASToken = sasToken
	}
	if anonymous != nil {
		config.Anonymous = *anonymous
	}
	if lockLeaseSecs > 0 {
		config.LockLease = time.Duration(lockLeaseSecs) * time.Second
	}
	if config.LockLease < minLockLease {
		config.LockLease = minLockLease
	}
	forms := 0
	if config.Key != "" {
		forms++
	}
	if config.SASToken != "" {
		forms++
	}
	if config.Anonymous {
		forms++
	}
	if forms > 1 {
		return AzureConfig{}, werr.Newf(werr.InvalidArgument,
			"Azure backend was given more than one credential form (account key, SAS token, anonymous); refusing to guess which one the endpoint should see")
	}
	if forms == 0 {
		return AzureConfig{}, werr.Newf(werr.InvalidArgument,
			"Azure backend needs one credential form: an account key (--azure-key, WEFT_AZURE_KEY, AZURE_STORAGE_KEY), a SAS token (--azure-sas, WEFT_AZURE_SAS, AZURE_STORAGE_SAS_TOKEN), or --azure-anonymous for an emulator")
	}
	if err := config.Validate(); err != nil {
		return AzureConfig{}, err
	}
	return config, nil
}

// Validate checks the configuration. It never guesses a missing field.
func (c AzureConfig) Validate() error {
	if c.Endpoint == "" {
		return werr.Newf(werr.InvalidArgument,
			"Azure backend needs an endpoint (`--azure-endpoint`, WEFT_AZURE_ENDPOINT, or AZURE_STORAGE_BLOB_ENDPOINT)")
	}
	if _, err := parseAzureEndpoint(c.Endpoint); err != nil {
		return err
	}
	if c.Account == "" {
		return werr.Newf(werr.InvalidArgument,
			"Azure backend needs an account name (`--azure-account`, WEFT_AZURE_ACCOUNT, or AZURE_STORAGE_ACCOUNT) for the SharedKey credential scope")
	}
	for i := 0; i < len(c.Account); i++ {
		b := c.Account[i]
		if !(b >= 'a' && b <= 'z') && !(b >= '0' && b <= '9') {
			return werr.Newf(werr.InvalidArgument,
				"Azure storage account `%s` must be lowercase letters and digits only", c.Account)
		}
	}
	if len(c.Container) < 3 || len(c.Container) > 63 {
		return werr.Newf(werr.InvalidArgument,
			"Azure container `%s` is %d bytes; a container name is 3..=63 bytes", c.Container, len(c.Container))
	}
	for i := 0; i < len(c.Container); i++ {
		b := c.Container[i]
		if !(b >= 'a' && b <= 'z') && !(b >= '0' && b <= '9') && b != '-' {
			return werr.Newf(werr.InvalidArgument,
				"Azure container `%s` must be lowercase letters, digits, and hyphens", c.Container)
		}
	}
	if strings.HasPrefix(c.Container, "-") || strings.HasSuffix(c.Container, "-") {
		return werr.Newf(werr.InvalidArgument,
			"Azure container `%s` must not start or end with a hyphen", c.Container)
	}
	if c.Key != "" {
		decoded, err := decodeBase64Any(c.Key)
		if err != nil {
			return werr.Newf(werr.InvalidArgument,
				"Azure account key is not valid base64 (%s); the key itself is not printed", err.Error())
		}
		if len(decoded) < 16 {
			return werr.Newf(werr.InvalidArgument,
				"Azure account key decodes to fewer than 16 bytes; refusing a credential that cannot be the account key")
		}
	}
	if c.SASToken != "" {
		if strings.HasPrefix(c.SASToken, "?") {
			return werr.Newf(werr.InvalidArgument,
				"Azure SAS token must not start with `?`; supply only the query string")
		}
		if strings.ContainsAny(c.SASToken, "# ") {
			return werr.Newf(werr.InvalidArgument,
				"Azure SAS token contains a byte that cannot appear in a query string")
		}
	}
	return nil
}

// azureEndpoint is a parsed endpoint. BasePath preserves a path-style account
// prefix, as Azurite requires.
type azureEndpoint struct {
	Scheme    string
	Authority string
	BasePath  string
}

func parseAzureEndpoint(text string) (azureEndpoint, error) {
	parsed, err := url.Parse(text)
	if err != nil {
		return azureEndpoint{}, werr.Newf(werr.InvalidArgument, "Azure endpoint `%s` is not a URL: %s", text, err.Error())
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return azureEndpoint{}, werr.Newf(werr.InvalidArgument,
			"Azure endpoint scheme `%s` is not http or https", parsed.Scheme)
	}
	if parsed.Host == "" {
		return azureEndpoint{}, werr.Newf(werr.InvalidArgument, "Azure endpoint `%s` has an empty host", text)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return azureEndpoint{}, werr.Newf(werr.InvalidArgument,
			"Azure endpoint `%s` must not carry a query or fragment", text)
	}
	base := strings.Trim(parsed.EscapedPath(), "/")
	if base != "" {
		base = "/" + base
	}
	return azureEndpoint{Scheme: parsed.Scheme, Authority: parsed.Host, BasePath: base}, nil
}

// azureQuery is one canonical query parameter, sent in sorted order.
type azureQuery struct {
	Name  string
	Value string
}

// azureHeader is an extra request header.
type azureHeader struct {
	Name  string
	Value string
}

// azureResponse is one HTTP response. Status codes are returned, never
// converted to errors here: the caller decides what each status means.
type azureResponse struct {
	Status        int
	ETag          string
	ContentLength int64
	LastModified  time.Time
	Body          []byte
}

type azureStats struct {
	requests                atomic.Uint64
	reads                   atomic.Uint64
	rangeReads              atomic.Uint64
	bytesRead               atomic.Uint64
	writes                  atomic.Uint64
	bytesWritten            atomic.Uint64
	conflicts               atomic.Uint64
	lockAcquires            atomic.Uint64
	fenceChecks             atomic.Uint64
	leaseRenewals           atomic.Uint64
	fenceRefusals           atomic.Uint64
	leaseExpiredPublication atomic.Uint64
	headPublications        atomic.Uint64
}

// AzureStatsSnapshot is a copy of the client counters. It is diagnostic
// evidence (requests and bytes on the wire), never a correctness input.
type AzureStatsSnapshot struct {
	Requests                uint64 `json:"requests"`
	Reads                   uint64 `json:"reads"`
	RangeReads              uint64 `json:"range_reads"`
	BytesRead               uint64 `json:"bytes_read"`
	Writes                  uint64 `json:"writes"`
	BytesWritten            uint64 `json:"bytes_written"`
	ConditionalConflict     uint64 `json:"conditional_conflicts"`
	LockAcquires            uint64 `json:"lock_acquires"`
	FenceChecks             uint64 `json:"fence_checks"`
	LeaseRenewals           uint64 `json:"lease_renewals"`
	FenceRefusals           uint64 `json:"fence_refusals"`
	LeaseExpiredPublication uint64 `json:"lease_expired_publications"`
	HeadPublications        uint64 `json:"head_publications"`
}

// azureClient is one connection to one container. Blob and commit planes share
// it, so the measured If-Match form and the LOCK lease are single.
type azureClient struct {
	config   AzureConfig
	endpoint azureEndpoint
	http     *http.Client

	mu       sync.Mutex
	probeMu  sync.Mutex
	notes    []string
	probed   bool
	probeErr error
	form     IfMatchForm

	lockMu  sync.Mutex
	lease   *azureLockLease
	stats   azureStats
	counter atomic.Uint64
}

// azureLockLease is this handle's copy of the published LOCK record.
type azureLockLease struct {
	owner      string
	fence      uint64
	sequence   uint64
	deadlineNS int64
	renewedNS  int64
	etag       string
	// The head this handle last published. Every LOCK rewrite carries it
	// forward so a crash never loses the attestation.
	headGeneration uint64
	headCommit     string
	headCommitLen  uint64
}

func newAzureClient(config AzureConfig) (*azureClient, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	endpoint, err := parseAzureEndpoint(config.Endpoint)
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
	return &azureClient{
		config:   config,
		endpoint: endpoint,
		http:     &http.Client{Timeout: config.RequestTimeout, Transport: transport},
	}, nil
}

func (c *azureClient) note(text string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.notes) < 32 {
		c.notes = append(c.notes, text)
	}
}

func (c *azureClient) diagnostics() []string {
	c.mu.Lock()
	out := append([]string(nil), c.notes...)
	probed := c.probed
	form := c.form
	c.mu.Unlock()
	if probed {
		out = append(out, "Azure If-Match form measured at open: "+form.String())
	}
	if conflicts := c.stats.conflicts.Load(); conflicts > 0 {
		out = append(out, fmt.Sprintf("Azure conditional writes observed %d lost/retried race(s)", conflicts))
	}
	return out
}

func (c *azureClient) headIfMatchForm() IfMatchForm {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.form
}

// urlPath is the encoded request path, starting with `/`: the optional base
// path (Azurite's account prefix), the container, then the encoded blob name.
func (c *azureClient) urlPath(blob string) string {
	path := c.endpoint.BasePath + "/" + c.config.Container
	if blob != "" {
		path += "/" + encodeAzurePath(blob)
	}
	return path
}

func (c *azureClient) describe(blob string) string {
	if blob == "" {
		return "azure container " + c.config.Container
	}
	return "azure://" + c.config.Container + "/" + blob
}

// do performs one signed request.
func (c *azureClient) do(method, blob string, query []azureQuery, body []byte, extra []azureHeader) (*azureResponse, error) {
	path := c.urlPath(blob)
	headers := map[string]string{
		"x-ms-date":    time.Now().UTC().Format(http.TimeFormat),
		"x-ms-version": azureAPIVersion,
	}
	sendsBody := method == "PUT" || method == "POST" || method == "PATCH"
	if sendsBody {
		headers["content-length"] = strconv.Itoa(len(body))
		headers["content-type"] = "application/octet-stream"
	}
	for _, header := range extra {
		headers[strings.ToLower(header.Name)] = header.Value
	}
	canonicalQuery := canonicalAzureQuery(query)
	urlQuery := canonicalQuery
	if c.config.SASToken != "" {
		if urlQuery == "" {
			urlQuery = c.config.SASToken
		} else {
			urlQuery = urlQuery + "&" + c.config.SASToken
		}
	}
	rawURL := c.endpoint.Scheme + "://" + c.endpoint.Authority + path
	if urlQuery != "" {
		rawURL += "?" + urlQuery
	}

	request, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot build Azure %s %s", method, c.describe(blob))
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	if c.config.Key != "" {
		signature, err := azureSharedKeySignature(c.config.Account, c.config.Key, method, headers, len(body), path, canonicalQuery)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", "SharedKey "+c.config.Account+":"+signature)
	}
	if sendsBody {
		request.ContentLength = int64(len(body))
	}

	c.stats.requests.Add(1)
	httpResponse, err := c.http.Do(request)
	if err != nil {
		// A transport failure stays `Io`: an unreachable endpoint is not a
		// damaged store.
		return nil, werr.Wrap(werr.Io, err, "Azure %s %s failed", method, c.describe(blob))
	}
	defer httpResponse.Body.Close()

	out := &azureResponse{
		Status:        httpResponse.StatusCode,
		ETag:          httpResponse.Header.Get("ETag"),
		ContentLength: httpResponse.ContentLength,
	}
	if modified := httpResponse.Header.Get("Last-Modified"); modified != "" {
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
	cap := azureMaxXMLBytes
	if method == "GET" && blob != "" {
		cap = azureMaxObjectBytes
	}
	data, err := readAzureBody(httpResponse.Body, out.ContentLength, cap, method, blob)
	if err != nil {
		return nil, err
	}
	out.Body = data
	return out, nil
}

// readAzureBody reads at most `cap` bytes and fails closed above it.
func readAzureBody(reader io.Reader, contentLength int64, cap uint64, method, blob string) ([]byte, error) {
	if contentLength > 0 && uint64(contentLength) > cap {
		return nil, werr.Newf(werr.LimitExceeded,
			"Azure %s %s response is %d bytes, above the backend's %d-byte bound",
			method, describeAzureBlob(blob), contentLength, cap)
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(cap)+1))
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot read Azure response for %s", describeAzureBlob(blob))
	}
	if uint64(len(data)) > cap {
		return nil, werr.Newf(werr.LimitExceeded,
			"Azure %s %s response exceeded the backend's %d-byte bound",
			method, describeAzureBlob(blob), cap)
	}
	return data, nil
}

func describeAzureBlob(blob string) string {
	if blob == "" {
		return "container"
	}
	return "`" + blob + "`"
}

// get reads a whole blob or a range. `length == 0` reads the whole blob.
func (c *azureClient) get(blob string, offset, length uint64) (*azureResponse, error) {
	var extra []azureHeader
	if length > 0 {
		end := offset + length - 1
		if end < offset {
			return nil, werr.Newf(werr.LimitExceeded, "range end overflows u64")
		}
		extra = append(extra, azureHeader{"range", fmt.Sprintf("bytes=%d-%d", offset, end)})
	}
	return c.do("GET", blob, nil, nil, extra)
}

func (c *azureClient) head(blob string) (*azureResponse, error) {
	return c.do("HEAD", blob, nil, nil, nil)
}

func (c *azureClient) delete(blob string) (*azureResponse, error) {
	return c.do("DELETE", blob, nil, nil, []azureHeader{{"x-ms-delete-snapshots", "include"}})
}

// putConditional publishes `body` under `blob`. When ifMatch is nil the write
// is create-once (`If-None-Match: *`); otherwise it is conditional on the
// endpoint's current ETag. `ok == false` means the precondition failed.
func (c *azureClient) putConditional(blob string, body []byte, ifMatch *string, countConflict bool) (string, bool, error) {
	value := ""
	if ifMatch != nil {
		value = c.headIfMatchForm().Encode(*ifMatch)
	}
	return c.putConditionalHeader(blob, body, value, countConflict)
}

// putConditionalHeader sends the literal header value. Only the probe passes a
// value that was not encoded through IfMatchForm.
func (c *azureClient) putConditionalHeader(blob string, body []byte, ifMatchValue string, countConflict bool) (string, bool, error) {
	if uint64(len(body)) > azureMaxObjectBytes {
		return "", false, werr.Newf(werr.LimitExceeded,
			"blob is %d bytes, above the backend's %d-byte bound", len(body), azureMaxObjectBytes)
	}
	extra := []azureHeader{{"x-ms-blob-type", "BlockBlob"}}
	if ifMatchValue == "" {
		extra = append(extra, azureHeader{"if-none-match", "*"})
	} else {
		extra = append(extra, azureHeader{"if-match", ifMatchValue})
	}
	response, err := c.do("PUT", blob, nil, body, extra)
	if err != nil {
		return "", false, err
	}
	switch {
	case response.Status >= 200 && response.Status < 300:
		c.stats.writes.Add(1)
		c.stats.bytesWritten.Add(uint64(len(body)))
		if response.ETag == "" {
			return "", false, werr.Newf(werr.Unsupported,
				"Azure accepted a Put Blob for `%s` without returning an ETag; refusing to continue because the next conditional write would have no token", blob)
		}
		return response.ETag, true, nil
	case response.Status == http.StatusConflict, response.Status == http.StatusPreconditionFailed:
		if countConflict {
			c.stats.conflicts.Add(1)
		}
		return "", false, nil
	case response.Status == http.StatusForbidden:
		return "", false, werr.Newf(werr.Unauthorized, "Azure denied PUT %s", c.describe(blob))
	case response.Status == http.StatusRequestEntityTooLarge:
		return "", false, werr.Newf(werr.LimitExceeded,
			"Azure rejected the %d-byte blob `%s` as too large", len(body), blob)
	default:
		return "", false, werr.Newf(werr.Io, "Azure PUT %s returned HTTP %d: %s",
			c.describe(blob), response.Status, azureBodySnippet(response.Body))
	}
}

// putReplace replaces a mutable record. It reads the current ETag, writes with
// If-Match, and retries a lost race from a fresh read; when the blob is absent
// it creates it once. It never issues an unconditional overwrite.
func (c *azureClient) putReplace(blob string, body []byte) error {
	for attempt := 0; attempt < 8; attempt++ {
		current, err := c.do("GET", blob, nil, nil, nil)
		if err != nil {
			return err
		}
		switch current.Status {
		case http.StatusOK:
			if current.ETag == "" {
				return werr.Newf(werr.Unsupported,
					"Azure did not return an ETag for `%s`; refusing an unconditional replacement", blob)
			}
			etag := current.ETag
			if _, ok, err := c.putConditional(blob, body, &etag, true); err != nil {
				return err
			} else if ok {
				return nil
			}
		case http.StatusNotFound:
			if _, ok, err := c.putConditional(blob, body, nil, true); err != nil {
				return err
			} else if ok {
				return nil
			}
		case http.StatusForbidden:
			return werr.Newf(werr.Unauthorized, "Azure denied GET %s", c.describe(blob))
		default:
			return werr.Newf(werr.Io, "Azure replace %s returned HTTP %d", c.describe(blob), current.Status)
		}
	}
	return werr.Newf(werr.Busy, "conditional replacement of %s kept losing a race", c.describe(blob))
}

// azureListBlob is one `List Blobs` entry.
type azureListBlob struct {
	Name       string `xml:"Name"`
	Properties struct {
		LastModified  string `xml:"Last-Modified"`
		ContentLength uint64 `xml:"Content-Length"`
	} `xml:"Properties"`
}

type azureListResult struct {
	XMLName xml.Name        `xml:"EnumerationResults"`
	Blobs   []azureListBlob `xml:"Blobs>Blob"`
	// Azurite and Azure return NextMarker empty on the last page.
	NextMarker string `xml:"NextMarker"`
}

// listBlobs enumerates every blob under `prefix`, following markers. A missing
// container is an empty result, matching the Rust client.
func (c *azureClient) listBlobs(prefix string) ([]azureListBlob, error) {
	var out []azureListBlob
	marker := ""
	for page := 0; page < 10000; page++ {
		query := []azureQuery{
			{"restype", "container"},
			{"comp", "list"},
			{"prefix", prefix},
			{"maxresults", "1000"},
		}
		if marker != "" {
			query = append(query, azureQuery{"marker", marker})
		}
		response, err := c.do("GET", "", query, nil, nil)
		if err != nil {
			return nil, err
		}
		if response.Status == http.StatusNotFound {
			return out, nil
		}
		if response.Status != http.StatusOK {
			return nil, werr.Newf(werr.Io, "Azure list returned HTTP %d: %s",
				response.Status, azureBodySnippet(response.Body))
		}
		var parsed azureListResult
		if err := xml.Unmarshal(response.Body, &parsed); err != nil {
			return nil, werr.Wrap(werr.Io, err, "cannot parse the Azure List Blobs response")
		}
		out = append(out, parsed.Blobs...)
		if parsed.NextMarker == "" {
			return out, nil
		}
		marker = parsed.NextMarker
	}
	return nil, werr.Newf(werr.LimitExceeded, "Azure List Blobs exceeded its page bound")
}

// ensureContainer creates the container when it does not exist. Idempotent.
func (c *azureClient) ensureContainer() error {
	response, err := c.do("HEAD", "", []azureQuery{{"restype", "container"}}, nil, nil)
	if err != nil {
		return err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
	case http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "Azure denied reading container `%s`", c.config.Container)
	default:
		return werr.Newf(werr.Io, "Azure Get Container Properties returned HTTP %d: %s",
			response.Status, azureBodySnippet(response.Body))
	}
	created, err := c.do("PUT", "", []azureQuery{{"restype", "container"}}, nil, nil)
	if err != nil {
		return err
	}
	switch created.Status {
	case http.StatusOK, http.StatusCreated, http.StatusNoContent:
		return nil
	case http.StatusConflict:
		// A concurrent creator won; that is the desired outcome.
		return nil
	case http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "Azure denied creating container `%s`", c.config.Container)
	default:
		return werr.Newf(werr.Io, "Azure Create Container `%s` returned HTTP %d: %s",
			c.config.Container, created.Status, azureBodySnippet(created.Body))
	}
}

func azureBodySnippet(body []byte) string {
	text := strings.TrimSpace(string(body))
	runes := []rune(text)
	if len(runes) > 240 {
		runes = runes[:240]
	}
	if len(runes) == 0 {
		return "(empty body)"
	}
	return string(runes)
}

// ---- SharedKey signing ---------------------------------------------------

// azureSharedKeySignature computes the `Authorization` signature value.
func azureSharedKeySignature(account, encodedKey, method string, headers map[string]string, bodyLen int, requestPath, canonicalQuery string) (string, error) {
	key, err := decodeBase64Any(encodedKey)
	if err != nil {
		return "", werr.Newf(werr.InvalidArgument,
			"Azure account key is not valid base64 (%s); the key itself is not printed", err.Error())
	}
	stringToSign := azureStringToSign(account, method, headers, bodyLen, requestPath, canonicalQuery)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// azureStringToSign is the exact Blob service string-to-sign. It is split out
// so a test can assert the field order and the canonicalised resource without
// re-deriving the HMAC.
func azureStringToSign(account, method string, headers map[string]string, bodyLen int, requestPath, canonicalQuery string) string {
	header := func(name string) string { return headers[name] }
	contentLength := ""
	if bodyLen > 0 {
		contentLength = strconv.Itoa(bodyLen)
	}
	var builder strings.Builder
	// Fixed field order from the Blob service specification. `Date` is empty
	// because `x-ms-date` is always sent; `Content-Length` is empty when the
	// body is empty even though the header itself is transmitted as `0`.
	for _, value := range []string{
		method,
		header("content-encoding"),
		header("content-language"),
		contentLength,
		header("content-md5"),
		header("content-type"),
		header("date"),
		header("if-modified-since"),
		header("if-match"),
		header("if-none-match"),
		header("if-unmodified-since"),
		header("range"),
	} {
		builder.WriteString(value)
		builder.WriteByte('\n')
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		if strings.HasPrefix(name, "x-ms-") {
			names = append(names, name)
		}
	}
	sortStrings(names)
	for _, name := range names {
		builder.WriteString(name)
		builder.WriteByte(':')
		builder.WriteString(strings.TrimSpace(headers[name]))
		builder.WriteByte('\n')
	}
	// The canonicalised resource is the account followed by the request path.
	// A path-style endpoint (Azurite) puts the account in the URL path, so the
	// account legitimately appears twice: that is exactly the string the
	// service recomputes.
	builder.WriteString("/")
	builder.WriteString(account)
	builder.WriteString(percentDecode(requestPath))
	for _, pair := range strings.Split(canonicalQuery, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		builder.WriteByte('\n')
		builder.WriteString(strings.ToLower(percentDecode(name)))
		builder.WriteByte(':')
		builder.WriteString(percentDecode(value))
	}
	return builder.String()
}

// ---- encoding helpers ----------------------------------------------------

// encodeAzurePath is RFC 3986 encoding with `/` preserved, so a logical key
// such as `objects/ab/<hash>` keeps its path segments.
func encodeAzurePath(path string) string {
	var builder strings.Builder
	for i := 0; i < len(path); i++ {
		b := path[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '~' || b == '/' {
			builder.WriteByte(b)
		} else {
			fmt.Fprintf(&builder, "%%%02X", b)
		}
	}
	return builder.String()
}

// encodeAzureComponent is the same encoding with `/` escaped as well.
func encodeAzureComponent(value string) string {
	var builder strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '~' {
			builder.WriteByte(b)
		} else {
			fmt.Fprintf(&builder, "%%%02X", b)
		}
	}
	return builder.String()
}

func percentDecode(value string) string {
	if !strings.Contains(value, "%") {
		return value
	}
	bytes := []byte(value)
	out := make([]byte, 0, len(bytes))
	for index := 0; index < len(bytes); {
		if bytes[index] == '%' && index+2 < len(bytes) {
			if decoded, err := hex.DecodeString(string(bytes[index+1 : index+3])); err == nil {
				out = append(out, decoded...)
				index += 3
				continue
			}
		}
		out = append(out, bytes[index])
		index++
	}
	return string(out)
}

func canonicalAzureQuery(query []azureQuery) string {
	encoded := make([]azureQuery, 0, len(query))
	for _, pair := range query {
		encoded = append(encoded, azureQuery{encodeAzureComponent(pair.Name), encodeAzureComponent(pair.Value)})
	}
	sortAzureQueries(encoded)
	var builder strings.Builder
	for i, pair := range encoded {
		if i > 0 {
			builder.WriteByte('&')
		}
		builder.WriteString(pair.Name)
		builder.WriteByte('=')
		builder.WriteString(pair.Value)
	}
	return builder.String()
}

func sortAzureQueries(pairs []azureQuery) {
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0; j-- {
			if pairs[j-1].Name < pairs[j].Name ||
				(pairs[j-1].Name == pairs[j].Name && pairs[j-1].Value <= pairs[j].Value) {
				break
			}
			pairs[j-1], pairs[j] = pairs[j], pairs[j-1]
		}
	}
}

// decodeBase64Any accepts the standard and URL-safe alphabets with optional
// padding. It is deliberately strict (invalid character, wrong padding, or
// non-canonical trailing bits is an error) so two different strings can never
// decode to the same key.
func decodeBase64Any(text string) ([]byte, error) {
	value := func(b byte) (byte, bool) {
		switch {
		case b >= 'A' && b <= 'Z':
			return b - 'A', true
		case b >= 'a' && b <= 'z':
			return b - 'a' + 26, true
		case b >= '0' && b <= '9':
			return b - '0' + 52, true
		case b == '+' || b == '-':
			return 62, true
		case b == '/' || b == '_':
			return 63, true
		default:
			return 0, false
		}
	}
	bytesIn := []byte(text)
	end := len(bytesIn)
	for end > 0 && bytesIn[end-1] == '=' {
		end--
	}
	padding := len(bytesIn) - end
	if padding > 2 {
		return nil, fmt.Errorf("base64 `%d` padding bytes; at most two are allowed", padding)
	}
	remainder := end % 4
	if remainder == 1 {
		return nil, fmt.Errorf("base64 has a trailing 6-bit character with no complete byte")
	}
	expectedPadding := 0
	switch remainder {
	case 0:
		expectedPadding = 0
	case 2:
		expectedPadding = 2
	default:
		expectedPadding = 1
	}
	if padding > 0 && padding != expectedPadding {
		return nil, fmt.Errorf("base64 padding of %d bytes is wrong for %d characters; expected %d",
			padding, end, expectedPadding)
	}
	out := make([]byte, 0, end/4*3+3)
	var accumulator uint32
	bits := uint32(0)
	for i := 0; i < end; i++ {
		v, ok := value(bytesIn[i])
		if !ok {
			return nil, fmt.Errorf("base64 byte 0x%02x is outside both RFC 4648 alphabets", bytesIn[i])
		}
		accumulator = (accumulator << 6) | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(accumulator>>bits))
			accumulator &= (1 << bits) - 1
		}
	}
	if bits > 0 && accumulator != 0 {
		return nil, fmt.Errorf("base64 trailing bits are not zero (non-canonical encoding)")
	}
	return out, nil
}

// ---- fenced LOCK record --------------------------------------------------

func encodeAzureLock(owner string, fence, sequence uint64, deadlineNS, renewedNS int64, pendingGeneration uint64, pendingCommit string, pendingCommitLen uint64) string {
	return encodeFenceLock(azureFenceSchemas, owner, fence, sequence, deadlineNS, renewedNS, pendingGeneration, pendingCommit, pendingCommitLen)
}

func encodeAzureReleased(owner string, fence, sequence uint64, releasedNS int64, releasedFrom string, pendingGeneration uint64, pendingCommit string, pendingCommitLen uint64) string {
	return encodeFenceReleased(azureFenceSchemas, owner, fence, sequence, releasedNS, releasedFrom, pendingGeneration, pendingCommit, pendingCommitLen)
}

func parseAzureLock(bytes []byte) (publishedLock, bool) {
	return parseFenceLock(bytes, azureFenceSchemas)
}
