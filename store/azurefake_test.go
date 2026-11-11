// In-process Azure Blob test double (subphase R14).
//
// This is a test double, not an Azurite stand-in. It exists so the failure
// modes a well-behaved emulator cannot produce — an endpoint that ignores
// `If-Match`, or one that compares the ETag literally — are exercised, and so
// the SharedKey signature is checked by a second, independently written
// implementation of the documented string-to-sign. The real service behaviour
// is covered by the Azurite court in `azure_integration_test.go`.
package store

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const azureFakeAccount = "devstoreaccount1"
const azureFakeKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
const azureFakeContainer = "weft-court"

type azureFakeObject struct {
	data  []byte
	etag  string
	mtime string
}

type azureFake struct {
	mu sync.Mutex
	// objects are keyed by their path after the container.
	objects map[string]*azureFakeObject
	counter uint64
	// ignoreIfMatch makes the endpoint accept a stale conditional write. A
	// store must refuse to open against such an endpoint.
	ignoreIfMatch bool
	// ignoreIfNoneMatch makes create-once unconditional.
	ignoreIfNoneMatch bool
	// literalCompare returns quoted ETags but compares If-Match literally against
	// the unquoted tag — the deviation the S3/RGW-style endpoints exhibit and the
	// probe must negotiate.
	literalCompare bool
	// rejectEverything answers 403 to data operations.
	forbid bool
	// badSignature makes every signature fail, to prove Unauthorized.
	badSignature bool
}

func newAzureFake() *azureFake {
	return &azureFake{objects: map[string]*azureFakeObject{}}
}

func (f *azureFake) newETag() string {
	f.counter++
	return fmt.Sprintf("\"0x8D%08X\"", f.counter)
}

func (f *azureFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.verifySignature(r) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "<Error><Code>AuthenticationFailed</Code></Error>")
		return
	}
	path := r.URL.Path
	prefix := "/" + azureFakeAccount
	if !strings.HasPrefix(path, prefix) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimPrefix(rest, "/")
	container, key, _ := strings.Cut(rest, "/")
	if container != azureFakeContainer {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	query := r.URL.Query()
	// Container-level operations.
	if key == "" {
		if query.Get("comp") == "list" && r.Method == http.MethodGet {
			f.list(w, query.Get("prefix"), query.Get("marker"))
			return
		}
		if query.Get("restype") == "container" || r.Method == http.MethodHead || r.Method == http.MethodPut {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if f.forbid {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodPut:
		f.put(w, r, key)
	case http.MethodGet:
		f.get(w, r, key)
	case http.MethodHead:
		f.head(w, key)
	case http.MethodDelete:
		if _, ok := f.objects[key]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.objects, key)
		w.WriteHeader(http.StatusAccepted)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *azureFake) put(w http.ResponseWriter, r *http.Request, key string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(azureMaxObjectBytes)+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	existing := f.objects[key]
	ifNone := r.Header.Get("If-None-Match")
	ifMatch := r.Header.Get("If-Match")
	if ifNone == "*" && existing != nil && !f.ignoreIfNoneMatch {
		w.WriteHeader(http.StatusConflict)
		return
	}
	if ifMatch != "" {
		if existing == nil {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		comparable := existing.etag
		candidate := ifMatch
		if f.literalCompare {
			// The endpoint holds the tag unquoted and compares the header
			// string to it with no normalisation, so a quoted header fails.
			comparable = strings.Trim(comparable, "\"")
		}
		if candidate != comparable && !f.ignoreIfMatch {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
	}
	etag := f.newETag()
	f.objects[key] = &azureFakeObject{data: body, etag: etag, mtime: "Mon, 02 Jan 2006 15:04:05 GMT"}
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusCreated)
}

func (f *azureFake) get(w http.ResponseWriter, r *http.Request, key string) {
	object, ok := f.objects[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", object.etag)
	if spec := r.Header.Get("Range"); spec != "" && strings.HasPrefix(spec, "bytes=") {
		parts := strings.SplitN(strings.TrimPrefix(spec, "bytes="), "-", 2)
		start, err1 := strconv.ParseUint(parts[0], 10, 64)
		end, err2 := strconv.ParseUint(parts[1], 10, 64)
		if err1 != nil || err2 != nil || start > end || start >= uint64(len(object.data)) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if end >= uint64(len(object.data)) {
			end = uint64(len(object.data)) - 1
		}
		w.Header().Set("Content-Length", strconv.FormatUint(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(object.data[start : end+1])
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(object.data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(object.data)
}

func (f *azureFake) head(w http.ResponseWriter, key string) {
	object, ok := f.objects[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", object.etag)
	w.Header().Set("Content-Length", strconv.Itoa(len(object.data)))
	w.Header().Set("Last-Modified", object.mtime)
	w.WriteHeader(http.StatusOK)
}

type azureFakeBlobXML struct {
	Name       string `xml:"Name"`
	Properties struct {
		LastModified  string `xml:"Last-Modified"`
		ContentLength uint64 `xml:"Content-Length"`
	} `xml:"Properties"`
}

func (f *azureFake) list(w http.ResponseWriter, prefix, _ string) {
	names := make([]string, 0, len(f.objects))
	for name := range f.objects {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	type blobs struct {
		Blob []azureFakeBlobXML `xml:"Blob"`
	}
	document := struct {
		XMLName   xml.Name `xml:"EnumerationResults"`
		Container string   `xml:"Container"`
		Blobs     blobs    `xml:"Blobs"`
	}{Container: azureFakeContainer}
	for _, name := range names {
		entry := azureFakeBlobXML{Name: name}
		entry.Properties.LastModified = f.objects[name].mtime
		entry.Properties.ContentLength = uint64(len(f.objects[name].data))
		document.Blobs.Blob = append(document.Blobs.Blob, entry)
	}
	body, _ := xml.Marshal(document)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// verifySignature recomputes the SharedKey signature from the raw request with
// an implementation written from the Blob service specification, independently
// of the client's signer.
func (f *azureFake) verifySignature(r *http.Request) bool {
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "SharedKey ") {
		return false
	}
	provided := strings.TrimPrefix(authorization, "SharedKey ")
	colon := strings.Index(provided, ":")
	if colon < 0 {
		return false
	}
	account := provided[:colon]
	signature := provided[colon+1:]
	if account != azureFakeAccount {
		return false
	}
	if f.badSignature {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(azureFakeKey)
	if err != nil {
		return false
	}
	expected := computeFakeSignature(key, r)
	return expected == signature
}

func computeFakeSignature(key []byte, r *http.Request) string {
	// The canonicalised headers are every x-ms-* header, lowercased and sorted.
	headers := map[string]string{}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-ms-") {
			headers[lower] = strings.TrimSpace(values[0])
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	canonicalHeaders := ""
	for _, name := range names {
		canonicalHeaders += name + ":" + headers[name] + "\n"
	}
	contentLength := ""
	if r.ContentLength > 0 {
		contentLength = strconv.FormatInt(r.ContentLength, 10)
	}
	stringToSign := r.Method + "\n" +
		r.Header.Get("Content-Encoding") + "\n" +
		r.Header.Get("Content-Language") + "\n" +
		contentLength + "\n" +
		r.Header.Get("Content-MD5") + "\n" +
		r.Header.Get("Content-Type") + "\n" +
		r.Header.Get("Date") + "\n" +
		r.Header.Get("If-Modified-Since") + "\n" +
		r.Header.Get("If-Match") + "\n" +
		r.Header.Get("If-None-Match") + "\n" +
		r.Header.Get("If-Unmodified-Since") + "\n" +
		r.Header.Get("Range") + "\n" +
		canonicalHeaders +
		"/" + azureFakeAccount + r.URL.Path
	// The canonicalised resource appends one line per query parameter, sorted
	// by name, with the value decoded.
	query := r.URL.Query()
	queryNames := make([]string, 0, len(query))
	for name := range query {
		queryNames = append(queryNames, name)
	}
	sort.Strings(queryNames)
	for _, name := range queryNames {
		stringToSign += "\n" + strings.ToLower(name) + ":" + query.Get(name)
	}
	return base64.StdEncoding.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
}

func accountFromRequest(r *http.Request) string {
	// The server knows its own account; a request cannot carry another one.
	return azureFakeAccount
}

// azureFakeClient starts the double and returns a client pointed at it.
func azureFakeClient(t *testing.T, fake *azureFake) *azureClient {
	t.Helper()
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	config := AzureConfig{
		Endpoint:       server.URL + "/" + azureFakeAccount,
		Container:      azureFakeContainer,
		Account:        azureFakeAccount,
		Key:            azureFakeKey,
		LockLease:      60 * time.Second,
		RequestTimeout: 10 * time.Second,
	}
	client, err := newAzureClient(config)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return client
}
