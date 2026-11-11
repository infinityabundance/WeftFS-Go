// Azure Blob blob plane: the immutable content-addressed namespace over an
// Azure Blob-compatible endpoint.
//
// The logical keys are exactly the local layout, so a store built through this
// plane is byte-identical to one built on a POSIX filesystem (or through the S3
// and GCS planes) and can be read by the other implementation without
// translation:
//
//	objects/<ab>/<hash>
//	manifests/<ab>/<hash>
//	indexes/<ab>/<hash>.idx
//	packs/<ab>/<hash>
//	pack-catalog/<ab>/<hash>
//
// Publication is create-once (`Put Blob` with `If-None-Match: *`). An existing
// key with identical bytes is idempotent; different bytes under a
// content-addressed name is `Exists`. There is no unconditional overwrite
// anywhere in this file.
//
// `durable_fsync` here means "the configured service acknowledged the write".
// Azure Blob has no separate fsync primitive. The Azurite court backs its data
// directory with a tmpfs, so it proves protocol and conditional-write
// behaviour, not media or power-loss durability.
package store

import (
	"net/http"
	"strings"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

type azureBlobPlane struct {
	client *azureClient
	caps   BlobCapabilities
}

func newAzureBlobPlane(client *azureClient) *azureBlobPlane {
	return &azureBlobPlane{client: client, caps: BlobCapabilities{
		Backend:        "azure",
		AtomicPublish:  true,
		DurableFSync:   true,
		TrueRangeReads: true,
		MaxObjectBytes: azureMaxObjectBytes,
		Consistency: "single-endpoint Azure Blob-compatible store; read-after-write " +
			"and list-after-write for published blobs; conditional writes " +
			"(If-None-Match: */If-Match: <ETag>) are required and measured at " +
			"writable open; a monotonic fencing token is carried in the LOCK blob",
		Publication: "Azure Put Blob (x-ms-blob-type: BlockBlob) with " +
			"If-None-Match: * (create-once); identical bytes under an existing " +
			"blob are idempotent and different bytes are refused; durability is " +
			"the service acknowledgement, not a local fsync",
	}}
}

func (p *azureBlobPlane) Label() string                  { return "azure" }
func (p *azureBlobPlane) Capabilities() BlobCapabilities { return p.caps }
func (p *azureBlobPlane) Root() string                   { return "azure://" + p.client.config.Container }
func (p *azureBlobPlane) Flush() error                   { return nil }
func (p *azureBlobPlane) Close() error {
	p.client.http.CloseIdleConnections()
	return nil
}

func (p *azureBlobPlane) ReclaimUnreferencedPacks() (PackReclaim, error) {
	return PackReclaim{}, nil
}

// EnsureBlobLayout creates the container if it is absent. Azure Blob has no
// directories.
func (p *azureBlobPlane) EnsureBlobLayout() error { return p.client.ensureContainer() }

func (p *azureBlobPlane) VerifyPacks() ([]string, error) { return nil, nil }

func (p *azureBlobPlane) key(kind BlobKind, id model.Hash32) string {
	return blobRelPath(kind, id)
}

func (p *azureBlobPlane) Get(kind BlobKind, id model.Hash32) ([]byte, error) {
	key := p.key(kind, id)
	response, err := p.client.get(key, 0, 0)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		p.client.stats.reads.Add(1)
		p.client.stats.bytesRead.Add(uint64(len(response.Body)))
		return response.Body, nil
	case http.StatusNotFound:
		return nil, werr.Newf(werr.NotFound, "blob azure://%s/%s does not exist", p.client.config.Container, key)
	case http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/%s", p.client.config.Container, key)
	default:
		return nil, werr.Newf(werr.Io, "Azure GET azure://%s/%s returned HTTP %d",
			p.client.config.Container, key, response.Status)
	}
}

func (p *azureBlobPlane) GetRange(kind BlobKind, id model.Hash32, offset, length uint64) ([]byte, error) {
	key := p.key(kind, id)
	response, err := p.client.get(key, offset, length)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusPartialContent:
		p.client.stats.reads.Add(1)
		p.client.stats.rangeReads.Add(1)
		p.client.stats.bytesRead.Add(uint64(len(response.Body)))
		return response.Body, nil
	case http.StatusOK:
		// The service ignored Range. Slice the whole blob.
		total := uint64(len(response.Body))
		if offset > total {
			return nil, werr.Newf(werr.InvalidArgument,
				"read offset %d is beyond azure://%s/%s (%d bytes)", offset, p.client.config.Container, key, total)
		}
		end := total
		if length < end-offset {
			end = offset + length
		}
		p.client.stats.reads.Add(1)
		p.client.stats.rangeReads.Add(1)
		p.client.stats.bytesRead.Add(end - offset)
		return response.Body[offset:end], nil
	case http.StatusNotFound:
		return nil, werr.Newf(werr.NotFound, "blob azure://%s/%s does not exist", p.client.config.Container, key)
	case http.StatusRequestedRangeNotSatisfiable:
		total, err := p.Length(kind, id)
		if err != nil {
			return nil, err
		}
		if offset == total {
			return []byte{}, nil
		}
		return nil, werr.Newf(werr.InvalidArgument,
			"read offset %d is beyond azure://%s/%s (%d bytes)", offset, p.client.config.Container, key, total)
	case http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "Azure denied GET azure://%s/%s", p.client.config.Container, key)
	default:
		return nil, werr.Newf(werr.Io, "Azure ranged GET azure://%s/%s returned HTTP %d",
			p.client.config.Container, key, response.Status)
	}
}

func (p *azureBlobPlane) Put(kind BlobKind, id model.Hash32, data []byte) error {
	key := p.key(kind, id)
	_, ok, err := p.client.putConditional(key, data, nil, true)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	existing, err := p.Get(kind, id)
	if err != nil {
		return err
	}
	if overlayBytesSame(existing, data) {
		return nil
	}
	return werr.Newf(werr.Exists, "blob azure://%s/%s already exists with different bytes", p.client.config.Container, key)
}

func (p *azureBlobPlane) Delete(kind BlobKind, id model.Hash32) error {
	return p.deleteKey(p.key(kind, id))
}

func (p *azureBlobPlane) DeleteEntry(entry BlobEntry) error {
	return p.deleteKey(entry.Rel)
}

func (p *azureBlobPlane) deleteKey(key string) error {
	head, err := p.client.head(key)
	if err != nil {
		return err
	}
	switch head.Status {
	case http.StatusOK, http.StatusNoContent:
	case http.StatusNotFound:
		return werr.Newf(werr.NotFound, "blob azure://%s/%s does not exist", p.client.config.Container, key)
	case http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "Azure denied HEAD azure://%s/%s", p.client.config.Container, key)
	default:
		return werr.Newf(werr.Io, "Azure HEAD azure://%s/%s returned HTTP %d",
			p.client.config.Container, key, head.Status)
	}
	response, err := p.client.delete(key)
	if err != nil {
		return err
	}
	switch response.Status {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return werr.Newf(werr.NotFound, "blob azure://%s/%s does not exist", p.client.config.Container, key)
	case http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "Azure denied DELETE azure://%s/%s", p.client.config.Container, key)
	default:
		return werr.Newf(werr.Io, "Azure DELETE azure://%s/%s returned HTTP %d",
			p.client.config.Container, key, response.Status)
	}
}

func (p *azureBlobPlane) Length(kind BlobKind, id model.Hash32) (uint64, error) {
	key := p.key(kind, id)
	response, err := p.client.head(key)
	if err != nil {
		return 0, err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		if response.ContentLength < 0 {
			return 0, werr.Newf(werr.Io, "Azure HEAD azure://%s/%s is missing Content-Length",
				p.client.config.Container, key)
		}
		return uint64(response.ContentLength), nil
	case http.StatusNotFound:
		return 0, werr.Newf(werr.NotFound, "blob azure://%s/%s does not exist", p.client.config.Container, key)
	case http.StatusForbidden:
		return 0, werr.Newf(werr.Unauthorized, "Azure denied HEAD azure://%s/%s", p.client.config.Container, key)
	default:
		return 0, werr.Newf(werr.Io, "Azure HEAD azure://%s/%s returned HTTP %d",
			p.client.config.Container, key, response.Status)
	}
}

func (p *azureBlobPlane) Exists(kind BlobKind, id model.Hash32) (bool, error) {
	key := p.key(kind, id)
	response, err := p.client.head(key)
	if err != nil {
		return false, err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusForbidden:
		return false, werr.Newf(werr.Unauthorized, "Azure denied HEAD azure://%s/%s", p.client.config.Container, key)
	default:
		return false, werr.Newf(werr.Io, "Azure HEAD azure://%s/%s returned HTTP %d",
			p.client.config.Container, key, response.Status)
	}
}

// List enumerates one namespace (`objects`, `manifests`, `packs`, ...) by key
// prefix. Unrecognized names are reported as problems, never silently dropped.
func (p *azureBlobPlane) List(kindDir string) ([]BlobEntry, []string, error) {
	prefix := strings.TrimSuffix(kindDir, "/") + "/"
	blobs, err := p.client.listBlobs(prefix)
	if err != nil {
		return nil, nil, err
	}
	entries := make([]BlobEntry, 0, len(blobs))
	problems := make([]string, 0)
	for _, blob := range blobs {
		if strings.HasSuffix(blob.Name, "/") {
			continue
		}
		kind, id, ok := parseBlobRel(blob.Name)
		if !ok {
			problems = append(problems, "unrecognized blob key azure://"+p.client.config.Container+"/"+blob.Name)
			continue
		}
		when, _ := time.Parse(time.RFC1123, blob.Properties.LastModified)
		entries = append(entries, BlobEntry{
			Kind: kind, ID: id, Rel: blob.Name, Size: blob.Properties.ContentLength, ModTime: when,
		})
	}
	return entries, problems, nil
}

func (p *azureBlobPlane) Modified(kind BlobKind, id model.Hash32) (time.Time, bool) {
	key := p.key(kind, id)
	response, err := p.client.head(key)
	if err != nil || (response.Status != http.StatusOK && response.Status != http.StatusNoContent) {
		return time.Time{}, false
	}
	if response.LastModified.IsZero() {
		return time.Time{}, false
	}
	return response.LastModified, true
}

// probe publishes a private 192-byte blob, HEADs its length, reads a 17-byte
// mid-range, deletes it, and observes the deletion. It is the same evidence the
// local and S3 planes produce, over the same hard limits.
func (p *azureBlobPlane) probe() (BlobProbe, error) {
	probe := BlobProbe{Backend: "azure"}
	data := probeBytes()
	rel := probeRelPath("blob")
	probe.Attempted = true
	probe.BytesProbed = uint64(len(data))
	if _, ok, err := p.client.putConditional(rel, data, nil, false); err != nil {
		return probe, err
	} else if !ok {
		return probe, werr.Newf(werr.Io, "Azure blob probe key %s already exists", rel)
	}
	// A second create-once write must be refused; if it succeeded the endpoint
	// is ignoring If-None-Match and a writable store cannot be proven safe.
	if _, ok, err := p.client.putConditional(rel, []byte("probe-overwrite"), nil, false); err != nil {
		return probe, err
	} else if ok {
		_, _ = p.client.delete(rel)
		return probe, werr.Newf(werr.Unsupported,
			"Azure-compatible endpoint ignored If-None-Match: *; refusing a writable store because create-once publication cannot be guaranteed")
	}
	stored, err := p.client.get(rel, 0, 0)
	if err != nil {
		_, _ = p.client.delete(rel)
		return probe, err
	}
	if stored.Status != http.StatusOK {
		_, _ = p.client.delete(rel)
		return probe, werr.Newf(werr.Io, "Azure blob probe read returned HTTP %d", stored.Status)
	}
	probe.CreateOnceVisible = overlayBytesSame(stored.Body, data)
	head, err := p.client.head(rel)
	if err == nil && (head.Status == http.StatusOK || head.Status == http.StatusNoContent) {
		probe.LengthMatch = uint64(head.ContentLength) == uint64(len(data))
	}
	start := uint64(len(data) / 3)
	want := uint64(len(data)) - start
	if want > 17 {
		want = 17
	}
	ranged, err := p.client.get(rel, start, want)
	if err != nil {
		_, _ = p.client.delete(rel)
		return probe, err
	}
	probe.RangeReadMatch = ranged.Status == http.StatusPartialContent &&
		overlayBytesSame(ranged.Body, data[start:start+uint64(len(ranged.Body))])
	if err := p.deleteKey(rel); err != nil {
		return probe, err
	}
	after, err := p.client.head(rel)
	probe.DeleteObserved = err == nil && after.Status == http.StatusNotFound
	if !probe.CreateOnceVisible || !probe.LengthMatch || !probe.RangeReadMatch || !probe.DeleteObserved {
		return probe, werr.Newf(werr.Io,
			"blob plane `azure` failed its capability probe (create_once_visible=%t, length_match=%t, range_read_match=%t, delete_observed=%t)",
			probe.CreateOnceVisible, probe.LengthMatch, probe.RangeReadMatch, probe.DeleteObserved)
	}
	probe.Detail = "published 192 bytes under a private key with If-None-Match: *, refused a second create, HEAD reported that length, a 17-byte ranged read matched, and delete was observed; durability is the service acknowledgement and is not proved here"
	return probe, nil
}
