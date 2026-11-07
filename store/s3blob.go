// S3 blob plane: the immutable content-addressed namespace over an
// S3-compatible endpoint.
//
// The logical keys are exactly the local layout, so a store built through this
// plane is byte-identical to one built on a POSIX filesystem and can be read by
// the other implementation without translation:
//
//	objects/<ab>/<hash>
//	manifests/<ab>/<hash>
//	indexes/<ab>/<hash>.idx
//	packs/<ab>/<hash>
//	pack-catalog/<ab>/<hash>
//
// Publication is create-once (`PUT` with `If-None-Match: *`). An existing key
// with identical bytes is idempotent; different bytes under a content-addressed
// name is `Exists`. There is no unconditional overwrite anywhere in this file.
//
// `durable_fsync` here means "the configured provider acknowledged the write".
// S3 has no separate fsync primitive. The MinIO court backs its data directory
// with a tmpfs, so it proves protocol and conditional-write behaviour, not
// media or power-loss durability.
package store

import (
	"net/http"
	"strings"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

type s3BlobPlane struct {
	client *s3Client
	caps   BlobCapabilities
}

func newS3BlobPlane(client *s3Client) *s3BlobPlane {
	return &s3BlobPlane{client: client, caps: BlobCapabilities{
		Backend:        "s3",
		AtomicPublish:  true,
		DurableFSync:   true,
		TrueRangeReads: true,
		MaxObjectBytes: s3MaxObjectBytes,
		Consistency: "single-node S3-compatible endpoint; read-after-write and " +
			"list-after-write for published keys; conditional writes are required " +
			"and measured at writable open",
		Publication: "S3 PUT with If-None-Match: * (create-once); identical bytes " +
			"under an existing key are idempotent and different bytes are refused; " +
			"durability is the provider acknowledgement, not a local fsync",
	}}
}

func (p *s3BlobPlane) Label() string                  { return "s3" }
func (p *s3BlobPlane) Capabilities() BlobCapabilities { return p.caps }
func (p *s3BlobPlane) Root() string                   { return "s3://" + p.client.config.Bucket }
func (p *s3BlobPlane) Flush() error                   { return nil }
func (p *s3BlobPlane) Close() error {
	p.client.http.CloseIdleConnections()
	return nil
}

func (p *s3BlobPlane) ReclaimUnreferencedPacks() (PackReclaim, error) {
	return PackReclaim{}, nil
}

// EnsureBlobLayout creates the bucket if it is absent. S3 has no directories.
func (p *s3BlobPlane) EnsureBlobLayout() error { return p.client.ensureBucket() }

func (p *s3BlobPlane) VerifyPacks() ([]string, error) { return nil, nil }

func (p *s3BlobPlane) key(kind BlobKind, id model.Hash32) string {
	return blobRelPath(kind, id)
}

func (p *s3BlobPlane) Get(kind BlobKind, id model.Hash32) ([]byte, error) {
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
		return nil, werr.Newf(werr.NotFound, "blob s3://%s/%s does not exist", p.client.config.Bucket, key)
	case http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/%s", p.client.config.Bucket, key)
	default:
		return nil, werr.Newf(werr.Io, "S3 GET s3://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, response.Status)
	}
}

func (p *s3BlobPlane) GetRange(kind BlobKind, id model.Hash32, offset, length uint64) ([]byte, error) {
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
		// The server ignored Range. Slice the whole object.
		total := uint64(len(response.Body))
		if offset > total {
			return nil, werr.Newf(werr.InvalidArgument,
				"read offset %d is beyond s3://%s/%s (%d bytes)", offset, p.client.config.Bucket, key, total)
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
		return nil, werr.Newf(werr.NotFound, "blob s3://%s/%s does not exist", p.client.config.Bucket, key)
	case http.StatusRequestedRangeNotSatisfiable:
		total, err := p.Length(kind, id)
		if err != nil {
			return nil, err
		}
		if offset == total {
			return []byte{}, nil
		}
		return nil, werr.Newf(werr.InvalidArgument,
			"read offset %d is beyond s3://%s/%s (%d bytes)", offset, p.client.config.Bucket, key, total)
	case http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "S3 denied GET s3://%s/%s", p.client.config.Bucket, key)
	default:
		return nil, werr.Newf(werr.Io, "S3 ranged GET s3://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, response.Status)
	}
}

func (p *s3BlobPlane) Put(kind BlobKind, id model.Hash32, data []byte) error {
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
	return werr.Newf(werr.Exists, "blob s3://%s/%s already exists with different bytes", p.client.config.Bucket, key)
}

func (p *s3BlobPlane) Delete(kind BlobKind, id model.Hash32) error {
	key := p.key(kind, id)
	return p.deleteKey(key)
}

func (p *s3BlobPlane) DeleteEntry(entry BlobEntry) error {
	return p.deleteKey(entry.Rel)
}

func (p *s3BlobPlane) deleteKey(key string) error {
	head, err := p.client.head(key)
	if err != nil {
		return err
	}
	switch head.Status {
	case http.StatusOK, http.StatusNoContent:
	case http.StatusNotFound:
		return werr.Newf(werr.NotFound, "blob s3://%s/%s does not exist", p.client.config.Bucket, key)
	case http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "S3 denied HEAD s3://%s/%s", p.client.config.Bucket, key)
	default:
		return werr.Newf(werr.Io, "S3 HEAD s3://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, head.Status)
	}
	response, err := p.client.delete(key)
	if err != nil {
		return err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return werr.Newf(werr.NotFound, "blob s3://%s/%s does not exist", p.client.config.Bucket, key)
	case http.StatusForbidden:
		return werr.Newf(werr.Unauthorized, "S3 denied DELETE s3://%s/%s", p.client.config.Bucket, key)
	default:
		return werr.Newf(werr.Io, "S3 DELETE s3://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, response.Status)
	}
}

func (p *s3BlobPlane) Length(kind BlobKind, id model.Hash32) (uint64, error) {
	key := p.key(kind, id)
	response, err := p.client.head(key)
	if err != nil {
		return 0, err
	}
	switch response.Status {
	case http.StatusOK, http.StatusNoContent:
		if response.ContentLength < 0 {
			return 0, werr.Newf(werr.Io, "S3 HEAD s3://%s/%s is missing Content-Length",
				p.client.config.Bucket, key)
		}
		return uint64(response.ContentLength), nil
	case http.StatusNotFound:
		return 0, werr.Newf(werr.NotFound, "blob s3://%s/%s does not exist", p.client.config.Bucket, key)
	case http.StatusForbidden:
		return 0, werr.Newf(werr.Unauthorized, "S3 denied HEAD s3://%s/%s", p.client.config.Bucket, key)
	default:
		return 0, werr.Newf(werr.Io, "S3 HEAD s3://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, response.Status)
	}
}

func (p *s3BlobPlane) Exists(kind BlobKind, id model.Hash32) (bool, error) {
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
		return false, werr.Newf(werr.Unauthorized, "S3 denied HEAD s3://%s/%s", p.client.config.Bucket, key)
	default:
		return false, werr.Newf(werr.Io, "S3 HEAD s3://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, response.Status)
	}
}

// List enumerates one namespace (`objects`, `manifests`, `packs`, ...) by key
// prefix. Unrecognized names are reported as problems, never silently dropped.
func (p *s3BlobPlane) List(kindDir string) ([]BlobEntry, []string, error) {
	prefix := strings.TrimSuffix(kindDir, "/") + "/"
	objects, err := p.client.listPrefix(prefix)
	if err != nil {
		return nil, nil, err
	}
	entries := make([]BlobEntry, 0, len(objects))
	problems := make([]string, 0)
	for _, object := range objects {
		if strings.HasSuffix(object.Key, "/") {
			continue
		}
		kind, id, ok := parseBlobRel(object.Key)
		if !ok {
			problems = append(problems, "unrecognized blob key s3://"+p.client.config.Bucket+"/"+object.Key)
			continue
		}
		entries = append(entries, BlobEntry{
			Kind: kind, ID: id, Rel: object.Key, Size: object.Size, ModTime: object.LastModified,
		})
	}
	return entries, problems, nil
}

func (p *s3BlobPlane) Modified(kind BlobKind, id model.Hash32) (time.Time, bool) {
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

// probe publishes a private 192-byte object, HEADs its length, reads a 17-byte
// mid-range, deletes it, and observes the deletion. It is the same evidence the
// local plane produces, over the same hard limits.
func (p *s3BlobPlane) probe() (BlobProbe, error) {
	probe := BlobProbe{Backend: "s3"}
	data := probeBytes()
	rel := probeRelPath("blob")
	probe.Attempted = true
	probe.BytesProbed = uint64(len(data))
	if _, ok, err := p.client.putConditional(rel, data, nil, false); err != nil {
		return probe, err
	} else if !ok {
		return probe, werr.Newf(werr.Io, "S3 blob probe key %s already exists", rel)
	}
	// A second create-once write must be refused; if it succeeded the endpoint
	// is ignoring If-None-Match and a writable store cannot be proven safe.
	if _, ok, err := p.client.putConditional(rel, []byte("probe-overwrite"), nil, false); err != nil {
		return probe, err
	} else if ok {
		_, _ = p.client.delete(rel)
		return probe, werr.Newf(werr.Unsupported,
			"S3-compatible endpoint ignored If-None-Match: *; refusing a writable store because create-once publication cannot be guaranteed")
	}
	stored, err := p.client.get(rel, 0, 0)
	if err != nil {
		_, _ = p.client.delete(rel)
		return probe, err
	}
	if stored.Status != http.StatusOK {
		_, _ = p.client.delete(rel)
		return probe, werr.Newf(werr.Io, "S3 blob probe read returned HTTP %d", stored.Status)
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
			"blob plane `s3` failed its capability probe (create_once_visible=%t, length_match=%t, range_read_match=%t, delete_observed=%t)",
			probe.CreateOnceVisible, probe.LengthMatch, probe.RangeReadMatch, probe.DeleteObserved)
	}
	probe.Detail = "published 192 bytes under a private key with If-None-Match: *, refused a second create, HEAD reported that length, a 17-byte ranged read matched, and delete was observed; durability is the provider acknowledgement and is not proved here"
	return probe, nil
}
