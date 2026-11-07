// GCS blob plane: the immutable content-addressed namespace over the GCS JSON
// API.
//
// The logical keys are exactly the local layout, so a store built through this
// plane is byte-identical to one built on a POSIX filesystem and can be read by
// the Rust implementation:
//
//	objects/<ab>/<hash>
//	manifests/<ab>/<hash>
//	indexes/<ab>/<commit>.idx
//	packs/<ab>/<hash>
//	pack-catalog/<ab>/<hash>
//
// Publication is create-once (`ifGenerationMatch=0`). An existing key with
// identical bytes is idempotent; different bytes under a content-addressed name
// is `Exists`. There is no unconditional overwrite anywhere in this file.
//
// `durable_fsync` here means "the configured provider acknowledged the write".
// GCS has no separate fsync primitive. The emulator court uses a memory
// backend, so it proves protocol and generation-precondition behaviour, not
// media or power-loss durability.
package store

import (
	"net/http"
	"strings"
	"time"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

type gcsBlobPlane struct {
	client *gcsClient
	caps   BlobCapabilities
}

func newGCSBlobPlane(client *gcsClient) *gcsBlobPlane {
	return &gcsBlobPlane{client: client, caps: BlobCapabilities{
		Backend:        "gcs",
		AtomicPublish:  true,
		DurableFSync:   true,
		TrueRangeReads: true,
		MaxObjectBytes: gcsMaxObjectBytes,
		Consistency: "single-endpoint GCS-compatible store; read-after-write and " +
			"list-after-write for published keys; generation preconditions " +
			"(ifGenerationMatch) are required and measured at writable open",
		Publication: "GCS JSON API upload with ifGenerationMatch=0 (create-once); " +
			"identical bytes under an existing key are idempotent and different " +
			"bytes are refused; durability is the provider acknowledgement, not " +
			"a local fsync",
	}}
}

func (p *gcsBlobPlane) Label() string                  { return "gcs" }
func (p *gcsBlobPlane) Capabilities() BlobCapabilities { return p.caps }
func (p *gcsBlobPlane) Root() string                   { return "gcs://" + p.client.config.Bucket }
func (p *gcsBlobPlane) Flush() error                   { return nil }
func (p *gcsBlobPlane) Close() error {
	p.client.http.CloseIdleConnections()
	return nil
}

func (p *gcsBlobPlane) ReclaimUnreferencedPacks() (PackReclaim, error) {
	return PackReclaim{}, nil
}

func (p *gcsBlobPlane) EnsureBlobLayout() error { return p.client.ensureBucket() }

func (p *gcsBlobPlane) VerifyPacks() ([]string, error) { return nil, nil }

func (p *gcsBlobPlane) key(kind BlobKind, id model.Hash32) string {
	return blobRelPath(kind, id)
}

func (p *gcsBlobPlane) Get(kind BlobKind, id model.Hash32) ([]byte, error) {
	key := p.key(kind, id)
	response, err := p.client.media(key, nil)
	if err != nil {
		return nil, err
	}
	switch response.Status {
	case http.StatusOK:
		p.client.stats.reads.Add(1)
		p.client.stats.bytesRead.Add(uint64(len(response.Body)))
		return response.Body, nil
	case http.StatusNotFound:
		return nil, werr.Newf(werr.NotFound, "blob gcs://%s/%s does not exist", p.client.config.Bucket, key)
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "GCS denied reading gcs://%s/%s", p.client.config.Bucket, key)
	default:
		return nil, werr.Newf(werr.Io, "GCS read gcs://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, response.Status)
	}
}

func (p *gcsBlobPlane) GetRange(kind BlobKind, id model.Hash32, offset, length uint64) ([]byte, error) {
	key := p.key(kind, id)
	response, err := p.client.media(key, &gcsRange{offset: offset, length: length})
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
				"read offset %d is beyond gcs://%s/%s (%d bytes)", offset, p.client.config.Bucket, key, total)
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
		return nil, werr.Newf(werr.NotFound, "blob gcs://%s/%s does not exist", p.client.config.Bucket, key)
	case http.StatusRequestedRangeNotSatisfiable:
		total, err := p.Length(kind, id)
		if err != nil {
			return nil, err
		}
		if offset == total {
			return []byte{}, nil
		}
		return nil, werr.Newf(werr.InvalidArgument,
			"read offset %d is beyond gcs://%s/%s (%d bytes)", offset, p.client.config.Bucket, key, total)
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, werr.Newf(werr.Unauthorized, "GCS denied reading gcs://%s/%s", p.client.config.Bucket, key)
	default:
		return nil, werr.Newf(werr.Io, "GCS ranged read gcs://%s/%s returned HTTP %d",
			p.client.config.Bucket, key, response.Status)
	}
}

func (p *gcsBlobPlane) Put(kind BlobKind, id model.Hash32, data []byte) error {
	key := p.key(kind, id)
	_, ok, err := p.client.upload(key, data, gcsMissing())
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
	return werr.Newf(werr.Exists, "blob gcs://%s/%s already exists with different bytes",
		p.client.config.Bucket, key)
}

func (p *gcsBlobPlane) Delete(kind BlobKind, id model.Hash32) error {
	return p.deleteKey(p.key(kind, id))
}

func (p *gcsBlobPlane) DeleteEntry(entry BlobEntry) error {
	return p.deleteKey(entry.Rel)
}

func (p *gcsBlobPlane) deleteKey(key string) error {
	meta, err := p.client.metadata(key)
	if err != nil {
		return err
	}
	if meta == nil {
		return werr.Newf(werr.NotFound, "blob gcs://%s/%s does not exist", p.client.config.Bucket, key)
	}
	return p.client.deleteObject(key)
}

func (p *gcsBlobPlane) Length(kind BlobKind, id model.Hash32) (uint64, error) {
	key := p.key(kind, id)
	meta, err := p.client.metadata(key)
	if err != nil {
		return 0, err
	}
	if meta == nil {
		return 0, werr.Newf(werr.NotFound, "blob gcs://%s/%s does not exist", p.client.config.Bucket, key)
	}
	return meta.Size, nil
}

func (p *gcsBlobPlane) Exists(kind BlobKind, id model.Hash32) (bool, error) {
	key := p.key(kind, id)
	meta, err := p.client.metadata(key)
	if err != nil {
		return false, err
	}
	return meta != nil, nil
}

// List enumerates one namespace (`objects`, `manifests`, `packs`, ...) by key
// prefix. Unrecognized names are reported as problems, never silently dropped.
func (p *gcsBlobPlane) List(kindDir string) ([]BlobEntry, []string, error) {
	prefix := strings.TrimSuffix(kindDir, "/") + "/"
	objects, err := p.client.listObjects(prefix)
	if err != nil {
		return nil, nil, err
	}
	entries := make([]BlobEntry, 0, len(objects))
	problems := make([]string, 0)
	for _, object := range objects {
		if strings.HasSuffix(object.Name, "/") {
			continue
		}
		kind, id, ok := parseBlobRel(object.Name)
		if !ok {
			problems = append(problems, "unrecognized blob key gcs://"+p.client.config.Bucket+"/"+object.Name)
			continue
		}
		entries = append(entries, BlobEntry{
			Kind: kind, ID: id, Rel: object.Name, Size: object.Size, ModTime: object.Updated,
		})
	}
	return entries, problems, nil
}

func (p *gcsBlobPlane) Modified(kind BlobKind, id model.Hash32) (time.Time, bool) {
	meta, err := p.client.metadata(p.key(kind, id))
	if err != nil || meta == nil || meta.Updated.IsZero() {
		return time.Time{}, false
	}
	return meta.Updated, true
}

// probe publishes a private 192-byte object, HEADs its length, reads a 17-byte
// mid-range, deletes it, and observes the deletion. It is the same evidence the
// local and S3 planes produce, over the same hard limits.
func (p *gcsBlobPlane) probe() (BlobProbe, error) {
	probe := BlobProbe{Backend: "gcs"}
	data := probeBytes()
	rel := probeRelPath("blob")
	probe.Attempted = true
	probe.BytesProbed = uint64(len(data))
	if _, ok, err := p.client.upload(rel, data, gcsMissing()); err != nil {
		return probe, err
	} else if !ok {
		return probe, werr.Newf(werr.Io, "GCS blob probe key %s already exists", rel)
	}
	// A second create-once write must be refused; if it succeeded the endpoint
	// is ignoring ifGenerationMatch=0 and a writable store cannot be proven safe.
	if _, ok, err := p.client.upload(rel, []byte("probe-overwrite"), gcsMissing()); err != nil {
		return probe, err
	} else if ok {
		_ = p.client.deleteObject(rel)
		return probe, werr.Newf(werr.Unsupported,
			"GCS-compatible endpoint ignored ifGenerationMatch=0; refusing a writable store because create-once publication cannot be guaranteed")
	}
	stored, err := p.client.media(rel, nil)
	if err != nil {
		_ = p.client.deleteObject(rel)
		return probe, err
	}
	if stored.Status != http.StatusOK {
		_ = p.client.deleteObject(rel)
		return probe, werr.Newf(werr.Io, "GCS blob probe read returned HTTP %d", stored.Status)
	}
	probe.CreateOnceVisible = overlayBytesSame(stored.Body, data)
	meta, err := p.client.metadata(rel)
	if err == nil && meta != nil {
		probe.LengthMatch = meta.Size == uint64(len(data))
	}
	start := uint64(len(data) / 3)
	want := uint64(len(data)) - start
	if want > 17 {
		want = 17
	}
	ranged, err := p.client.media(rel, &gcsRange{offset: start, length: want})
	if err != nil {
		_ = p.client.deleteObject(rel)
		return probe, err
	}
	probe.RangeReadMatch = ranged.Status == http.StatusPartialContent &&
		overlayBytesSame(ranged.Body, data[start:start+uint64(len(ranged.Body))])
	if err := p.deleteKey(rel); err != nil {
		return probe, err
	}
	after, err := p.client.metadata(rel)
	probe.DeleteObserved = err == nil && after == nil
	if !probe.CreateOnceVisible || !probe.LengthMatch || !probe.RangeReadMatch || !probe.DeleteObserved {
		return probe, werr.Newf(werr.Io,
			"blob plane `gcs` failed its capability probe (create_once_visible=%t, length_match=%t, range_read_match=%t, delete_observed=%t)",
			probe.CreateOnceVisible, probe.LengthMatch, probe.RangeReadMatch, probe.DeleteObserved)
	}
	probe.Detail = "published 192 bytes under a private key with ifGenerationMatch=0, refused a second create, metadata reported that length, a 17-byte ranged read matched, and delete was observed; durability is the provider acknowledgement and is not proved here"
	return probe, nil
}
