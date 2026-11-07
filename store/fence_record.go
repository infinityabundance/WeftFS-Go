// Fenced writer record encoding and parsing, shared by every object-store
// backend.
//
// The record is backend-agnostic text: one schema line naming the backend and
// deployment, then `key=value` lines. Only the schema spellings differ between
// the S3 and GCS planes; the fields, the monotonic fencing token, the absolute
// lease deadline, and the `pending_generation`/`pending_commit`/
// `pending_commit_len` attestation are identical. S3 and GCS therefore parse
// and publish with one body, and a receipt can compare them field for field.
//
// This file was factored out of `s3client.go` with no wire change: the S3
// encoders below still emit exactly the same bytes.
package store

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/model"
)

// fenceSchemas names the accepted schema lines for one backend.
type fenceSchemas struct {
	v3         string
	v2         string
	v1         string
	releasedV2 string
	releasedV1 string
}

var s3FenceSchemas = fenceSchemas{
	v3:         s3LockSchema,
	v2:         s3LockSchemaV2,
	v1:         s3LockSchemaV1,
	releasedV2: s3ReleasedSchema,
	releasedV1: s3ReleasedSchemaV1,
}

var gcsFenceSchemas = fenceSchemas{
	v3:         gcsLockSchema,
	v2:         gcsLockSchemaV2,
	v1:         gcsLockSchemaV1,
	releasedV2: gcsReleasedSchema,
	releasedV1: gcsReleasedSchemaV1,
}

func encodeFenceLock(schemas fenceSchemas, owner string, fence, sequence uint64, deadlineNS, renewedNS int64, pendingGeneration uint64, pendingCommit string, pendingCommitLen uint64) string {
	if pendingCommit == "" {
		pendingCommit = "-"
	}
	if pendingGeneration == 0 {
		pendingCommitLen = 0
	}
	return fmt.Sprintf("%s\nowner=%s\nfence=%d\nsequence=%d\nlease_deadline_ns=%d\nrenewed_ns=%d\npending_generation=%d\npending_commit=%s\npending_commit_len=%d\n",
		schemas.v3, owner, fence, sequence, deadlineNS, renewedNS, pendingGeneration, pendingCommit, pendingCommitLen)
}

func encodeFenceReleased(schemas fenceSchemas, owner string, fence, sequence uint64, releasedNS int64, releasedFrom string, pendingGeneration uint64, pendingCommit string, pendingCommitLen uint64) string {
	if pendingCommit == "" {
		pendingCommit = "-"
	}
	if pendingGeneration == 0 {
		pendingCommitLen = 0
	}
	return fmt.Sprintf("%s\nowner=%s\nfence=%d\nsequence=%d\nreleased_ns=%d\nreleased_from=%s\npending_generation=%d\npending_commit=%s\npending_commit_len=%d\n",
		schemas.releasedV2, owner, fence, sequence, releasedNS, releasedFrom, pendingGeneration, pendingCommit, pendingCommitLen)
}

// parseFenceLock accepts the v3 publication record, the fenced v2 record, the
// legacy v1 record (fence 0), and both released tombstones. It is a direct port
// of Rust `writer_fence::parse_lock`; the only backend input is the schema set.
func parseFenceLock(bytes []byte, schemas fenceSchemas) (publishedLock, bool) {
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
	case schemas.v3:
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
		pendingLen, ok := unsigned("pending_commit_len")
		if !ok {
			return out, false
		}
		commit, ok := fields["pending_commit"]
		if !ok {
			commit = "-"
		}
		return publishedLock{
			schemaVersion: 3,
			owner:         owner, fence: fence, sequence: sequence, deadlineNS: deadline,
			renewedNS: renewed, pendingGeneration: pending, pendingCommit: commit,
			pendingCommitLen: pendingLen,
		}, true
	case schemas.v2:
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
			schemaVersion: 2,
			owner:         owner, fence: fence, sequence: sequence, deadlineNS: deadline,
			renewedNS: renewed, pendingGeneration: pending, pendingCommit: commit,
		}, true
	case schemas.v1:
		owner, ok := fields["owner"]
		if !ok {
			return out, false
		}
		deadline, ok := number("expires_ns")
		if !ok {
			return out, false
		}
		return publishedLock{schemaVersion: 1, owner: owner, deadlineNS: deadline, pendingCommit: "-"}, true
	case schemas.releasedV2:
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
		pending, ok := unsigned("pending_generation")
		if !ok {
			return out, false
		}
		pendingLen, ok := unsigned("pending_commit_len")
		if !ok {
			return out, false
		}
		commit, ok := fields["pending_commit"]
		if !ok {
			commit = "-"
		}
		return publishedLock{
			schemaVersion: 3,
			owner:         owner, fence: fence, sequence: sequence, deadlineNS: released,
			renewedNS: released, pendingGeneration: pending, pendingCommit: commit,
			pendingCommitLen: pendingLen, released: true,
			releasedFrom: fields["released_from"],
		}, true
	case schemas.releasedV1:
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
			schemaVersion: 2,
			owner:         owner, fence: fence, sequence: sequence, deadlineNS: released,
			renewedNS: released, pendingCommit: "-", released: true,
			releasedFrom: fields["released_from"],
		}, true
	default:
		return out, false
	}
}

// attestedCommit parses the commit hex a parsed record names.
func attestedCommit(commit string) (model.Hash32, bool) {
	if commit == "" || commit == "-" {
		return model.Hash32{}, false
	}
	parsed, err := hash.FromHex(commit)
	if err != nil {
		return model.Hash32{}, false
	}
	return parsed, true
}
