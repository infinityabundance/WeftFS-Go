package store

// MW2 multi-writer transactions (subphase R4), independent Go implementation.
//
// The normative contract is spec/WEFT-MULTIWRITER.md. This file mirrors the
// Rust transaction API and the on-disk `txs/<id>` / `writers` records byte for
// byte. The default remains WriterModeSingle (MW1); WriterModeOptimistic is
// opt-in and applies to the explicit transaction API only.

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// WriterMode selects the control-state publication contract.
type WriterMode string

const (
	// WriterModeSingle is MW1: one exclusive committer (the default).
	WriterModeSingle WriterMode = "single"
	// WriterModeOptimistic is MW2: independent committers publishing through a
	// conditional head compare-and-swap.
	WriterModeOptimistic WriterMode = "optimistic"
)

// WritersSchema is the writer-mode policy record schema.
const WritersSchema = "weft.writers.v1"

// TxSchema is the transaction discovery record schema.
const TxSchema = "weft.tx.v1"

// TxDigestDomain is the deterministic transaction digest domain.
const TxDigestDomain = "weft/tx/v1"

const (
	defaultTxMaxAttempts    = 8
	defaultTxOutcomeWindow  = 256
	defaultTxBackoffMicros  = 200
	defaultTxBackoffMaxMs   = 25
	defaultTxMaxOps         = 4096
	publicationLockDeadline = 10 * time.Second
)

func parseWriterMode(s string) (WriterMode, error) {
	switch WriterMode(s) {
	case "", WriterModeSingle:
		return WriterModeSingle, nil
	case WriterModeOptimistic:
		return WriterModeOptimistic, nil
	default:
		return "", werr.Newf(werr.InvalidArgument, "unknown writer mode %q (expected single or optimistic)", s)
	}
}

// TransactionOptions bounds one transaction.
type TransactionOptions struct {
	MaxAttempts    uint32
	OutcomeWindow  uint64
	BackoffBaseUS  uint64
	BackoffMaxMS   uint64
	MaxOps         int
	FailAfterTries uint32
}

// DefaultTransactionOptions returns the spec defaults.
func DefaultTransactionOptions() TransactionOptions {
	return TransactionOptions{
		MaxAttempts:   defaultTxMaxAttempts,
		OutcomeWindow: defaultTxOutcomeWindow,
		BackoffBaseUS: defaultTxBackoffMicros,
		BackoffMaxMS:  defaultTxBackoffMaxMs,
		MaxOps:        defaultTxMaxOps,
	}
}

func (o TransactionOptions) backoff(attempt uint32) time.Duration {
	shift := attempt
	if shift > 0 {
		shift--
	}
	if shift > 16 {
		shift = 16
	}
	us := o.BackoffBaseUS << shift
	if max := o.BackoffMaxMS * 1000; us > max {
		us = max
	}
	return time.Duration(us) * time.Microsecond
}

// PreValue is the pre-image a transaction observed for one state key.
type PreValue struct {
	Absent bool
	Hash   model.Hash32
	Entry  *model.EntryRecord
}

func (p PreValue) equal(other PreValue) bool {
	if p.Absent != other.Absent {
		return false
	}
	if p.Absent {
		return true
	}
	if (p.Entry == nil) != (other.Entry == nil) {
		return false
	}
	if p.Entry != nil {
		a, b := *p.Entry, *other.Entry
		return a.ID == b.ID && a.Parent == b.Parent && a.Target == b.Target && bytes.Equal(a.Name, b.Name)
	}
	return p.Hash == other.Hash
}

// Precondition is one observed pre-image plus an optional idempotent value.
type Precondition struct {
	Label      string
	Expected   PreValue
	Idempotent *PreValue
}

func (p Precondition) matches(current PreValue) bool {
	if p.Expected.equal(current) {
		return true
	}
	return p.Idempotent != nil && p.Idempotent.equal(current)
}

// AuthCheck is re-evaluated against the rebased state on every attempt.
type AuthCheck struct {
	Object    model.Hash32
	Principal auth.Principal
}

// Transaction is a prepared MW2 transaction.
type Transaction struct {
	ID             string
	BaseHead       model.Hash32
	BaseGeneration uint64
	Ops            []model.Op
	Preconditions  []Precondition
	Auth           []AuthCheck
	Pins           []model.Hash32
}

// IDHex is the transaction id.
func (t *Transaction) IDHex() string { return t.ID }

// Add appends one op and its precondition.
func (t *Transaction) add(op model.Op, pre Precondition, maxOps int) error {
	if len(t.Ops) >= maxOps {
		return werr.Newf(werr.LimitExceeded, "transaction exceeds the %d-op bound", maxOps)
	}
	if put, ok := op.(model.PutObjectOp); ok {
		if put.Record.Kind == model.KindFile && put.Record.Content != model.ZeroHash {
			found := false
			for _, pin := range t.Pins {
				if pin == put.Record.Content {
					found = true
					break
				}
			}
			if !found {
				t.Pins = append(t.Pins, put.Record.Content)
				sort.Slice(t.Pins, func(i, j int) bool {
					return bytes.Compare(t.Pins[i].Bytes(), t.Pins[j].Bytes()) < 0
				})
			}
		}
	}
	t.Ops = append(t.Ops, op)
	t.Preconditions = append(t.Preconditions, pre)
	return nil
}

// PutObject adds or replaces an object record.
func (t *Transaction) PutObject(state *model.State, record model.ObjectRecord) error {
	expected := PreValue{Absent: true}
	if existing, ok := state.Objects[record.ID]; ok {
		expected = PreValue{Hash: existing.Version}
	}
	idempotent := PreValue{Hash: record.Version}
	return t.add(model.PutObjectOp{Record: record}, Precondition{
		Label: "object", Expected: expected, Idempotent: &idempotent,
	}, defaultTxMaxOps)
}

// PutObjectCreate adds an object only if its id is absent.
func (t *Transaction) PutObjectCreate(record model.ObjectRecord) error {
	idempotent := PreValue{Hash: record.Version}
	return t.add(model.PutObjectOp{Record: record}, Precondition{
		Label: "object", Expected: PreValue{Absent: true}, Idempotent: &idempotent,
	}, defaultTxMaxOps)
}

// DeleteObject removes an object that must still be the observed version.
func (t *Transaction) DeleteObject(state *model.State, id model.Hash32) error {
	existing, ok := state.Objects[id]
	if !ok {
		return werr.Newf(werr.NotFound, "no such object to delete")
	}
	return t.add(model.DeleteObjectOp{ID: id}, Precondition{
		Label: "object", Expected: PreValue{Hash: existing.Version},
	}, defaultTxMaxOps)
}

// PutEntry adds or replaces a directory entry.
func (t *Transaction) PutEntry(state *model.State, record model.EntryRecord) error {
	expected := PreValue{Absent: true}
	if existing, ok := state.Entries[record.ID]; ok {
		copy := existing
		copy.Name = append([]byte(nil), existing.Name...)
		expected = PreValue{Entry: &copy}
	}
	idempotentEntry := record
	idempotentEntry.Name = append([]byte(nil), record.Name...)
	idempotent := PreValue{Entry: &idempotentEntry}
	return t.add(model.PutEntryOp{Record: record}, Precondition{
		Label: "entry", Expected: expected, Idempotent: &idempotent,
	}, defaultTxMaxOps)
}

// PutEntryCreate adds an entry only if (parent,name) is absent.
func (t *Transaction) PutEntryCreate(record model.EntryRecord) error {
	copy := record
	copy.Name = append([]byte(nil), record.Name...)
	idempotent := PreValue{Entry: &copy}
	return t.add(model.PutEntryOp{Record: record}, Precondition{
		Label: "entry", Expected: PreValue{Absent: true}, Idempotent: &idempotent,
	}, defaultTxMaxOps)
}

// DelEntry removes a directory entry that must still name the observed target.
func (t *Transaction) DelEntry(state *model.State, id model.Hash32) error {
	existing, ok := state.Entries[id]
	if !ok {
		return werr.Newf(werr.NotFound, "no such entry to remove")
	}
	copy := existing
	copy.Name = append([]byte(nil), existing.Name...)
	return t.add(model.DelEntryOp{ID: id}, Precondition{
		Label: "entry", Expected: PreValue{Entry: &copy},
	}, defaultTxMaxOps)
}

// PutRelation adds a relation with its deterministic id.
func (t *Transaction) PutRelation(state *model.State, record model.RelationRecord) error {
	expected := PreValue{Absent: true}
	if _, ok := state.Relations[record.ID]; ok {
		expected = PreValue{Hash: record.ID}
	}
	idempotent := PreValue{Hash: record.ID}
	return t.add(model.PutRelationOp{Record: record}, Precondition{
		Label: "relation", Expected: expected, Idempotent: &idempotent,
	}, defaultTxMaxOps)
}

// DelRelation removes a relation that must still be present.
func (t *Transaction) DelRelation(state *model.State, id model.Hash32) error {
	if _, ok := state.Relations[id]; !ok {
		return werr.Newf(werr.NotFound, "no such relation to remove")
	}
	return t.add(model.DelRelationOp{ID: id}, Precondition{
		Label: "relation", Expected: PreValue{Hash: id},
	}, defaultTxMaxOps)
}

// SetSnapshot publishes a named pointer; a different commit is a conflict.
func (t *Transaction) SetSnapshot(state *model.State, name string, commit model.Hash32) error {
	expected := PreValue{Absent: true}
	if existing, ok := state.Snapshots[name]; ok {
		expected = PreValue{Hash: existing}
	}
	idempotent := PreValue{Hash: commit}
	return t.add(model.SetSnapshotOp{SnapshotName: name, Commit: commit}, Precondition{
		Label: "snapshot", Expected: expected, Idempotent: &idempotent,
	}, defaultTxMaxOps)
}

// SetTip sets an object tip that must still be the observed version.
func (t *Transaction) SetTip(state *model.State, object, version model.Hash32) error {
	expected := PreValue{Absent: true}
	if existing, ok := state.Tips[object]; ok {
		expected = PreValue{Hash: existing}
	}
	idempotent := PreValue{Hash: version}
	return t.add(model.SetTipOp{Object: object, Version: version}, Precondition{
		Label: "tip", Expected: expected, Idempotent: &idempotent,
	}, defaultTxMaxOps)
}

// RequireReadable requires that object is readable by principal on every
// attempt. A revoke that wins the race denies publication.
func (t *Transaction) RequireReadable(object model.Hash32, principal auth.Principal) {
	t.Auth = append(t.Auth, AuthCheck{Object: object, Principal: principal})
}

// Digest is the deterministic op digest used for outcome discovery.
func (t *Transaction) Digest() (model.Hash32, error) {
	ops := make([]wcb.Value, len(t.Ops))
	for i, op := range t.Ops {
		ops[i] = op.ToWCB()
	}
	// The digest covers the logical transaction (id + op set), never the
	// attempt's observed parent: a retry from a newer head must resolve to the
	// same outcome.
	bytesValue, err := model.EncodeWCB(model.Map(map[string]wcb.Value{
		"id":  wcb.TextValue(t.ID),
		"ops": wcb.ArrayValue(ops),
	}))
	if err != nil {
		return model.Hash32{}, err
	}
	return hash.Domain(TxDigestDomain, bytesValue), nil
}

// TransactionOutcome is the result of a successful publication.
type TransactionOutcome struct {
	ID         string
	Commit     model.Hash32
	Generation uint64
	Attempts   uint32
	Idempotent bool
}

// OutcomeLookup is the result of a transaction-id lookup.
type OutcomeLookup struct {
	State     string // "committed", "unknown", "absent"
	Committed *TransactionOutcome
}

// TxRecordState is the state stored in a `txs/<id>` record.
type TxRecordState string

const (
	TxPrepared  TxRecordState = "prepared"
	TxCommitted TxRecordState = "committed"
)

// TxRecord is one decoded transaction discovery record.
type TxRecord struct {
	ID               string
	State            TxRecordState
	Digest           model.Hash32
	ParentGeneration uint64
	Commit           *model.Hash32
	UpdatedNS        int64
	Pins             []model.Hash32
}

// EncodeTxRecord encodes the canonical WCB record.
func EncodeTxRecord(r TxRecord) ([]byte, error) {
	pins := make([]wcb.Value, len(r.Pins))
	for i, pin := range r.Pins {
		pins[i] = model.HashValue(pin)
	}
	return model.EncodeWCB(model.Map(map[string]wcb.Value{
		"schema":            wcb.TextValue(TxSchema),
		"id":                wcb.TextValue(r.ID),
		"state":             wcb.TextValue(string(r.State)),
		"digest":            model.HashValue(r.Digest),
		"parent_generation": wcb.U64Value(r.ParentGeneration),
		"commit":            model.OptHashValue(r.Commit),
		"updated_ns":        wcb.TimestampValue(r.UpdatedNS),
		"pins":              wcb.ArrayValue(pins),
	}))
}

// DecodeTxRecord decodes and validates a transaction record.
func DecodeTxRecord(data []byte) (TxRecord, error) {
	value, err := model.DecodeWCB(data)
	if err != nil {
		return TxRecord{}, err
	}
	m, err := model.AsMap(value)
	if err != nil {
		return TxRecord{}, err
	}
	if err := model.CheckKeys(m, "schema", "id", "state", "digest",
		"parent_generation", "commit", "updated_ns", "pins"); err != nil {
		return TxRecord{}, err
	}
	schema, err := model.GetText(m, "schema")
	if err != nil {
		return TxRecord{}, err
	}
	if schema != TxSchema {
		return TxRecord{}, werr.Newf(werr.Unsupported, "transaction record schema %q is not %q", schema, TxSchema)
	}
	stateText, err := model.GetText(m, "state")
	if err != nil {
		return TxRecord{}, err
	}
	var state TxRecordState
	switch TxRecordState(stateText) {
	case TxPrepared, TxCommitted:
		state = TxRecordState(stateText)
	default:
		return TxRecord{}, werr.Newf(werr.Malformed, "unknown transaction state %q", stateText)
	}
	digest, err := model.GetHash(m, "digest")
	if err != nil {
		return TxRecord{}, err
	}
	parent, err := model.GetU64(m, "parent_generation")
	if err != nil {
		return TxRecord{}, err
	}
	commit, err := model.GetOptHash(m, "commit")
	if err != nil {
		return TxRecord{}, err
	}
	updated, err := model.GetTimestamp(m, "updated_ns")
	if err != nil {
		return TxRecord{}, err
	}
	pinValues, err := model.GetArray(m, "pins")
	if err != nil {
		return TxRecord{}, err
	}
	pins := make([]model.Hash32, len(pinValues))
	for i, value := range pinValues {
		if value.Kind != wcb.Bytes || len(value.Bytes) != 32 {
			return TxRecord{}, werr.Newf(werr.Malformed, "pins must be bytes32")
		}
		var raw [32]byte
		copy(raw[:], value.Bytes)
		pins[i] = hash.FromBytes(raw)
	}
	return TxRecord{
		ID:               mustText(m, "id"),
		State:            state,
		Digest:           digest,
		ParentGeneration: parent,
		Commit:           commit,
		UpdatedNS:        updated,
		Pins:             pins,
	}, nil
}

func mustText(m map[string]wcb.Value, key string) string {
	text, _ := model.GetText(m, key)
	return text
}

// EncodeWritersRecord encodes the writer-mode policy record.
func EncodeWritersRecord(mode WriterMode, minReader string, createdNS int64) ([]byte, error) {
	return model.EncodeWCB(model.Map(map[string]wcb.Value{
		"schema":     wcb.TextValue(WritersSchema),
		"mode":       wcb.TextValue(string(mode)),
		"min_reader": wcb.TextValue(minReader),
		"created_ns": wcb.TimestampValue(createdNS),
	}))
}

// DecodeWritersMode decodes the policy record.
func DecodeWritersMode(data []byte) (WriterMode, error) {
	value, err := model.DecodeWCB(data)
	if err != nil {
		return "", err
	}
	m, err := model.AsMap(value)
	if err != nil {
		return "", err
	}
	if err := model.CheckKeys(m, "schema", "mode", "min_reader", "created_ns"); err != nil {
		return "", err
	}
	schema, err := model.GetText(m, "schema")
	if err != nil {
		return "", err
	}
	if schema != WritersSchema {
		return "", werr.Newf(werr.Unsupported, "writers record schema %q is not %q", schema, WritersSchema)
	}
	mode, err := model.GetText(m, "mode")
	if err != nil {
		return "", err
	}
	return parseWriterMode(mode)
}

// BeginTransaction starts a transaction against the selected head.
func (s *Store) BeginTransaction(id string) (*Transaction, error) {
	if s.mode != ReadWrite {
		return nil, werr.New(werr.ReadOnly, "store is opened read-only; a transaction cannot publish")
	}
	if s.options.WriterMode != WriterModeOptimistic {
		return nil, werr.New(werr.InvalidArgument,
			"transactions require WriterModeOptimistic; the default single-writer store keeps its exclusive committer")
	}
	if !validTxID(id) {
		return nil, werr.New(werr.InvalidArgument, "transaction id must be 32 lowercase hex characters")
	}
	return &Transaction{
		ID:             id,
		BaseHead:       s.head,
		BaseGeneration: s.generation,
	}, nil
}

func validTxID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// PrepareContent stores content-addressed bytes and returns
// (manifest id, content hash, size) without publishing a commit.
func (s *Store) PrepareContent(data []byte) (model.Hash32, model.Hash32, uint64, error) {
	if err := s.requireWritable(); err != nil {
		return model.Hash32{}, model.Hash32{}, 0, err
	}
	return s.storeFileContent(data)
}

// PrepareTransaction writes the prepared discovery record without publishing.
func (s *Store) PrepareTransaction(tx *Transaction) error {
	if err := s.requireWritable(); err != nil {
		return err
	}
	if s.options.WriterMode != WriterModeOptimistic {
		return werr.New(werr.InvalidArgument, "preparing a transaction requires WriterModeOptimistic")
	}
	return s.writeTxRecord(tx, TxPrepared, nil)
}

// ExecuteTransaction publishes one transaction with a bounded optimistic loop.
func (s *Store) ExecuteTransaction(tx *Transaction, opts TransactionOptions) (TransactionOutcome, error) {
	if err := s.requireWritable(); err != nil {
		return TransactionOutcome{}, err
	}
	if s.options.WriterMode != WriterModeOptimistic {
		return TransactionOutcome{}, werr.New(werr.InvalidArgument, "transactions require WriterModeOptimistic")
	}
	if len(tx.Ops) == 0 {
		return TransactionOutcome{}, werr.New(werr.InvalidArgument, "transaction has no ops")
	}
	if opts.MaxOps > 0 && len(tx.Ops) > opts.MaxOps {
		return TransactionOutcome{}, werr.Newf(werr.LimitExceeded,
			"transaction has %d ops, above the %d-op bound", len(tx.Ops), opts.MaxOps)
	}

	lookup, err := s.TransactionOutcome(tx.ID)
	if err != nil {
		return TransactionOutcome{}, err
	}
	switch lookup.State {
	case "committed":
		if record, ok, err := s.readTxRecord(tx.ID); err != nil {
			return TransactionOutcome{}, err
		} else if ok {
			digest, err := tx.Digest()
			if err != nil {
				return TransactionOutcome{}, err
			}
			if record.Digest != digest {
				return TransactionOutcome{}, werr.New(werr.Conflict, "transaction id was reused with a different op set")
			}
		}
		return *lookup.Committed, nil
	case "unknown":
		if record, ok, err := s.readTxRecord(tx.ID); err != nil {
			return TransactionOutcome{}, err
		} else if ok {
			if commit, generation, found, err := s.findTxCommit(tx, record.ParentGeneration, opts.OutcomeWindow); err != nil {
				return TransactionOutcome{}, err
			} else if found {
				if err := s.writeTxRecord(tx, TxCommitted, &commit); err != nil {
					return TransactionOutcome{}, err
				}
				return TransactionOutcome{ID: tx.ID, Commit: commit, Generation: generation, Idempotent: true}, nil
			}
		}
	}

	if err := s.writeTxRecord(tx, TxPrepared, nil); err != nil {
		return TransactionOutcome{}, err
	}
	crashPoint("mw2_prepared")

	var attempts uint32
	for {
		attempts++
		if attempts > 1 || s.headAdvanced() {
			if err := s.reloadFromPlane(); err != nil {
				return TransactionOutcome{}, err
			}
		}
		if err := validatePreconditions(s.state, tx); err != nil {
			return TransactionOutcome{}, err
		}
		for _, check := range tx.Auth {
			record, ok := s.state.Objects[check.Object]
			if !ok {
				return TransactionOutcome{}, werr.New(werr.NotFound, "authorization subject object does not exist")
			}
			if !auth.CanRead(record, check.Principal) {
				return TransactionOutcome{}, werr.New(werr.Unauthorized, "object is not readable by this principal")
			}
		}
		generation := s.generation + 1
		if generation == 0 {
			return TransactionOutcome{}, werr.New(werr.LimitExceeded, "generation counter overflow")
		}
		nextState := s.state.Clone()
		if err := nextState.ApplyOps(tx.Ops); err != nil {
			return TransactionOutcome{}, err
		}
		nextState.Generation = generation
		ops := append([]model.Op(nil), tx.Ops...)
		quotaPlan, err := s.quotaPreflight(ops, quotaPreMap(s.state, ops))
		if err != nil {
			return TransactionOutcome{}, err
		}
		if quotaPlan != nil {
			ops = append(ops, quotaUsageOpFromMap(quotaPlan.usageAfter))
		}
		interval := s.options.CheckpointInterval
		var checkpoint *model.Hash32
		if interval > 0 && generation%interval == 0 {
			encoded, err := model.EncodeState(nextState, generation)
			if err != nil {
				return TransactionOutcome{}, err
			}
			id, err := s.storeBlob(BlobManifest, model.DomainManifest, encoded)
			if err != nil {
				return TransactionOutcome{}, err
			}
			checkpoint = &id
		}
		commit := model.Commit{
			Generation: generation, Parent: hashPtr(s.head), TimestampNS: s.nowNS(),
			Ops: ops, Checkpoint: checkpoint,
		}
		attestation, builtIndex, err := s.indexAttestationFor(nextState, generation, &commit)
		if err != nil {
			return TransactionOutcome{}, err
		}
		commit.IndexAttestation = attestation
		s.state = nextState
		s.nextGeneration = generation + 1
		hashID, err := s.publishCommit(commit)
		if err != nil {
			if werr.ClassOf(err) == werr.Busy {
				forced := opts.FailAfterTries > 0 && attempts >= opts.FailAfterTries
				if attempts >= opts.MaxAttempts || forced {
					_ = s.reloadFromPlane()
					return TransactionOutcome{}, werr.Newf(werr.Busy,
						"transaction %s exhausted its %d-attempt budget; outcome is unknown (resolve it by transaction id)",
						tx.ID, attempts)
				}
				time.Sleep(opts.backoff(attempts))
				continue
			}
			_ = s.reloadFromPlane()
			return TransactionOutcome{}, err
		}
		s.head = hashID
		s.generation = generation
		if builtIndex != nil {
			s.persistBuiltIndex(hashID, builtIndex)
		}
		if quotaPlan != nil {
			s.recordQuotaAfterCommit(quotaPlan)
		}
		if err := s.writeTxRecord(tx, TxCommitted, &hashID); err != nil {
			return TransactionOutcome{}, err
		}
		crashPoint("mw2_after_ack")
		return TransactionOutcome{ID: tx.ID, Commit: hashID, Generation: generation, Attempts: attempts}, nil
	}
}

func (s *Store) headAdvanced() bool {
	view, err := s.commits.ReadSuperblock()
	if err != nil {
		return true
	}
	generation, commit, ok := highestSlot(view)
	if !ok {
		return s.generation != 0 || s.head != model.ZeroHash
	}
	return generation != s.generation || commit != s.head
}

func highestSlot(view SuperblockView) (uint64, model.Hash32, bool) {
	var generation uint64
	var commit model.Hash32
	found := false
	for index := 0; index < 2; index++ {
		if !view.Valid[index] {
			continue
		}
		slot := view.Slots[index]
		if !found || slot.Generation > generation {
			generation = slot.Generation
			commit = slot.Commit
			found = true
		}
	}
	return generation, commit, found
}

// TransactionOutcome looks a transaction id up without publishing.
func (s *Store) TransactionOutcome(id string) (OutcomeLookup, error) {
	record, ok, err := s.readTxRecord(id)
	if err != nil {
		return OutcomeLookup{}, err
	}
	if !ok {
		return OutcomeLookup{State: "absent"}, nil
	}
	if record.ID != id {
		return OutcomeLookup{}, werr.New(werr.Corrupt, "transaction record id does not match its key")
	}
	if record.State == TxCommitted {
		if record.Commit == nil {
			return OutcomeLookup{}, werr.New(werr.Corrupt, "a committed transaction record has no commit hash")
		}
		inChain, err := s.commitInChain(record, *record.Commit, defaultTxOutcomeWindow)
		if err != nil {
			return OutcomeLookup{}, err
		}
		if inChain {
			return OutcomeLookup{State: "committed", Committed: &TransactionOutcome{
				ID: id, Commit: *record.Commit, Generation: record.ParentGeneration + 1, Idempotent: true,
			}}, nil
		}
	}
	return OutcomeLookup{State: "unknown"}, nil
}

func (s *Store) readTxRecord(id string) (TxRecord, bool, error) {
	data, ok, err := s.commits.ReadRecord("txs/" + id)
	if err != nil {
		return TxRecord{}, false, err
	}
	if !ok {
		return TxRecord{}, false, nil
	}
	record, err := DecodeTxRecord(data)
	if err != nil {
		return TxRecord{}, false, err
	}
	return record, true, nil
}

func (s *Store) writeTxRecord(tx *Transaction, state TxRecordState, commit *model.Hash32) error {
	digest, err := tx.Digest()
	if err != nil {
		return err
	}
	if existing, ok, err := s.readTxRecord(tx.ID); err != nil {
		return err
	} else if ok {
		if existing.Digest != digest {
			return werr.New(werr.Conflict, "transaction id was reused with a different op set")
		}
		if state == TxPrepared {
			// Either an earlier attempt prepared it, or the transaction already
			// committed. Neither needs another create-once write.
			return nil
		}
	}
	parentGeneration := tx.BaseGeneration
	if existing, ok, _ := s.readTxRecord(tx.ID); ok {
		parentGeneration = existing.ParentGeneration
	}
	record := TxRecord{
		ID: tx.ID, State: state, Digest: digest,
		ParentGeneration: parentGeneration, Commit: commit,
		UpdatedNS: s.nowNS(), Pins: append([]model.Hash32(nil), tx.Pins...),
	}
	data, err := EncodeTxRecord(record)
	if err != nil {
		return err
	}
	name := "txs/" + tx.ID
	if state == TxPrepared {
		if err := os.MkdirAll(filepath.Join(s.commits.Root(), "txs"), 0o755); err != nil {
			return werr.Wrap(werr.Io, err, "cannot create txs directory")
		}
		if err := s.commits.WriteRecordNew(name, data); err != nil {
			if werr.ClassOf(err) == werr.Exists {
				existing, ok, readErr := s.readTxRecord(tx.ID)
				if readErr != nil {
					return readErr
				}
				if ok && existing.Digest == digest {
					return nil
				}
				return werr.New(werr.Conflict, "transaction id was reused with a different op set")
			}
			return err
		}
		return nil
	}
	return s.commits.WriteRecordReplace(name, data)
}

func (s *Store) findTxCommit(tx *Transaction, parentGeneration, window uint64) (model.Hash32, uint64, bool, error) {
	if s.generation == 0 {
		return model.Hash32{}, 0, false, nil
	}
	floor := parentGeneration + 1
	if s.generation > window && s.generation-window > floor {
		floor = s.generation - window
	}
	for generation := s.generation; generation >= floor && generation > 0; generation-- {
		loaded, err := s.commits.ReadCommit(generation)
		if err != nil {
			continue
		}
		ops := loaded.Commit.Ops
		if len(ops) > 0 {
			if _, isUsage := ops[len(ops)-1].(model.SetQuotaUsageOp); isUsage {
				ops = ops[:len(ops)-1]
			}
		}
		if sameOps(ops, tx.Ops) {
			return loaded.Hash, generation, true, nil
		}
	}
	return model.Hash32{}, 0, false, nil
}

func (s *Store) commitInChain(record TxRecord, commit model.Hash32, window uint64) (bool, error) {
	if s.generation == 0 {
		return false, nil
	}
	target := record.ParentGeneration + 1
	if target > s.generation {
		return false, nil
	}
	floor := uint64(0)
	if s.generation > window {
		floor = s.generation - window
	}
	if target < floor {
		return false, nil
	}
	generation := s.generation
	hashID := s.head
	for generation >= target && generation > 0 {
		if generation == target {
			return hashID == commit, nil
		}
		loaded, err := s.commits.ReadCommit(generation)
		if err != nil {
			return false, nil
		}
		if loaded.Commit.Parent == nil {
			return false, nil
		}
		hashID = *loaded.Commit.Parent
		generation--
	}
	return false, nil
}

func (s *Store) reloadFromPlane() error {
	recovery, err := recoverForWrite(headAttestHider{s.commits}, s.blobs)
	if err != nil {
		return err
	}
	base := recovery.Generation
	if recovery.HighestFileGeneration > base {
		base = recovery.HighestFileGeneration
	}
	if base == ^uint64(0) {
		return werr.New(werr.LimitExceeded, "generation counter overflow")
	}
	s.state = recovery.State
	s.head = recovery.Head
	s.generation = recovery.Generation
	s.nextGeneration = base + 1
	s.rejected = recovery.Rejected
	s.notes = recovery.Notes
	s.blobIndex = map[model.Hash32]uint64{}
	s.blobIndexReady = false
	s.loadQuotaRecord()
	return nil
}

// headAttestHider deliberately does not implement AttestedHead: an optimistic
// store's superblock is authoritative and a stale writer-lock record from an
// earlier single-writer life must not override it.
type headAttestHider struct{ commitSource }

// ensureWriterPolicy confirms or creates the policy record.
func (s *Store) ensureWriterPolicy(mode WriterMode) error {
	if mode == "" {
		mode = WriterModeSingle
	}
	data, ok, err := s.commits.ReadRecord("writers")
	if err != nil {
		return err
	}
	if ok {
		stored, err := DecodeWritersMode(data)
		if err != nil {
			return err
		}
		if stored != mode {
			return werr.Newf(werr.Unsupported,
				"store writer mode is %q; this handle requested %q. Writer modes are not mixed.",
				stored, mode)
		}
		return nil
	}
	if mode == WriterModeSingle {
		return nil
	}
	bytesValue, err := EncodeWritersRecord(mode, "weftfs-go", s.nowNS())
	if err != nil {
		return err
	}
	if err := s.commits.WriteRecordNew("writers", bytesValue); err != nil {
		if werr.ClassOf(err) == werr.Exists {
			data, ok, readErr := s.commits.ReadRecord("writers")
			if readErr != nil {
				return readErr
			}
			if ok {
				stored, decodeErr := DecodeWritersMode(data)
				if decodeErr != nil {
					return decodeErr
				}
				if stored == mode {
					return nil
				}
			}
			return werr.New(werr.Unsupported, "a concurrent open created a different writer-mode policy record")
		}
		return err
	}
	return nil
}

// publishCommitOptimistic is the MW2 publication: create-once commit record
// plus one superblock slot write under a short cross-process publication lock.
func (s *Store) publishCommitOptimistic(commit model.Commit) (model.Hash32, error) {
	if err := s.blobs.Flush(); err != nil {
		return model.Hash32{}, err
	}
	wcbBytes, err := commit.Encode()
	if err != nil {
		return model.Hash32{}, err
	}
	hashID := model.CommitIDBytes(wcbBytes)
	fileBytes := EncodeCommitFile(wcbBytes)

	lock, err := s.acquirePublicationLock()
	if err != nil {
		return model.Hash32{}, err
	}
	defer func() { _ = releaseLock(lock) }()

	view, err := s.commits.ReadSuperblock()
	if err != nil {
		return model.Hash32{}, err
	}
	generation, current, ok := highestSlot(view)
	if !ok || generation != s.generation || current != s.head {
		return model.Hash32{}, werr.Newf(werr.Busy,
			"head publication refused: expected generation %d, observed %d", s.generation, generation)
	}
	crashPoint("mw2_before_head")
	if exists, err := s.commits.HasCommit(commit.Generation); err != nil {
		return model.Hash32{}, err
	} else if exists {
		return model.Hash32{}, werr.Newf(werr.Busy,
			"commit generation %d already exists; retry against the new head", commit.Generation)
	}
	if err := s.commits.CreateCommit(commit.Generation, fileBytes); err != nil {
		return model.Hash32{}, err
	}
	crashPoint("after_commit_file")
	slot := SuperblockSlot{
		Generation: commit.Generation, Commit: hashID,
		CommitLen: uint64(len(wcbBytes)), TimestampNS: commit.TimestampNS,
	}
	if err := s.commits.PublishSuperblockSlot(slot, int(commit.Generation%2)); err != nil {
		_ = s.commits.DeleteRecord("commits/" + itoa(commit.Generation) + ".commit")
		return model.Hash32{}, err
	}
	crashPoint("mw2_after_head")
	crashPoint("after_superblock_write")
	if err := s.commits.Sync(); err != nil {
		return model.Hash32{}, err
	}
	return hashID, nil
}

func (s *Store) acquirePublicationLock() (*os.File, error) {
	path := filepath.Join(s.commits.Root(), "LOCK.publish")
	deadline := time.Now().Add(publicationLockDeadline)
	for {
		lock, _, err := lockExclusive(path)
		if err == nil {
			return lock, nil
		}
		if werr.ClassOf(err) != werr.Busy {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, werr.New(werr.Busy, "publication lock is held by another committer")
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// validatePreconditions applies the conflict table against a candidate state.
func validatePreconditions(state *model.State, tx *Transaction) error {
	if len(tx.Ops) != len(tx.Preconditions) {
		return werr.New(werr.Corrupt, "transaction op and precondition lists have different lengths")
	}
	for index, op := range tx.Ops {
		pre := tx.Preconditions[index]
		var current PreValue
		switch typed := op.(type) {
		case model.PutObjectOp:
			if existing, ok := state.Objects[typed.Record.ID]; ok {
				current = PreValue{Hash: existing.Version}
			} else {
				current = PreValue{Absent: true}
			}
		case model.DeleteObjectOp:
			if existing, ok := state.Objects[typed.ID]; ok {
				current = PreValue{Hash: existing.Version}
			} else {
				current = PreValue{Absent: true}
			}
		case model.PutEntryOp:
			if existing, ok := state.Entries[typed.Record.ID]; ok {
				copy := existing
				copy.Name = append([]byte(nil), existing.Name...)
				current = PreValue{Entry: &copy}
			} else {
				current = PreValue{Absent: true}
			}
		case model.DelEntryOp:
			if existing, ok := state.Entries[typed.ID]; ok {
				copy := existing
				copy.Name = append([]byte(nil), existing.Name...)
				current = PreValue{Entry: &copy}
			} else {
				current = PreValue{Absent: true}
			}
		case model.PutRelationOp:
			if _, ok := state.Relations[typed.Record.ID]; ok {
				current = PreValue{Hash: typed.Record.ID}
			} else {
				current = PreValue{Absent: true}
			}
		case model.DelRelationOp:
			if _, ok := state.Relations[typed.ID]; ok {
				current = PreValue{Hash: typed.ID}
			} else {
				current = PreValue{Absent: true}
			}
		case model.SetSnapshotOp:
			if existing, ok := state.Snapshots[typed.SnapshotName]; ok {
				current = PreValue{Hash: existing}
			} else {
				current = PreValue{Absent: true}
			}
		case model.SetTipOp:
			if existing, ok := state.Tips[typed.Object]; ok {
				current = PreValue{Hash: existing}
			} else {
				current = PreValue{Absent: true}
			}
		case model.SetQuotaUsageOp:
			continue
		default:
			return werr.Newf(werr.Malformed, "unknown transaction op %T", op)
		}
		if !pre.matches(current) {
			return werr.Newf(werr.Conflict, "transaction conflict at op %d: %s (%s)", index, conflictClass(pre), pre.Label)
		}
	}
	return nil
}

func conflictClass(pre Precondition) string {
	switch pre.Label {
	case "entry":
		if pre.Expected.Absent {
			return "NameExists"
		}
		return "EntryChanged"
	case "object":
		if pre.Expected.Absent {
			return "ObjectExists"
		}
		return "ObjectChanged"
	case "relation":
		return "RelationConflict"
	case "snapshot":
		return "SnapshotConflict"
	case "tip":
		return "TipChanged"
	default:
		return "ObjectChanged"
	}
}

func sameOps(left, right []model.Op) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if !wcbValuesEqual(left[i].ToWCB(), right[i].ToWCB()) {
			return false
		}
	}
	return true
}

func wcbValuesEqual(a, b wcb.Value) bool {
	left, err := model.EncodeWCB(a)
	if err != nil {
		return false
	}
	right, err := model.EncodeWCB(b)
	if err != nil {
		return false
	}
	return bytes.Equal(left, right)
}
