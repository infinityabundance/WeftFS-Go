// Lineage-aware rebasing of hot tensor objects (Go parity with src/rebase.rs).
//
// A candidate must have been read at least once, have
// `reads * estimated_decode_ns(current representation)` above the threshold,
// and have a standalone representation that decodes strictly faster and is not
// larger than the logical bytes. Rebase publishes a NEW version whose causal
// parent is the previous version, records a `weft.provenance.v1` receipt with
// `operation: "rebase"`, and consumes the read counter so a second run is a
// no-op. Existing versions and snapshots are never mutated.
package store

import (
	"sort"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// RebaseTool is the environment tool name recorded in rebase provenance.
const RebaseTool = "weftfs"

// storeVersion is the tool version recorded in a provenance record. It must
// track the released crate version (Rust records `env!("CARGO_PKG_VERSION")` at
// compile time), so a Go record and a Rust record name the same tool. It was
// stale at "1.1.0" through the v1.2.0 release; R14 aligns it.
const storeVersion = "1.2.0"

// ProvenanceSchema is the canonical receipt schema.
const ProvenanceSchema = "weft.provenance.v1"

// ProvenanceDomain is the receipt identity domain.
const ProvenanceDomain = "weft/provenance/v1"

// ProvenancePredicate is the relation predicate linking an object to a receipt.
const ProvenancePredicate = "provenance"

// RebaseOptions is a rebase request.
type RebaseOptions struct {
	ThresholdNS  uint64
	LambdaNS     uint64
	CostModel    CostModelKind
	Cost         *CostTable
	StrategyHint *TensorStrategy
	MaxObjects   int
	DryRun       bool
}

// DefaultRebaseOptions is the conservative default (dry run).
func DefaultRebaseOptions() RebaseOptions {
	return RebaseOptions{
		ThresholdNS: 1_000_000_000,
		CostModel:   DefaultCostModel,
		MaxObjects:  100_000,
		DryRun:      true,
	}
}

// RebaseCandidate is one selected object.
type RebaseCandidate struct {
	Object          model.Hash32
	Path            string
	Reads           uint64
	FromStrategy    string
	FromCostClass   string
	LogicalBytes    uint64
	EstimatedDecode uint64
	ReadCostNS      uint64
	ToStrategy      TensorStrategy
	NewPhysical     uint64
	NewDecode       uint64
	Candidates      []TensorPlanCandidate
}

// RebaseSkip records one examined object that was not selected.
type RebaseSkip struct {
	Object model.Hash32
	Path   string
	Reason string
}

// RebasePlan is the complete decision.
type RebasePlan struct {
	Root        model.Hash32
	ThresholdNS uint64
	CostModel   CostModelKind
	Scanned     int
	Truncated   bool
	Candidates  []RebaseCandidate
	Skipped     []RebaseSkip
}

// RebaseOutcome is one applied rebase.
type RebaseOutcome struct {
	Object        model.Hash32
	Path          string
	OldVersion    model.Hash32
	NewVersion    model.Hash32
	Content       model.Hash32
	FromStrategy  string
	ToStrategy    TensorStrategy
	ReadsConsumed uint64
	ProvenanceID  model.Hash32
}

// RebaseReport is a plan plus the applied outcomes.
type RebaseReport struct {
	Plan    RebasePlan
	Applied []RebaseOutcome
}

func (o RebaseOptions) normalized() RebaseOptions {
	if o.CostModel == "" {
		o.CostModel = DefaultCostModel
	}
	if o.MaxObjects <= 0 {
		o.MaxObjects = 100_000
	}
	return o
}

// PlanRebase enumerates live objects under root and prices a rebase.
func (s *Store) PlanRebase(root model.Hash32, options RebaseOptions) (RebasePlan, error) {
	options = options.normalized()
	if options.ThresholdNS == 0 {
		return RebasePlan{}, werr.Newf(werr.InvalidArgument,
			"rebase threshold must be greater than zero")
	}
	objects, truncated, err := s.collectSubtree(root, options.MaxObjects)
	if err != nil {
		return RebasePlan{}, err
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].id.Less(objects[j].id) })
	plan := RebasePlan{
		Root: root, ThresholdNS: options.ThresholdNS, CostModel: options.CostModel,
		Truncated: truncated,
	}
	planOptions := TensorPlanOptions{
		LambdaNS: options.LambdaNS, CostModel: options.CostModel, Cost: options.Cost,
	}
	for _, entry := range objects {
		plan.Scanned++
		record, ok := s.state.Objects[entry.id]
		if !ok || record.Kind != model.KindFile {
			continue
		}
		reads := s.AccessReads(entry.id)
		if reads == 0 {
			continue
		}
		meta, err := s.TensorMetadata(entry.id)
		if err != nil {
			if werr.ClassOf(err) == werr.NotFound {
				continue
			}
			plan.Skipped = append(plan.Skipped, RebaseSkip{
				Object: entry.id, Path: entry.path,
				Reason: "tensor metadata unreadable: " + err.Error(),
			})
			continue
		}
		manifest, err := readManifest(s.blobs, record.Content)
		if err != nil {
			return RebasePlan{}, err
		}
		fromStrategy := model.StrategyRaw
		if manifest.Representation != nil {
			fromStrategy = manifest.Representation.Strategy
		}
		class, ok := ParseCostClass(fromStrategy)
		if !ok {
			class = CostClassRaw
		}
		decodeCost, err := s.currentDecodeCost(record.Content, record.Size, options.CostModel, options.Cost, 0, map[model.Hash32]bool{})
		if err != nil {
			plan.Skipped = append(plan.Skipped, RebaseSkip{
				Object: entry.id, Path: entry.path,
				Reason: "decode cost could not be priced: " + err.Error(),
			})
			continue
		}
		readCost := saturatingMul(reads, decodeCost)
		if readCost <= options.ThresholdNS {
			continue
		}
		independent, err := s.PlanTensorIndependent(entry.id, planOptions, options.StrategyHint)
		if err != nil {
			plan.Skipped = append(plan.Skipped, RebaseSkip{
				Object: entry.id, Path: entry.path,
				Reason: "independent representation could not be priced: " + err.Error(),
			})
			continue
		}
		if independent.EstimatedDecode >= decodeCost {
			plan.Skipped = append(plan.Skipped, RebaseSkip{
				Object: entry.id, Path: entry.path,
				Reason: "no standalone representation decodes faster than `" +
					fromStrategy + "`",
			})
			continue
		}
		if independent.PhysicalBytes > record.Size {
			plan.Skipped = append(plan.Skipped, RebaseSkip{
				Object: entry.id, Path: entry.path,
				Reason: "standalone representation is larger than the logical bytes",
			})
			continue
		}
		_ = meta
		plan.Candidates = append(plan.Candidates, RebaseCandidate{
			Object: entry.id, Path: entry.path, Reads: reads,
			FromStrategy: fromStrategy, FromCostClass: string(class),
			LogicalBytes: record.Size, EstimatedDecode: decodeCost,
			ReadCostNS: readCost, ToStrategy: independent.Chosen,
			NewPhysical: independent.PhysicalBytes, NewDecode: independent.EstimatedDecode,
			Candidates: independent.Candidates,
		})
	}
	return plan, nil
}

// Rebase applies a planned rebase. A dry run returns the plan with no writes.
func (s *Store) Rebase(root model.Hash32, options RebaseOptions) (RebaseReport, error) {
	options = options.normalized()
	plan, err := s.PlanRebase(root, options)
	if err != nil {
		return RebaseReport{}, err
	}
	if options.DryRun {
		return RebaseReport{Plan: plan}, nil
	}
	if err := s.requireWritable(); err != nil {
		return RebaseReport{}, err
	}
	planOptions := TensorPlanOptions{
		LambdaNS: options.LambdaNS, CostModel: options.CostModel, Cost: options.Cost,
	}
	report := RebaseReport{Plan: plan}
	for _, candidate := range plan.Candidates {
		rebase, err := s.RebaseTensorObject(candidate.Object, planOptions, options.StrategyHint)
		if err != nil {
			return RebaseReport{}, err
		}
		reads := s.ConsumeAccessReads(candidate.Object)
		provenance, err := s.recordRebaseProvenance(candidate, rebase, options)
		if err != nil {
			return RebaseReport{}, err
		}
		report.Applied = append(report.Applied, RebaseOutcome{
			Object: candidate.Object, Path: candidate.Path,
			OldVersion: rebase.OldVersion, NewVersion: rebase.NewVersion,
			Content: rebase.NewContent, FromStrategy: rebase.OldStrategy,
			ToStrategy: rebase.Plan.Chosen, ReadsConsumed: reads,
			ProvenanceID: provenance,
		})
	}
	if err := s.FlushAccessCounts(); err != nil {
		return RebaseReport{}, err
	}
	return report, nil
}

func (s *Store) currentDecodeCost(
	content model.Hash32,
	size uint64,
	modelCost CostModelKind,
	table *CostTable,
	depth int,
	seen map[model.Hash32]bool,
) (uint64, error) {
	if depth > MaxCodecDependencyDepth {
		return 0, werr.Newf(werr.Corrupt,
			"rebase decode-cost depth exceeds %d", MaxCodecDependencyDepth)
	}
	if seen[content] {
		return 0, werr.Newf(werr.Corrupt, "rebase decode-cost cycle")
	}
	seen[content] = true
	manifest, err := readManifest(s.blobs, content)
	if err != nil {
		return 0, err
	}
	strategy := model.StrategyRaw
	var dependencies []model.Hash32
	if manifest.Representation != nil {
		strategy = manifest.Representation.Strategy
		dependencies = manifest.Representation.Dependencies
	}
	class, ok := ParseCostClass(strategy)
	if !ok {
		class = CostClassRaw
	}
	total := EstimateDecodeNSWith(class, size, modelCost, table)
	for _, dependency := range dependencies {
		dependencyManifest, err := readManifest(s.blobs, dependency)
		if err != nil {
			return 0, err
		}
		child, err := s.currentDecodeCost(
			dependency, dependencyManifest.Size, modelCost, table, depth+1, seen)
		if err != nil {
			return 0, err
		}
		total = saturatingAdd(total, child)
	}
	delete(seen, content)
	return total, nil
}

type subtreeEntry struct {
	id   model.Hash32
	path string
}

func (s *Store) collectSubtree(root model.Hash32, limit int) ([]subtreeEntry, bool, error) {
	var out []subtreeEntry
	stack := []subtreeEntry{{id: root, path: "/"}}
	for len(stack) > 0 {
		entry := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if len(out) >= limit {
			return out, true, nil
		}
		record, ok := s.state.Objects[entry.id]
		if !ok {
			continue
		}
		switch record.Kind {
		case model.KindDir:
			children, err := s.ListDir(entry.id)
			if err != nil {
				return nil, false, err
			}
			sort.Slice(children, func(i, j int) bool {
				return string(children[i].Name) < string(children[j].Name)
			})
			for index := len(children) - 1; index >= 0; index-- {
				child := children[index]
				path := entry.path + "/" + string(child.Name)
				if entry.path == "/" {
					path = "/" + string(child.Name)
				}
				stack = append(stack, subtreeEntry{id: child.Target, path: path})
			}
		case model.KindFile:
			out = append(out, entry)
		}
	}
	return out, false, nil
}

func (s *Store) recordRebaseProvenance(
	candidate RebaseCandidate,
	rebase TensorRebase,
	options RebaseOptions,
) (model.Hash32, error) {
	params := map[string]wcb.Value{
		"read_cost_ns":        wcb.U64Value(candidate.ReadCostNS),
		"threshold_ns":        wcb.U64Value(options.ThresholdNS),
		"reads":               wcb.U64Value(candidate.Reads),
		"from_strategy":       wcb.TextValue(candidate.FromStrategy),
		"to_strategy":         wcb.TextValue(string(rebase.Plan.Chosen)),
		"estimated_decode_ns": wcb.U64Value(candidate.EstimatedDecode),
		"old_version":         wcb.BytesValue(rebase.OldVersion.Bytes()),
		"new_version":         wcb.BytesValue(rebase.NewVersion.Bytes()),
		"cost_model":          wcb.TextValue(string(options.CostModel)),
	}
	inputs := []wcb.Value{wcb.MapValue(map[string]wcb.Value{
		"role":    wcb.TextValue("source"),
		"content": wcb.BytesValue(rebase.OldContent.Bytes()),
		"object":  wcb.BytesValue(candidate.Object.Bytes()),
	})}
	outputs := []wcb.Value{wcb.BytesValue(rebase.NewContent.Bytes())}
	environment := wcb.MapValue(map[string]wcb.Value{
		"tool":     wcb.TextValue(RebaseTool),
		"version":  wcb.TextValue(storeVersion),
		"env_hash": wcb.NullValue(),
	})
	principal := wcb.MapValue(map[string]wcb.Value{
		"uid": wcb.U64Value(s.options.OwnerUID),
		"gid": wcb.U64Value(s.options.OwnerGID),
	})
	record := wcb.MapValue(map[string]wcb.Value{
		"schema":       wcb.TextValue(ProvenanceSchema),
		"operation":    wcb.TextValue("rebase"),
		"params":       wcb.MapValue(params),
		"inputs":       wcb.ArrayValue(inputs),
		"outputs":      wcb.ArrayValue(outputs),
		"environment":  environment,
		"determinism":  wcb.TextValue("exact"),
		"principal":    principal,
		"timestamp_ns": wcb.TimestampValue(s.nowNS()),
	})
	encoded, err := wcb.EncodeDefault(record)
	if err != nil {
		return model.Hash32{}, werr.FromCodec(err)
	}
	id := hash.Domain(ProvenanceDomain, encoded)
	if _, err := s.storeBlob(BlobManifest, ProvenanceDomain, encoded); err != nil {
		return model.Hash32{}, err
	}
	relation, err := model.NewRelationRecord(
		candidate.Object, ProvenancePredicate,
		model.ValueTarget(wcb.TextValue(id.Hex())), nil, nil)
	if err != nil {
		return model.Hash32{}, err
	}
	if _, err := s.commitOps([]model.Op{model.PutRelationOp{Record: relation}}, false); err != nil {
		return model.Hash32{}, err
	}
	return id, nil
}
