// `weftfs rebase` — lineage-aware rebasing of hot tensor objects.
//
// This is the CLI surface for the Go decision implemented in
// `store/rebase.go`. It deliberately matches the Rust verb: the same flags
// (`--root`, `--threshold`, `--dry-run`, `--strategy`, `--lambda-ns`,
// `--max-objects`), the same selection rule, and the same
// `weft.provenance.v1` receipt. Neither implementation invokes the other.
package main

import (
	"flag"
	"fmt"

	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func cmdRebase(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("rebase", flag.ContinueOnError)
	rootText := fs.String("root", "/", "store path or 64-hex ObjectId to scan (inclusive)")
	threshold := fs.Uint64("threshold", 1_000_000_000,
		"rebase when reads * estimated_decode_ns exceeds this value")
	dryRun := fs.Bool("dry-run", false, "show the decision without writing anything")
	strategy := fs.String("strategy", "",
		"force a standalone representation (raw, zstd, float-tensor, tensor-sharded)")
	lambdaNS := fs.Uint64("lambda-ns", 0, "bytes charged per estimated decode nanosecond")
	maxObjects := fs.Int("max-objects", 100_000, "bound on the number of objects examined")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return werr.Newf(werr.InvalidArgument, "rebase accepts no positional arguments")
	}
	if *threshold == 0 {
		return werr.Newf(werr.InvalidArgument, "rebase threshold must be greater than zero")
	}
	if *maxObjects <= 0 {
		return werr.Newf(werr.InvalidArgument, "rebase --max-objects must be greater than zero")
	}
	var hint *store.TensorStrategy
	if *strategy != "" && *strategy != "auto" {
		parsed, err := store.ParseTensorStrategy(*strategy)
		if err != nil {
			return err
		}
		if !parsed.IsIndependent() {
			return werr.Newf(werr.InvalidArgument,
				"rebase requires a standalone strategy (raw, zstd, float-tensor, "+
					"tensor-sharded); `%s` carries a dependency and cannot be the rebase target",
				parsed.String())
		}
		hint = &parsed
	}
	mode := store.ReadWrite
	if *dryRun {
		mode = store.ReadOnly
	}
	s, err := openStore(storeDir, mode)
	if err != nil {
		return err
	}
	defer s.Close()
	root, err := rebaseRoot(s, *rootText)
	if err != nil {
		return err
	}
	options := store.DefaultRebaseOptions()
	options.ThresholdNS = *threshold
	options.LambdaNS = *lambdaNS
	options.StrategyHint = hint
	options.MaxObjects = *maxObjects
	options.DryRun = *dryRun
	report, err := s.Rebase(root, options)
	if err != nil {
		return err
	}
	if jsonOut {
		candidates := make([]map[string]any, 0, len(report.Plan.Candidates))
		for _, item := range report.Plan.Candidates {
			inner := make([]map[string]any, 0, len(item.Candidates))
			for _, candidate := range item.Candidates {
				inner = append(inner, map[string]any{
					"strategy":            candidate.Strategy.String(),
					"physical_bytes":      candidate.PhysicalBytes,
					"estimated_decode_ns": candidate.EstimatedDecodeNS,
				})
			}
			candidates = append(candidates, map[string]any{
				"object":                  item.Object.Hex(),
				"path":                    item.Path,
				"reads":                   item.Reads,
				"from_strategy":           item.FromStrategy,
				"from_cost_class":         item.FromCostClass,
				"logical_bytes":           item.LogicalBytes,
				"estimated_decode_ns":     item.EstimatedDecode,
				"read_cost_ns":            item.ReadCostNS,
				"to_strategy":             item.ToStrategy.String(),
				"new_physical_bytes":      item.NewPhysical,
				"new_estimated_decode_ns": item.NewDecode,
				"candidates":              inner,
			})
		}
		skipped := make([]map[string]any, 0, len(report.Plan.Skipped))
		for _, item := range report.Plan.Skipped {
			skipped = append(skipped, map[string]any{
				"object": item.Object.Hex(),
				"path":   item.Path,
				"reason": item.Reason,
			})
		}
		applied := make([]map[string]any, 0, len(report.Applied))
		for _, item := range report.Applied {
			applied = append(applied, map[string]any{
				"object":         item.Object.Hex(),
				"path":           item.Path,
				"old_version":    item.OldVersion.Hex(),
				"new_version":    item.NewVersion.Hex(),
				"content":        item.Content.Hex(),
				"from_strategy":  item.FromStrategy,
				"to_strategy":    item.ToStrategy.String(),
				"reads_consumed": item.ReadsConsumed,
				"provenance_id":  item.ProvenanceID.Hex(),
			})
		}
		return printJSON(map[string]any{
			"root":         report.Plan.Root.Hex(),
			"threshold_ns": report.Plan.ThresholdNS,
			"cost_model":   string(report.Plan.CostModel),
			"dry_run":      *dryRun,
			"scanned":      report.Plan.Scanned,
			"truncated":    report.Plan.Truncated,
			"candidates":   candidates,
			"skipped":      skipped,
			"applied":      applied,
		})
	}
	fmt.Printf("scanned=%d candidates=%d applied=%d threshold_ns=%d cost_model=%s\n",
		report.Plan.Scanned, len(report.Plan.Candidates), len(report.Applied),
		report.Plan.ThresholdNS, report.Plan.CostModel)
	for _, item := range report.Plan.Candidates {
		fmt.Printf("rebase %s %s reads=%d %s->%s read_cost_ns=%d new_bytes=%d\n",
			item.Object.Hex(), item.Path, item.Reads, item.FromStrategy,
			item.ToStrategy.String(), item.ReadCostNS, item.NewPhysical)
	}
	for _, item := range report.Plan.Skipped {
		fmt.Printf("skip %s %s reason=%s\n", item.Object.Hex(), item.Path, item.Reason)
	}
	for _, item := range report.Applied {
		fmt.Printf("applied %s %s version=%s provenance=%s\n",
			item.Object.Hex(), item.Path, item.NewVersion.Hex(),
			item.ProvenanceID.Hex())
	}
	return nil
}

// rebaseRoot accepts the same two forms as Rust: a store path or a 64-hex
// ObjectId. A 64-character string of hex is an id; anything else is a path.
func rebaseRoot(s *store.Store, text string) (model.Hash32, error) {
	if len(text) == 64 && isLowerHex(text) {
		return parseHash(text)
	}
	return s.ResolvePath(text)
}

func isLowerHex(text string) bool {
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
