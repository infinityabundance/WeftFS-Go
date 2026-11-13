// Command mw2writer drives the MW2 transaction API for the R4 courts, and the
// X13/N14 Azure mixed-language court.
//
// Modes:
//
//	init        --store DIR [--backend local|object|azure] [--fixed-timestamp-ns N]
//	parity      --store DIR --name NAME --content TEXT --seed SEED
//	write       --store DIR --writer ID --count N --prefix P [--hot F]
//	outcome     --store DIR --tx-id ID
//	verify      --store DIR --writer ID --count N --prefix P
//	verify-full --store DIR
//	read        --store DIR --name NAME
//	stat        --store DIR --name NAME
//	head        --store DIR
//	snapshot    --store DIR --name NAME
//	gc          --store DIR [--apply]
//	single      --store DIR --name NAME --content TEXT --seed SEED
//	hold-read   --store DIR --name NAME --ready FILE --gate FILE
//	open-check  --store DIR [--mode single|optimistic]
//
// Azure is selected with `--backend azure` plus `--container` and the usual
// WEFT_AZURE_* endpoint/account/key environment, or the explicit flags.
//
// The Azure ambiguous-success fault point is `WEFT_AZURE_AMBIGUOUS_READY`: when
// that path appears this process kills itself with SIGKILL. The court's proxy
// writes it only after the conditional head PUT has been applied upstream and
// before its response is returned. Inert unless the variable is set.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

const defaultNow int64 = 1_700_000_000_000_000_000

func arg(args []string, name string) string {
	for i, value := range args {
		if value == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func fixedNow(args []string) int64 {
	if text := arg(args, "--fixed-timestamp-ns"); text != "" {
		if value, err := strconv.ParseInt(text, 10, 64); err == nil {
			return value
		}
	}
	return defaultNow
}

func options(bf backendFlags, mode store.WriterMode, now int64) (store.Options, error) {
	opts := store.DefaultOptions()
	opts.FixedTimestampNS = &now
	opts.CheckpointInterval = 0
	opts.WriterMode = mode
	// Court hook: a shorter sweep grace lets the GC scenario reclaim data it
	// has just made unreachable. Inert unless the court sets it.
	if text := os.Getenv("WEFT_MW2_GC_GRACE_SECS"); text != "" {
		if value, err := strconv.ParseUint(text, 10, 64); err == nil {
			opts.GCGraceSecs = value
		}
	}
	if err := applyBackend(&opts, bf); err != nil {
		return store.Options{}, err
	}
	return opts, nil
}

// backendFlags selects the physical planes for the court driver.
type backendFlags struct {
	plane         string
	container     string
	endpoint      string
	account       string
	key           string
	lockLeaseSecs uint64
}

func parseBackend(args []string) backendFlags {
	flags := backendFlags{plane: "local"}
	if value := arg(args, "--backend"); value != "" {
		flags.plane = value
	}
	flags.container = arg(args, "--container")
	if flags.container == "" {
		flags.container = os.Getenv("WEFT_AZURE_TEST_CONTAINER")
	}
	flags.endpoint = arg(args, "--endpoint")
	if flags.endpoint == "" {
		flags.endpoint = os.Getenv("WEFT_AZURE_TEST_ENDPOINT")
	}
	if flags.endpoint == "" {
		flags.endpoint = os.Getenv("WEFT_AZURE_ENDPOINT")
	}
	flags.account = arg(args, "--account")
	if flags.account == "" {
		flags.account = os.Getenv("WEFT_AZURE_ACCOUNT")
	}
	flags.key = arg(args, "--key")
	if flags.key == "" {
		flags.key = os.Getenv("WEFT_AZURE_KEY")
	}
	if text := arg(args, "--lock-lease-secs"); text != "" {
		if value, err := strconv.ParseUint(text, 10, 64); err == nil {
			flags.lockLeaseSecs = value
		}
	} else if text := os.Getenv("WEFT_AZURE_LOCK_LEASE_SECS"); text != "" {
		if value, err := strconv.ParseUint(text, 10, 64); err == nil {
			flags.lockLeaseSecs = value
		}
	}
	return flags
}

func applyBackend(opts *store.Options, bf backendFlags) error {
	switch bf.plane {
	case "", "local":
		return nil
	case "object":
		opts.BlobBackend = store.PlaneObject
		opts.CommitBackend = store.PlaneObject
		return nil
	case "azure":
		if bf.container == "" {
			return fmt.Errorf("--container or WEFT_AZURE_TEST_CONTAINER is required for azure")
		}
		config, err := store.ResolveAzure(bf.endpoint, bf.container, bf.account, bf.key, "", nil, bf.lockLeaseSecs)
		if err != nil {
			return err
		}
		opts.BlobBackend = store.PlaneAzure
		opts.CommitBackend = store.PlaneAzure
		opts.Azure = &config
		return nil
	default:
		return fmt.Errorf("unknown --backend %q", bf.plane)
	}
}

func mustOptions(bf backendFlags, mode store.WriterMode, now int64) store.Options {
	opts, err := options(bf, mode, now)
	if err != nil {
		fail(err)
	}
	return opts
}

// armAmbiguousExit is the Azure ambiguous-success fault point. The court's
// proxy creates WEFT_AZURE_AMBIGUOUS_READY after the conditional head PUT has
// been applied upstream and before the response is returned; this process then
// SIGKILLs itself without recording any outcome.
func armAmbiguousExit() {
	if os.Getenv("WEFT_AZURE_AMBIGUOUS_HEAD") == "" {
		return
	}
	ready := os.Getenv("WEFT_AZURE_AMBIGUOUS_READY")
	if ready == "" {
		return
	}
	go func() {
		for i := 0; i < 6000; i++ {
			if _, err := os.Stat(ready); err == nil {
				_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
				select {}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
}

func classOf(err error) string {
	if err == nil {
		return ""
	}
	return string(werr.ClassOf(err))
}

// readNamed reads one file from a held handle without refreshing its head.
func readNamed(s *store.Store, name string) map[string]any {
	id, err := s.Lookup(model.RootID, []byte(name))
	if err != nil {
		if werr.ClassOf(err) == werr.NotFound {
			return map[string]any{"present": false}
		}
		return map[string]any{"present": false, "class": classOf(err), "error": err.Error()}
	}
	body, err := s.ReadObject(id)
	if err != nil {
		return map[string]any{"present": true, "class": classOf(err), "error": err.Error()}
	}
	return map[string]any{
		"present": true, "object_id": id.Hex(), "len": len(body),
		"content_hash": model.ContentHash(body).Hex(),
	}
}

func emit(value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}

func main() {
	args := os.Args
	mode := "help"
	if len(args) > 1 {
		mode = args[1]
	}
	storePath := arg(args, "--store")
	if storePath == "" {
		storePath = "."
	}
	now := fixedNow(args)
	bf := parseBackend(args)

	switch mode {
	case "init":
		s, err := store.Init(storePath, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		if err := s.Close(); err != nil {
			fail(err)
		}
		emit(map[string]any{"ok": true})
	case "parity":
		name := arg(args, "--name")
		if name == "" {
			name = "parity.bin"
		}
		content := arg(args, "--content")
		if content == "" {
			content = "parity"
		}
		seed := arg(args, "--seed")
		if seed == "" {
			seed = "seed"
		}
		if bf.plane == "local" {
			if _, err := os.Stat(filepath.Join(storePath, "FORMAT")); err != nil {
				s, initErr := store.Init(storePath, mustOptions(bf, store.WriterModeSingle, now))
				if initErr != nil {
					fail(initErr)
				}
				_ = s.Close()
			}
		}
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, store.WriterModeOptimistic, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		manifest, contentRoot, size, err := s.PrepareContent([]byte(content))
		if err != nil {
			fail(err)
		}
		objectID := model.ObjectIDFromSeed([]byte(seed))
		version, err := model.DeriveVersionID(objectID, manifest, size, now, nil)
		if err != nil {
			fail(err)
		}
		record := model.ObjectRecord{
			ID: objectID, Kind: model.KindFile, Mode: 0o644,
			MtimeNS: now, Version: version, Content: manifest, Size: size,
			Attrs: map[string]wcb.Value{},
		}
		entryID, err := model.DeriveEntryID(model.RootID, []byte(name))
		if err != nil {
			fail(err)
		}
		entry := model.EntryRecord{ID: entryID, Parent: model.RootID, Name: []byte(name), Target: objectID}
		txID := "00000000000000000000000000000001"
		tx, err := s.BeginTransaction(txID)
		if err != nil {
			fail(err)
		}
		if err := tx.PutObjectCreate(record); err != nil {
			fail(err)
		}
		if err := tx.PutEntryCreate(entry); err != nil {
			fail(err)
		}
		if err := tx.SetTip(s.CurrentState(), objectID, version); err != nil {
			fail(err)
		}
		outcome, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions())
		if err != nil {
			fail(err)
		}
		emit(map[string]any{
			"ok": true, "head": outcome.Commit.Hex(), "generation": outcome.Generation,
			"manifest": manifest.Hex(), "content_root": contentRoot.Hex(),
			"object_id": objectID.Hex(), "entry_id": entryID.Hex(),
			"version": version.Hex(), "size": size, "tx_id": txID,
		})
	case "write":
		writer := arg(args, "--writer")
		if writer == "" {
			writer = "w0"
		}
		count := uint64(10)
		if text := arg(args, "--count"); text != "" {
			if value, err := strconv.ParseUint(text, 10, 64); err == nil {
				count = value
			}
		}
		prefix := arg(args, "--prefix")
		if prefix == "" {
			prefix = writer
		}
		hot := arg(args, "--hot")
		explicitTx := arg(args, "--tx-id")
		pauseMS := uint64(0)
		if text := arg(args, "--pause-before-execute-ms"); text != "" {
			if value, err := strconv.ParseUint(text, 10, 64); err == nil {
				pauseMS = value
			}
		}
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, store.WriterModeOptimistic, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		armAmbiguousExit()
		started := time.Now()
		committed, conflicts, attempts := uint64(0), uint64(0), uint64(0)
		errorsList := []string{}
		for index := uint64(0); index < count; index++ {
			name := hot
			if name == "" {
				name = fmt.Sprintf("%s-%06d", prefix, index)
			}
			content := fmt.Sprintf("%s:%d", writer, index)
			seed := fmt.Sprintf("%s:%d:seed", writer, index)
			manifest, _, size, err := s.PrepareContent([]byte(content))
			if err != nil {
				errorsList = append(errorsList, err.Error())
				continue
			}
			objectID := model.ObjectIDFromSeed([]byte(seed))
			version, err := model.DeriveVersionID(objectID, manifest, size, now, nil)
			if err != nil {
				errorsList = append(errorsList, err.Error())
				continue
			}
			record := model.ObjectRecord{
				ID: objectID, Kind: model.KindFile, Mode: 0o644,
				MtimeNS: now, Version: version, Content: manifest, Size: size,
				Attrs: map[string]wcb.Value{},
			}
			entryID, err := model.DeriveEntryID(model.RootID, []byte(name))
			if err != nil {
				errorsList = append(errorsList, err.Error())
				continue
			}
			entry := model.EntryRecord{ID: entryID, Parent: model.RootID, Name: []byte(name), Target: objectID}
			txID := ""
			if explicitTx != "" && count == 1 {
				txID = explicitTx
			} else {
				txID = hash.Domain("weft/tx/id/v1", []byte(fmt.Sprintf("%s:%d", writer, index))).Hex()[:32]
			}
			tx, err := s.BeginTransaction(txID)
			if err != nil {
				errorsList = append(errorsList, err.Error())
				continue
			}
			if err := tx.PutObjectCreate(record); err != nil {
				errorsList = append(errorsList, err.Error())
				continue
			}
			if err := tx.PutEntryCreate(entry); err != nil {
				errorsList = append(errorsList, err.Error())
				continue
			}
			if err := tx.SetTip(s.CurrentState(), objectID, version); err != nil {
				errorsList = append(errorsList, err.Error())
				continue
			}
			if pauseMS > 0 {
				time.Sleep(time.Duration(pauseMS) * time.Millisecond)
			}
			options := store.DefaultTransactionOptions()
			options.MaxAttempts = 64
			outcome, err := s.ExecuteTransaction(tx, options)
			outer := uint32(0)
			for err != nil && werr.ClassOf(err) == werr.Busy && outer < 3 {
				time.Sleep(20 * time.Millisecond)
				outer++
				outcome, err = s.ExecuteTransaction(tx, options)
			}
			switch {
			case err == nil:
				committed++
				attempts += uint64(outcome.Attempts) + uint64(outer)
			case werr.ClassOf(err) == werr.Conflict:
				conflicts++
			default:
				errorsList = append(errorsList, err.Error())
			}
		}
		emit(map[string]any{
			"ok": len(errorsList) == 0, "writer": writer,
			"committed": committed, "conflicts": conflicts, "attempts": attempts,
			"errors": errorsList, "elapsed_ms": time.Since(started).Milliseconds(),
			"head": s.Head().Hex(), "generation": s.Generation(),
		})
	case "head":
		s, err := store.OpenWithOptions(storePath, store.ReadOnly, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		emit(map[string]any{
			"ok": true, "generation": s.Generation(), "head": s.Head().Hex(),
		})
	case "verify-full":
		s, err := store.OpenWithOptions(storePath, store.ReadOnly, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		report, err := s.Verify(true)
		if err != nil {
			fail(err)
		}
		problems := []string{}
		for _, problem := range report.Problems {
			problems = append(problems, problem.Class+": "+problem.Detail)
		}
		emit(map[string]any{
			"ok": report.OK && len(problems) == 0, "generation": report.Generation,
			"checked_commits": report.CheckedCommits, "checked_objects": report.CheckedObjects,
			"checked_manifests": report.CheckedManifests, "checked_chunks": report.CheckedChunks,
			"problems": problems,
		})
	case "stat":
		name := arg(args, "--name")
		s, err := store.OpenWithOptions(storePath, store.ReadOnly, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		report := readNamed(s, name)
		report["ok"] = true
		emit(report)
	case "snapshot":
		name := arg(args, "--name")
		if name == "" {
			name = "snapshot"
		}
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, store.WriterModeOptimistic, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		txID := arg(args, "--tx-id")
		if txID == "" {
			txID = hash.Domain("weft/tx/id/v1", []byte(fmt.Sprintf("snapshot:%s:%d", name, s.Generation()))).Hex()[:32]
		}
		tx, err := s.BeginTransaction(txID)
		if err != nil {
			fail(err)
		}
		if err := tx.SetSnapshot(s.CurrentState(), name, s.Head()); err != nil {
			fail(err)
		}
		outcome, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions())
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		emit(map[string]any{
			"ok": true, "snapshot": name, "head": outcome.Commit.Hex(),
			"generation": outcome.Generation, "attempts": outcome.Attempts,
		})
	case "gc":
		apply := false
		for _, value := range args {
			if value == "--apply" {
				apply = true
			}
		}
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, store.WriterModeOptimistic, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		report, err := s.GC(apply)
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		emit(map[string]any{
			"ok": true, "applied": report.Applied,
			"marked_chunks": report.MarkedChunks, "marked_manifests": report.MarkedManifests,
			"candidates": len(report.Candidates), "deleted": len(report.Deleted),
			"deleted_bytes": report.DeletedBytes, "deleted_index_bytes": report.DeletedIndexBytes,
			"removed_orphans": len(report.RemovedOrphans), "generation": s.Generation(),
		})
	case "single":
		name := arg(args, "--name")
		if name == "" {
			name = "single.bin"
		}
		content := arg(args, "--content")
		if content == "" {
			content = "single"
		}
		seed := arg(args, "--seed")
		if seed == "" {
			seed = "single-seed"
		}
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		defer s.Close()
		objectID, err := s.CreateFileSeeded(model.RootID, []byte(name), []byte(content), 0o644, 0, 0, map[string]wcb.Value{}, []byte(seed))
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		emit(map[string]any{
			"ok": true, "name": name, "object_id": objectID.Hex(),
			"head": s.Head().Hex(), "generation": s.Generation(),
		})
	case "hold-read":
		name := arg(args, "--name")
		if name == "" {
			name = "hold.bin"
		}
		s, err := store.OpenWithOptions(storePath, store.ReadOnly, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		before := readNamed(s, name)
		if ready := arg(args, "--ready"); ready != "" {
			line, _ := json.Marshal(map[string]any{
				"pid": os.Getpid(), "generation": s.Generation(), "head": s.Head().Hex(), "before": before,
			})
			_ = os.WriteFile(ready, append(line, '\n'), 0o644)
		}
		if gate := arg(args, "--gate"); gate != "" {
			for i := 0; i < 12000; i++ {
				if _, err := os.Stat(gate); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		after := readNamed(s, name)
		emit(map[string]any{
			"ok": true, "generation": s.Generation(), "head": s.Head().Hex(),
			"before": before, "after": after,
		})
	case "open-check":
		writerMode := store.WriterModeSingle
		if arg(args, "--mode") == "optimistic" {
			writerMode = store.WriterModeOptimistic
		}
		opened, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, writerMode, now))
		report := map[string]any{"ok": true}
		if err != nil {
			report = map[string]any{"ok": false, "class": classOf(err), "error": err.Error()}
		} else {
			report = map[string]any{"ok": true, "generation": opened.Generation(), "head": opened.Head().Hex()}
			_ = opened.Close()
		}
		emit(map[string]any{"ok": true, "mode": writerMode, "open": report})
	case "outcome":
		txID := arg(args, "--tx-id")
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, store.WriterModeOptimistic, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		lookup, err := s.TransactionOutcome(txID)
		if err != nil {
			fail(err)
		}
		commit := ""
		if lookup.Committed != nil {
			commit = lookup.Committed.Commit.Hex()
		}
		emit(map[string]any{"ok": true, "state": lookup.State, "commit": commit})
	case "verify":
		writer := arg(args, "--writer")
		if writer == "" {
			writer = "w0"
		}
		count := uint64(10)
		if text := arg(args, "--count"); text != "" {
			if value, err := strconv.ParseUint(text, 10, 64); err == nil {
				count = value
			}
		}
		prefix := arg(args, "--prefix")
		if prefix == "" {
			prefix = writer
		}
		s, err := store.OpenWithOptions(storePath, store.ReadOnly, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		checked := uint64(0)
		mismatches := []string{}
		for index := uint64(0); index < count; index++ {
			name := fmt.Sprintf("%s-%06d", prefix, index)
			expected := fmt.Sprintf("%s:%d", writer, index)
			id, err := s.Lookup(model.RootID, []byte(name))
			if err != nil {
				mismatches = append(mismatches, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			body, err := s.ReadObject(id)
			if err != nil {
				mismatches = append(mismatches, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			checked++
			if string(body) != expected {
				mismatches = append(mismatches, name+": content mismatch")
			}
		}
		emit(map[string]any{"ok": len(mismatches) == 0, "checked": checked, "mismatches": mismatches})
	case "read":
		name := arg(args, "--name")
		s, err := store.OpenWithOptions(storePath, store.ReadOnly, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		id, err := s.Lookup(model.RootID, []byte(name))
		if err != nil {
			fail(err)
		}
		body, err := s.ReadObject(id)
		if err != nil {
			fail(err)
		}
		emit(map[string]any{
			"ok": true, "object_id": id.Hex(), "len": len(body),
			"content_hash": model.ContentHash(body).Hex(),
		})
	case "delete":
		name := arg(args, "--name")
		if name == "" {
			name = "delete.bin"
		}
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, mustOptions(bf, store.WriterModeOptimistic, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		txID := arg(args, "--tx-id")
		if txID == "" {
			txID = hash.Domain("weft/tx/id/v1", []byte(fmt.Sprintf("delete:%s:%d", name, s.Generation()))).Hex()[:32]
		}
		objectID, err := s.Lookup(model.RootID, []byte(name))
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		entryID, err := model.DeriveEntryID(model.RootID, []byte(name))
		if err != nil {
			fail(err)
		}
		tx, err := s.BeginTransaction(txID)
		if err != nil {
			fail(err)
		}
		state := s.CurrentState()
		if _, present := state.Entries[entryID]; present {
			if err := tx.DelEntry(state, entryID); err != nil {
				fail(err)
			}
		}
		if err := tx.DeleteObject(state, objectID); err != nil {
			fail(err)
		}
		outcome, err := s.ExecuteTransaction(tx, store.DefaultTransactionOptions())
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		emit(map[string]any{
			"ok": true, "deleted": name, "head": outcome.Commit.Hex(), "generation": outcome.Generation,
		})
	case "read-snapshot":
		snapshot := arg(args, "--snapshot")
		name := arg(args, "--name")
		if name == "" {
			name = "snap.bin"
		}
		s, err := store.OpenWithOptions(storePath, store.ReadOnly, mustOptions(bf, store.WriterModeSingle, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
		commit, err := s.LookupSnapshot(snapshot)
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		id, err := s.ResolvePathAt(&commit, "/"+name)
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		body, err := s.ReadObjectAt(&commit, id)
		if err != nil {
			emit(map[string]any{"ok": false, "class": classOf(err), "error": err.Error()})
			return
		}
		emit(map[string]any{
			"ok": true, "read": map[string]any{
				"present": true, "snapshot_commit": commit.Hex(), "object_id": id.Hex(),
				"len": len(body), "content_hash": model.ContentHash(body).Hex(),
			},
		})
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %s\n", mode)
		os.Exit(2)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}
