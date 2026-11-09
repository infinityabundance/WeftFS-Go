// Command mw2writer drives the MW2 transaction API for the R4 courts.
//
// Modes:
//
//	init   --store DIR [--fixed-timestamp-ns N]
//	parity --store DIR --name NAME --content TEXT --seed SEED
//	write  --store DIR --writer ID --count N --prefix P [--hot F]
//	read   --store DIR --name NAME
//
// It is a court driver, not a product CLI.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

func options(mode store.WriterMode, now int64) store.Options {
	opts := store.DefaultOptions()
	opts.FixedTimestampNS = &now
	opts.CheckpointInterval = 0
	opts.WriterMode = mode
	return opts
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

	switch mode {
	case "init":
		s, err := store.Init(storePath, options(store.WriterModeSingle, now))
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
		if _, err := os.Stat(filepath.Join(storePath, "FORMAT")); err != nil {
			s, initErr := store.Init(storePath, options(store.WriterModeSingle, now))
			if initErr != nil {
				fail(initErr)
			}
			_ = s.Close()
		}
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, options(store.WriterModeOptimistic, now))
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
		s, err := store.OpenWithOptions(storePath, store.ReadWrite, options(store.WriterModeOptimistic, now))
		if err != nil {
			fail(err)
		}
		defer s.Close()
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
			txID := hash.Domain("weft/tx/id/v1", []byte(fmt.Sprintf("%s:%d", writer, index))).Hex()[:32]
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
		})
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
		s, err := store.Open(storePath, store.ReadOnly)
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
		s, err := store.Open(storePath, store.ReadOnly)
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
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %s\n", mode)
		os.Exit(2)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	os.Exit(1)
}
