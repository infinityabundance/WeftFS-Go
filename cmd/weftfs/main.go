// Command weftfs is the WeftFS-Go store and FUSE CLI. Every command opens the
// store explicitly; mutations take the exclusive writer lock. Errors are
// printed as `Class: message` and exit nonzero. No command invokes Rust.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	weftcontext "github.com/infinityabundance/WeftCodec-Go/context"
	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
	"github.com/infinityabundance/WeftCodec-Go/tensor"
	"github.com/infinityabundance/WeftCodec-Go/wcb"

	"github.com/infinityabundance/WeftFS-Go/auth"
	"github.com/infinityabundance/WeftFS-Go/fusefs"
	"github.com/infinityabundance/WeftFS-Go/model"
	"github.com/infinityabundance/WeftFS-Go/store"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

func main() {
	rest, storeDir, jsonOut, err := globals(os.Args[1:])
	if err != nil {
		fail(err)
	}
	if len(rest) == 0 {
		usage()
		os.Exit(64)
	}
	switch rest[0] {
	case "help", "-h", "--help":
		usage()
		return
	}
	if err := run(rest[0], rest[1:], storeDir, jsonOut); err != nil {
		fail(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: weftfs [--store DIR] [--json] [--representation raw|codec-auto|overlay]
              [--content-identity whole-file|merkle] [--codec-min-bytes N]
              [--quota SPEC] [--quota-file FILE] <command> [args]

commands:
  init info create write cat ls stat mkdir unlink rmdir rename link symlink
  readlink setattr xattr relation query snapshot verify gc checkpoint pin mount
  context causal uri tensor quota merge rebase compact
`)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// fixedTimestampNS is the optional fixture clock override, extracted from the
// global --fixed-timestamp-ns flag. Store options are not persisted, so every
// command that opens the store must apply it to keep fixtures reproducible.
var fixedTimestampNS *int64

// Representation policy flags. They are global in the same sense as the Rust
// CLI: read-only commands accept and ignore them, invalid values fail before
// any command runs, and every writable open applies them to new content.
var (
	representationMode  = store.RepresentationModeRaw
	codecMinBytes       = store.DefaultCodecMinBytes
	contentIdentityMode = model.ContentIdentityWholeFile
	// contentIdentityExplicit records whether --content-identity was supplied.
	// `mount` defaults to Merkle identity when it was not; every other command
	// keeps the frozen whole-file default so existing fixtures stay v1.
	contentIdentityExplicit bool
	// quotaBudgets are the --quota/--quota-file budgets supplied on this
	// invocation. They install (or replace) the persisted policy on a writable
	// open; an empty slice enforces the persisted policy unchanged.
	quotaBudgets []store.QuotaBudget
)

func applyRepresentationPolicy(opts *store.Options) {
	opts.Representation = representationMode
	opts.CodecMinBytes = codecMinBytes
	opts.ContentIdentity = contentIdentityMode
}

func readQuotaFile(path string) ([]store.QuotaBudget, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot read --quota-file %s", path)
	}
	return store.ParseQuotaFile(string(contents))
}

func applyQuotaPolicy(opts *store.Options) {
	opts.Quotas = quotaBudgets
}

// globals extracts --store, --json, and the representation policy wherever
// they appear, leaving the subcommand and its flags in source order.
func globals(args []string) (rest []string, storeDir string, jsonOut bool, err error) {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--store":
			if i+1 >= len(args) {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--store requires a directory")
			}
			storeDir = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--store="):
			storeDir = strings.TrimPrefix(args[i], "--store=")
		case args[i] == "--json":
			jsonOut = true
		case args[i] == "--representation" || args[i] == "-representation":
			if i+1 >= len(args) {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--representation requires a value")
			}
			mode, parseErr := store.ParseRepresentationMode(args[i+1])
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			representationMode = mode
			i++
		case strings.HasPrefix(args[i], "--representation="):
			mode, parseErr := store.ParseRepresentationMode(strings.TrimPrefix(args[i], "--representation="))
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			representationMode = mode
		case args[i] == "--codec-min-bytes" || args[i] == "-codec-min-bytes":
			if i+1 >= len(args) {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--codec-min-bytes requires a value")
			}
			value, parseErr := strconv.ParseUint(args[i+1], 10, 64)
			if parseErr != nil {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--codec-min-bytes must be a non-negative integer (got `%s`)", args[i+1])
			}
			codecMinBytes = value
			i++
		case strings.HasPrefix(args[i], "--codec-min-bytes="):
			text := strings.TrimPrefix(args[i], "--codec-min-bytes=")
			value, parseErr := strconv.ParseUint(text, 10, 64)
			if parseErr != nil {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--codec-min-bytes must be a non-negative integer (got `%s`)", text)
			}
			codecMinBytes = value
		case args[i] == "--content-identity" || args[i] == "-content-identity":
			if i+1 >= len(args) {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--content-identity requires a value")
			}
			identity, parseErr := store.ParseContentIdentity(args[i+1])
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			contentIdentityMode = identity
			contentIdentityExplicit = true
			i++
		case strings.HasPrefix(args[i], "--content-identity="):
			identity, parseErr := store.ParseContentIdentity(strings.TrimPrefix(args[i], "--content-identity="))
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			contentIdentityMode = identity
			contentIdentityExplicit = true
		case args[i] == "--quota" || args[i] == "-quota":
			if i+1 >= len(args) {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--quota requires a value")
			}
			budget, parseErr := store.ParseQuotaBudget(args[i+1])
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			quotaBudgets = append(quotaBudgets, budget)
			i++
		case strings.HasPrefix(args[i], "--quota="):
			budget, parseErr := store.ParseQuotaBudget(strings.TrimPrefix(args[i], "--quota="))
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			quotaBudgets = append(quotaBudgets, budget)
		case args[i] == "--quota-file" || args[i] == "-quota-file":
			if i+1 >= len(args) {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--quota-file requires a path")
			}
			budgets, parseErr := readQuotaFile(args[i+1])
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			quotaBudgets = append(quotaBudgets, budgets...)
			i++
		case strings.HasPrefix(args[i], "--quota-file="):
			budgets, parseErr := readQuotaFile(strings.TrimPrefix(args[i], "--quota-file="))
			if parseErr != nil {
				return nil, "", false, parseErr
			}
			quotaBudgets = append(quotaBudgets, budgets...)
		case args[i] == "--fixed-timestamp-ns" || args[i] == "-fixed-timestamp-ns":
			if i+1 >= len(args) {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "--fixed-timestamp-ns requires a value")
			}
			value, parseErr := strconv.ParseInt(args[i+1], 10, 64)
			if parseErr != nil {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "invalid --fixed-timestamp-ns value")
			}
			fixedTimestampNS = &value
			i++
		case strings.HasPrefix(args[i], "--fixed-timestamp-ns="):
			value, parseErr := strconv.ParseInt(strings.TrimPrefix(args[i], "--fixed-timestamp-ns="), 10, 64)
			if parseErr != nil {
				return nil, "", false, werr.Newf(werr.InvalidArgument, "invalid --fixed-timestamp-ns value")
			}
			fixedTimestampNS = &value
		default:
			rest = append(rest, args[i])
		}
	}
	return rest, storeDir, jsonOut, nil
}

func run(command string, args []string, storeDir string, jsonOut bool) error {
	switch command {
	case "init":
		return cmdInit(args, storeDir, jsonOut)
	case "info", "open":
		return cmdInfo(storeDir, jsonOut)
	case "create":
		return cmdCreate(args, storeDir)
	case "write":
		return cmdWrite(args, storeDir)
	case "cat":
		return cmdCat(args, storeDir)
	case "ls":
		return cmdLs(args, storeDir)
	case "stat":
		return cmdStat(args, storeDir, jsonOut)
	case "mkdir":
		return cmdMkdir(args, storeDir)
	case "unlink":
		return cmdUnlink(args, storeDir)
	case "rmdir":
		return cmdRmdir(args, storeDir)
	case "rename":
		return cmdRename(args, storeDir)
	case "link":
		return cmdLink(args, storeDir)
	case "symlink":
		return cmdSymlink(args, storeDir)
	case "readlink":
		return cmdReadlink(args, storeDir)
	case "setattr":
		return cmdSetattr(args, storeDir)
	case "xattr":
		return cmdXattr(args, storeDir, jsonOut)
	case "relation":
		return cmdRelation(args, storeDir, jsonOut)
	case "query":
		return cmdQuery(args, storeDir, jsonOut)
	case "snapshot":
		return cmdSnapshot(args, storeDir, jsonOut)
	case "quota":
		return cmdQuota(args, storeDir, jsonOut)
	case "merge":
		return cmdMerge(args, storeDir, jsonOut)
	case "verify":
		return cmdVerify(args, storeDir, jsonOut)
	case "gc":
		return cmdGC(args, storeDir, jsonOut)
	case "checkpoint":
		return cmdCheckpoint(storeDir)
	case "pin":
		return cmdPin(args, storeDir, jsonOut)
	case "mount":
		return cmdMount(args, storeDir)
	case "context":
		return cmdContext(args, storeDir, jsonOut)
	case "causal":
		return cmdCausal(args, storeDir, jsonOut)
	case "uri":
		return cmdURI(args, storeDir, jsonOut)
	case "tensor":
		return cmdTensor(args, storeDir, jsonOut)
	case "rebase":
		return cmdRebase(args, storeDir, jsonOut)
	case "compact":
		return cmdCompact(args, storeDir, jsonOut)
	default:
		return werr.Newf(werr.InvalidArgument, "unknown command `%s`", command)
	}
}

func requireStore(storeDir string) error {
	if storeDir == "" {
		return werr.Newf(werr.InvalidArgument, "--store <DIR> is required for this command")
	}
	return nil
}

func openStore(storeDir string, mode store.OpenMode) (*store.Store, error) {
	if err := requireStore(storeDir); err != nil {
		return nil, err
	}
	opts := store.DefaultOptions()
	applyRepresentationPolicy(&opts)
	applyQuotaPolicy(&opts)
	if fixedTimestampNS != nil {
		opts.FixedTimestampNS = fixedTimestampNS
	}
	return store.OpenWithOptions(storeDir, mode, opts)
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// ---- init / info ---------------------------------------------------------

func cmdInit(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	uid := fs.Uint64("uid", uint64(os.Getuid()), "owner uid")
	gid := fs.Uint64("gid", uint64(os.Getgid()), "owner gid")
	chunkSize := fs.Uint64("chunk-size", model.DefaultChunkSize, "chunk size")
	checkpoint := fs.Uint64("checkpoint-interval", store.DefaultCheckpointInterval, "commits between checkpoints")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := requireStore(storeDir); err != nil {
		return err
	}
	opts := store.DefaultOptions()
	opts.OwnerUID = *uid
	opts.OwnerGID = *gid
	opts.ChunkSize = *chunkSize
	opts.CheckpointInterval = *checkpoint
	applyRepresentationPolicy(&opts)
	applyQuotaPolicy(&opts)
	if fixedTimestampNS != nil {
		opts.FixedTimestampNS = fixedTimestampNS
	}
	s, err := store.Init(storeDir, opts)
	if err != nil {
		return err
	}
	defer s.Close()
	if jsonOut {
		return printJSON(map[string]any{
			"generation": s.Generation(), "snapshot_root": s.Head().Hex(),
		})
	}
	fmt.Printf("generation=%d\nsnapshot_root=%s\n", s.Generation(), s.Head().Hex())
	return nil
}

func cmdInfo(storeDir string, jsonOut bool) error {
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	state := s.CurrentState()
	if jsonOut {
		snapshots := map[string]string{}
		for name, commit := range state.Snapshots {
			snapshots[name] = commit.Hex()
		}
		return printJSON(map[string]any{
			"format":               "weftfs-store 1",
			"generation":           s.Generation(),
			"snapshot_root":        s.Head().Hex(),
			"objects":              len(state.Objects),
			"entries":              len(state.Entries),
			"relations":            len(state.Relations),
			"snapshots":            snapshots,
			"representation":       representationMode.AsString(),
			"content_identity":     store.ContentIdentityString(contentIdentityMode),
			"codec_min_bytes":      codecMinBytes,
			"rejected_generations": s.RejectedGenerations(),
			"recovery_notes":       s.RecoveryNotes(),
		})
	}
	fmt.Printf("format=weftfs-store 1\ngeneration=%d\nsnapshot_root=%s\n", s.Generation(), s.Head().Hex())
	fmt.Printf("objects=%d\nentries=%d\nrelations=%d\nsnapshots=%d\n",
		len(state.Objects), len(state.Entries), len(state.Relations), len(state.Snapshots))
	fmt.Printf("representation=%s\ncontent_identity=%s\ncodec_min_bytes=%d\n", representationMode.AsString(), store.ContentIdentityString(contentIdentityMode), codecMinBytes)
	for _, generation := range s.RejectedGenerations() {
		fmt.Printf("rejected_generation=%d\n", generation)
	}
	for _, note := range s.RecoveryNotes() {
		fmt.Printf("recovery_note=%s\n", note)
	}
	return nil
}

// ---- paths ---------------------------------------------------------------

func splitPath(path string) ([]string, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, werr.Newf(werr.InvalidArgument, "paths must be absolute")
	}
	parts := strings.Split(path, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return nil, werr.Newf(werr.InvalidName, "`..` is not accepted")
		}
		out = append(out, part)
	}
	return out, nil
}

func parentAndName(s *store.Store, path string) (model.Hash32, []byte, error) {
	parts, err := splitPath(path)
	if err != nil {
		return model.Hash32{}, nil, err
	}
	if len(parts) == 0 {
		return model.Hash32{}, nil, werr.Newf(werr.InvalidArgument, "cannot operate on /")
	}
	components := make([][]byte, 0, len(parts)-1)
	for _, part := range parts[:len(parts)-1] {
		components = append(components, []byte(part))
	}
	parent, err := s.ResolveComponents(components)
	if err != nil {
		return model.Hash32{}, nil, err
	}
	return parent, []byte(parts[len(parts)-1]), nil
}

func resolveObject(s *store.Store, path string) (model.Hash32, error) {
	return s.ResolvePath(path)
}

func readInput(text *string, file *string) ([]byte, error) {
	if text != nil && file != nil {
		return nil, werr.Newf(werr.InvalidArgument, "--text and --file are mutually exclusive")
	}
	if text != nil {
		return []byte(*text), nil
	}
	if file != nil {
		return os.ReadFile(*file)
	}
	return nil, nil
}

func parseMode(text string) (uint64, error) {
	value, err := strconv.ParseUint(text, 8, 32)
	if err != nil {
		return 0, werr.Newf(werr.InvalidArgument, "invalid octal mode %q", text)
	}
	return value, nil
}

// ---- file commands -------------------------------------------------------

func cmdCreate(args []string, storeDir string) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)
	text := fs.String("text", "", "file contents")
	file := fs.String("file", "", "read contents from a file")
	mode := fs.String("mode", "0644", "octal mode")
	uid := fs.Uint64("uid", uint64(os.Getuid()), "owner uid")
	gid := fs.Uint64("gid", uint64(os.Getgid()), "owner gid")
	seed := fs.String("seed", "", "explicit ObjectId seed")
	causal := fs.String("causal", "", "comma-separated causal parent ids")
	tenant := fs.String("tenant", "", "attribute the object to a tenant write budget")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "create requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	parent, name, err := parentAndName(s, fs.Arg(0))
	if err != nil {
		return err
	}
	var data []byte
	if *file != "" {
		data, err = os.ReadFile(*file)
		if err != nil {
			return werr.Wrap(werr.Io, err, "cannot read %s", *file)
		}
	} else {
		data = []byte(*text)
	}
	perm, err := parseMode(*mode)
	if err != nil {
		return err
	}
	var id model.Hash32
	var attrs map[string]wcb.Value
	if *tenant != "" {
		attrs = map[string]wcb.Value{model.AttrTenant: wcb.TextValue(*tenant)}
	}
	causalIDs, err := parseCausalEntries(*causal)
	if err != nil {
		return err
	}
	if len(causalIDs) != 0 {
		if *seed == "" {
			seedBytes := make([]byte, 32)
			if _, err := rand.Read(seedBytes); err != nil {
				return werr.Wrap(werr.Io, err, "cannot read CSPRNG")
			}
			*seed = string(seedBytes)
		}
		id, err = s.CreateFileSeededCausal(parent, name, data, perm, *uid, *gid, attrs, []byte(*seed), causalIDs)
	} else if *seed != "" {
		id, err = s.CreateFileSeeded(parent, name, data, perm, *uid, *gid, attrs, []byte(*seed))
	} else {
		id, err = s.CreateFile(parent, name, data, perm, *uid, *gid, attrs)
	}
	if err != nil {
		return err
	}
	fmt.Println(id.Hex())
	return nil
}

func cmdWrite(args []string, storeDir string) error {
	fs := flag.NewFlagSet("write", flag.ContinueOnError)
	offset := fs.Uint64("offset", 0, "byte offset")
	text := fs.String("text", "", "bytes to write")
	file := fs.String("file", "", "read bytes from a file")
	causal := fs.String("causal", "", "comma-separated causal parent ids")
	tensorFlag := fs.Bool("tensor", false, "treat the input as a logical tensor (creates a new file)")
	dtype := fs.String("dtype", "", "tensor dtype (bf16, f32, q8_0, ...)")
	shapeText := fs.String("shape", "", "comma-separated tensor dimensions")
	layoutName := fs.String("layout", "row-major", "row-major, column-major, blocked, or sharded")
	blockShape := fs.String("block-shape", "", "blocked layout block shape")
	shardAxis := fs.Uint("shard-axis", 0, "sharded layout axis")
	shards := fs.Uint("shards", 1, "sharded layout shard count")
	shardIndex := fs.Uint("shard-index", 0, "sharded layout shard index")
	strategyText := fs.String("strategy", "auto", "auto, or a required tensor strategy")
	lambdaNS := fs.Uint64("lambda-ns", 0, "bytes charged per estimated decode nanosecond")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "write requires exactly one path")
	}
	var data []byte
	var err error
	if *file != "" {
		data, err = os.ReadFile(*file)
		if err != nil {
			return werr.Wrap(werr.Io, err, "cannot read %s", *file)
		}
	} else {
		data = []byte(*text)
	}
	causalIDs, err := parseCausalEntries(*causal)
	if err != nil {
		return err
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	if *tensorFlag {
		if *dtype == "" {
			return werr.Newf(werr.InvalidArgument, "--tensor requires --dtype")
		}
		if *shapeText == "" {
			return werr.Newf(werr.InvalidArgument, "--tensor requires --shape")
		}
		shape, err := parseU64List(*shapeText, "--shape")
		if err != nil {
			return err
		}
		layout, err := parseTensorLayout(*layoutName, *blockShape, uint32(*shardAxis), uint32(*shards), uint32(*shardIndex))
		if err != nil {
			return err
		}
		hint, err := store.ParseTensorStrategyHint(*strategyText)
		if err != nil {
			return err
		}
		parent, name, err := parentAndName(s, fs.Arg(0))
		if err != nil {
			return err
		}
		id, err := s.WriteTensorFileWithSpec(parent, name, *dtype, shape, data, layout, store.TensorWriteSpec{
			StrategyHint: hint,
			Causal:       causalIDs,
			Plan:         store.TensorPlanOptions{LambdaNS: *lambdaNS},
		})
		if err != nil {
			return err
		}
		fmt.Println(id.Hex())
		return nil
	}
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	version, err := s.WriteFileCausal(id, *offset, data, causalIDs)
	if err != nil {
		return err
	}
	fmt.Println(version.Hex())
	return nil
}

func cmdCompact(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("compact", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "compact requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	report, err := s.Compact(id)
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(map[string]any{
			"object_id":        report.Object.Hex(),
			"previous_content": report.PreviousContent.Hex(),
			"content":          report.Content.Hex(),
			"version_id":       report.Version.Hex(),
			"size":             report.Size,
			"content_root":     report.ContentRoot.Hex(),
			"chunks":           report.Chunks,
			"overlay_depth":    report.OverlayDepth,
			"overlay_bytes":    report.OverlayBytes,
			"verified_bytes":   report.VerifiedBytes,
			"generation":       s.Generation(),
		})
	}
	fmt.Println(report.Content.Hex())
	fmt.Printf("version=%s\n", report.Version.Hex())
	fmt.Printf("content_root=%s\n", report.ContentRoot.Hex())
	fmt.Printf("chunks=%d\n", report.Chunks)
	fmt.Printf("overlay_depth=%d\n", report.OverlayDepth)
	fmt.Printf("overlay_bytes=%d\n", report.OverlayBytes)
	fmt.Printf("verified_bytes=%d\n", report.VerifiedBytes)
	return nil
}

func cmdCat(args []string, storeDir string) error {
	fs := flag.NewFlagSet("cat", flag.ContinueOnError)
	offset := fs.Uint64("offset", 0, "byte offset")
	length := fs.Uint64("len", 0, "byte length (0 means to EOF)")
	regionText := fs.String("region", "", "logical tensor region s0,s1:e0,e1")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "cat requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	var data []byte
	if *regionText != "" {
		region, err := parseRegion(*regionText)
		if err != nil {
			return err
		}
		read, err := s.ReadTensorRegion(id, region)
		if err != nil {
			return err
		}
		data = read.Bytes
	} else if *length == 0 {
		data, err = s.ReadObject(id)
	} else {
		data, err = s.ReadRange(id, *offset, *length)
	}
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

// cmdTensor exposes tensor identity: `tensor logical-root PATH` or
// `tensor meta PATH`.
func cmdTensor(args []string, storeDir string, jsonOut bool) error {
	if len(args) < 1 {
		return werr.Newf(werr.InvalidArgument,
			"tensor requires `logical-root` or `meta` and a path")
	}
	action := args[0]
	fs := flag.NewFlagSet("tensor "+action, flag.ContinueOnError)
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "tensor %s requires exactly one path", action)
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	switch action {
	case "logical-root":
		root, err := s.TensorLogicalRoot(id)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{"object_id": id.Hex(), "logical_root": root.Hex()})
		}
		fmt.Println(root.Hex())
		return nil
	case "meta":
		meta, err := s.TensorMetadata(id)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{
				"object_id":    id.Hex(),
				"dtype":        meta.Dtype,
				"shape":        meta.Shape,
				"layout":       meta.Layout.Name(),
				"logical_root": meta.LogicalRoot.Hex(),
				"strategy":     meta.Strategy,
			})
		}
		fmt.Printf("dtype=%s\nshape=%v\nlayout=%s\nlogical_root=%s\nstrategy=%s\n",
			meta.Dtype, meta.Shape, meta.Layout.Name(), meta.LogicalRoot.Hex(), meta.Strategy)
		return nil
	default:
		return werr.Newf(werr.InvalidArgument,
			"unknown tensor action `%s` (expected logical-root or meta)", action)
	}
}

func parseU64List(text, flagName string) ([]uint64, error) {
	parts := strings.Split(text, ",")
	out := make([]uint64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, werr.Newf(werr.InvalidArgument, "%s has an empty component", flagName)
		}
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, werr.Newf(werr.InvalidArgument,
				"%s component `%s` is not a u64", flagName, part)
		}
		out = append(out, value)
	}
	return out, nil
}

func parseTensorLayout(name, blockShape string, axis, shards, index uint32) (store.TensorLayoutSpec, error) {
	switch name {
	case "row-major":
		return store.RowMajorTensorLayout(), nil
	case "column-major":
		return store.ColumnMajorTensorLayout(), nil
	case "blocked":
		if blockShape == "" {
			return store.TensorLayoutSpec{},
				werr.Newf(werr.InvalidArgument, "--layout blocked requires --block-shape")
		}
		block, err := parseU64List(blockShape, "--block-shape")
		if err != nil {
			return store.TensorLayoutSpec{}, err
		}
		return store.BlockedTensorLayout(block), nil
	case "sharded":
		return store.ShardedTensorLayout(axis, shards, index), nil
	default:
		return store.TensorLayoutSpec{}, werr.Newf(werr.InvalidArgument,
			"--layout must be row-major, column-major, blocked, or sharded (got `%s`)", name)
	}
}

func parseRegion(text string) (tensor.Region, error) {
	startText, endText, ok := strings.Cut(text, ":")
	if !ok {
		return tensor.Region{}, werr.Newf(werr.InvalidArgument,
			"--region must be `s0,s1:e0,e1`")
	}
	start, err := parseU64List(startText, "--region start")
	if err != nil {
		return tensor.Region{}, err
	}
	end, err := parseU64List(endText, "--region end")
	if err != nil {
		return tensor.Region{}, err
	}
	if len(start) != len(end) {
		return tensor.Region{}, werr.Newf(werr.InvalidArgument,
			"--region start and end ranks differ")
	}
	return tensor.NewRegion(start, end), nil
}

func cmdLs(args []string, storeDir string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "ls requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	entries, err := s.ListDir(id)
	if err != nil {
		return err
	}
	if *jsonOut {
		out := make([]map[string]string, 0, len(entries))
		for _, entry := range entries {
			out = append(out, map[string]string{
				"name": string(entry.Name), "entry_id": entry.EntryID.Hex(), "target": entry.Target.Hex(),
			})
		}
		return printJSON(out)
	}
	for _, entry := range entries {
		fmt.Printf("%s\t%s\n", entry.Target.Hex(), string(entry.Name))
	}
	return nil
}

func cmdStat(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("stat", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "stat requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	record, err := s.ObjectMeta(id)
	if err != nil {
		return err
	}
	links, _ := s.NLink(id)
	info := map[string]any{
		"object_id": id.Hex(),
		"kind":      string(record.Kind),
		"mode":      fmt.Sprintf("%04o", record.Mode),
		"uid":       record.UID,
		"gid":       record.GID,
		"mtime_ns":  record.MtimeNS,
		"version":   record.Version.Hex(),
		"content":   record.Content.Hex(),
		"size":      record.Size,
		"nlink":     links,
	}
	if record.Kind == model.KindFile {
		if manifest, err := store.ReadManifest(storeDir, record.Content); err == nil {
			info["content_hash"] = manifest.ContentHash.Hex()
			info["content_identity"] = store.ContentIdentityString(manifest.Identity)
			info["chunk_size"] = manifest.ChunkSize
			info["chunks"] = len(manifest.Chunks)
		}
	}
	if jsonOut {
		return printJSON(info)
	}
	for _, key := range []string{"object_id", "kind", "mode", "uid", "gid", "mtime_ns", "version", "content", "size", "nlink", "content_hash", "chunk_size", "chunks"} {
		if value, ok := info[key]; ok {
			fmt.Printf("%s=%v\n", key, value)
		}
	}
	return nil
}

func cmdMkdir(args []string, storeDir string) error {
	fs := flag.NewFlagSet("mkdir", flag.ContinueOnError)
	mode := fs.String("mode", "0755", "octal mode")
	uid := fs.Uint64("uid", uint64(os.Getuid()), "owner uid")
	gid := fs.Uint64("gid", uint64(os.Getgid()), "owner gid")
	seed := fs.String("seed", "", "explicit ObjectId seed")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "mkdir requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	parent, name, err := parentAndName(s, fs.Arg(0))
	if err != nil {
		return err
	}
	perm, err := parseMode(*mode)
	if err != nil {
		return err
	}
	var id model.Hash32
	if *seed != "" {
		id, err = s.MkdirSeeded(parent, name, perm, *uid, *gid, []byte(*seed))
	} else {
		id, err = s.Mkdir(parent, name, perm, *uid, *gid)
	}
	if err != nil {
		return err
	}
	fmt.Println(id.Hex())
	return nil
}

func cmdUnlink(args []string, storeDir string) error {
	fs := flag.NewFlagSet("unlink", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return mutateParent(fs.Args(), storeDir, func(s *store.Store, parent model.Hash32, name []byte) error {
		return s.Unlink(parent, name)
	})
}

func cmdRmdir(args []string, storeDir string) error {
	fs := flag.NewFlagSet("rmdir", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return mutateParent(fs.Args(), storeDir, func(s *store.Store, parent model.Hash32, name []byte) error {
		return s.Rmdir(parent, name)
	})
}

func mutateParent(args []string, storeDir string, action func(*store.Store, model.Hash32, []byte) error) error {
	if len(args) != 1 {
		return werr.Newf(werr.InvalidArgument, "this command requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	parent, name, err := parentAndName(s, args[0])
	if err != nil {
		return err
	}
	return action(s, parent, name)
}

func cmdRename(args []string, storeDir string) error {
	fs := flag.NewFlagSet("rename", flag.ContinueOnError)
	noReplace := fs.Bool("no-replace", false, "fail if the destination exists")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return werr.Newf(werr.InvalidArgument, "rename requires FROM and TO")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	fromParent, fromName, err := parentAndName(s, fs.Arg(0))
	if err != nil {
		return err
	}
	toParent, toName, err := parentAndName(s, fs.Arg(1))
	if err != nil {
		return err
	}
	if *noReplace {
		return s.RenameNoReplace(fromParent, fromName, toParent, toName)
	}
	return s.Rename(fromParent, fromName, toParent, toName)
}

func cmdLink(args []string, storeDir string) error {
	fs := flag.NewFlagSet("link", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return werr.Newf(werr.InvalidArgument, "link requires TARGET and PATH")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	target, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	parent, name, err := parentAndName(s, fs.Arg(1))
	if err != nil {
		return err
	}
	return s.Link(target, parent, name)
}

func cmdSymlink(args []string, storeDir string) error {
	fs := flag.NewFlagSet("symlink", flag.ContinueOnError)
	uid := fs.Uint64("uid", uint64(os.Getuid()), "owner uid")
	gid := fs.Uint64("gid", uint64(os.Getgid()), "owner gid")
	seed := fs.String("seed", "", "explicit ObjectId seed")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return werr.Newf(werr.InvalidArgument, "symlink requires TARGET and PATH")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	parent, name, err := parentAndName(s, fs.Arg(1))
	if err != nil {
		return err
	}
	var id model.Hash32
	if *seed != "" {
		id, err = s.SymlinkSeeded(parent, name, []byte(fs.Arg(0)), *uid, *gid, []byte(*seed))
	} else {
		id, err = s.Symlink(parent, name, []byte(fs.Arg(0)), *uid, *gid)
	}
	if err != nil {
		return err
	}
	fmt.Println(id.Hex())
	return nil
}

func cmdReadlink(args []string, storeDir string) error {
	fs := flag.NewFlagSet("readlink", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "readlink requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	target, err := s.ReadObject(id)
	if err != nil {
		return err
	}
	fmt.Println(string(target))
	return nil
}

func cmdSetattr(args []string, storeDir string) error {
	fs := flag.NewFlagSet("setattr", flag.ContinueOnError)
	mode := fs.String("mode", "", "octal mode")
	uid := fs.Uint64("uid", 0, "owner uid")
	gid := fs.Uint64("gid", 0, "owner gid")
	mtime := fs.Int64("mtime-ns", 0, "mtime in nanoseconds")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "setattr requires exactly one path")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	changes := store.SetAttr{}
	set := false
	if *mode != "" {
		perm, err := parseMode(*mode)
		if err != nil {
			return err
		}
		changes.Mode = &perm
		set = true
	}
	if flagSet(fs, "uid") {
		changes.UID = uid
		set = true
	}
	if flagSet(fs, "gid") {
		changes.GID = gid
		set = true
	}
	if flagSet(fs, "mtime-ns") {
		changes.MtimeNS = mtime
		set = true
	}
	if !set {
		return werr.Newf(werr.InvalidArgument, "setattr needs at least one attribute")
	}
	version, err := s.Setattr(id, changes)
	if err != nil {
		return err
	}
	fmt.Println(version.Hex())
	return nil
}

// flagSet reports whether a flag was provided (the flag package has no public
// query, so main tracks it by inspecting args).
func flagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// parseFlags accepts flags interleaved with positional arguments. The standard
// flag package stops at the first positional, which would make
// `create PATH --text ...` fail; this reorders known flags ahead of
// positionals while preserving the positionals' relative order.
func parseFlags(fs *flag.FlagSet, args []string) error {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if len(arg) > 1 && arg[0] == '-' {
			flags = append(flags, arg)
			if strings.Contains(arg, "=") {
				continue
			}
			name := strings.TrimLeft(arg, "-")
			definition := fs.Lookup(name)
			if definition == nil {
				// Let fs.Parse report the unknown flag.
				continue
			}
			if boolFlag, ok := definition.Value.(interface{ IsBoolFlag() bool }); ok && boolFlag.IsBoolFlag() {
				continue
			}
			if i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return fs.Parse(append(flags, positionals...))
}

func cmdXattr(args []string, storeDir string, jsonOut bool) error {
	if len(args) == 0 {
		return werr.Newf(werr.InvalidArgument, "xattr requires list|get|set|remove")
	}
	action := args[0]
	fs := flag.NewFlagSet("xattr "+action, flag.ContinueOnError)
	value := fs.String("value", "", "attribute value")
	if err := parseFlags(fs, args[1:]); err != nil {
		return err
	}
	switch action {
	case "list":
		if fs.NArg() != 1 {
			return werr.Newf(werr.InvalidArgument, "xattr list requires a path")
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		id, err := resolveObject(s, fs.Arg(0))
		if err != nil {
			return err
		}
		names, err := s.ListXattr(id)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(names)
		}
		for _, name := range names {
			fmt.Println(name)
		}
		return nil
	case "get":
		if fs.NArg() != 2 {
			return werr.Newf(werr.InvalidArgument, "xattr get requires a path and a name")
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		id, err := resolveObject(s, fs.Arg(0))
		if err != nil {
			return err
		}
		data, ok, err := s.GetXattr(id, fs.Arg(1))
		if err != nil {
			return err
		}
		if !ok {
			return werr.Newf(werr.NotFound, "no such extended attribute")
		}
		_, err = os.Stdout.Write(data)
		return err
	case "set":
		if fs.NArg() != 2 {
			return werr.Newf(werr.InvalidArgument, "xattr set requires a path and a name")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		id, err := resolveObject(s, fs.Arg(0))
		if err != nil {
			return err
		}
		return s.SetXattr(id, fs.Arg(1), []byte(*value))
	case "remove":
		if fs.NArg() != 2 {
			return werr.Newf(werr.InvalidArgument, "xattr remove requires a path and a name")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		id, err := resolveObject(s, fs.Arg(0))
		if err != nil {
			return err
		}
		removed, err := s.RemoveXattr(id, fs.Arg(1))
		if err != nil {
			return err
		}
		if !removed {
			return werr.Newf(werr.NotFound, "no such extended attribute")
		}
		return nil
	default:
		return werr.Newf(werr.InvalidArgument, "unknown xattr action `%s`", action)
	}
}

// ---- relations -----------------------------------------------------------

func parseAttrs(pairs []string) (map[string]wcb.Value, error) {
	attrs := map[string]wcb.Value{}
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, werr.Newf(werr.InvalidArgument, "--attr expects key=value, got %q", pair)
		}
		attrs[key] = wcb.TextValue(value)
	}
	return attrs, nil
}

func cmdRelation(args []string, storeDir string, jsonOut bool) error {
	if len(args) == 0 {
		return werr.Newf(werr.InvalidArgument, "relation requires add|list|delete")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("relation add", flag.ContinueOnError)
		subject := fs.String("subject", "", "subject object path or hex id")
		predicate := fs.String("predicate", "", "predicate text")
		object := fs.String("object", "", "object target path or hex id")
		value := fs.String("value", "", "scalar text target")
		valueInt := fs.Int64("value-int", 0, "scalar integer target")
		var attrs multiFlag
		fs.Var(&attrs, "attr", "attribute key=value")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		subjectID, err := resolveMaybeHex(s, *subject)
		if err != nil {
			return err
		}
		if *predicate == "" {
			return werr.Newf(werr.InvalidArgument, "--predicate is required")
		}
		var target model.RelationTarget
		switch {
		case *object != "" && (*value != "" || flagSet(fs, "value-int")):
			return werr.Newf(werr.InvalidArgument, "--object and --value are mutually exclusive")
		case *object != "":
			targetID, err := resolveMaybeHex(s, *object)
			if err != nil {
				return err
			}
			target = model.ObjectTarget(targetID)
		case flagSet(fs, "value-int"):
			target = model.ValueTarget(wcb.I64Value(*valueInt))
		default:
			target = model.ValueTarget(wcb.TextValue(*value))
		}
		attrValues, err := parseAttrs(attrs)
		if err != nil {
			return err
		}
		id, err := s.RelationAdd(subjectID, *predicate, target, nil, attrValues)
		if err != nil {
			return err
		}
		fmt.Println(id.Hex())
		return nil
	case "list":
		fs := flag.NewFlagSet("relation list", flag.ContinueOnError)
		subject := fs.String("subject", "", "filter by subject")
		predicate := fs.String("predicate", "", "filter by predicate")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		out := make([]map[string]any, 0)
		for _, id := range model.SortHashKeys(s.CurrentState().Relations) {
			relation := s.CurrentState().Relations[id]
			if *subject != "" {
				subjectID, err := parseHashOrPath(s, *subject)
				if err != nil {
					return err
				}
				if relation.Subject != subjectID {
					continue
				}
			}
			if *predicate != "" && relation.Predicate != *predicate {
				continue
			}
			if !jsonOut {
				fmt.Printf("%s\t%s\t%s\n", id.Hex(), relation.Predicate, relation.Subject.Hex())
				continue
			}
			entry := map[string]any{
				"id": id.Hex(), "subject": relation.Subject.Hex(),
				"predicate": relation.Predicate, "kind": string(relation.Kind),
			}
			if relation.Target.Object != nil {
				entry["object"] = relation.Target.Object.Hex()
			} else {
				entry["object"] = valueJSON(relation.Target.Value)
			}
			out = append(out, entry)
		}
		if jsonOut {
			return printJSON(out)
		}
		return nil
	case "delete":
		fs := flag.NewFlagSet("relation delete", flag.ContinueOnError)
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return werr.Newf(werr.InvalidArgument, "relation delete requires a relation id")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		id, err := parseHexHash(fs.Arg(0))
		if err != nil {
			return err
		}
		return s.RelationDelete(id)
	default:
		return werr.Newf(werr.InvalidArgument, "unknown relation action `%s`", args[0])
	}
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func parseHashOrPath(s *store.Store, text string) (model.Hash32, error) {
	if len(text) == 64 {
		if id, err := parseHexHash(text); err == nil {
			return id, nil
		}
	}
	return s.ResolvePath(text)
}

func resolveMaybeHex(s *store.Store, text string) (model.Hash32, error) {
	if text == "" {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "a path or object id is required")
	}
	return parseHashOrPath(s, text)
}

func parseHexHash(text string) (model.Hash32, error) {
	var id model.Hash32
	if len(text) != 64 {
		return id, werr.Newf(werr.InvalidArgument, "hash hex must be 64 characters")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return id, werr.Newf(werr.InvalidArgument, "invalid hash hex")
	}
	copy(id[:], decoded)
	return id, nil
}

func valueJSON(value wcb.Value) any {
	switch value.Kind {
	case wcb.Null:
		return nil
	case wcb.Bool:
		return value.Bool
	case wcb.U64:
		return value.U
	case wcb.I64, wcb.Timestamp:
		return value.I
	case wcb.Text:
		return value.Str
	case wcb.Bytes:
		return hex.EncodeToString(value.Bytes)
	case wcb.Array:
		out := make([]any, 0, len(value.Array))
		for _, item := range value.Array {
			out = append(out, valueJSON(item))
		}
		return out
	case wcb.Map:
		out := map[string]any{}
		for key, item := range value.Map {
			out[key] = valueJSON(item)
		}
		return out
	default:
		return nil
	}
}

// ---- selectors -----------------------------------------------------------

func cmdQuery(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	snapshot := fs.String("snapshot", "", "snapshot name or commit hex")
	uid := fs.Uint64("uid", 0, "principal uid")
	gid := fs.Uint64("gid", 0, "principal gid")
	groups := fs.String("groups", "", "comma-separated supplementary groups")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "query requires one WeftQL expression")
	}
	parsed, err := selector.Parse(fs.Arg(0))
	if err != nil {
		return werr.FromCodec(err)
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	var snapshotID *model.Hash32
	if *snapshot != "" {
		id, err := s.LookupSnapshot(*snapshot)
		if err != nil {
			return err
		}
		snapshotID = &id
	}
	principal := auth.New(*uid, *gid, parseGroups(*groups))
	resolution, err := s.Resolve(parsed, snapshotID, principal, limits.Default())
	if err != nil {
		return err
	}
	if jsonOut {
		results := make([]map[string]string, 0, len(resolution.Results))
		for _, result := range resolution.Results {
			results = append(results, map[string]string{
				"object_id": result.ObjectID.Hex(), "version_id": result.VersionID.Hex(),
				"content_id": result.ContentID.Hex(), "namespace": result.Namespace,
			})
		}
		return printJSON(map[string]any{
			"selector_id":   resolution.SelectorID.Hex(),
			"snapshot_id":   resolution.SnapshotID.Hex(),
			"matched_count": resolution.MatchedCount,
			"results":       results,
		})
	}
	fmt.Printf("selector_id=%s\nsnapshot_id=%s\nmatched_count=%d\n",
		resolution.SelectorID.Hex(), resolution.SnapshotID.Hex(), resolution.MatchedCount)
	for _, result := range resolution.Results {
		fmt.Println(result.ObjectID.Hex())
	}
	return nil
}

func parseGroups(text string) []uint64 {
	if text == "" {
		return nil
	}
	out := make([]uint64, 0)
	for _, part := range strings.Split(text, ",") {
		value, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err == nil {
			out = append(out, value)
		}
	}
	return out
}

// ---- write budgets -------------------------------------------------------

func cmdQuota(args []string, storeDir string, jsonOut bool) error {
	if len(args) == 0 {
		return werr.Newf(werr.InvalidArgument, "quota requires show|reset|rebuild")
	}
	switch args[0] {
	case "show":
		fs := flag.NewFlagSet("quota show", flag.ContinueOnError)
		uid := fs.Uint64("uid", 0, "caller uid")
		gid := fs.Uint64("gid", 0, "caller gid")
		tenant := fs.String("tenant", "", "tenant principal")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		if problem := s.QuotaProblem(); problem != "" {
			return werr.Newf(werr.Corrupt, "quota usage record is unusable: %s", problem)
		}
		principal := store.PosixPrincipal(*uid, *gid)
		if *tenant != "" {
			principal = store.TenantPrincipal(*tenant)
		}
		usage := s.QuotaUsage(principal)
		budget, configured := s.QuotaBudget(principal)
		if jsonOut {
			out := map[string]any{
				"principal": principal.Display(), "configured": configured,
				"used_bytes": usage.UsedBytes, "used_objects": usage.UsedObjects,
			}
			if configured {
				out["max_new_bytes"] = budget.MaxNewBytes
				out["max_objects"] = budget.MaxObjects
			}
			return printJSON(out)
		}
		fmt.Printf("principal=%s\nconfigured=%v\nused_bytes=%d\nused_objects=%d\n",
			principal.Display(), configured, usage.UsedBytes, usage.UsedObjects)
		if configured {
			fmt.Printf("max_new_bytes=%d\nmax_objects=%d\n", budget.MaxNewBytes, budget.MaxObjects)
		}
		return nil
	case "reset":
		fs := flag.NewFlagSet("quota reset", flag.ContinueOnError)
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.QuotaReset(); err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{"reset": true, "generation": s.Generation()})
		}
		fmt.Println("reset=true")
		return nil
	case "rebuild":
		fs := flag.NewFlagSet("quota rebuild", flag.ContinueOnError)
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		commits, err := s.QuotaRebuild()
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{
				"rebuilt": true, "commits": commits, "generation": s.Generation(),
			})
		}
		fmt.Println("rebuilt=true")
		fmt.Printf("commits=%d\n", commits)
		return nil
	default:
		return werr.Newf(werr.InvalidArgument, "unknown quota action `%s`", args[0])
	}
}

// ---- merge ---------------------------------------------------------------

func cmdMerge(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return werr.Newf(werr.InvalidArgument, "merge requires <left> <right>")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	report, err := s.MergeBranches(fs.Arg(0), fs.Arg(1))
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(map[string]any{
			"left": report.Left.Hex(), "right": report.Right.Hex(),
			"paths": report.Paths, "added_objects": report.AddedObjects,
			"added_entries": report.AddedEntries, "merged": report.Head.Hex(),
			"generation": report.Generation,
		})
	}
	fmt.Printf("left=%s\nright=%s\npaths=%d\nadded_objects=%d\nadded_entries=%d\nmerged=%s\ngeneration=%d\n",
		report.Left.Hex(), report.Right.Hex(), report.Paths, report.AddedObjects,
		report.AddedEntries, report.Head.Hex(), report.Generation)
	return nil
}

// ---- snapshots / verify --------------------------------------------------

func cmdSnapshot(args []string, storeDir string, jsonOut bool) error {
	if len(args) == 0 {
		return werr.Newf(werr.InvalidArgument, "snapshot requires create|list")
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("snapshot create", flag.ContinueOnError)
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return werr.Newf(werr.InvalidArgument, "snapshot create requires a name")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		commit, err := s.SnapshotCreate(fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Println(commit.Hex())
		return nil
	case "branch":
		fs := flag.NewFlagSet("snapshot branch", flag.ContinueOnError)
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return werr.Newf(werr.InvalidArgument, "snapshot branch requires <source> <name>")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		commit, err := s.SnapshotBranch(fs.Arg(0), fs.Arg(1))
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{
				"name": fs.Arg(1), "source": fs.Arg(0),
				"snapshot_id": commit.Hex(), "generation": s.Generation(),
			})
		}
		fmt.Println(commit.Hex())
		return nil
	case "list":
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		list := s.SnapshotList()
		if jsonOut {
			out := map[string]string{}
			for _, entry := range list {
				out[entry.Name] = entry.Commit.Hex()
			}
			return printJSON(out)
		}
		for _, entry := range list {
			fmt.Printf("%s\t%s\n", entry.Name, entry.Commit.Hex())
		}
		return nil
	default:
		return werr.Newf(werr.InvalidArgument, "unknown snapshot action `%s`", args[0])
	}
}

func cmdVerify(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	full := fs.Bool("full", false, "hash every chunk and whole content")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	report, err := s.Verify(*full)
	if err != nil {
		return err
	}
	if jsonOut {
		if err := printJSON(report); err != nil {
			return err
		}
	} else {
		fmt.Printf("ok=%v\nfull=%v\ngeneration=%d\n", report.OK, report.Full, report.Generation)
		if report.Commit != nil {
			fmt.Printf("commit=%s\n", report.Commit.Hex())
		}
		fmt.Printf("checked_commits=%d\nchecked_objects=%d\nchecked_manifests=%d\nchecked_chunks=%d\n",
			report.CheckedCommits, report.CheckedObjects, report.CheckedManifests, report.CheckedChunks)
		fmt.Printf("checked_representations=%d\n", report.CheckedRepresentations)
		for _, generation := range report.RejectedGenerations {
			fmt.Printf("rejected_generation=%d\n", generation)
		}
		for _, problem := range report.Problems {
			fmt.Printf("problem=%s: %s\n", problem.Class, problem.Detail)
		}
	}
	if !report.OK {
		return werr.Newf(werr.Corrupt, "verification found %d problem(s)", len(report.Problems))
	}
	return nil
}

// cmdGC runs mark-and-sweep. A dry run is the default; --apply deletes only
// unreachable blobs admitted by the grace gate. Counts are reported in files
// and bytes for reachable, unreachable, and deleted sets.
func cmdGC(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "delete unreachable blobs (default: dry run)")
	dryRun := fs.Bool("dry-run", false, "report candidates without deleting (the default)")
	graceSecs := fs.Uint64("grace-secs", store.DefaultGCGraceSecs, "retain unmarked blobs younger than this many seconds (0 disables)")
	watch := fs.Bool("watch", false, "run periodic background passes until SIGINT/SIGTERM (requires --apply)")
	interval := fs.Duration("interval", time.Duration(store.DefaultGCIntervalSecs)*time.Second, "watch pass interval")
	maxDeletes := fs.Int("max-deletes", int(store.DefaultGCWatchMaxDeletes), "maximum blobs deleted per watch pass (0 = unbounded)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return werr.Newf(werr.InvalidArgument, "gc takes no positional arguments")
	}
	if *dryRun && *apply {
		return werr.Newf(werr.InvalidArgument, "--dry-run and --apply are mutually exclusive")
	}
	if *watch && !*apply {
		return werr.Newf(werr.InvalidArgument, "--watch requires --apply; the collector is disabled by default")
	}
	if *watch && *maxDeletes < 0 {
		return werr.Newf(werr.InvalidArgument, "--max-deletes must be >= 0")
	}
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	options := s.Options()
	options.GCGraceSecs = *graceSecs
	if err := s.SetOptions(options); err != nil {
		return err
	}
	if *watch {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		encoder := json.NewEncoder(os.Stdout)
		return s.GCWatch(ctx, *interval, *maxDeletes, func(report store.GCReport) {
			if jsonOut {
				_ = encoder.Encode(map[string]any{
					"applied":           report.Applied,
					"deleted_files":     report.DeletedFiles,
					"deleted_bytes":     report.DeletedBytes,
					"unreachable_files": report.UnreachableFiles,
					"remaining_files":   report.RemainingFiles,
					"grace_retained":    report.GraceRetained,
					"removed_orphans":   len(report.RemovedOrphans),
					"problems":          len(report.Problems),
				})
				return
			}
			fmt.Printf("pass applied=%v deleted_files=%d deleted_bytes=%d unreachable_files=%d remaining_files=%d grace_retained=%d\n",
				report.Applied, report.DeletedFiles, report.DeletedBytes, report.UnreachableFiles, report.RemainingFiles, report.GraceRetained)
		})
	}
	report, err := s.GC(*apply)
	if err != nil {
		return err
	}
	if jsonOut {
		candidates := report.Candidates
		if candidates == nil {
			candidates = []string{}
		}
		deleted := report.Deleted
		if deleted == nil {
			deleted = []string{}
		}
		removedOrphans := report.RemovedOrphans
		if removedOrphans == nil {
			removedOrphans = []string{}
		}
		problems := report.Problems
		if problems == nil {
			problems = []string{}
		}
		return printJSON(map[string]any{
			"applied":           report.Applied,
			"marked_manifests":  report.MarkedManifests,
			"marked_chunks":     report.MarkedChunks,
			"reachable_files":   report.ReachableFiles,
			"reachable_bytes":   report.ReachableBytes,
			"unreachable_files": report.UnreachableFiles,
			"unreachable_bytes": report.UnreachableBytes,
			"remaining_files":   report.RemainingFiles,
			"remaining_bytes":   report.RemainingBytes,
			"deleted_files":     report.DeletedFiles,
			"deleted_bytes":     report.DeletedBytes,
			"retained":          report.Retained,
			"grace_retained":    report.GraceRetained,
			"removed_orphans":   removedOrphans,
			"candidates":        candidates,
			"deleted":           deleted,
			"problems":          problems,
		})
	}
	fmt.Printf("applied=%v\n", report.Applied)
	fmt.Printf("marked_manifests=%d\n", report.MarkedManifests)
	fmt.Printf("marked_chunks=%d\n", report.MarkedChunks)
	fmt.Printf("reachable_files=%d\n", report.ReachableFiles)
	fmt.Printf("reachable_bytes=%d\n", report.ReachableBytes)
	fmt.Printf("unreachable_files=%d\n", report.UnreachableFiles)
	fmt.Printf("unreachable_bytes=%d\n", report.UnreachableBytes)
	fmt.Printf("remaining_files=%d\n", report.RemainingFiles)
	fmt.Printf("remaining_bytes=%d\n", report.RemainingBytes)
	fmt.Printf("deleted_files=%d\n", report.DeletedFiles)
	fmt.Printf("deleted_bytes=%d\n", report.DeletedBytes)
	fmt.Printf("retained=%d\n", report.Retained)
	fmt.Printf("grace_retained=%d\n", report.GraceRetained)
	for _, id := range report.RemovedOrphans {
		fmt.Printf("removed_orphan=%s\n", id)
	}
	for _, candidate := range report.Candidates {
		fmt.Printf("candidate=%s\n", candidate)
	}
	for _, problem := range report.Problems {
		fmt.Printf("problem=%s\n", problem)
	}
	return nil
}

func cmdCheckpoint(storeDir string) error {
	s, err := openStore(storeDir, store.ReadWrite)
	if err != nil {
		return err
	}
	defer s.Close()
	commit, err := s.Checkpoint()
	if err != nil {
		return err
	}
	fmt.Println(commit.Hex())
	return nil
}

func cmdPin(args []string, storeDir string, jsonOut bool) error {
	fs := flag.NewFlagSet("pin", flag.ContinueOnError)
	snapshot := fs.String("snapshot", "", "snapshot name or commit hex")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "pin requires one path")
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := resolveObject(s, fs.Arg(0))
	if err != nil {
		return err
	}
	var snapshotID *model.Hash32
	if *snapshot != "" {
		commit, err := s.LookupSnapshot(*snapshot)
		if err != nil {
			return err
		}
		snapshotID = &commit
	}
	ref, err := s.Pin(id, snapshotID)
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(map[string]string{
			"namespace": ref.Namespace, "snapshot": ref.Snapshot.Hex(),
			"object_id": ref.ObjectID.Hex(), "version_id": ref.VersionID.Hex(),
			"content_id": ref.ContentID.Hex(),
		})
	}
	fmt.Printf("object_id=%s\nversion_id=%s\ncontent_id=%s\nsnapshot=%s\n",
		ref.ObjectID.Hex(), ref.VersionID.Hex(), ref.ContentID.Hex(), ref.Snapshot.Hex())
	return nil
}

// ---- mount ---------------------------------------------------------------

func cmdMount(args []string, storeDir string) error {
	fs := flag.NewFlagSet("mount", flag.ContinueOnError)
	mountpoint := fs.String("mountpoint", "", "existing directory to mount on")
	snapshot := fs.String("snapshot", "", "mount a named snapshot or commit hex read-only")
	contextName := fs.String("context", "", "mount a Context Root's result set as the read-only root")
	at := fs.String("at", "", "mount the newest commit at or before this time (RFC 3339 or unix ns)")
	readOnly := fs.Bool("read-only", false, "mount the current state read-only")
	allowOther := fs.Bool("allow-other", false, "allow other users")
	debug := fs.Bool("debug", false, "go-fuse debug logging")
	capabilityPath := fs.String("capability", "", "capability JSON or hex file narrowing exact-id and saved-context views")
	gcWatch := fs.Bool("gc-watch", false, "run online background GC on a writable live mount (disabled by default)")
	gcInterval := fs.Duration("gc-interval", time.Duration(store.DefaultGCIntervalSecs)*time.Second, "background GC pass interval")
	gcMaxDeletes := fs.Int("gc-max-deletes", int(store.DefaultGCWatchMaxDeletes), "maximum blobs deleted per background GC pass")
	writeBack := fs.Bool("write-back", false, "buffer each handle's writes and commit at flush/fsync/release (off by default)")
	groupCommit := fs.Bool("group-commit", false, "batch independent mutations within a short window into one durable commit (off by default)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *mountpoint == "" {
		return werr.Newf(werr.InvalidArgument, "--mountpoint is required")
	}
	if *contextName != "" && *at != "" {
		return werr.Newf(werr.InvalidArgument, "--context pins its own snapshot; --at cannot be combined with it")
	}
	if err := requireStore(storeDir); err != nil {
		return err
	}
	var capability *auth.Capability
	if *capabilityPath != "" {
		loaded, err := loadCapabilityFile(*capabilityPath)
		if err != nil {
			return err
		}
		capability = loaded
	}
	mode := store.ReadWrite
	if *readOnly || *snapshot != "" || *contextName != "" || *at != "" || capability != nil {
		mode = store.ReadOnly
	}
	if *gcWatch && mode != store.ReadWrite {
		return werr.Newf(werr.InvalidArgument, "--gc-watch requires a writable live mount (remove --read-only/--snapshot/--context/--at/--capability)")
	}
	if *gcWatch && *gcMaxDeletes <= 0 {
		return werr.Newf(werr.InvalidArgument, "--gc-max-deletes must be >= 1")
	}
	if mode != store.ReadWrite && (*writeBack || *groupCommit) {
		return werr.Newf(werr.InvalidArgument, "--write-back and --group-commit require a writable live mount")
	}
	// The mount default is Merkle identity; an explicit flag always wins and
	// non-mount commands keep whole-file.
	if !contentIdentityExplicit {
		if representationMode == store.RepresentationModeCodecAuto {
			return werr.Newf(werr.InvalidArgument, "--representation codec-auto requires an explicit --content-identity whole-file (a v3 Merkle manifest carries a raw representation only)")
		}
		contentIdentityMode = model.ContentIdentityMerkleV1
	}
	mountOpts := store.DefaultOptions()
	applyRepresentationPolicy(&mountOpts)
	if fixedTimestampNS != nil {
		mountOpts.FixedTimestampNS = fixedTimestampNS
	}
	s, err := store.OpenWithOptions(storeDir, mode, mountOpts)
	if err != nil {
		return err
	}
	defer s.Close()
	if *gcWatch {
		options := s.Options()
		options.GCBackground = true
		options.GCIntervalSecs = uint64(*gcInterval / time.Second)
		options.GCWatchMaxDeletes = uint64(*gcMaxDeletes)
		if err := s.SetOptions(options); err != nil {
			return err
		}
	}
	opts := fusefs.Options{
		Mountpoint: *mountpoint, ReadOnly: *readOnly || capability != nil, AllowOther: *allowOther, Debug: *debug,
		Capability: capability, WriteBack: *writeBack, GroupCommit: *groupCommit,
	}
	switch {
	case *contextName != "":
		resolved, err := s.ResolveContext(*contextName, capability, auth.Root(), limits.Default(), s.ClockNowNS())
		if err != nil {
			return err
		}
		results := make([]model.Hash32, 0, len(resolved.Resolution.Results))
		for _, result := range resolved.Resolution.Results {
			results = append(results, result.ObjectID)
		}
		snapshotID := resolved.Stored.Root.Snapshot
		opts.Snapshot = &snapshotID
		opts.Context = &fusefs.ContextMount{
			Name:          resolved.Stored.Name,
			ContextRootID: resolved.Stored.ContextRootID,
			Snapshot:      snapshotID,
			SelectorID:    resolved.Resolution.SelectorID,
			Results:       results,
		}
	case *at != "":
		atNS, err := parseAtNS(*at)
		if err != nil {
			return err
		}
		base := s.Head()
		if *snapshot != "" {
			base, err = s.LookupSnapshot(*snapshot)
			if err != nil {
				return err
			}
		}
		selected, err := s.CommitAtOrBefore(base, atNS)
		if err != nil {
			return err
		}
		if selected == nil {
			return werr.Newf(werr.NotFound, "no commit at or before %d ns in the mounted lineage", atNS)
		}
		opts.Snapshot = &selected.Commit
	case *snapshot != "":
		commit, err := s.LookupSnapshot(*snapshot)
		if err != nil {
			return err
		}
		opts.Snapshot = &commit
	}
	server, srv, err := fusefs.Mount(s, opts)
	if err != nil {
		return err
	}
	defer srv.StopBackgroundGC()
	defer srv.StopGroupCommit()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		_ = server.Unmount()
	}()
	server.Wait()
	return nil
}

// parseAtNS accepts unix nanoseconds or an RFC 3339 timestamp.
func parseAtNS(text string) (int64, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, werr.Newf(werr.InvalidArgument, "--at must not be empty")
	}
	digits := trimmed
	negative := false
	if strings.HasPrefix(digits, "-") {
		negative = true
		digits = digits[1:]
	}
	if digits != "" && strings.Trim(digits, "0123456789") == "" {
		value, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			return 0, werr.Newf(werr.InvalidArgument, "--at unix nanoseconds are out of range")
		}
		if negative {
			value = -value
		}
		return value, nil
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return 0, werr.Newf(werr.InvalidArgument, "--at must be unix nanoseconds or an RFC 3339 timestamp")
	}
	return parsed.UnixNano(), nil
}

func parseHashList(text string, what string) ([]model.Hash32, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	out := make([]model.Hash32, 0)
	for _, entry := range strings.Split(text, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, werr.Newf(werr.InvalidArgument, "%s contains an empty entry", what)
		}
		hashValue, err := parseHash(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, hashValue)
	}
	return out, nil
}

func parseCausalEntries(text string) ([]model.Hash32, error) {
	return parseHashList(text, "causal entries")
}

func parseHash(text string) (model.Hash32, error) {
	if len(text) != 64 {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "hash must be 64 lowercase hex digits")
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return model.Hash32{}, werr.Newf(werr.InvalidArgument, "hash must be lowercase hexadecimal")
		}
	}
	value, err := hex.DecodeString(text)
	if err != nil || len(value) != 32 {
		return model.Hash32{}, werr.Newf(werr.InvalidArgument, "invalid hash")
	}
	var out model.Hash32
	copy(out[:], value)
	return out, nil
}

func readSelectorSource(spec string) (string, error) {
	if strings.HasPrefix(spec, "@") {
		data, err := os.ReadFile(spec[1:])
		if err != nil {
			return "", werr.Wrap(werr.Io, err, "cannot read selector file %s", spec[1:])
		}
		return string(data), nil
	}
	return spec, nil
}

func loadCapabilityFile(path string) (*auth.Capability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "cannot read capability %s", path)
	}
	scope, err := store.ParseCapabilityText(string(data))
	if err != nil {
		return nil, err
	}
	return auth.NewCapability(scope)
}

func budgetFromFlags(maxResults, maxBytes, maxDepth, maxWork *uint64) (*weftcontext.Budget, error) {
	budget := &weftcontext.Budget{}
	if *maxResults != 0 {
		value := *maxResults
		budget.MaxResults = &value
	}
	if *maxBytes != 0 {
		value := *maxBytes
		budget.MaxBytes = &value
	}
	if *maxDepth != 0 {
		value := *maxDepth
		budget.MaxDepth = &value
	}
	if *maxWork != 0 {
		value := *maxWork
		budget.MaxWork = &value
	}
	if budget.IsEmpty() {
		return nil, nil
	}
	if err := budget.Validate(); err != nil {
		return nil, werr.FromCodec(err)
	}
	return budget, nil
}

func contextJSON(stored store.StoredContextRoot) (map[string]any, error) {
	closure := make([]string, 0, len(stored.Root.Causal))
	for _, item := range stored.Root.Causal {
		closure = append(closure, item.Hex())
	}
	var capability any
	if stored.Root.CapabilityHash != nil {
		capability = stored.Root.CapabilityHash.Hex()
	}
	return map[string]any{
		"name": stored.Name, "context_root_id": stored.ContextRootID.Hex(),
		"uri": stored.URI, "relation_id": stored.RelationID.Hex(),
		"namespace": stored.Root.Namespace, "selector_id": stored.Root.SelectorID.Hex(),
		"selector_canonical_hex": hex.EncodeToString(stored.Root.SelectorBytes),
		"snapshot_id":            stored.Root.Snapshot.Hex(), "resolver": stored.Root.Resolver,
		"ordering": stored.Root.Ordering, "closure": closure,
		"capability_hash": capability, "budget": stored.Root.Budget.JSON(),
		"canonical_hex": stored.RecordHex,
	}, nil
}

func cmdContext(args []string, storeDir string, jsonOut bool) error {
	if len(args) == 0 {
		return werr.Newf(werr.InvalidArgument, "context requires create|branch|list|show|resolve|materialize|uri|delete")
	}
	switch args[0] {
	case "branch":
		fs := flag.NewFlagSet("context branch", flag.ContinueOnError)
		task := fs.String("task", "", "additional attrs.task equality filter")
		modelName := fs.String("model", "", "additional attrs.model equality filter")
		replace := fs.Bool("replace", false, "replace an existing same-name root")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return werr.Newf(werr.InvalidArgument, "context branch requires <source> <name>")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		var taskPtr, modelPtr *string
		if *task != "" {
			taskPtr = task
		}
		if *modelName != "" {
			modelPtr = modelName
		}
		stored, err := s.BranchContextRoot(fs.Arg(0), fs.Arg(1), taskPtr, modelPtr, *replace)
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{
				"name": stored.Name, "context_root_id": stored.ContextRootID.Hex(),
				"uri": stored.URI, "snapshot_id": stored.Root.Snapshot.Hex(),
				"derived_from": fs.Arg(0), "generation": s.Generation(),
			})
		}
		fmt.Printf("context_root_id=%s\nuri=%s\nsnapshot_id=%s\nderived_from=%s\n",
			stored.ContextRootID.Hex(), stored.URI, stored.Root.Snapshot.Hex(), fs.Arg(0))
		return nil
	case "create":
		fs := flag.NewFlagSet("context create", flag.ContinueOnError)
		name := fs.String("name", "", "context root name")
		selectorText := fs.String("selector", "", "selector source text or @file")
		snapshot := fs.String("snapshot", "", "snapshot name or commit hex")
		causal := fs.String("causal", "", "comma-separated causal entries")
		capabilityPath := fs.String("capability", "", "capability JSON or hex file")
		maxResults := fs.Uint64("max-results", 0, "budget max_results")
		maxBytes := fs.Uint64("max-bytes", 0, "budget max_bytes")
		maxDepth := fs.Uint64("max-depth", 0, "budget max_depth")
		maxWork := fs.Uint64("max-work", 0, "budget max_work")
		replace := fs.Bool("replace", false, "replace an existing same-name root")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *name == "" || *selectorText == "" || *snapshot == "" {
			return werr.Newf(werr.InvalidArgument, "context create requires --name, --selector, and --snapshot")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		source, err := readSelectorSource(*selectorText)
		if err != nil {
			return err
		}
		parsed, err := selector.Parse(source)
		if err != nil {
			return werr.FromCodec(err)
		}
		snapshotID, err := s.LookupSnapshot(*snapshot)
		if err != nil {
			return err
		}
		causalIDs, err := parseCausalEntries(*causal)
		if err != nil {
			return err
		}
		if len(causalIDs) != 0 {
			closure, err := store.ComputeCausalClosure(s.CurrentState(), causalIDs, limits.Default())
			if err != nil {
				return err
			}
			causalIDs = closure.Closure
		}
		var capability *auth.Capability
		if *capabilityPath != "" {
			capability, err = loadCapabilityFile(*capabilityPath)
			if err != nil {
				return err
			}
		}
		budget, err := budgetFromFlags(maxResults, maxBytes, maxDepth, maxWork)
		if err != nil {
			return err
		}
		var capabilityHash *model.Hash32
		var capabilityScope *weftcontext.CapabilityScope
		if capability != nil {
			value := capability.Hash
			capabilityHash = &value
			capabilityScope = capability.Scope
		}
		root, err := weftcontext.NewContextRoot(parsed, snapshotID, weftcontext.DefaultResolver, causalIDs, capabilityHash, budget)
		if err != nil {
			return werr.FromCodec(err)
		}
		if _, err := s.SaveContextRoot(*name, root, capabilityScope, *replace); err != nil {
			return err
		}
		stored, err := s.LoadContextRoot(*name)
		if err != nil {
			return err
		}
		if jsonOut {
			output, err := contextJSON(stored)
			if err != nil {
				return err
			}
			output["generation"] = s.Generation()
			return printJSON(output)
		}
		fmt.Printf("context_root_id=%s\nuri=%s\nrelation_id=%s\n",
			stored.ContextRootID.Hex(), stored.URI, stored.RelationID.Hex())
		return nil
	case "list":
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		contexts, err := s.ListContextRoots()
		if err != nil {
			return err
		}
		if jsonOut {
			items := make([]map[string]any, 0, len(contexts))
			for _, stored := range contexts {
				item, err := contextJSON(stored)
				if err != nil {
					return err
				}
				items = append(items, item)
			}
			return printJSON(map[string]any{"contexts": items})
		}
		for _, stored := range contexts {
			fmt.Printf("%s %s %s\n", stored.Name, stored.ContextRootID.Hex(), stored.URI)
		}
		return nil
	case "show":
		if len(args) < 2 {
			return werr.Newf(werr.InvalidArgument, "context show requires a name or URI")
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		stored, err := s.LoadContextRoot(args[1])
		if err != nil {
			return err
		}
		if jsonOut {
			output, err := contextJSON(stored)
			if err != nil {
				return err
			}
			return printJSON(output)
		}
		fmt.Printf("name=%s\ncontext_root_id=%s\nuri=%s\nselector_id=%s\nsnapshot_id=%s\nresolver=%s\nordering=%s\n",
			stored.Name, stored.ContextRootID.Hex(), stored.URI, stored.Root.SelectorID.Hex(),
			stored.Root.Snapshot.Hex(), stored.Root.Resolver, stored.Root.Ordering)
		for _, item := range stored.Root.Causal {
			fmt.Printf("closure=%s\n", item.Hex())
		}
		if stored.Root.CapabilityHash != nil {
			fmt.Printf("capability_hash=%s\n", stored.Root.CapabilityHash.Hex())
		}
		return nil
	case "resolve":
		fs := flag.NewFlagSet("context resolve", flag.ContinueOnError)
		capabilityPath := fs.String("capability", "", "capability JSON or hex file")
		uid := fs.Uint64("uid", uint64(os.Getuid()), "principal uid")
		gid := fs.Uint64("gid", uint64(os.Getgid()), "principal gid")
		groups := fs.String("groups", "", "comma-separated supplementary groups")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return werr.Newf(werr.InvalidArgument, "context resolve requires one name or URI")
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		var capability *auth.Capability
		if *capabilityPath != "" {
			capability, err = loadCapabilityFile(*capabilityPath)
			if err != nil {
				return err
			}
		}
		principal := auth.New(*uid, *gid, parseGroups(*groups))
		resolved, err := s.ResolveContext(fs.Arg(0), capability, principal, limits.Default(), s.ClockNowNS())
		if err != nil {
			return err
		}
		state, err := s.StateAt(resolved.Resolution.SnapshotID)
		if err != nil {
			return err
		}
		results := make([]map[string]any, 0, len(resolved.Resolution.Results))
		for _, result := range resolved.Resolution.Results {
			record, ok := state.Objects[result.ObjectID]
			item := map[string]any{
				"object_id": result.ObjectID.Hex(), "version_id": result.VersionID.Hex(),
				"content_id": result.ContentID.Hex(),
			}
			if ok {
				item["size"] = record.Size
				item["kind"] = string(record.Kind)
				if path, ok := state.PathFor(result.ObjectID); ok {
					item["path"] = string(path)
				}
				closure := make([]string, 0)
				if stored, err := model.ObjectCausalClosure(record); err == nil && stored != nil {
					for _, entry := range stored.Closure {
						closure = append(closure, entry.Hex())
					}
				}
				item["causal_closure"] = closure
			}
			results = append(results, item)
		}
		closure := make([]string, 0, len(resolved.Stored.Root.Causal))
		for _, item := range resolved.Stored.Root.Causal {
			closure = append(closure, item.Hex())
		}
		var capabilityHash any
		if resolved.CapabilityHash != nil {
			capabilityHash = resolved.CapabilityHash.Hex()
		}
		if jsonOut {
			return printJSON(map[string]any{
				"name": resolved.Stored.Name, "uri": resolved.Stored.URI,
				"context_root_id": resolved.Stored.ContextRootID.Hex(),
				"selector_id":     resolved.Resolution.SelectorID.Hex(),
				"snapshot_id":     resolved.Resolution.SnapshotID.Hex(),
				"matched_count":   resolved.Resolution.MatchedCount,
				"returned":        len(resolved.Resolution.Results),
				"truncated":       resolved.Truncated, "closure": closure,
				"capability_hash": capabilityHash,
				"budget":          resolved.EffectiveBudget.JSON(),
				"work_units":      resolved.WorkUnits, "results": results,
			})
		}
		for _, result := range resolved.Resolution.Results {
			fmt.Println(result.ObjectID.Hex())
		}
		fmt.Printf("context_root_id=%s selector_id=%s snapshot_id=%s matched_count=%d returned=%d truncated=%v\n",
			resolved.Stored.ContextRootID.Hex(), resolved.Resolution.SelectorID.Hex(),
			resolved.Resolution.SnapshotID.Hex(), resolved.Resolution.MatchedCount,
			len(resolved.Resolution.Results), resolved.Truncated)
		return nil
	case "materialize":
		fs := flag.NewFlagSet("context materialize", flag.ContinueOnError)
		out := fs.String("out", "", "output directory")
		capabilityPath := fs.String("capability", "", "capability JSON or hex file")
		uid := fs.Uint64("uid", uint64(os.Getuid()), "principal uid")
		gid := fs.Uint64("gid", uint64(os.Getgid()), "principal gid")
		groups := fs.String("groups", "", "comma-separated supplementary groups")
		requireOne := fs.Bool("require-one", false, "fail with Ambiguous unless exactly one object matches")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 || *out == "" {
			return werr.Newf(werr.InvalidArgument, "context materialize requires NAME|URI and --out DIR")
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		var capability *auth.Capability
		if *capabilityPath != "" {
			capability, err = loadCapabilityFile(*capabilityPath)
			if err != nil {
				return err
			}
		}
		principal := auth.New(*uid, *gid, parseGroups(*groups))
		if *requireOne {
			resolved, err := s.ResolveContext(fs.Arg(0), capability, principal, limits.Default(), s.ClockNowNS())
			if err != nil {
				return err
			}
			if resolved.Resolution.MatchedCount != 1 {
				ids := make([]string, 0, len(resolved.Resolution.Results))
				for _, result := range resolved.Resolution.Results {
					ids = append(ids, result.ObjectID.Hex())
				}
				return werr.Newf(werr.Ambiguous,
					"context matched %d authorized objects; require_one needs exactly 1 (object_ids: %s)",
					resolved.Resolution.MatchedCount, strings.Join(ids, ","))
			}
		}
		report, err := s.MaterializeContext(fs.Arg(0), *out, capability, principal, limits.Default(), s.ClockNowNS())
		if err != nil {
			return err
		}
		if jsonOut {
			closure := make([]string, 0, len(report.Closure))
			for _, item := range report.Closure {
				closure = append(closure, item.Hex())
			}
			return printJSON(map[string]any{
				"out": report.Out, "manifest": report.ManifestPath, "files": report.Files,
				"bytes": report.Bytes, "context_root_id": report.ContextRootID.Hex(),
				"snapshot_id": report.SnapshotID.Hex(), "selector_id": report.SelectorID.Hex(),
				"closure": closure,
			})
		}
		fmt.Printf("out=%s\nmanifest=%s\nfiles=%d\nbytes=%d\n", report.Out, report.ManifestPath, report.Files, report.Bytes)
		return nil
	case "uri":
		if len(args) < 2 {
			return werr.Newf(werr.InvalidArgument, "context uri requires a name or URI")
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		stored, err := s.LoadContextRoot(args[1])
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{"uri": stored.URI, "context_root_id": stored.ContextRootID.Hex()})
		}
		fmt.Println(stored.URI)
		return nil
	case "delete":
		if len(args) < 2 {
			return werr.Newf(werr.InvalidArgument, "context delete requires a name")
		}
		s, err := openStore(storeDir, store.ReadWrite)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.DeleteContextRoot(args[1]); err != nil {
			return err
		}
		fmt.Printf("deleted %s\n", args[1])
		return nil
	default:
		return werr.Newf(werr.InvalidArgument, "context requires create|list|show|resolve|materialize|uri|delete")
	}
}

func findObjectByAnyID(s *store.Store, target string) (model.ObjectRecord, error) {
	if hashValue, err := parseHash(target); err == nil {
		if record, err := s.ObjectMeta(hashValue); err == nil {
			return record, nil
		}
		for _, record := range s.CurrentState().Objects {
			if record.Version == hashValue || record.Content == hashValue {
				return record.Clone(), nil
			}
		}
		return model.ObjectRecord{}, werr.Newf(werr.NotFound, "no object has this identity")
	}
	id, err := s.ResolvePath(target)
	if err != nil {
		return model.ObjectRecord{}, err
	}
	return s.ObjectMeta(id)
}

func cmdCausal(args []string, storeDir string, jsonOut bool) error {
	if len(args) == 0 || args[0] != "show" {
		return werr.Newf(werr.InvalidArgument, "causal requires show")
	}
	if len(args) < 2 {
		return werr.Newf(werr.InvalidArgument, "causal show requires an object path or id")
	}
	s, err := openStore(storeDir, store.ReadOnly)
	if err != nil {
		return err
	}
	defer s.Close()
	record, err := findObjectByAnyID(s, args[1])
	if err != nil {
		return err
	}
	closure, err := model.ObjectCausalClosure(record)
	if err != nil {
		return err
	}
	mode := weftcontext.BytesOnly.String()
	if value, ok := record.Attrs[model.AttrIdentityMode]; ok && value.Kind == wcb.Text && value.Str == weftcontext.CausalExact.String() {
		mode = weftcontext.CausalExact.String()
	}
	var causalHash *model.Hash32
	if value, ok := record.Attrs[model.AttrCausalHash]; ok && value.Kind == wcb.Bytes {
		if parsed, err := parseHash(hex.EncodeToString(value.Bytes)); err == nil {
			causalHash = &parsed
		}
	}
	parents := make([]string, 0)
	closureEntries := make([]string, 0)
	if closure != nil {
		for _, item := range closure.Parents {
			parents = append(parents, item.Hex())
		}
		for _, item := range closure.Closure {
			closureEntries = append(closureEntries, item.Hex())
		}
	}
	if jsonOut {
		var hashValue any
		if causalHash != nil {
			hashValue = causalHash.Hex()
		}
		return printJSON(map[string]any{
			"object_id": record.ID.Hex(), "version_id": record.Version.Hex(),
			"identity_mode": mode, "causal_hash": hashValue,
			"parents": parents, "closure": closureEntries,
		})
	}
	fmt.Printf("object_id=%s\nversion_id=%s\nidentity_mode=%s\n", record.ID.Hex(), record.Version.Hex(), mode)
	if causalHash != nil {
		fmt.Printf("causal_hash=%s\n", causalHash.Hex())
	}
	for _, item := range parents {
		fmt.Printf("parent=%s\n", item)
	}
	for _, item := range closureEntries {
		fmt.Printf("closure=%s\n", item)
	}
	return nil
}

func cmdURI(args []string, storeDir string, jsonOut bool) error {
	if len(args) == 0 {
		return werr.Newf(werr.InvalidArgument, "uri requires canonicalize|show")
	}
	switch args[0] {
	case "canonicalize":
		if len(args) < 2 {
			return werr.Newf(werr.InvalidArgument, "uri canonicalize requires a URI")
		}
		parsed, err := weftcontext.ParseContextURI(args[1], limits.Default())
		if err != nil {
			return werr.FromCodec(err)
		}
		canonical, err := parsed.CanonicalURI(limits.Default())
		if err != nil {
			return werr.FromCodec(err)
		}
		if jsonOut {
			output := map[string]any{"uri": canonical, "form": parsed.Form}
			if parsed.Form == weftcontext.FormDescriptor {
				root, err := parsed.ToContextRoot(limits.Default())
				if err != nil {
					return werr.FromCodec(err)
				}
				id, err := root.ID()
				if err != nil {
					return werr.FromCodec(err)
				}
				output["context_root_id"] = id.Hex()
			}
			return printJSON(output)
		}
		fmt.Println(canonical)
		return nil
	case "show":
		if len(args) < 2 {
			return werr.Newf(werr.InvalidArgument, "uri show requires a name or URI")
		}
		s, err := openStore(storeDir, store.ReadOnly)
		if err != nil {
			return err
		}
		defer s.Close()
		stored, err := s.LoadContextRoot(args[1])
		if err != nil {
			return err
		}
		if jsonOut {
			return printJSON(map[string]any{"uri": stored.URI, "context_root_id": stored.ContextRootID.Hex(), "name": stored.Name})
		}
		fmt.Println(stored.URI)
		return nil
	default:
		return werr.Newf(werr.InvalidArgument, "uri requires canonicalize|show")
	}
}
