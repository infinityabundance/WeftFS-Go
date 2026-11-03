// Command weftfs is the WeftFS-Go store and FUSE CLI. Every command opens the
// store explicitly; mutations take the exclusive writer lock. Errors are
// printed as `Class: message` and exit nonzero. No command invokes Rust.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/selector"
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
	fmt.Fprint(os.Stderr, `usage: weftfs [--store DIR] [--json] <command> [args]

commands:
  init info create write cat ls stat mkdir unlink rmdir rename link symlink
  readlink setattr xattr relation query snapshot verify gc checkpoint pin mount
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

// globals extracts --store and --json wherever they appear, leaving the
// subcommand and its flags in source order.
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
	if fixedTimestampNS == nil {
		return store.Open(storeDir, mode)
	}
	opts := store.DefaultOptions()
	opts.FixedTimestampNS = fixedTimestampNS
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
			"rejected_generations": s.RejectedGenerations(),
			"recovery_notes":       s.RecoveryNotes(),
		})
	}
	fmt.Printf("format=weftfs-store 1\ngeneration=%d\nsnapshot_root=%s\n", s.Generation(), s.Head().Hex())
	fmt.Printf("objects=%d\nentries=%d\nrelations=%d\nsnapshots=%d\n",
		len(state.Objects), len(state.Entries), len(state.Relations), len(state.Snapshots))
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
	if *seed != "" {
		id, err = s.CreateFileSeeded(parent, name, data, perm, *uid, *gid, nil, []byte(*seed))
	} else {
		id, err = s.CreateFile(parent, name, data, perm, *uid, *gid, nil)
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
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return werr.Newf(werr.InvalidArgument, "write requires exactly one path")
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
	var data []byte
	if *file != "" {
		data, err = os.ReadFile(*file)
		if err != nil {
			return werr.Wrap(werr.Io, err, "cannot read %s", *file)
		}
	} else {
		data = []byte(*text)
	}
	version, err := s.WriteFile(id, *offset, data)
	if err != nil {
		return err
	}
	fmt.Println(version.Hex())
	return nil
}

func cmdCat(args []string, storeDir string) error {
	fs := flag.NewFlagSet("cat", flag.ContinueOnError)
	offset := fs.Uint64("offset", 0, "byte offset")
	length := fs.Uint64("len", 0, "byte length (0 means to EOF)")
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
	if *length == 0 {
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
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return werr.Newf(werr.InvalidArgument, "gc takes no positional arguments")
	}
	if *dryRun && *apply {
		return werr.Newf(werr.InvalidArgument, "--dry-run and --apply are mutually exclusive")
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
	readOnly := fs.Bool("read-only", false, "mount the current state read-only")
	allowOther := fs.Bool("allow-other", false, "allow other users")
	debug := fs.Bool("debug", false, "go-fuse debug logging")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *mountpoint == "" {
		return werr.Newf(werr.InvalidArgument, "--mountpoint is required")
	}
	if err := requireStore(storeDir); err != nil {
		return err
	}
	mode := store.ReadWrite
	if *readOnly || *snapshot != "" {
		mode = store.ReadOnly
	}
	s, err := store.Open(storeDir, mode)
	if err != nil {
		return err
	}
	defer s.Close()
	opts := fusefs.Options{
		Mountpoint: *mountpoint, ReadOnly: *readOnly, AllowOther: *allowOther, Debug: *debug,
	}
	if *snapshot != "" {
		commit, err := s.LookupSnapshot(*snapshot)
		if err != nil {
			return err
		}
		opts.Snapshot = &commit
	}
	server, _, err := fusefs.Mount(s, opts)
	if err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		_ = server.Unmount()
	}()
	server.Wait()
	return nil
}
