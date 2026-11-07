// Host decode-cost calibration (`weft.calibration.v1`).
//
// Go accepts the document Rust writes with `weftfs calibrate` and applies it
// with `--calibration`. Validation is exact and has no fallback:
//
//   - the document is at most 1 MiB, exactly the six schema keys, and the
//     digest over the compact key-sorted document (digest removed) must match;
//   - `host` carries exactly ten declared fields, `method` exactly five with
//     the documented affine fit text;
//   - `rows` carries exactly ten rows in `CostClassAll` order, each with
//     exactly five keys and no duplicates;
//   - measured rows need at least five samples, reused/declared rows record
//     zero samples, fixed_ns and ns_per_mib are bounded, and every class must
//     price 64 MiB above 1 MiB;
//   - `--calibration` is only legal with `--planner-cost-model measured`.
//
// A rejected document refuses the command; it is never replaced by the baked
// table.
package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/infinityabundance/WeftCodec-Go/hash"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Calibration document constants. They equal src/calibration.rs.
const (
	CalibrationSchema             = "weft.calibration.v1"
	CalibrationDomain             = "weft/decode-calibration/v1"
	MaxCalibrationBytes    uint64 = 1 << 20
	MinCalibrationSamples  uint64 = 5
	MaxCalibrationFixedNS  uint64 = 60_000_000_000
	MaxCalibrationNSperMiB uint64 = 100_000_000_000
	calibrationFitText            = "fixed_ns + ns_per_mib * decoded_bytes / 1048576; fit from the small and large medians; delta rows subtract the measured base read"
)

const mib = uint64(1_048_576)

// RowOrigin records how a calibration row was obtained.
type RowOrigin string

const (
	OriginMeasured RowOrigin = "measured"
	OriginReused   RowOrigin = "reused"
	OriginDeclared RowOrigin = "declared"
)

// CalibrationRow is one validated row.
type CalibrationRow struct {
	Class    CostClass
	FixedNS  uint64
	NSperMiB uint64
	Samples  uint64
	Origin   RowOrigin
}

// HostIdentity is recorded with a calibration for the receipt.
type HostIdentity struct {
	Hostname          string `json:"hostname"`
	Kernel            string `json:"kernel"`
	Arch              string `json:"arch"`
	CPUs              uint64 `json:"cpus"`
	Image             string `json:"image"`
	ImageID           string `json:"image_id"`
	MemoryLimit       string `json:"memory_limit"`
	PidsLimit         string `json:"pids_limit"`
	WeftFSRevision    string `json:"weftfs_revision"`
	WeftCodecRevision string `json:"weftcodec_revision"`
}

// CalibrationMethod records the measurement method.
type CalibrationMethod struct {
	Reps        uint64
	WarmupReads uint64
	SmallBytes  uint64
	LargeBytes  uint64
}

// Calibration is a validated, complete host calibration.
type Calibration struct {
	ID            string
	CreatedUnixNS uint64
	Host          HostIdentity
	Method        CalibrationMethod
	rows          [10]CalibrationRow
	table         *CostTable
	document      map[string]any
}

// Rows returns the ten rows in canonical order.
func (c *Calibration) Rows() [10]CalibrationRow { return c.rows }

// Table returns the validated affine table used for pricing.
func (c *Calibration) Table() *CostTable { return c.table }

// Document returns a deep copy of the validated in-memory document (including
// `digest`). Copying prevents a caller from mutating the record the digest was
// computed over.
func (c *Calibration) Document() map[string]any {
	data, err := json.Marshal(c.document)
	if err != nil {
		return c.document
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var clone map[string]any
	if err := decoder.Decode(&clone); err != nil {
		return c.document
	}
	return clone
}

// WriteFile writes the document as indented JSON. The digest is over the
// compact key-sorted form, so indentation cannot change it.
func (c *Calibration) WriteFile(path string) error {
	data, err := json.MarshalIndent(c.document, "", "  ")
	if err != nil {
		return calibrationError("cannot serialise calibration: %s", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return werr.Wrap(werr.Io, err, "calibration `%s`", path)
	}
	return nil
}

// Install atomically writes the validated document into
// `<store>/calibrations/<id>.json`, matching Rust
// `Calibration::install`. The directory is advisory: it is not part of the
// frozen format and is ignored by replay, verify, and GC. Re-installing the
// same document is idempotent because the file name is the content digest.
func (c *Calibration) Install(storeDir string) (string, error) {
	directory := filepath.Join(storeDir, "calibrations")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return "", werr.Wrap(werr.Io, err, "cannot create calibration directory `%s`", directory)
	}
	path := filepath.Join(directory, c.ID+".json")
	tmp := filepath.Join(directory, "."+c.ID+"."+strconv.Itoa(os.Getpid())+".tmp")
	data, err := json.MarshalIndent(c.document, "", "  ")
	if err != nil {
		return "", calibrationError("cannot serialise calibration: %s", err)
	}
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return "", werr.Wrap(werr.Io, err, "calibration `%s`", tmp)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return "", werr.Wrap(werr.Io, err, "calibration `%s`", tmp)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(tmp)
		return "", werr.Wrap(werr.Io, err, "calibration `%s`", tmp)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", werr.Wrap(werr.Io, err, "calibration `%s`", tmp)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", werr.Wrap(werr.Io, err, "calibration `%s`", path)
	}
	if dir, err := os.Open(directory); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return path, nil
}

// Row returns one class's row.
func (c *Calibration) Row(class CostClass) CalibrationRow { return c.rows[class.Index()] }

// EstimateNS prices `decodedBytes` under this calibration.
func (c *Calibration) EstimateNS(class CostClass, decodedBytes uint64) uint64 {
	return c.table.EstimateNS(class, decodedBytes)
}

func calibrationError(format string, args ...any) error {
	return werr.Newf(werr.InvalidArgument, "calibration: "+format, args...)
}

// LoadCalibration reads and validates a calibration file.
func LoadCalibration(path string) (*Calibration, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "calibration `%s`", path)
	}
	if uint64(info.Size()) > MaxCalibrationBytes {
		return nil, calibrationError("`%s` is %d bytes, above the %d-byte bound",
			path, info.Size(), MaxCalibrationBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, werr.Wrap(werr.Io, err, "calibration `%s`", path)
	}
	if uint64(len(data)) > MaxCalibrationBytes {
		return nil, calibrationError("`%s` grew past the %d-byte bound while reading",
			path, MaxCalibrationBytes)
	}
	document, err := decodeCalibrationJSON(data)
	if err != nil {
		return nil, calibrationError("`%s` is not valid JSON: %s", path, err)
	}
	return CalibrationFromDocument(document)
}

func decodeCalibrationJSON(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, fmt.Errorf("trailing data after the document")
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("document must be a JSON object")
	}
	return object, nil
}

// CalibrationFromDocument validates an already-decoded document.
func CalibrationFromDocument(document map[string]any) (*Calibration, error) {
	if err := exactKeys(document, "calibration",
		"schema", "created_unix_ns", "host", "method", "rows", "digest"); err != nil {
		return nil, err
	}
	schema, err := stringField(document, "schema", "calibration")
	if err != nil {
		return nil, err
	}
	if schema != CalibrationSchema {
		return nil, calibrationError("schema is `%s`, expected `%s`", schema, CalibrationSchema)
	}
	created, err := u64Field(document, "created_unix_ns", "calibration")
	if err != nil {
		return nil, err
	}
	if created == 0 {
		return nil, calibrationError("created_unix_ns must be greater than zero")
	}
	hostValue, ok := document["host"].(map[string]any)
	if !ok {
		return nil, calibrationError("host must be a JSON object")
	}
	host, err := hostFromJSON(hostValue)
	if err != nil {
		return nil, err
	}
	methodValue, ok := document["method"].(map[string]any)
	if !ok {
		return nil, calibrationError("method must be a JSON object")
	}
	method, err := methodFromJSON(methodValue)
	if err != nil {
		return nil, err
	}
	rowsValue, ok := document["rows"].([]any)
	if !ok {
		return nil, calibrationError("rows must be an array")
	}
	if len(rowsValue) != len(CostClassAll) {
		return nil, calibrationError("rows has %d entries, expected exactly %d (one per class)",
			len(rowsValue), len(CostClassAll))
	}
	var rows [10]CalibrationRow
	var seen [10]bool
	for _, entry := range rowsValue {
		object, ok := entry.(map[string]any)
		if !ok {
			return nil, calibrationError("row must be a JSON object")
		}
		row, err := rowFromJSON(object)
		if err != nil {
			return nil, err
		}
		index := row.Class.Index()
		if seen[index] {
			return nil, calibrationError("duplicate row for class `%s`", row.Class)
		}
		seen[index] = true
		rows[index] = row
	}
	for index, present := range seen {
		if !present {
			return nil, calibrationError("missing row for class `%s`", CostClassAll[index])
		}
	}
	digestText, err := stringField(document, "digest", "calibration")
	if err != nil {
		return nil, err
	}
	digest, err := hash.FromHex(digestText)
	if err != nil {
		return nil, calibrationError("digest is not 64 hex characters: %s", err)
	}
	withoutDigest := make(map[string]any, len(document)-1)
	for key, value := range document {
		if key == "digest" {
			continue
		}
		withoutDigest[key] = value
	}
	computed, err := calibrationDigest(withoutDigest)
	if err != nil {
		return nil, err
	}
	if computed != digest {
		return nil, calibrationError("digest mismatch: file says %s, document hashes to %s",
			digest.Hex(), computed.Hex())
	}
	table, err := buildCalibrationTable(rows)
	if err != nil {
		return nil, err
	}
	return &Calibration{
		ID: digest.Hex(), CreatedUnixNS: created, Host: host, Method: method,
		rows: rows, table: table, document: document,
	}, nil
}

func hostFromJSON(object map[string]any) (HostIdentity, error) {
	if err := exactKeys(object, "host",
		"hostname", "kernel", "arch", "cpus", "image", "image_id",
		"memory_limit", "pids_limit", "weftfs_revision", "weftcodec_revision"); err != nil {
		return HostIdentity{}, err
	}
	readString := func(key string) (string, error) { return stringField(object, key, "host") }
	var host HostIdentity
	var err error
	if host.Hostname, err = readString("hostname"); err != nil {
		return HostIdentity{}, err
	}
	if host.Kernel, err = readString("kernel"); err != nil {
		return HostIdentity{}, err
	}
	if host.Arch, err = readString("arch"); err != nil {
		return HostIdentity{}, err
	}
	if host.CPUs, err = u64Field(object, "cpus", "host"); err != nil {
		return HostIdentity{}, err
	}
	if host.Image, err = readString("image"); err != nil {
		return HostIdentity{}, err
	}
	if host.ImageID, err = readString("image_id"); err != nil {
		return HostIdentity{}, err
	}
	if host.MemoryLimit, err = readString("memory_limit"); err != nil {
		return HostIdentity{}, err
	}
	if host.PidsLimit, err = readString("pids_limit"); err != nil {
		return HostIdentity{}, err
	}
	if host.WeftFSRevision, err = readString("weftfs_revision"); err != nil {
		return HostIdentity{}, err
	}
	if host.WeftCodecRevision, err = readString("weftcodec_revision"); err != nil {
		return HostIdentity{}, err
	}
	return host, nil
}

func methodFromJSON(object map[string]any) (CalibrationMethod, error) {
	if err := exactKeys(object, "method", "reps", "warmup_reads", "small_bytes", "large_bytes", "fit"); err != nil {
		return CalibrationMethod{}, err
	}
	fit, err := stringField(object, "fit", "method")
	if err != nil {
		return CalibrationMethod{}, err
	}
	if fit != calibrationFitText {
		return CalibrationMethod{}, calibrationError("method.fit is not the documented affine fit")
	}
	method := CalibrationMethod{}
	if method.Reps, err = u64Field(object, "reps", "method"); err != nil {
		return CalibrationMethod{}, err
	}
	if method.WarmupReads, err = u64Field(object, "warmup_reads", "method"); err != nil {
		return CalibrationMethod{}, err
	}
	if method.SmallBytes, err = u64Field(object, "small_bytes", "method"); err != nil {
		return CalibrationMethod{}, err
	}
	if method.LargeBytes, err = u64Field(object, "large_bytes", "method"); err != nil {
		return CalibrationMethod{}, err
	}
	if method.Reps < MinCalibrationSamples {
		return CalibrationMethod{}, calibrationError(
			"method.reps is %d but at least %d repetitions are required", method.Reps, MinCalibrationSamples)
	}
	if method.WarmupReads < 1 {
		return CalibrationMethod{}, calibrationError("method.warmup_reads must be at least 1")
	}
	if method.SmallBytes < 64*1024 {
		return CalibrationMethod{}, calibrationError("method.small_bytes must be at least 64 KiB")
	}
	if method.LargeBytes < 8*mib {
		return CalibrationMethod{}, calibrationError("method.large_bytes must be at least 8 MiB")
	}
	if method.SmallBytes >= method.LargeBytes {
		return CalibrationMethod{}, calibrationError("method.small_bytes must be smaller than method.large_bytes")
	}
	return method, nil
}

func rowFromJSON(object map[string]any) (CalibrationRow, error) {
	if err := exactKeys(object, "row", "class", "fixed_ns", "ns_per_mib", "samples", "origin"); err != nil {
		return CalibrationRow{}, err
	}
	name, err := stringField(object, "class", "row")
	if err != nil {
		return CalibrationRow{}, err
	}
	class, ok := ParseCostClass(name)
	if !ok {
		return CalibrationRow{}, calibrationError("unknown cost class `%s`", name)
	}
	originText, err := stringField(object, "origin", "row")
	if err != nil {
		return CalibrationRow{}, err
	}
	var origin RowOrigin
	switch RowOrigin(originText) {
	case OriginMeasured, OriginReused, OriginDeclared:
		origin = RowOrigin(originText)
	default:
		return CalibrationRow{}, calibrationError("unknown row origin `%s`", originText)
	}
	row := CalibrationRow{Class: class, Origin: origin}
	if row.FixedNS, err = u64Field(object, "fixed_ns", "row"); err != nil {
		return CalibrationRow{}, err
	}
	if row.NSperMiB, err = u64Field(object, "ns_per_mib", "row"); err != nil {
		return CalibrationRow{}, err
	}
	if row.Samples, err = u64Field(object, "samples", "row"); err != nil {
		return CalibrationRow{}, err
	}
	if err := validateCalibrationRow(row); err != nil {
		return CalibrationRow{}, err
	}
	return row, nil
}

func validateCalibrationRow(row CalibrationRow) error {
	name := string(row.Class)
	if row.FixedNS > MaxCalibrationFixedNS {
		return calibrationError("`%s` fixed_ns %d exceeds the %d ns bound", name, row.FixedNS, MaxCalibrationFixedNS)
	}
	if row.NSperMiB == 0 {
		return calibrationError("`%s` ns_per_mib must be greater than zero", name)
	}
	if row.NSperMiB > MaxCalibrationNSperMiB {
		return calibrationError("`%s` ns_per_mib %d exceeds the %d ns/MiB bound", name, row.NSperMiB, MaxCalibrationNSperMiB)
	}
	switch row.Origin {
	case OriginMeasured:
		if row.Samples < MinCalibrationSamples {
			return calibrationError("`%s` is measured but has %d samples, below %d", name, row.Samples, MinCalibrationSamples)
		}
	case OriginReused, OriginDeclared:
		if row.Samples != 0 {
			return calibrationError("`%s` is %s but records %d samples; only measured rows carry samples",
				name, row.Origin, row.Samples)
		}
	}
	return nil
}

func buildCalibrationTable(rows [10]CalibrationRow) (*CostTable, error) {
	var coefficients [10]Coefficients
	for index, row := range rows {
		coefficients[index] = Coefficients{FixedNS: row.FixedNS, NSperMiB: row.NSperMiB}
	}
	table := NewCostTable(coefficients)
	for _, class := range CostClassAll {
		small := table.EstimateNS(class, mib)
		large := table.EstimateNS(class, 64*mib)
		if large <= small {
			return nil, calibrationError("`%s` is not monotonic: %d ns at 1 MiB, %d ns at 64 MiB",
				class, small, large)
		}
	}
	return table, nil
}

func exactKeys(object map[string]any, context string, keys ...string) error {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowed[key]; !ok {
			return calibrationError("%s has unknown key `%s` (expected %v)", context, key, sortedKeys(allowed))
		}
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return calibrationError("%s is missing key `%s`", context, key)
		}
	}
	return nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func stringField(object map[string]any, key, context string) (string, error) {
	value, ok := object[key].(string)
	if !ok {
		return "", calibrationError("%s.%s must be a string", context, key)
	}
	return value, nil
}

func u64Field(object map[string]any, key, context string) (uint64, error) {
	number, ok := object[key].(json.Number)
	if !ok {
		return 0, calibrationError("%s.%s must be an unsigned integer", context, key)
	}
	parsed, parseErr := parseU64Exact(number.String())
	if parseErr != nil {
		return 0, calibrationError("%s.%s must be an unsigned integer", context, key)
	}
	return parsed, nil
}

func parseU64Exact(text string) (uint64, error) {
	if text == "" {
		return 0, fmt.Errorf("empty")
	}
	var value uint64
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a decimal integer")
		}
		next := value*10 + uint64(c-'0')
		if next < value {
			return 0, fmt.Errorf("overflow")
		}
		value = next
	}
	return value, nil
}

// calibrationDigest hashes the compact, key-sorted document exactly as
// serde_json writes it in Rust (BTreeMap ordering, no spaces, no HTML escaping).
func calibrationDigest(document map[string]any) (hash.Hash32, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return hash.Hash32{}, calibrationError("cannot serialise calibration: %s", err)
	}
	data := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	return hash.Domain(CalibrationDomain, data), nil
}
