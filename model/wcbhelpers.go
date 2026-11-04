package model

import (
	"sort"

	"github.com/infinityabundance/WeftCodec-Go/limits"
	"github.com/infinityabundance/WeftCodec-Go/wcb"
	"github.com/infinityabundance/WeftFS-Go/werr"
)

// EncodeWCB encodes a value with normative default limits.
func EncodeWCB(v wcb.Value) ([]byte, error) {
	b, err := wcb.Encode(v, limits.Default())
	if err != nil {
		return nil, werr.FromCodec(err)
	}
	return b, nil
}

// DecodeWCB decodes canonical WCB with normative default limits.
func DecodeWCB(b []byte) (wcb.Value, error) {
	v, err := wcb.Decode(b, limits.Default())
	if err != nil {
		return wcb.Value{}, werr.FromCodec(err)
	}
	return v, nil
}

// HashValue is the bytes32 WCB form of an identity.
func HashValue(h Hash32) wcb.Value { return wcb.BytesValue(h.Bytes()) }

// OptHashValue is a nullable bytes32.
func OptHashValue(h *Hash32) wcb.Value {
	if h == nil {
		return wcb.NullValue()
	}
	return HashValue(*h)
}

// Map builds a WCB map; the encoder sorts keys canonically.
func Map(pairs map[string]wcb.Value) wcb.Value { return wcb.MapValue(pairs) }

// CloneValue deep-copies a WCB value so state snapshots never alias.
func CloneValue(v wcb.Value) wcb.Value {
	switch v.Kind {
	case wcb.Bytes:
		return wcb.BytesValue(append([]byte(nil), v.Bytes...))
	case wcb.Array:
		items := make([]wcb.Value, len(v.Array))
		for i := range v.Array {
			items[i] = CloneValue(v.Array[i])
		}
		return wcb.ArrayValue(items)
	case wcb.Map:
		m := make(map[string]wcb.Value, len(v.Map))
		for k, inner := range v.Map {
			m[k] = CloneValue(inner)
		}
		return wcb.MapValue(m)
	default:
		return v
	}
}

// CloneAttrs deep-copies an attribute map.
func CloneAttrs(attrs map[string]wcb.Value) map[string]wcb.Value {
	out := make(map[string]wcb.Value, len(attrs))
	for k, v := range attrs {
		out[k] = CloneValue(v)
	}
	return out
}

// AsMap requires a WCB map.
func AsMap(v wcb.Value) (map[string]wcb.Value, error) {
	if v.Kind != wcb.Map {
		return nil, werr.Newf(werr.Malformed, "expected a WCB map")
	}
	return v.Map, nil
}

// CheckKeys rejects maps with keys outside allowed.
func CheckKeys(m map[string]wcb.Value, allowed ...string) error {
	for key := range m {
		found := false
		for _, want := range allowed {
			if key == want {
				found = true
				break
			}
		}
		if !found {
			return werr.Newf(werr.Malformed, "unexpected map key `%s`", key)
		}
	}
	return nil
}

// Field requires a field.
func Field(m map[string]wcb.Value, key string) (wcb.Value, error) {
	v, ok := m[key]
	if !ok {
		return wcb.Value{}, werr.Newf(werr.Malformed, "missing map key `%s`", key)
	}
	return v, nil
}

// GetText requires a text field.
func GetText(m map[string]wcb.Value, key string) (string, error) {
	v, err := Field(m, key)
	if err != nil {
		return "", err
	}
	if v.Kind != wcb.Text {
		return "", werr.Newf(werr.Malformed, "key `%s` must be text", key)
	}
	return v.Str, nil
}

// GetU64 requires a u64 field.
func GetU64(m map[string]wcb.Value, key string) (uint64, error) {
	v, err := Field(m, key)
	if err != nil {
		return 0, err
	}
	if v.Kind != wcb.U64 {
		return 0, werr.Newf(werr.Malformed, "key `%s` must be u64", key)
	}
	return v.U, nil
}

// GetTimestamp requires a timestamp field.
func GetTimestamp(m map[string]wcb.Value, key string) (int64, error) {
	v, err := Field(m, key)
	if err != nil {
		return 0, err
	}
	if v.Kind != wcb.Timestamp {
		return 0, werr.Newf(werr.Malformed, "key `%s` must be a timestamp", key)
	}
	return v.I, nil
}

// GetBytes requires a bytes field.
func GetBytes(m map[string]wcb.Value, key string) ([]byte, error) {
	v, err := Field(m, key)
	if err != nil {
		return nil, err
	}
	if v.Kind != wcb.Bytes {
		return nil, werr.Newf(werr.Malformed, "key `%s` must be bytes", key)
	}
	return v.Bytes, nil
}

// GetHash requires exactly 32 bytes.
func GetHash(m map[string]wcb.Value, key string) (Hash32, error) {
	b, err := GetBytes(m, key)
	if err != nil {
		return Hash32{}, err
	}
	h, err := hashFromSlice(b)
	if err != nil {
		return Hash32{}, werr.Newf(werr.Malformed, "key `%s` must be exactly 32 bytes", key)
	}
	return h, nil
}

func hashFromSlice(b []byte) (Hash32, error) {
	var h Hash32
	if len(b) != 32 {
		return h, werr.Newf(werr.Malformed, "hash must be 32 bytes, got %d", len(b))
	}
	copy(h[:], b)
	return h, nil
}

// GetOptHash requires a nullable bytes32.
func GetOptHash(m map[string]wcb.Value, key string) (*Hash32, error) {
	v, err := Field(m, key)
	if err != nil {
		return nil, err
	}
	switch v.Kind {
	case wcb.Null:
		return nil, nil
	case wcb.Bytes:
		h, err := hashFromSlice(v.Bytes)
		if err != nil {
			return nil, werr.Newf(werr.Malformed, "key `%s` must be bytes32 or null", key)
		}
		return &h, nil
	default:
		return nil, werr.Newf(werr.Malformed, "key `%s` must be bytes32 or null", key)
	}
}

// GetMap requires a map field (returned as a deep copy).
func GetMap(m map[string]wcb.Value, key string) (map[string]wcb.Value, error) {
	v, err := Field(m, key)
	if err != nil {
		return nil, err
	}
	inner, err := AsMap(v)
	if err != nil {
		return nil, werr.Newf(werr.Malformed, "key `%s` must be a map", key)
	}
	out := make(map[string]wcb.Value, len(inner))
	for k, val := range inner {
		out[k] = CloneValue(val)
	}
	return out, nil
}

// GetOptMap requires a map-or-null field.
func GetOptMap(m map[string]wcb.Value, key string) (map[string]wcb.Value, error) {
	v, err := Field(m, key)
	if err != nil {
		return nil, err
	}
	switch v.Kind {
	case wcb.Null:
		return nil, nil
	case wcb.Map:
		out := make(map[string]wcb.Value, len(v.Map))
		for k, val := range v.Map {
			out[k] = CloneValue(val)
		}
		return out, nil
	default:
		return nil, werr.Newf(werr.Malformed, "key `%s` must be a map or null", key)
	}
}

// GetArray requires an array field.
func GetArray(m map[string]wcb.Value, key string) ([]wcb.Value, error) {
	v, err := Field(m, key)
	if err != nil {
		return nil, err
	}
	if v.Kind != wcb.Array {
		return nil, werr.Newf(werr.Malformed, "key `%s` must be an array", key)
	}
	return v.Array, nil
}

// ValidateScalar requires a scalar relation target.
func ValidateScalar(v wcb.Value) error {
	switch v.Kind {
	case wcb.Null, wcb.Bool, wcb.U64, wcb.I64, wcb.Timestamp, wcb.Text:
		return nil
	default:
		return werr.Newf(werr.Malformed, "relation value target must be a WCB scalar")
	}
}

// SortHashKeys returns map keys sorted by unsigned byte order.
func SortHashKeys[V any](m map[Hash32]V) []Hash32 {
	keys := make([]Hash32, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
	return keys
}
