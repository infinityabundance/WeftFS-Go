package fusefs

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/infinityabundance/WeftFS-Go/model"
)

// escapeComponent percent-encodes a raw name component so it is printable,
// contains no `/` or NUL, and is never `.`/`..`. The result is deterministic
// and byte-reversible.
func escapeComponent(bytesValue []byte) []byte {
	out := make([]byte, 0, len(bytesValue))
	for _, b := range bytesValue {
		switch {
		case b == '%':
			out = append(out, []byte("%25")...)
		case b == '/':
			out = append(out, []byte("%2F")...)
		case b >= 0x20 && b <= 0x7e:
			out = append(out, b)
		default:
			out = append(out, []byte(fmt.Sprintf("%%%02X", b))...)
		}
	}
	if len(out) == 0 {
		out = append(out, []byte("object")...)
	}
	if bytes.Equal(out, []byte(".")) || bytes.Equal(out, []byte("..")) {
		out = []byte("%2E")
	}
	return out
}

// contextEntryNames produces deterministic display names for a context result
// set: the escaped basename of the object's first path, then
// `--<8+ hex prefix of the ObjectId>`. Prefixes are extended in 8-character
// steps if two results would collide, so no result is silently dropped.
func contextEntryNames(ids []model.Hash32, state *model.State) []struct {
	Name []byte
	ID   model.Hash32
} {
	type ordered struct {
		id   model.Hash32
		base []byte
	}
	items := make([]ordered, 0, len(ids))
	for _, id := range ids {
		base := []byte("object")
		if path, ok := state.PathFor(id); ok {
			parts := bytes.Split(path, []byte{'/'})
			if len(parts) > 0 && len(parts[len(parts)-1]) > 0 {
				base = append([]byte(nil), parts[len(parts)-1]...)
			}
		}
		items = append(items, ordered{id: id, base: escapeComponent(base)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].id.Less(items[j].id) })

	used := make(map[string]bool, len(items))
	out := make([]struct {
		Name []byte
		ID   model.Hash32
	}, 0, len(items))
	for _, item := range items {
		hex := item.id.Hex()
		prefix := 8
		var name []byte
		for {
			if prefix > len(hex) {
				prefix = len(hex)
			}
			suffix := "--" + hex[:prefix]
			maxBase := 255 - len(suffix)
			if maxBase < 0 {
				maxBase = 0
			}
			candidate := append([]byte(nil), item.base...)
			if len(candidate) > maxBase {
				candidate = candidate[:maxBase]
			}
			candidate = append(candidate, []byte(suffix)...)
			if !used[string(candidate)] || prefix >= 64 {
				name = candidate
				break
			}
			prefix += 8
			if prefix > 64 {
				prefix = 64
			}
		}
		used[string(name)] = true
		out = append(out, struct {
			Name []byte
			ID   model.Hash32
		}{Name: name, ID: item.id})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].Name, out[j].Name) < 0 })
	return out
}
