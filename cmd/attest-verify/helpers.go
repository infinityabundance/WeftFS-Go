package main

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/infinityabundance/WeftCodec-Go/wcb"
)

func mapOf(value wcb.Value) (map[string]wcb.Value, bool) {
	if value.Kind != wcb.Map {
		return nil, false
	}
	return value.Map, true
}

func arrayOf(value wcb.Value) ([]wcb.Value, bool) {
	if value.Kind != wcb.Array {
		return nil, false
	}
	return value.Array, true
}

func text(record map[string]wcb.Value, key string) string {
	value, ok := record[key]
	if !ok || value.Kind != wcb.Text {
		return ""
	}
	return value.Str
}

func hashBytes(value wcb.Value) ([]byte, error) {
	if value.Kind != wcb.Bytes {
		return nil, fmt.Errorf("value is not bytes")
	}
	return value.Bytes, nil
}

func hexOf(record map[string]wcb.Value, key string) string {
	value, ok := record[key]
	if !ok || value.Kind != wcb.Bytes {
		return ""
	}
	return hex.EncodeToString(value.Bytes)
}

// checkKeys requires the map's key set to be exactly `allowed`.
func checkKeys(record map[string]wcb.Value, allowed []string) error {
	want := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		want[key] = struct{}{}
	}
	var missing, extra []string
	for _, key := range allowed {
		if _, ok := record[key]; !ok {
			missing = append(missing, key)
		}
	}
	for key := range record {
		if _, ok := want[key]; !ok {
			extra = append(extra, key)
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		sort.Strings(missing)
		sort.Strings(extra)
		return fmt.Errorf("missing [%s] unexpected [%s]",
			strings.Join(missing, ","), strings.Join(extra, ","))
	}
	return nil
}
