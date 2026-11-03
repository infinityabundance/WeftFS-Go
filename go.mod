module github.com/infinityabundance/WeftFS-Go

go 1.23

require (
	github.com/hanwen/go-fuse/v2 v2.12.1
	github.com/infinityabundance/WeftCodec-Go v0.0.0
)

require (
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	golang.org/x/sys v0.28.0 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
)

// Monorepo development uses a path replacement so edits to WeftCodec-Go are
// visible immediately. The standalone WeftFS-Go repository replaces this with
// a versioned requirement (see README.md, "Module wiring"). This directive is
// not used by the on-disk format and never affects bytes written to a store.
replace github.com/infinityabundance/WeftCodec-Go => ../WeftCodec-Go
