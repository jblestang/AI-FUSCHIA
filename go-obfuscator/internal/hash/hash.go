package hash

import (
	"crypto/sha256"
	"encoding/hex"
)

// Name derives a short obfuscated identifier from seed, package path, and original name.
func Name(seed, pkgPath, original string) string {
	sum := digest(seed, pkgPath, original)
	// Hex keeps identifier characters valid for Go ([a-zA-Z0-9_]).
	s := hex.EncodeToString(sum[:4])
	return "o" + s
}

// Bytes derives deterministic bytes from seed, package path, and a context label.
func Bytes(seed, pkgPath, context string, n int) []byte {
	if n <= 0 {
		return nil
	}
	sum := digest(seed, pkgPath, context)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = sum[i%len(sum)]
	}
	return out
}

// Int derives a deterministic int from seed, package path, and context.
func Int(seed, pkgPath, context string) int {
	return int(Int64(seed, pkgPath, context))
}

// Int64 derives a deterministic int64 from seed, package path, and context.
func Int64(seed, pkgPath, context string) int64 {
	sum := digest(seed, pkgPath, context)
	return int64(sum[0]) | int64(sum[1])<<8 | int64(sum[2])<<16 | int64(sum[3])<<24
}

// Uint64 derives a deterministic uint64 from seed, package path, and context.
func Uint64(seed, pkgPath, context string) uint64 {
	sum := digest(seed, pkgPath, context)
	return uint64(sum[4]) | uint64(sum[5])<<8 | uint64(sum[6])<<16 | uint64(sum[7])<<24
}

func digest(seed, pkgPath, context string) [32]byte {
	h := sha256.New()
	h.Write([]byte(seed))
	h.Write([]byte{0})
	h.Write([]byte(pkgPath))
	h.Write([]byte{0})
	h.Write([]byte(context))
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
