package awgconf

import (
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// KeyLen is the length of a WireGuard / AmneziaWG Curve25519 key in bytes.
const KeyLen = 32

// CloudflareWARPPublicKey is the canonical public key of the Cloudflare WARP
// servers, shared by every WARP endpoint.
const CloudflareWARPPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

// Key parsing errors, suitable for errors.Is.
var (
	ErrKeyInvalidBase64 = errors.New("key is not a valid base64 string")
	ErrKeyInvalidLength = errors.New("decoded key length is not 32 bytes")
	ErrKeyWeakOrZero    = errors.New("key contains all zeros (weak/uninitialized)")
)

// KeyEqual compares two keys in constant time.
func KeyEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ValidateKey checks that s is a valid base64 key decoding to 32 bytes and is
// not degenerate (all zeros).
func ValidateKey(s string) ([]byte, error) {
	b, err := ParseKeyBase64(s)
	if err != nil {
		return nil, err
	}
	if KeyZero(b) {
		return nil, ErrKeyWeakOrZero
	}
	return b, nil
}

// ParseKeyBase64 decodes a base64 key and requires the result to be exactly 32
// bytes. It mirrors wgtypes.ParseKey.
func ParseKeyBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyInvalidBase64, err)
	}
	if len(b) != KeyLen {
		return nil, fmt.Errorf("%w (got %d)", ErrKeyInvalidLength, len(b))
	}
	return b, nil
}

// DerivePublicKey computes the Curve25519 public key for a private key using
// crypto/ecdh.
func DerivePublicKey(priv []byte) ([]byte, error) {
	if len(priv) != KeyLen {
		return nil, ErrKeyInvalidLength
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// CheckKeyPair reports whether pub is the public key corresponding to priv.
func CheckKeyPair(priv, pub []byte) (bool, error) {
	derived, err := DerivePublicKey(priv)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(derived, pub) == 1, nil
}

// KeyZero reports whether k consists entirely of zero bytes.
func KeyZero(k []byte) bool {
	var acc byte
	for _, b := range k {
		acc |= b
	}
	return acc == 0
}

// ParseReserved parses the Cloudflare WARP client_id / reserved field.
//
// Accepted forms are "123, 45, 67", "[123, 45, 67]" and a 3-byte base64 value
// (for example "AAAA").
func ParseReserved(s string) ([3]byte, error) {
	var res [3]byte
	clean := s
	if len(clean) >= 2 && clean[0] == '[' && clean[len(clean)-1] == ']' {
		clean = clean[1 : len(clean)-1]
	}
	// Try base64 first.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 3 {
		copy(res[:], b)
		return res, nil
	}
	// Then a decimal byte list.
	parts := splitCommaList(clean)
	if len(parts) != 3 {
		return res, fmt.Errorf("reserved must contain exactly 3 bytes (e.g. '123, 45, 67' or base64)")
	}
	for i, p := range parts {
		var val int
		if _, err := fmt.Sscanf(p, "%d", &val); err != nil || val < 0 || val > 255 {
			return res, fmt.Errorf("byte #%d (%q) is not in range 0..255", i+1, p)
		}
		res[i] = byte(val)
	}
	return res, nil
}

// EncodeBase64 returns the standard base64 representation of a key.
func EncodeBase64(k []byte) string {
	return base64.StdEncoding.EncodeToString(k)
}
