package awgconf

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseUint16Range parses a "N" or "lo-hi" range into uint16 bounds.
func ParseUint16Range(s string) (lo, hi uint16, err error) {
	l, h, err := parseRange(s, 16)
	return uint16(l), uint16(h), err
}

// ParseUint32Range parses a "N" or "lo-hi" range into uint32 bounds.
func ParseUint32Range(s string) (lo, hi uint32, err error) {
	l, h, err := parseRange(s, 32)
	return uint32(l), uint32(h), err
}

// parseRange parses a decimal "N" or "lo-hi" range, requiring hi >= lo.
func parseRange(s string, bits int) (lo, hi uint64, err error) {
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return 0, 0, fmt.Errorf("invalid range format %q", s)
	}
	lo, err = strconv.ParseUint(strings.TrimSpace(parts[0]), 10, bits)
	if err != nil {
		return 0, 0, err
	}
	hi = lo
	if len(parts) > 1 {
		hi, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, bits)
		if err != nil {
			return 0, 0, err
		}
	}
	if hi < lo {
		return 0, 0, fmt.Errorf("range inverted: hi (%d) < lo (%d)", hi, lo)
	}
	return lo, hi, nil
}

// ParseBoolAWG parses the boolean forms accepted by wg-quick and WireSock:
// on/off, yes/no, true/false and 1/0 (case-insensitive).
func ParseBoolAWG(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "on", "yes", "true", "1":
		return true, nil
	case "off", "no", "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean value %q (expected on/off/true/false)", s)
}
