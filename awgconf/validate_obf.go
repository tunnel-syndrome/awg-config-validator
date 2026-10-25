package awgconf

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// validateObfChains validates I1..I5 obfuscation chain specs and stores them in
// cfg.Interface.
func validateObfChains(s *RawSection, cfg *Config, rep *Report) {
	keys := []string{"I1", "I2", "I3", "I4", "I5"}
	targets := []*string{&cfg.Interface.I1, &cfg.Interface.I2, &cfg.Interface.I3, &cfg.Interface.I4, &cfg.Interface.I5}

	for i, k := range keys {
		if v, ok := s.GetFirst(k); ok {
			*targets[i] = v
			if err := validateSingleObfChain(v); err != nil {
				rep.Error(CodeAWGObfChainInvalid, s.LineOf(k), s.Name, k, "%s: %v", k, err)
			}
		}
	}
}

// validateSingleObfChain checks that an obfuscation chain consists only of
// well-formed <tag ...> entries, with no stray characters between them
// (mirrors amneziawg-go's device/obf.go parser).
func validateSingleObfChain(spec string) error {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return fmt.Errorf("obfuscation chain cannot be empty")
	}

	pos := 0
	foundTags := 0
	for pos < len(spec) {
		start := strings.IndexByte(spec[pos:], '<')
		if start == -1 {
			tail := strings.TrimSpace(spec[pos:])
			if tail != "" {
				return fmt.Errorf("unexpected characters %q outside tags", tail)
			}
			break
		}
		between := strings.TrimSpace(spec[pos : pos+start])
		if between != "" {
			return fmt.Errorf("unexpected characters %q between tags", between)
		}
		absStart := pos + start
		end := strings.IndexByte(spec[absStart:], '>')
		if end == -1 {
			return fmt.Errorf("missing closing '>' for tag starting at offset %d", absStart)
		}
		absEnd := absStart + end
		tagContent := strings.TrimSpace(spec[absStart+1 : absEnd])
		if err := validateTagContent(tagContent); err != nil {
			return fmt.Errorf("tag <%s>: %w", tagContent, err)
		}
		foundTags++
		pos = absEnd + 1
	}

	if foundTags == 0 {
		return fmt.Errorf("no tags found in spec")
	}
	return nil
}

// validateTagContent validates a single obfuscation tag:
//
//	<b 0xHEX>              raw bytes
//	<r N>, <rc N>, <rd N>  random bytes / chars / digits
//	<ds N>, <dz N>         data string / data size
//	<t ...>, <d ...>       timestamp / data (optional argument)
func validateTagContent(c string) error {
	fields := strings.Fields(c)
	if len(fields) == 0 {
		return fmt.Errorf("empty tag")
	}
	tagType := fields[0]
	switch tagType {
	case "b":
		if len(fields) != 2 {
			return fmt.Errorf("expected '<b 0xHEX>'")
		}
		rawHex := strings.TrimPrefix(fields[1], "0x")
		rawHex = strings.TrimPrefix(rawHex, "0X")
		if len(rawHex)%2 != 0 {
			return fmt.Errorf("hex string must have even number of digits")
		}
		if _, err := hex.DecodeString(rawHex); err != nil {
			return fmt.Errorf("invalid hex string: %v", err)
		}
	case "r", "rc", "rd", "ds", "dz":
		if len(fields) != 2 {
			return fmt.Errorf("expected '<%s size>'", tagType)
		}
		sz, err := strconv.Atoi(fields[1])
		if err != nil || sz < 0 || sz > 65535 {
			return fmt.Errorf("invalid size %q (must be 0..65535)", fields[1])
		}
	case "t", "d":
		// Argument is optional.
	default:
		return fmt.Errorf("unknown tag type %q", tagType)
	}
	return nil
}
