package awgconf

import (
	"net/netip"
	"strconv"
	"strings"
)

// checkStandardWGHeaders warns when an H1..H4 range includes one of the four
// standard WireGuard message types (1..4). For WARP these values are expected,
// so this check is only applied to non-WARP profiles.
func checkStandardWGHeaders(cfg *Config, s *RawSection, rep *Report) {
	headers := []struct {
		name string
		val  [2]uint32
	}{
		{"H1", cfg.Interface.H1},
		{"H2", cfg.Interface.H2},
		{"H3", cfg.Interface.H3},
		{"H4", cfg.Interface.H4},
	}
	for _, h := range headers {
		if _, ok := s.GetFirst(h.name); ok {
			for stdType := uint32(1); stdType <= 4; stdType++ {
				if h.val[0] <= stdType && stdType <= h.val[1] {
					rep.Warn(CodeAWGHeaderStandardWG, s.LineOf(h.name), s.Name, h.name, "%s range [%d,%d] contains standard WireGuard message type %d (breaks obfuscation against DPI on standard AWG)", h.name, h.val[0], h.val[1], stdType)
					break
				}
			}
		}
	}
}

// validateInterface validates the [Interface] section and fills cfg.Interface.
// It returns the Curve25519 public key derived from PrivateKey (nil when the
// key is missing or invalid), which is used later to detect a self-handshake.
func validateInterface(s *RawSection, cfg *Config, rep *Report) (derivedClientPub []byte) {
	// Classify keys and detect which feature sets the config uses.
	for _, rawK := range s.Keys {
		lk := strings.ToLower(rawK)
		switch {
		case stdInterfaceKeys[lk]:
		case awgInterfaceKeys[lk]:
			rep.HasAWG = true
		case wireSockInterfaceKeys[lk]:
			rep.HasWireSock = true
			rep.Info(CodeNonStandardSection, s.LineOf(rawK), s.Name, rawK, "key %q is WireSock specific", rawK)
		case lk == "reserved":
			// WARP reserved bytes, handled below.
		default:
			rep.Warn(CodeUnknownKey, s.LineOf(rawK), s.Name, rawK, "unknown key %q in [Interface]", rawK)
		}
	}

	// PrivateKey
	if privStr, ok := s.GetFirst("PrivateKey"); !ok {
		rep.Error(CodeMissingRequired, s.Line, s.Name, "PrivateKey", "missing PrivateKey")
	} else {
		cfg.Interface.PrivateKey = privStr
		b, err := ValidateKey(privStr)
		if err != nil {
			rep.Error(CodeKeyInvalid, s.LineOf("PrivateKey"), s.Name, "PrivateKey", "PrivateKey: %v", err)
		} else {
			if pub, err := DerivePublicKey(b); err == nil {
				derivedClientPub = pub
			}
		}
	}

	// Address: one or more comma-separated lists; bare IPs default to /32 or
	// /128, matching wg-quick behaviour.
	addrStrs := s.GetAll("Address")
	if len(addrStrs) == 0 {
		rep.Warn(CodeMissingRequired, s.Line, s.Name, "Address", "missing Address")
	} else {
		for _, addrLine := range addrStrs {
			lineNum := s.LineOf("Address")
			for _, part := range splitCommaList(addrLine) {
				pfx, err := parsePrefixOrIP(part)
				if err != nil {
					rep.Error(CodeInvalidAddress, lineNum, s.Name, "Address", "Address %q: %v", part, err)
				} else {
					cfg.Interface.Addresses = append(cfg.Interface.Addresses, pfx)
				}
			}
		}
	}

	// DNS: must be IP literals (hostnames are not supported by wg-quick).
	dnsStrs := s.GetAll("DNS")
	for _, dnsLine := range dnsStrs {
		lineNum := s.LineOf("DNS")
		for _, part := range splitCommaList(dnsLine) {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				rep.Warn(CodeInvalidAddress, lineNum, s.Name, "DNS", "DNS %q is not an IP literal", part)
			} else {
				cfg.Interface.DNS = append(cfg.Interface.DNS, addr)
			}
		}
	}

	// MTU
	if v, ok := s.GetFirst("MTU"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 65535 {
			rep.Error(CodeMTUInvalid, s.LineOf("MTU"), s.Name, "MTU", "invalid MTU %q (must be 576..65535)", v)
		} else {
			cfg.Interface.MTU = n
			if n < 1280 {
				rep.Warn(CodeMTUTooLow, s.LineOf("MTU"), s.Name, "MTU", "MTU %d is below IPv6 minimum (1280)", n)
			}
		}
	}

	// Reserved (WARP client_id), accepted in [Interface] by some clients.
	if v, ok := s.GetFirst("Reserved"); ok {
		res, err := ParseReserved(v)
		if err != nil {
			rep.Error(CodeKeyInvalid, s.LineOf("Reserved"), s.Name, "Reserved", "Reserved: %v", err)
		} else {
			cfg.Interface.Reserved = &res
		}
	}

	// AmneziaWG parameters. Jmax is validated against the effective MTU, so
	// resolve it first.
	effectiveMTU := resolveMTU(cfg.Interface.MTU)
	validateJunkParams(s, cfg, effectiveMTU, rep)
	validatePaddingParams(s, cfg, rep)
	validateHeaderRanges(s, cfg, rep)
	validateObfChains(s, cfg, rep)
	validateAWG3Ranges(s, cfg, rep)
	validateWireSockInterface(s, cfg, rep)

	return derivedClientPub
}

// validateJunkParams validates Jc/Jmin/Jmax and their dependencies.
func validateJunkParams(s *RawSection, cfg *Config, mtu int, rep *Report) {
	jcStr, hasJc := s.GetFirst("Jc")
	jminStr, hasJmin := s.GetFirst("Jmin")
	jmaxStr, hasJmax := s.GetFirst("Jmax")

	if hasJc {
		val, err := strconv.ParseUint(jcStr, 10, 16)
		if err != nil {
			rep.Error(CodeAWGJunkCountRange, s.LineOf("Jc"), s.Name, "Jc", "Jc %q: invalid uint16", jcStr)
		} else {
			cfg.Interface.Jc = uint16(val)
			if val > 128 {
				rep.Error(CodeAWGJunkCountRange, s.LineOf("Jc"), s.Name, "Jc", "Jc (%d) exceeds recommended maximum 128", val)
			}
		}
	}

	var jmin, jmax uint64
	var errMin, errMax error
	if hasJmin {
		jmin, errMin = strconv.ParseUint(jminStr, 10, 16)
		if errMin != nil {
			rep.Error(CodeSyntaxError, s.LineOf("Jmin"), s.Name, "Jmin", "Jmin %q: invalid uint16", jminStr)
		}
		cfg.Interface.Jmin = uint16(jmin)
	}
	if hasJmax {
		jmax, errMax = strconv.ParseUint(jmaxStr, 10, 16)
		if errMax != nil {
			rep.Error(CodeSyntaxError, s.LineOf("Jmax"), s.Name, "Jmax", "Jmax %q: invalid uint16", jmaxStr)
		}
		cfg.Interface.Jmax = uint16(jmax)
	}

	if hasJmin && hasJmax && errMin == nil && errMax == nil {
		if jmin >= jmax {
			rep.Error(CodeAWGJminGteJmax, s.LineOf("Jmin"), s.Name, "Jmin", "Jmin (%d) must be strictly less than Jmax (%d)", jmin, jmax)
		}
		if int(jmax) > mtu {
			rep.Error(CodeAWGJmaxExceedsMTU, s.LineOf("Jmax"), s.Name, "Jmax", "Jmax (%d) exceeds interface MTU (%d): packets will fragment", jmax, mtu)
		}
	} else if hasJc && cfg.Interface.Jc > 0 && (!hasJmin || !hasJmax) {
		rep.Warn(CodeMissingRequired, s.LineOf("Jc"), s.Name, "Jc", "Jc > 0 specified without explicit Jmin/Jmax")
	}
}

// validatePaddingParams validates S1..S4 and their relation to
// HeaderProtectionKey: the header cipher needs at least a 12-byte nonce, so
// every padding must be >= 12 when header protection is enabled.
func validatePaddingParams(s *RawSection, cfg *Config, rep *Report) {
	keys := []string{"S1", "S2", "S3", "S4"}
	targets := []*uint16{&cfg.Interface.S1, &cfg.Interface.S2, &cfg.Interface.S3, &cfg.Interface.S4}

	for i, k := range keys {
		if v, ok := s.GetFirst(k); ok {
			val, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				rep.Error(CodeSyntaxError, s.LineOf(k), s.Name, k, "%s %q: invalid uint16", k, v)
			} else {
				*targets[i] = uint16(val)
			}
		}
	}

	hpStr, hasHP := s.GetFirst("HeaderProtectionKey")
	if hasHP {
		cfg.Interface.HeaderProtectionKey = hpStr
		if _, err := ParseKeyBase64(hpStr); err != nil {
			rep.Error(CodeKeyInvalid, s.LineOf("HeaderProtectionKey"), s.Name, "HeaderProtectionKey", "HeaderProtectionKey: %v", err)
		}
		for i, k := range keys {
			if *targets[i] < 12 {
				rep.Error(CodeAWGHPRequiresPadding, s.LineOf(k), s.Name, k, "%s = %d: must be >= 12 when HeaderProtectionKey is set", k, *targets[i])
			}
		}
	}
}

// validateHeaderRanges validates H1..H4, which are either a single uint32 or a
// "lo-hi" range, and checks that the four ranges do not overlap.
func validateHeaderRanges(s *RawSection, cfg *Config, rep *Report) {
	keys := []string{"H1", "H2", "H3", "H4"}
	targets := []*[2]uint32{&cfg.Interface.H1, &cfg.Interface.H2, &cfg.Interface.H3, &cfg.Interface.H4}
	isSet := [4]bool{}

	for i, k := range keys {
		if v, ok := s.GetFirst(k); ok {
			lo, hi, err := ParseUint32Range(v)
			if err != nil {
				rep.Error(CodeSyntaxError, s.LineOf(k), s.Name, k, "%s %q: %v", k, v, err)
			} else {
				*targets[i] = [2]uint32{lo, hi}
				isSet[i] = true
			}
		}
	}

	for i := 0; i < 4; i++ {
		if !isSet[i] {
			continue
		}
		for j := i + 1; j < 4; j++ {
			if !isSet[j] {
				continue
			}
			r1, r2 := targets[i], targets[j]
			if r1[0] <= r2[1] && r2[0] <= r1[1] {
				rep.Error(CodeAWGHeaderOverlap, s.LineOf(keys[i]), s.Name, keys[i], "%s [%d,%d] and %s [%d,%d] ranges overlap", keys[i], r1[0], r1[1], keys[j], r2[0], r2[1])
			}
		}
	}
}

// validateAWG3Ranges validates the AmneziaWG 3.x range-typed and boolean
// parameters.
func validateAWG3Ranges(s *RawSection, cfg *Config, rep *Report) {
	rangeKeys := []struct {
		name   string
		target *[2]uint16
	}{
		{"ContentPaddingAddition", &cfg.Interface.ContentPaddingAddition},
		{"RekeyAfterTime", &cfg.Interface.RekeyAfterTime},
		{"RekeyTimeout", &cfg.Interface.RekeyTimeout},
		{"RejectAfterTime", &cfg.Interface.RejectAfterTime},
		{"KeepaliveTimeout", &cfg.Interface.KeepaliveTimeout},
		{"MaxHandshakeAttempts", &cfg.Interface.MaxHandshakeAttempts},
	}
	for _, entry := range rangeKeys {
		if v, ok := s.GetFirst(entry.name); ok {
			lo, hi, err := ParseUint16Range(v)
			if err != nil {
				rep.Error(CodeSyntaxError, s.LineOf(entry.name), s.Name, entry.name, "%s %q: %v", entry.name, v, err)
			} else {
				*entry.target = [2]uint16{lo, hi}
			}
		}
	}

	for _, k := range []string{"RandomTrailers", "DisableCookies"} {
		if v, ok := s.GetFirst(k); ok {
			b, err := ParseBoolAWG(v)
			if err != nil {
				rep.Error(CodeSyntaxError, s.LineOf(k), s.Name, k, "%s: %v", k, err)
			} else if k == "RandomTrailers" {
				cfg.Interface.RandomTrailers = b
			} else {
				cfg.Interface.DisableCookies = b
			}
		}
	}
}

// validateAWGTimings enforces the ordering between RekeyAfterTime and
// RejectAfterTime: a session must be rekeyed strictly before it is rejected.
func validateAWGTimings(iface *InterfaceConfig, s *RawSection, rep *Report) {
	if s == nil {
		return
	}
	if iface.RekeyAfterTime[0] > 0 && iface.RejectAfterTime[0] > 0 {
		_, rekeyMax := DurationRange(iface.RekeyAfterTime)
		rejectMin, _ := DurationRange(iface.RejectAfterTime)
		if rekeyMax >= rejectMin {
			rep.Error(CodeAWGTimingConflict, s.LineOf("RejectAfterTime"), "Interface", "RejectAfterTime", "RejectAfterTime lo (%v) must be strictly greater than RekeyAfterTime hi (%v)", rejectMin, rekeyMax)
		}
	}
}

// validateWireSockInterface validates the WireSock [Interface] extensions:
// Id (masking domain), Ip (protocol), Ib (browser signature) and Jd (junk
// packet delay in milliseconds).
func validateWireSockInterface(s *RawSection, cfg *Config, rep *Report) {
	if v, ok := s.GetFirst("Id"); ok {
		cfg.WireSock.Id = v
	}
	if v, ok := s.GetFirst("Ip"); ok {
		cfg.WireSock.Ip = v
		if !knownProtocols[strings.ToLower(v)] {
			rep.Warn(CodeSyntaxError, s.LineOf("Ip"), s.Name, "Ip", "unusual WireSock Ip protocol: %q", v)
		}
	}
	if v, ok := s.GetFirst("Ib"); ok {
		cfg.WireSock.Ib = v
		if !knownSignatures[strings.ToLower(v)] {
			rep.Warn(CodeSyntaxError, s.LineOf("Ib"), s.Name, "Ib", "unusual WireSock Ib signature: %q", v)
		}
	}
	if v, ok := s.GetFirst("Jd"); ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.WireSock.Jd = n
		} else {
			rep.Error(CodeSyntaxError, s.LineOf("Jd"), s.Name, "Jd", "invalid Jd delay: %q", v)
		}
	}
}
