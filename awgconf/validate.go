package awgconf

import (
	"errors"
	"os"
	"strings"
)

// Options controls optional validation behaviour.
type Options struct {
	ResolveDNS bool
}

// Known keys, stored lower-case for case-insensitive lookup.

// stdInterfaceKeys are the core wg-quick [Interface] keys.
var stdInterfaceKeys = map[string]bool{
	"privatekey": true, "address": true, "dns": true, "mtu": true,
	"listenport": true, "fwmark": true, "table": true,
	"preup": true, "postup": true, "predown": true, "postdown": true,
	"saveconfig": true,
}

// awgInterfaceKeys are the AmneziaWG [Interface] keys (1.x through 3.x).
var awgInterfaceKeys = map[string]bool{
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"headerprotectionkey": true, "contentpaddingaddition": true,
	"rekeyaftertime": true, "rekeytimeout": true, "rejectaftertime": true,
	"keepalivetimeout": true, "maxhandshakeattempts": true,
	"randomtrailers": true, "disablecookies": true,
}

// wireSockInterfaceKeys are WireSock-specific [Interface] keys: protocol
// masking (Id/Ip/Ib, the WireSock 3.x replacement for I1..I5) and the junk
// packet delay Jd.
var wireSockInterfaceKeys = map[string]bool{
	"id": true, "ip": true, "ib": true, "jd": true,
}

// stdPeerKeys are the core [Peer] keys.
var stdPeerKeys = map[string]bool{
	"publickey": true, "presharedkey": true, "allowedips": true,
	"endpoint": true, "persistentkeepalive": true,
}

// wireSockPeerKeys are WireSock-specific [Peer] keys (per-application routing
// and SOCKS5 proxy options).
var wireSockPeerKeys = map[string]bool{
	"allowedapps": true, "disallowedapps": true, "disallowedips": true,
	"socks5proxy": true, "socks5proxyusername": true,
	"socks5proxypassword": true, "socks5proxyalltraffic": true,
}

// knownProtocols are the application protocols accepted by WireSock "Ip".
var knownProtocols = map[string]bool{
	"quic": true, "tls": true, "http": true, "dns": true, "sip": true, "stun": true,
}

// knownSignatures are the browser/TLS signatures accepted by WireSock "Ib".
var knownSignatures = map[string]bool{
	"curl": true, "chrome": true, "firefox": true, "edge": true, "safari": true,
}

// ValidateBytes parses and validates a config supplied as raw bytes.
//
// It returns the typed Config (nil when parsing failed), a Report that is
// always non-nil, and the parser error, if any. A parse error is also recorded
// in the report as CodeSyntaxError, so callers may rely on the report alone.
func ValidateBytes(data []byte, opt Options) (*Config, *Report, error) {
	parsed, err := Parse(string(data))
	if err != nil {
		rep := &Report{Path: "<memory>"}
		if pErr, ok := errors.AsType[*ParseError](err); ok {
			rep.Error(pErr.Code, pErr.Line, "", "", "Parse error: %s", pErr.Msg)
		} else {
			rep.Error(CodeSyntaxError, 0, "", "", "Parse error: %v", err)
		}
		return nil, rep, err
	}
	cfg, rep := Validate("<memory>", parsed, opt)
	return cfg, rep, nil
}

// ValidateString is a convenience wrapper around ValidateBytes.
func ValidateString(content string, opt Options) (*Config, *Report, error) {
	return ValidateBytes([]byte(content), opt)
}

// ValidateFile reads and validates a config file from disk.
//
// A file read error is returned as-is (with a nil report); a parse error is
// returned together with a report containing CodeSyntaxError.
func ValidateFile(path string, opt Options) (*Config, *Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := Parse(string(data))
	if err != nil {
		rep := &Report{Path: path}
		if pErr, ok := errors.AsType[*ParseError](err); ok {
			rep.Error(pErr.Code, pErr.Line, "", "", "Parse error: %s", pErr.Msg)
		} else {
			rep.Error(CodeSyntaxError, 0, "", "", "Parse error: %v", err)
		}
		return nil, rep, err
	}
	cfg, rep := Validate(path, parsed, opt)
	return cfg, rep, nil
}

// Validate performs the full validation of an already parsed file.
//
// It builds a Config from the raw sections and records every finding in the
// returned Report. Both return values are non-nil: even configs with fatal
// errors produce a partially populated Config so callers can inspect what could
// be parsed.
func Validate(path string, f *ParsedFile, opt Options) (*Config, *Report) {
	rep := &Report{Path: path}
	cfg := &Config{Extra: make(map[string]map[string]string)}

	ifaceSecs := f.SectionsNamed("Interface")
	if len(ifaceSecs) == 0 {
		rep.Error(CodeMissingRequired, 0, "Interface", "", "missing required [Interface] section")
	} else if len(ifaceSecs) > 1 {
		// Multiple [Interface] sections are ambiguous; wg-quick would merge
		// them, which is almost certainly a mistake in a hand-written config.
		rep.Error(CodeDuplicateKey, ifaceSecs[1].Line, "Interface", "", "multiple [Interface] sections are not allowed")
	}

	peerSecs := f.SectionsNamed("Peer")
	if len(peerSecs) == 0 {
		rep.Warn(CodeMissingRequired, 0, "Peer", "", "no [Peer] sections: tunnel cannot connect")
	}

	// Handle top-level custom sections.
	for _, sec := range f.Sections {
		switch strings.ToLower(sec.Name) {
		case "":
			for _, k := range sec.Keys {
				// Protection against index out of range: we use sec.LineOf(k)
				rep.Warn(CodeSyntaxError, sec.LineOf(k), "", k, "key %q outside of any section", k)
			}
		case "interface", "peer":
			// validated below
		case "socks5":
			cfg.Socks5 = validateSocks5Section(sec, rep)
		default:
			rep.Info(CodeNonStandardSection, sec.Line, sec.Name, "", "non-standard section [%s] (custom client)", sec.Name)
			secMap := make(map[string]string)
			for _, k := range sec.Keys {
				if v, ok := sec.GetFirst(k); ok {
					secMap[k] = v
				}
			}
			cfg.Extra[sec.Name] = secMap
		}
	}

	var clientPubKey []byte
	var ifaceSec *RawSection
	if len(ifaceSecs) > 0 {
		ifaceSec = ifaceSecs[0]
		clientPubKey = validateInterface(ifaceSec, cfg, rep)
		cfg.Interface.MTU = resolveMTU(cfg.Interface.MTU)
	}

	for _, pSec := range peerSecs {
		validatePeer(pSec, cfg, clientPubKey, rep, opt)
	}

	// Detect a Cloudflare WARP profile and apply its stricter rules.
	rep.IsWARP, rep.WARPConfidence = evaluateWARP(cfg)
	if rep.IsWARP {
		rep.Info(CodeWARPDetected, 0, "", "", "WARP profile detected (confidence: %s)", rep.WARPConfidence)
		applyWARPStrictRules(cfg, ifaceSec, peerSecs, rep)
	}

	// For non-WARP profiles, standard WireGuard message types in H1..H4 mean
	// header obfuscation is effectively disabled.
	if ifaceSec != nil && !rep.IsWARP {
		checkStandardWGHeaders(cfg, ifaceSec, rep)
	}

	validateAWGTimings(&cfg.Interface, ifaceSec, rep)

	return cfg, rep
}

// resolveMTU returns mtu when set, otherwise the wg-quick default (1420).
func resolveMTU(mtu int) int {
	if mtu > 0 {
		return mtu
	}
	return 1420
}
