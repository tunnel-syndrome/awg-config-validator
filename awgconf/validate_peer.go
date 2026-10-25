package awgconf

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// validatePeer validates a single [Peer] section and appends the resulting
// PeerConfig to cfg.Peers. clientPub is the public key derived from the
// Interface PrivateKey; when it matches the peer PublicKey the config would
// connect to itself, which is rejected.
func validatePeer(s *RawSection, cfg *Config, clientPub []byte, rep *Report, opt Options) {
	for _, rawK := range s.Keys {
		lk := strings.ToLower(rawK)
		switch {
		case stdPeerKeys[lk]:
		case wireSockPeerKeys[lk]:
			rep.HasWireSock = true
			rep.Info(CodeNonStandardSection, s.LineOf(rawK), s.Name, rawK, "key %q is WireSock specific", rawK)
		case lk == "reserved":
			// WARP reserved bytes, handled below.
		default:
			rep.Warn(CodeUnknownKey, s.LineOf(rawK), s.Name, rawK, "unknown key %q in [Peer]", rawK)
		}
	}

	peer := PeerConfig{}

	// PublicKey
	if pubStr, ok := s.GetFirst("PublicKey"); !ok {
		rep.Error(CodeMissingRequired, s.Line, s.Name, "PublicKey", "missing PublicKey")
	} else {
		peer.PublicKey = pubStr
		pubBytes, err := ValidateKey(pubStr)
		if err != nil {
			rep.Error(CodeKeyInvalid, s.LineOf("PublicKey"), s.Name, "PublicKey", "PublicKey: %v", err)
		} else if len(clientPub) == KeyLen && KeyEqual(clientPub, pubBytes) {
			rep.Error(CodeKeySelfHandshake, s.LineOf("PublicKey"), s.Name, "PublicKey", "PublicKey matches Interface PrivateKey's public key (cannot connect to self)")
		}
	}

	// PresharedKey: a zeroed value is legal and simply means "no PSK".
	if pskStr, ok := s.GetFirst("PresharedKey"); ok {
		peer.PresharedKey = pskStr
		if b, err := ParseKeyBase64(pskStr); err != nil {
			rep.Error(CodeKeyInvalid, s.LineOf("PresharedKey"), s.Name, "PresharedKey", "PresharedKey: %v", err)
		} else if KeyZero(b) {
			rep.Info(CodeKeyInvalid, s.LineOf("PresharedKey"), s.Name, "PresharedKey", "PresharedKey is zeroed (ignored)")
		}
	}

	// AllowedIPs
	aLines := s.GetAll("AllowedIPs")
	if len(aLines) == 0 {
		rep.Warn(CodeMissingRequired, s.Line, s.Name, "AllowedIPs", "missing AllowedIPs")
	} else {
		for _, al := range aLines {
			lineNum := s.LineOf("AllowedIPs")
			for _, part := range splitCommaList(al) {
				pfx, err := parsePrefixOrIP(part)
				if err != nil {
					rep.Error(CodeInvalidAddress, lineNum, s.Name, "AllowedIPs", "AllowedIPs %q: %v", part, err)
				} else {
					peer.AllowedIPs = append(peer.AllowedIPs, pfx)
				}
			}
		}
	}

	// Endpoint
	if ep, ok := s.GetFirst("Endpoint"); !ok {
		rep.Warn(CodeMissingRequired, s.Line, s.Name, "Endpoint", "missing Endpoint")
	} else {
		peer.Endpoint = ep
		validateEndpoint(s.LineOf("Endpoint"), ep, rep, opt)
	}

	// PersistentKeepalive (WS 3.1 also allows a "lo-hi" range here)
	if pkStr, ok := s.GetFirst("PersistentKeepalive"); ok {
		lo, hi, err := ParseUint16Range(pkStr)
		if err != nil {
			rep.Error(CodeSyntaxError, s.LineOf("PersistentKeepalive"), s.Name, "PersistentKeepalive", "PersistentKeepalive %q: %v", pkStr, err)
		} else {
			peer.PersistentKeepalive = [2]uint16{lo, hi}
		}
	}

	// Reserved (WARP client_id), accepted in [Peer] by some clients.
	if resStr, ok := s.GetFirst("Reserved"); ok {
		res, err := ParseReserved(resStr)
		if err != nil {
			rep.Error(CodeKeyInvalid, s.LineOf("Reserved"), s.Name, "Reserved", "Reserved: %v", err)
		} else {
			peer.Reserved = &res
		}
	}

	cfg.Peers = append(cfg.Peers, peer)
}

// validateEndpoint validates an Endpoint in host:port form. The host must be an
// IP literal or, when Options.ResolveDNS is set, a resolvable hostname.
func validateEndpoint(line int, ep string, rep *Report, opt Options) {
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		rep.Error(CodeInvalidEndpoint, line, "Peer", "Endpoint", "expected host:port (%v)", err)
		return
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		rep.Error(CodeInvalidEndpoint, line, "Peer", "Endpoint", "invalid port %q (must be 1..65535)", portStr)
		return
	}
	if host == "" {
		rep.Error(CodeInvalidEndpoint, line, "Peer", "Endpoint", "host cannot be empty")
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	if opt.ResolveDNS {
		if _, err := net.LookupHost(host); err != nil {
			rep.Warn(CodeEndpointNoDNS, line, "Peer", "Endpoint", "DNS lookup failed for %q: %v", host, err)
		}
	}
}

// validateSocks5Section validates the [Socks5] section used by CLI clients
// (e.g. WireSock) to expose a local SOCKS5 proxy.
func validateSocks5Section(s *RawSection, rep *Report) *Socks5Config {
	cfg := &Socks5Config{}
	if bAddr, ok := s.GetFirst("BindAddress"); ok {
		ap, err := netip.ParseAddrPort(bAddr)
		if err != nil {
			rep.Error(CodeInvalidEndpoint, s.LineOf("BindAddress"), s.Name, "BindAddress", "invalid BindAddress: %v", err)
		} else {
			cfg.BindAddress = ap
		}
	}
	return cfg
}

// splitCommaList splits a comma-separated list, trimming spaces and dropping
// empty entries.
func splitCommaList(s string) []string {
	parts := strings.Split(s, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			res = append(res, t)
		}
	}
	return res
}

// parsePrefixOrIP accepts CIDR notation or a bare IP. A bare IPv4/IPv6 address
// becomes a /32 or /128 prefix, matching wg-quick.
func parsePrefixOrIP(s string) (netip.Prefix, error) {
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx, nil
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		bits := 32
		if ip.Is6() {
			bits = 128
		}
		return netip.PrefixFrom(ip, bits), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid IP/CIDR %q", s)
}
