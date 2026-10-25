package awgconf

import (
	"net"
	"net/netip"
	"strings"
)

// warpEndpointPrefixes — the complete list of official Cloudflare Anycast subnets used for WARP endpoints.
var warpEndpointPrefixes = []netip.Prefix{
	// 162.159.x.x
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.193.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("162.159.204.0/24"),

	// 188.114.x.x
	netip.MustParsePrefix("188.114.96.0/24"),
	netip.MustParsePrefix("188.114.97.0/24"),
	netip.MustParsePrefix("188.114.98.0/24"),
	netip.MustParsePrefix("188.114.99.0/24"),

	// 8.x.x.x Anycast pools
	netip.MustParsePrefix("8.6.112.0/24"),
	netip.MustParsePrefix("8.34.70.0/24"),
	netip.MustParsePrefix("8.34.146.0/24"),
	netip.MustParsePrefix("8.35.211.0/24"),
	netip.MustParsePrefix("8.39.125.0/24"),
	netip.MustParsePrefix("8.39.204.0/24"),
	netip.MustParsePrefix("8.39.214.0/24"),
	netip.MustParsePrefix("8.47.69.0/24"),

	// IPv6 WARP endpoints
	netip.MustParsePrefix("2606:4700:d0::/48"),
	netip.MustParsePrefix("2606:4700:d1::/48"),
}

// warpClientV6Prefix — range of client IPv6 addresses of Cloudflare WARP.
var warpClientV6Prefix = netip.MustParsePrefix("2606:4700:110::/48")

// evaluateWARP decides whether the config targets Cloudflare WARP and returns
// the detection confidence ("100%", "high" or "none").
//
// Detection is based on the canonical WARP server public key, the
// *.cloudflareclient.com endpoint or an endpoint inside Cloudflare's WARP
// address ranges; a 172.16.0.2 interface address raises confidence to "high".
func evaluateWARP(cfg *Config) (bool, string) {
	for _, p := range cfg.Peers {
		// immutable reference public key of WARP servers -> 100% guarantee
		if p.PublicKey == CloudflareWARPPublicKey {
			return true, "100%"
		}

		// domain or ip of warp endpoint
		host, _, err := net.SplitHostPort(p.Endpoint)
		if err == nil {
			lhost := strings.ToLower(host)
			if lhost == "engage.cloudflareclient.com" || strings.HasSuffix(lhost, ".cloudflareclient.com") {
				return true, "100%"
			}
			if ip, err := netip.ParseAddr(host); err == nil && isCloudflareIP(ip) {
				return true, "high"
			}
		}
	}

	// analysis of client interface addresses (172.16.0.2 or 2606:4700:110::/48)
	for _, pfx := range cfg.Interface.Addresses {
		addr := pfx.Addr()
		if addr.String() == "172.16.0.2" || (addr.Is6() && warpClientV6Prefix.Contains(addr)) {
			return true, "high"
		}
	}
	return false, "none"
}

// isCloudflareIP reports whether ip belongs to one of Cloudflare's WARP ndpoint ranges.
func isCloudflareIP(ip netip.Addr) bool {
	for _, pfx := range warpEndpointPrefixes {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// applyWARPStrictRules enforces the constraints of the real Cloudflare WARP
// service: no packet padding, standard WireGuard headers, no PresharedKey and
// host-style /32 and /128 interface addresses.
func applyWARPStrictRules(cfg *Config, ifaceSec *RawSection, peerSecs []*RawSection, rep *Report) {
	if ifaceSec != nil {
		// WARP does not support padding: S1..S4 must be zero.
		sPaddings := []struct {
			name string
			val  uint16
		}{
			{"S1", cfg.Interface.S1},
			{"S2", cfg.Interface.S2},
			{"S3", cfg.Interface.S3},
			{"S4", cfg.Interface.S4},
		}
		for _, sp := range sPaddings {
			if sp.val != 0 {
				rep.Error(CodeWARPStrictPadding, ifaceSec.LineOf(sp.name), "Interface", sp.name,
					"WARP server does not support packet padding: %s must be 0 (got %d)", sp.name, sp.val)
			}
		}

		// WARP requires the standard WireGuard message types: H1..H4 = 1..4.
		hHeaders := []struct {
			name     string
			rangeVal [2]uint32
			expected uint32
		}{
			{"H1", cfg.Interface.H1, 1},
			{"H2", cfg.Interface.H2, 2},
			{"H3", cfg.Interface.H3, 3},
			{"H4", cfg.Interface.H4, 4},
		}
		for _, hh := range hHeaders {
			if _, ok := ifaceSec.GetFirst(hh.name); ok {
				if hh.rangeVal[0] != hh.expected || hh.rangeVal[1] != hh.expected {
					rep.Error(CodeWARPStrictHeader, ifaceSec.LineOf(hh.name), "Interface", hh.name,
						"WARP requires standard WireGuard header for %s: must be %d (got %d-%d)",
						hh.name, hh.expected, hh.rangeVal[0], hh.rangeVal[1])
				}
			}
		}

		// WARP hands out host prefixes; subnets usually mean a mistake.
		for _, pfx := range cfg.Interface.Addresses {
			if pfx.Addr().Is4() && pfx.Bits() != 32 {
				rep.Warn(CodeWARPAddressSubnet, ifaceSec.LineOf("Address"), "Interface", "Address",
					"WARP IPv4 address usually has /32 mask, got /%d (%s)", pfx.Bits(), pfx)
			}
			if pfx.Addr().Is6() && pfx.Bits() != 128 {
				rep.Warn(CodeWARPAddressSubnet, ifaceSec.LineOf("Address"), "Interface", "Address",
					"WARP IPv6 address usually has /128 mask, got /%d (%s)", pfx.Bits(), pfx)
			}
		}
	}

	// Cloudflare WARP does not use a PresharedKey (validated regardless of the presence of the Interface).
	for i, p := range cfg.Peers {
		if p.PresharedKey != "" && i < len(peerSecs) {
			sec := peerSecs[i]
			rep.Error(CodeWARPUnexpectedPSK, sec.LineOf("PresharedKey"), "Peer", "PresharedKey",
				"Cloudflare WARP does not use PresharedKey")
		}
	}
}
