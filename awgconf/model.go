package awgconf

import (
	"net/netip"
	"time"
)

// Config is the typed representation of a parsed and validated configuration.
type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
	WireSock  WireSockConfig
	Socks5    *Socks5Config
	Extra     map[string]map[string]string // unknown sections, kept for custom clients
}

// InterfaceConfig holds the standard WireGuard and AmneziaWG [Interface]
// parameters.
type InterfaceConfig struct {
	// Core WireGuard / wg-quick.
	PrivateKey string
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int // resolved value; defaults to 1420 when unset
	ListenPort int
	FwMark     uint32
	Table      string

	// AmneziaWG 1.x / 2.x.
	Jc   uint16
	Jmin uint16
	Jmax uint16
	S1   uint16
	S2   uint16
	S3   uint16
	S4   uint16
	H1   [2]uint32 // lo, hi; lo == hi for a single header value
	H2   [2]uint32
	H3   [2]uint32
	H4   [2]uint32

	// AmneziaWG 3.x.
	I1                     string
	I2                     string
	I3                     string
	I4                     string
	I5                     string
	HeaderProtectionKey    string
	ContentPaddingAddition [2]uint16
	RekeyAfterTime         [2]uint16
	RekeyTimeout           [2]uint16
	RejectAfterTime        [2]uint16
	KeepaliveTimeout       [2]uint16
	MaxHandshakeAttempts   [2]uint16
	RandomTrailers         bool
	DisableCookies         bool

	// WARP client ID bytes ("reserved"), when present.
	Reserved *[3]byte
}

// PeerConfig holds the parameters of a [Peer] section.
type PeerConfig struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []netip.Prefix
	Endpoint            string
	PersistentKeepalive [2]uint16 // lo, hi; lo == hi for a single value
	Reserved            *[3]byte
}

// WireSockConfig holds the WireSock client extensions.
type WireSockConfig struct {
	Id string // domain used for SNI / Host masking
	Ip string // protocol to mimic: quic, tls, http, dns, sip, stun
	Ib string // TLS/browser signature: curl, chrome, firefox, edge, safari
	Jd int    // junk packet delay in milliseconds

	AllowedApps           []string
	DisallowedApps        []string
	Socks5Proxy           string
	Socks5ProxyUsername   string
	Socks5ProxyPassword   string
	Socks5ProxyAllTraffic bool
}

// Socks5Config holds the parameters of the [Socks5] section used by CLI
// clients to expose a local SOCKS5 proxy.
type Socks5Config struct {
	BindAddress netip.AddrPort
}

// DurationRange converts a second-based range into a Duration pair.
func DurationRange(r [2]uint16) (time.Duration, time.Duration) {
	return time.Duration(r[0]) * time.Second, time.Duration(r[1]) * time.Second
}
