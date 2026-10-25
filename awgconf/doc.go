// Package awgconf parses and validates WireGuard, AmneziaWG and Cloudflare
// WARP configuration files in the wg-quick "Key = Value" INI format.
//
// The checker is intended for tools that need a verdict on a user-supplied
// config before they try to connect: it reports recoverable problems as
// structured issues instead of failing on the first one, and it never touches
// the network unless Options.ResolveDNS is enabled.
//
// # Supported flavour
//
//   - WireGuard: PrivateKey, Address, DNS, MTU, ListenPort, FwMark, Table,
//     PreUp/PostUp/PreDown/PostDown, SaveConfig, and the [Peer] keys
//     PublicKey, PresharedKey, AllowedIPs, Endpoint, PersistentKeepalive.
//   - AmneziaWG 1.x/2.x: Jc, Jmin, Jmax, S1, S2, H1..H4.
//   - AmneziaWG 3.x: S3, S4, I1..I5 obfuscation chains, HeaderProtectionKey,
//     ContentPaddingAddition, RekeyAfterTime, RekeyTimeout, RejectAfterTime,
//     KeepaliveTimeout, MaxHandshakeAttempts, RandomTrailers, DisableCookies,
//     range-valued headers (H1 = "lo-hi") and range-valued
//     PersistentKeepalive.
//   - Cloudflare WARP: Reserved (client_id) parsing, canonical server public
//     key detection and the stricter WARP constraints.
//   - WireSock extensions: Id/Ip/Ib protocol masking, Jd, AllowedApps,
//     DisallowedApps, DisallowedIPs and the Socks5Proxy options; the [Socks5]
//     section with BindAddress.
//
// Unknown sections and keys are preserved (Config.Extra) and reported as INFO
// or WARNING rather than rejected, because custom clients extend the format.
//
// # Entry points
//
// ValidateFile, ValidateBytes and ValidateString parse and validate in one
// call. For finer control, use Parse followed by Validate.
//
//	cfg, rep, err := awgconf.ValidateFile("warp.conf", awgconf.Options{})
//	if rep.HasErrors() {
//		fmt.Print(rep)
//	}
//
// Every entry point returns a non-nil *Report; a parse failure is also recorded
// there as CodeSyntaxError. Reports render as text via String or as JSON via
// ToJSON, and each Issue carries a stable ErrorCode.
//
// # Rules
//
// Validation follows the reference implementations:
//
//   - keys: base64 that decodes to exactly 32 bytes (wgtypes.ParseKey);
//   - H1..H4 must not overlap (`headers must not overlap` in amneziawg-go);
//   - when HeaderProtectionKey is set, S1..S4 must be >= 12, the header cipher
//     nonce size (amneziawg-go device/uapi.go);
//   - I1..I5 must be chains of known tags: b, t, r, rc, rd, d, ds, dz;
//   - Jc is capped at 128, Jmin must be < Jmax and Jmax must not exceed the
//     effective MTU;
//   - RekeyAfterTime must end before RejectAfterTime begins;
//   - a Peer PublicKey equal to the Interface private key's public key is a
//     self-handshake and is rejected.
//
// Sources: amnezia-vpn/amneziawg-go, amnezia-vpn/amneziawg-tools (3.1),
// golang.zx2c4.com/wireguard/wgctrl/wgtypes, ViRb3/wgcf and the WireSock
// advanced parameter documentation.
package awgconf
