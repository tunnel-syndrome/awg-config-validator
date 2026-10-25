# amnezia-wg-checker

A config and key checker for **WireGuard**, **AmneziaWG** (1.x through 3.x) and
**Cloudflare WARP**, with first-class support for the WireSock client
extensions. Available both as a CLI and as a small Go library.

The checker never connects anywhere and never modifies the config: it parses
the file, builds a typed model and reports every problem it can find, with a
stable machine-readable code for each finding. Network access is used only when
`--dns` is explicitly requested.

## Features

- **Keys** — base64 with an exact 32-byte payload, weak/all-zero rejection,
  public-key derivation and pair verification.
- **Addressing** — `Address`, `AllowedIPs` (CIDR or bare IP, which defaults to
  `/32`/`/128` like wg-quick), `DNS` must be IP literals.
- **Endpoint** — `host:port`, port range 1..65535, optional DNS resolution.
- **AmneziaWG 1.x/2.x** — `Jc`, `Jmin`, `Jmax` (`Jc <= 128`, `Jmin < Jmax`,
  `Jmax <= MTU`), `S1`, `S2`, non-overlapping `H1..H4`.
- **AmneziaWG 3.x** — `S3`, `S4`, `I1..I5` obfuscation chains with tag and
  argument validation, `HeaderProtectionKey` (requires `S1..S4 >= 12`),
  `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`,
  `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`,
  `RandomTrailers`, `DisableCookies`, range-valued headers (`H1 = lo-hi`) and
  `PersistentKeepalive`.
- **Cloudflare WARP** — detection with confidence score (canonical server
  public key, `*.cloudflareclient.com` endpoint, Cloudflare IP ranges,
  `172.16.0.2` interface address), `Reserved`/`client_id` parsing and strict
  WARP rules: `S1..S4 == 0`, `H1..H4 == 1..4`, no `PresharedKey`, `/32` and
  `/128` interface addresses.
- **WireSock** — `Id`/`Ip`/`Ib` protocol masking, `Jd`, `AllowedApps`,
  `DisallowedApps`, `DisallowedIPs`, the `Socks5Proxy*` options and the
  `[Socks5]` `BindAddress`.
- **Safety checks** — self-handshake detection (peer key equals the derived
  client key), duplicate `[Interface]` sections, duplicate keys, junk
  characters around obfuscation tags, inverted time ranges.
- **Forward compatible** — unknown sections and keys are preserved and reported
  as INFO/WARNING instead of being rejected.

## Build

```sh
go build -o amnezia-wg-checker .
```

Requires Go 1.27.2 or newer (see `go.mod`). The checker uses only the standard
library, so there are no third-party dependencies to download.

## CLI usage

```
amnezia-wg-checker check [--json] [--dns] <file.conf ... | ->
amnezia-wg-checker key <base64Key>
amnezia-wg-checker keypair <privateKey> <publicKey>
```

### Validate configs

```sh
amnezia-wg-checker check warp.conf
```

```
== Config: warp.conf
   Profile: Cloudflare WARP (Confidence: 100%)
   Profile: AmneziaWG Obfuscation Enabled
   Features: WireSock Extensions Present
   INFO    line 27 : [NON_STANDARD_SECTION] key "Id" is WireSock specific
   INFO    line 28 : [NON_STANDARD_SECTION] key "Ip" is WireSock specific
   INFO    line 29 : [NON_STANDARD_SECTION] key "Ib" is WireSock specific
   INFO    [WARP_DETECTED] WARP profile detected (confidence: 100%)
   Summary: 0 error(s), 0 warning(s), 4 info
```

- `--json` prints the structured report instead of text.
- `--dns` resolves `Endpoint` hostnames; without it hostnames are accepted
  as-is.
- `-` reads a config from STDIN:

```sh
cat warp.conf | amnezia-wg-checker check -
```

Multiple files can be passed in one invocation; the exit status is 1 if any of
them has errors.

### Validate keys

```sh
amnezia-wg-checker key '8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE='
```

```
VALID Curve25519 key (base64, 32 bytes)
Derived public key (if input was private): 6LMOP32rjSY639hfTyb+cgKgfSHDJuwtQZaXXJn8Fho=
```

Any valid 32-byte base64 blob is also a valid *public* key, so the checker
cannot tell the two apart; the derived key is printed as a convenience.

```sh
amnezia-wg-checker keypair <privateKey> <publicKey>
```

Prints `MATCH` and exits 0 when the public key belongs to the private key,
otherwise `MISMATCH` and exit 1. The canonical Cloudflare WARP server key is
recognised and announced.

### Exit codes

| Code | Meaning                                           |
|------|---------------------------------------------------|
| `0`  | Success: all configs valid, keys match            |
| `1`  | Validation errors found                           |
| `2`  | I/O error, parse failure or invalid CLI arguments |

## Library usage

```go
import "github.com/tunnel-syndrome/awg-config-validator/awgconf"

cfg, rep, err := awgconf.ValidateFile("warp.conf", awgconf.Options{})
if err != nil {
    log.Fatal(err)
}
if rep.HasErrors() {
    fmt.Print(rep) // or rep.ToJSON()
    return
}
fmt.Println("WARP:", rep.IsWARP, "AmneziaWG:", rep.HasAWG)
for _, p := range cfg.Peers {
    fmt.Println("endpoint:", p.Endpoint, "allowed:", p.AllowedIPs)
}
```

Other entry points: `ValidateBytes`, `ValidateString`, or `Parse` +
`Validate` for full control. `Report.Issues` carries `ErrorCode`, `Severity`,
`Line`, `Section`, `Key` and a message; `Report.Errors()` / `Warnings()` filter
by severity.

### Error codes

| Group | Codes |
|---|---|
| Syntax and keys | `SYNTAX_ERROR`, `DUPLICATE_KEY`, `KEY_INVALID`, `KEY_SELF_HANDSHAKE`,<br/>`MISSING_REQUIRED`, `UNKNOWN_KEY`, `NON_STANDARD_SECTION` |
| Networking | `INVALID_ADDRESS`, `INVALID_ENDPOINT`, `ENDPOINT_DNS_FAIL`, `MTU_INVALID`, `MTU_TOO_LOW` |
| AmneziaWG | `AWG_JUNK_COUNT_RANGE`, `AWG_JMIN_GTE_JMAX`, `AWG_JMAX_EXCEEDS_MTU`, `AWG_HEADER_OVERLAP`,<br/>`AWG_HEADER_STANDARD_WG`, `AWG_OBF_CHAIN_INVALID`, `AWG_HP_REQUIRES_PADDING`, `AWG_TIMING_CONFLICT` |
| WARP | `WARP_DETECTED`, `WARP_STRICT_HEADER_MISMATCH`, `WARP_STRICT_PADDING_MISMATCH`, `WARP_UNEXPECTED_PSK`,<br/>`WARP_ADDRESS_SUBNET_UNUSUAL` |

## Project layout

```
awgconf/
  doc.go                package documentation
  model.go              typed config model (Config, InterfaceConfig, PeerConfig, ...)
  parse.go              INI/wg-quick parser and raw section tree
  values.go             range and boolean value parsers
  keys.go               key validation, public-key derivation, Reserved parsing
  report.go             Issue/Report, error codes, text and JSON output
  validate.go           entry points, Options, key whitelists, orchestration
  validate_interface.go [Interface] and AmneziaWG parameter rules
  validate_obf.go       I1..I5 obfuscation chain validation
  validate_peer.go      [Peer], Endpoint and [Socks5] validation
  warp.go               WARP detection and strict WARP rules
  awgconf_test.go       unit tests
main.go                 CLI
warp.conf               sample WARP/AmneziaWG/WireSock config
research_notes.md       notes on the reference implementations
```

## Rules and references

The validation rules follow the reference implementations:

- [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) —
  UAPI parsing, header overlap and header-protection constraints
  (`device/uapi.go`, `device/noise-types.go`, `device/obf.go`).
- [amnezia-vpn/amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools)
  (3.1) — `.conf` parameter set, ranges and uint limits (`src/config.c`,
  `src/type.c`).
- [WireGuard/wgctrl-go](https://github.com/WireGuard/wgctrl-go) —
  `wgtypes.ParseKey` key rules.
- [ViRb3/wgcf](https://github.com/ViRb3/wgcf) — WARP profile shape, key
  handling, keepalive limits.
- [WireSock advanced parameters](https://wiresock.net/documentation/wiresock-secure-connect/advanced-parameters.html)
  — `Id`/`Ip`/`Ib`, `Jd`, app filters and SOCKS5 options.

