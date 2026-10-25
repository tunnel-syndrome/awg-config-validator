# awg-config-validator

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

## Library usage

Add the dependency to your module:

```bash
go get github.com/tunnel-syndrome/awg-config-validator/awgconf
```

The library is designed for backend services, APIs, and CLI wrappers: it is
**fully offline by default**, **goroutine-safe**, and constructs a strongly
typed AST using modern `net/netip` types.

### 1. Validating a configuration file or byte stream

`ValidateBytes`, `ValidateString`, and `ValidateFile` are the primary entry points.
They run validation without touching the network unless `ResolveDNS` is explicitly enabled:

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/tunnel-syndrome/awg-config-validator/awgconf"
)

func handleConfigUpload(w http.ResponseWriter, r *http.Request) {
    // Validate directly from an in-memory byte slice (e.g. multipart upload)
    cfg, rep, _ := awgconf.ValidateBytes(payload, awgconf.Options{
        ResolveDNS: false, // keep false for instant, fully offline validation
    })

    // Inspect validation results (syntax errors, overlaps, invalid keys)
    if rep.HasErrors() {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusUnprocessableEntity)
        jsonReport, _ := rep.ToJSON()
        w.Write([]byte(jsonReport))
        return
    }

    // Access strongly-typed AST (addresses, keepalive, timings, etc.)
    fmt.Printf("MTU: %d\n", cfg.Interface.MTU)
    fmt.Printf("Is WARP: %v (confidence: %s)\n", rep.IsWARP, rep.WARPConfidence)
    for _, addr := range cfg.Interface.Addresses {
        // addr is netip.Prefix: zero allocations, safe to compare and store
        fmt.Println("Interface IP:", addr.Addr(), "Mask:", addr.Bits())
    }
}

// Or validate a file on disk:
func checkFileOnDisk(path string) {
    cfg, rep, err := awgconf.ValidateFile(path, awgconf.Options{})
    if err != nil && rep == nil {
        log.Fatalf("OS file read error: %v", err)
    }
    if rep.HasErrors() {
        log.Printf("Config has errors:\n%s", rep)
        return
    }
    _ = cfg
}
```

### 2. Standalone Key API (Curve25519) & WARP Helpers

You can validate keys, derive public keys, and check key pairs independently
of configuration files (e.g. for validating form inputs or generating client
credentials):

```go
import "github.com/tunnel-syndrome/awg-config-validator/awgconf"

// 1. Validate a single key (checks base64, exact 32 bytes, rejects all-zeros)
privBytes, err := awgconf.ValidateKey(userPrivateKey)
if err != nil {
    log.Fatalf("Invalid private key: %v", err)
}

// 2. Derive Curve25519 public key using crypto/ecdh
pubBytes, err := awgconf.DerivePublicKey(privBytes)
pubKeyBase64 := awgconf.EncodeBase64(pubBytes)

// 3. Verify that a public key strictly corresponds to a private key
matches, err := awgconf.CheckKeyPair(privBytes, pubBytes)

// 4. Constant-time equality comparison between two keys
isSame := awgconf.KeyEqual(keyA, keyB)

// 5. Compare against canonical Cloudflare WARP Server Public Key
if userPubKey == awgconf.CloudflareWARPPublicKey {
    fmt.Println("Target peer is Cloudflare WARP")
}

// 6. Parse WARP client_id / reserved field ("1, 2, 3", "[1, 2, 3]" or base64)
reservedBytes, err := awgconf.ParseReserved("123, 45, 67")
```

### 3. Inspecting findings programmatically

The `Report` structure provides convenient helpers to filter issues for UI alerts or REST API error responses:

```go
// Check status
if rep.HasErrors() {
    for _, issue := range rep.Errors() {
        fmt.Printf("[%s] Line %d (Key: %s): %s\n",
            issue.Code, issue.Line, issue.Key, issue.Message)
    }
}

if rep.HasWarnings() {
    for _, warn := range rep.Warnings() {
        fmt.Printf("WARNING [%s] Line %d: %s\n", warn.Code, warn.Line, warn.Message)
    }
}

// Export clean, indented JSON for API responses or audit logs:
jsonStr, err := rep.ToJSON()
```

### 4. Advanced: AST & Typed Configuration Model

When `Validate` runs, it maps raw INI sections into a clean, typed model:

- **`cfg.Interface`** — `Addresses` (`[]netip.Prefix`), `DNS` (`[]netip.Addr`),
  resolved `MTU` (`int`), `PrivateKey`, `Reserved` (`*[3]byte`), port and firewall marks.
- **`cfg.Interface` (AmneziaWG)** — parsed `Jc`, `Jmin`, `Jmax`, `S1..S4`,
  `H1..H4` ranges (`[2]uint32`), `I1..I5` specs, and 3.x timing parameters
  convertible via `awgconf.DurationRange(cfg.Interface.RekeyAfterTime)`.
- **`cfg.Peers`** — slice of `PeerConfig` with parsed `AllowedIPs`
  (`[]netip.Prefix`), `PersistentKeepalive` ranges, and WARP `Reserved` bytes.
- **`cfg.WireSock`** — extracted protocol masking (`Id`, `Ip`, `Ib`, `Jd`) and
  application rules.
- **`cfg.Socks5`** — typed `BindAddress` (`netip.AddrPort`).
- **`cfg.Extra`** — `map[string]map[string]string` preserving all non-standard
  custom sections for downstream processing.

### Error codes

`Report.Issues` carries `ErrorCode`, `Severity`,
`Line`, `Section`, `Key` and a message; `Report.Errors()` / `Warnings()` filter
by severity.

| Group | Codes |
|---|---|
| Syntax and keys | `SYNTAX_ERROR`, `DUPLICATE_KEY`, `KEY_INVALID`, `KEY_SELF_HANDSHAKE`,<br/>`MISSING_REQUIRED`, `UNKNOWN_KEY`, `NON_STANDARD_SECTION` |
| Networking | `INVALID_ADDRESS`, `INVALID_ENDPOINT`, `ENDPOINT_DNS_FAIL`, `MTU_INVALID`, `MTU_TOO_LOW` |
| AmneziaWG | `AWG_JUNK_COUNT_RANGE`, `AWG_JMIN_GTE_JMAX`, `AWG_JMAX_EXCEEDS_MTU`, `AWG_HEADER_OVERLAP`,<br/>`AWG_HEADER_STANDARD_WG`, `AWG_OBF_CHAIN_INVALID`, `AWG_HP_REQUIRES_PADDING`, `AWG_TIMING_CONFLICT` |
| WARP | `WARP_DETECTED`, `WARP_STRICT_HEADER_MISMATCH`, `WARP_STRICT_PADDING_MISMATCH`, `WARP_UNEXPECTED_PSK`,<br/>`WARP_ADDRESS_SUBNET_UNUSUAL` |

## Build as CLI

```sh
go build -o awgconf .
```

Requires Go 1.27.2 or newer (see `go.mod`). The checker uses only the standard
library, so there are no third-party dependencies to download.

## CLI usage

```
awgconf check [--json] [--dns] <file.conf ... | ->
awgconf key <base64Key>
awgconf keypair <privateKey> <publicKey>
```

### Validate configs

```sh
awgconf check warp.conf
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
cat warp.conf | awgconf check -
```

Multiple files can be passed in one invocation; the exit status is 1 if any of
them has errors.

### Validate keys

```sh
awgconf key '8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE='
```

```
VALID Curve25519 key (base64, 32 bytes)
Derived public key (if input was private): 6LMOP32rjSY639hfTyb+cgKgfSHDJuwtQZaXXJn8Fho=
```

Any valid 32-byte base64 blob is also a valid *public* key, so the checker
cannot tell the two apart; the derived key is printed as a convenience.

```sh
awgconf keypair <privateKey> <publicKey>
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

