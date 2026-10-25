// Command amnezia-wg-checker validates WireGuard / AmneziaWG / Cloudflare WARP
// configuration files and Curve25519 keys.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tunnel-syndrome/awg-config-validator/awgconf"
)

const usage = `AmneziaWG / Cloudflare WARP Config & Key Checker

Usage:
  amnezia-wg-checker check [--json] [--dns] <file.conf ... | ->
      Validate one or more config files. Pass '-' to read from STDIN.
  amnezia-wg-checker key <base64Key>
      Validate 32-byte Curve25519 base64 key and derive public key.
  amnezia-wg-checker keypair <privateKey> <publicKey>
      Verify if public key strictly matches private key.

Exit codes:
  0: Success (all configs valid, keys match)
  1: Validation errors found
  2: System/IO error or invalid CLI arguments
`

//goland:noinspection GoUnhandledErrorResult
func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "check":
		runCheck(os.Args[2:])
	case "key":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "Usage: amnezia-wg-checker key <base64Key>")
			os.Exit(2)
		}
		runKey(os.Args[2])
	case "keypair":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "Usage: amnezia-wg-checker keypair <privateKey> <publicKey>")
			os.Exit(2)
		}
		runKeypair(os.Args[2], os.Args[3])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// runCheck validates every CLI target and exits with status 1 when any config
// contains errors. The special target "-" reads a config from STDIN.
//
//goland:noinspection GoUnhandledErrorResult
func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output report as JSON")
	dnsCheck := fs.Bool("dns", false, "resolve endpoint hostnames via network DNS")
	fs.Parse(args)

	targets := fs.Args()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no configuration files provided. Use '-' to read from STDIN.")
		os.Exit(2)
	}

	hadIOError := false
	hadValidationErrors := false
	opt := awgconf.Options{ResolveDNS: *dnsCheck}

	for _, target := range targets {
		var rep *awgconf.Report

		if target == "-" {
			content, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading STDIN: %v\n", err)
				hadIOError = true
				continue
			}
			var parseErr error
			_, rep, parseErr = awgconf.ValidateBytes(content, opt)
			_ = parseErr
		} else {
			var err error
			_, rep, err = awgconf.ValidateFile(target, opt)
			if rep == nil {
				// Disk read error (file not found, no permissions, etc.)
				fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", target, err)
				hadIOError = true
				continue
			}
		}
		if rep == nil {
			continue
		}

		printReport(rep, *jsonOut)
		if rep.HasErrors() {
			hadValidationErrors = true
		}
	}

	if hadIOError {
		os.Exit(2)
	}
	if hadValidationErrors {
		os.Exit(1)
	}
}

// printReport writes a report as JSON or text; a nil report is ignored.
func printReport(rep *awgconf.Report, asJSON bool) {
	if rep == nil {
		return
	}
	if asJSON {
		j, _ := rep.ToJSON()
		fmt.Println(j)
	} else {
		fmt.Print(rep.String())
	}
}

// runKey validates a single key and prints the public key derived from it.
func runKey(k string) {
	cleanKey := strings.TrimSpace(k)
	b, err := awgconf.ValidateKey(cleanKey)
	if err != nil {
		if errors.Is(err, awgconf.ErrKeyWeakOrZero) {
			fmt.Println("INVALID key: all bytes are zero (weak/uninitialized)")
		} else {
			fmt.Printf("INVALID key: %v\n", err)
		}
		os.Exit(1)
	}

	pub, err := awgconf.DerivePublicKey(b)
	if err != nil {
		fmt.Printf("VALID Curve25519 format, but failed to derive pubkey: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("VALID Curve25519 key (base64, 32 bytes)")
	if cleanKey == awgconf.CloudflareWARPPublicKey {
		fmt.Println("NOTE: This key is the canonical Cloudflare WARP Server Public Key.")
	}
	fmt.Printf("Derived public key (if input was private): %s\n", awgconf.EncodeBase64(pub))
}

// runKeypair verifies that the second key is the public key of the first.
func runKeypair(privStr, pubStr string) {
	priv, err := awgconf.ValidateKey(strings.TrimSpace(privStr))
	if err != nil {
		fmt.Printf("Private key INVALID: %v\n", err)
		os.Exit(1)
	}
	pub, err := awgconf.ValidateKey(strings.TrimSpace(pubStr))
	if err != nil {
		fmt.Printf("Public key INVALID: %v\n", err)
		os.Exit(1)
	}

	match, err := awgconf.CheckKeyPair(priv, pub)
	if err != nil {
		fmt.Printf("Comparison error: %v\n", err)
		os.Exit(1)
	}
	if match {
		fmt.Println("MATCH: public key strictly corresponds to the private key.")
		os.Exit(0)
	}

	fmt.Println("MISMATCH: public key does NOT correspond to the private key.")
	os.Exit(1)
}
