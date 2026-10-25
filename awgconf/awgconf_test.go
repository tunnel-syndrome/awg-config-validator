package awgconf_test

import (
	"strings"
	"testing"

	"github.com/tunnel-syndrome/awg-config-validator/awgconf"
)

const sampleWarpConf = `
[Interface]
PrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=
Address = 172.16.0.2, 2606:4700:110:8485:448f:2205:cb9d:95ee
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
I1 = <b 0xc00000000108><r 8><r 8><b 0x0044c4><r 4><b 0x060040a20100009c0303><r 32><b 0x000004130113030100006f00000011000f00000c79617374617469632e6e6574001000050003026833000a00060004001d0017002b00030203040039001201048000ea60040480100000060480100000003300260024001d0020><r 32><r 1050>
Jc = 4
Jmin = 40
Jmax = 70
ContentPaddingAddition = 27-97
RekeyAfterTime = 116-131
RejectAfterTime = 171-196
KeepaliveTimeout = 9-16
MaxHandshakeAttempts = 18-26
RandomTrailers = on
DisableCookies = on
S1 = 0
S2 = 0
S3 = 0
S4 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

# WireSock:
Id = tnt-online.ru
Ip = quic
Ib = curl

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408

[Socks5]
BindAddress = 127.0.0.1:25344 # inline comment
`

func TestSampleWarpConfig(t *testing.T) {
	cfg, rep, err := awgconf.ValidateString(sampleWarpConf, awgconf.Options{})
	if err != nil {
		t.Fatalf("ValidateString error: %v", err)
	}
	if rep.HasErrors() {
		t.Fatalf("expected valid config, but got errors:\n%s", rep.String())
	}
	if !rep.IsWARP || rep.WARPConfidence != "100%" {
		t.Errorf("expected 100%% WARP detection, got is_warp=%v, conf=%s", rep.IsWARP, rep.WARPConfidence)
	}
	if !rep.HasAWG {
		t.Errorf("expected HasAWG=true")
	}
	if !rep.HasWireSock {
		t.Errorf("expected HasWireSock=true")
	}
	if cfg.Socks5 == nil || cfg.Socks5.BindAddress.String() != "127.0.0.1:25344" {
		t.Errorf("failed to parse [Socks5] BindAddress")
	}
}

func TestWARPStrictRules(t *testing.T) {
	// 1. S1 != 0 on WARP.
	badS1 := strings.Replace(sampleWarpConf, "S1 = 0", "S1 = 15", 1)
	f, _ := awgconf.Parse(badS1)
	_, rep := awgconf.Validate("test", f, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error for S1 != 0 on WARP")
	}

	// 2. H1 != 1 on WARP.
	badH1 := strings.Replace(sampleWarpConf, "H1 = 1", "H1 = 12345", 1)
	f, _ = awgconf.Parse(badH1)
	_, rep = awgconf.Validate("test", f, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error for H1 != 1 on WARP")
	}

	// 3. PresharedKey on WARP.
	pskWarp := strings.Replace(sampleWarpConf, "Endpoint = engage.cloudflareclient.com:2408", "Endpoint = engage.cloudflareclient.com:2408\nPresharedKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=", 1)
	f, _ = awgconf.Parse(pskWarp)
	_, rep = awgconf.Validate("test", f, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error for PresharedKey on WARP")
	}
}

func TestJunkConstraints(t *testing.T) {
	// Jc > 128
	badJc := strings.Replace(sampleWarpConf, "Jc = 4", "Jc = 150", 1)
	f, _ := awgconf.Parse(badJc)
	_, rep := awgconf.Validate("test", f, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error for Jc > 128")
	}

	// Jmin >= Jmax
	badJmin := strings.Replace(sampleWarpConf, "Jmin = 40", "Jmin = 80", 1)
	f, _ = awgconf.Parse(badJmin)
	_, rep = awgconf.Validate("test", f, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error for Jmin >= Jmax")
	}

	// Jmax > MTU (1280)
	badJmax := strings.Replace(sampleWarpConf, "Jmax = 70", "Jmax = 1300", 1)
	f, _ = awgconf.Parse(badJmax)
	_, rep = awgconf.Validate("test", f, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error for Jmax > MTU")
	}
}

func TestSelfHandshake(t *testing.T) {
	priv, err := awgconf.ParseKeyBase64("8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=")
	if err != nil {
		t.Fatalf("ParseKeyBase64 failed: %v", err)
	}
	pub, err := awgconf.DerivePublicKey(priv)
	if err != nil {
		t.Fatalf("DerivePublicKey failed: %v", err)
	}
	pubB64 := awgconf.EncodeBase64(pub)

	conf := `
[Interface]
PrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=
Address = 10.0.0.2/32

[Peer]
PublicKey = ` + pubB64 + `
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
`
	f, err := awgconf.Parse(conf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	_, rep := awgconf.Validate("test", f, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error when Peer PublicKey matches Interface derived public key")
	}
}

func TestDurationRange(t *testing.T) {
	lo, hi := awgconf.DurationRange([2]uint16{5, 15})
	if lo.Seconds() != 5 || hi.Seconds() != 15 {
		t.Errorf("expected 5s-15s, got %v-%v", lo, hi)
	}
}

func TestDuplicateMultiValueKeys(t *testing.T) {
	conf := `
[Interface]
PrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=
Address = 10.0.0.2/32
Address = fd00::2/128
DNS = 1.1.1.1
DNS = 8.8.8.8

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 10.0.0.0/24
AllowedIPs = 192.168.1.0/24
Endpoint = 1.2.3.4:51820
`
	f, err := awgconf.Parse(conf)
	if err != nil {
		t.Fatalf("Parse failed on valid duplicate Address/DNS/AllowedIPs: %v", err)
	}
	cfg, rep := awgconf.Validate("test", f, awgconf.Options{})
	if rep.HasErrors() {
		t.Fatalf("unexpected validation errors: %v", rep.Issues)
	}
	if len(cfg.Interface.Addresses) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(cfg.Interface.Addresses))
	}
	if len(cfg.Interface.DNS) != 2 {
		t.Errorf("expected 2 DNS, got %d", len(cfg.Interface.DNS))
	}
}

func TestHeaderOverlap(t *testing.T) {
	conf := `
[Interface]
PrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=
Address = 10.0.0.2/32
H1 = 100-200
H2 = 150-300

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
`
	f, err := awgconf.Parse(conf)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	_, rep := awgconf.Validate("test", f, awgconf.Options{})

	foundOverlap := false
	for _, issue := range rep.Issues {
		if issue.Code == awgconf.CodeAWGHeaderOverlap {
			foundOverlap = true
			break
		}
	}

	if !foundOverlap {
		t.Errorf("expected issue with code %s, but got: %v", awgconf.CodeAWGHeaderOverlap, rep.Issues)
	}
}

func TestMultipleInterfaceSections(t *testing.T) {
	conf := `
[Interface]
PrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=
Address = 10.0.0.2/32

[Interface]
PrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=
Address = 10.0.0.3/32

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
`
	_, rep, _ := awgconf.ValidateString(conf, awgconf.Options{})
	if !rep.HasErrors() {
		t.Error("expected error for multiple [Interface] sections")
	}
}

func TestParseErrorLinePropagation(t *testing.T) {
	conf := "[Interface]\nPrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=\n[BrokenSection"
	_, rep, err := awgconf.ValidateString(conf, awgconf.Options{})
	if err == nil || rep == nil {
		t.Fatal("expected parse error")
	}
	if len(rep.Issues) == 0 {
		t.Fatal("expected issue in report")
	}
	if rep.Issues[0].Line != 3 {
		t.Errorf("expected syntax error at line 3, got line %d", rep.Issues[0].Line)
	}
	if rep.Issues[0].Code != awgconf.CodeSyntaxError {
		t.Errorf("expected code %s, got %s", awgconf.CodeSyntaxError, rep.Issues[0].Code)
	}
}

func TestWARPAlternativeSubnets(t *testing.T) {
	// Config with a non-standard public IP from the 188.114.97.0/24 pool and an arbitrary key
	conf := `
[Interface]
PrivateKey = 8M0jT6m3fQDDtFS/mW2By9mX/YKzLRoRuafsCsvkfkE=
Address = 10.0.0.2/32

[Peer]
PublicKey = 6LMOP32rjSY639hfTyb+cgKgfSHDJuwtQZaXXJn8Fho=
AllowedIPs = 0.0.0.0/0
Endpoint = 188.114.97.10:2408
`
	_, rep, err := awgconf.ValidateString(conf, awgconf.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rep.IsWARP || rep.WARPConfidence != "high" {
		t.Errorf("expected WARP detection with 'high' confidence, got is_warp=%v, conf=%s", rep.IsWARP, rep.WARPConfidence)
	}
}
