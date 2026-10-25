package awgconf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity classifies a finding.
type Severity string

// Severity levels.
const (
	SevError   Severity = "ERROR"   // the config is invalid and will not work
	SevWarning Severity = "WARNING" // suspicious, but parseable
	SevInfo    Severity = "INFO"    // informational note
)

// ErrorCode is a stable, machine-readable identifier for a validation finding.
type ErrorCode string

// Error codes, grouped by validation area.
const (
	// Syntax and keys.
	CodeSyntaxError        ErrorCode = "SYNTAX_ERROR"
	CodeDuplicateKey       ErrorCode = "DUPLICATE_KEY"
	CodeKeyInvalid         ErrorCode = "KEY_INVALID"
	CodeKeySelfHandshake   ErrorCode = "KEY_SELF_HANDSHAKE"
	CodeMissingRequired    ErrorCode = "MISSING_REQUIRED"
	CodeUnknownKey         ErrorCode = "UNKNOWN_KEY"
	CodeNonStandardSection ErrorCode = "NON_STANDARD_SECTION"

	// Networking.
	CodeInvalidAddress  ErrorCode = "INVALID_ADDRESS"
	CodeInvalidEndpoint ErrorCode = "INVALID_ENDPOINT"
	CodeEndpointNoDNS   ErrorCode = "ENDPOINT_DNS_FAIL"
	CodeMTUInvalid      ErrorCode = "MTU_INVALID"
	CodeMTUTooLow       ErrorCode = "MTU_TOO_LOW"

	// AmneziaWG.
	CodeAWGJunkCountRange    ErrorCode = "AWG_JUNK_COUNT_RANGE"
	CodeAWGJminGteJmax       ErrorCode = "AWG_JMIN_GTE_JMAX"
	CodeAWGJmaxExceedsMTU    ErrorCode = "AWG_JMAX_EXCEEDS_MTU"
	CodeAWGHeaderOverlap     ErrorCode = "AWG_HEADER_OVERLAP"
	CodeAWGHeaderStandardWG  ErrorCode = "AWG_HEADER_STANDARD_WG"
	CodeAWGObfChainInvalid   ErrorCode = "AWG_OBF_CHAIN_INVALID"
	CodeAWGHPRequiresPadding ErrorCode = "AWG_HP_REQUIRES_PADDING"
	CodeAWGTimingConflict    ErrorCode = "AWG_TIMING_CONFLICT"

	// Cloudflare WARP rules.
	CodeWARPDetected      ErrorCode = "WARP_DETECTED"
	CodeWARPStrictHeader  ErrorCode = "WARP_STRICT_HEADER_MISMATCH"
	CodeWARPStrictPadding ErrorCode = "WARP_STRICT_PADDING_MISMATCH"
	CodeWARPUnexpectedPSK ErrorCode = "WARP_UNEXPECTED_PSK"
	CodeWARPAddressSubnet ErrorCode = "WARP_ADDRESS_SUBNET_UNUSUAL"
)

// Issue is a single finding produced by the checker.
type Issue struct {
	Code     ErrorCode `json:"code"`
	Severity Severity  `json:"severity"`
	Line     int       `json:"line,omitempty"`
	Section  string    `json:"section,omitempty"`
	Key      string    `json:"key,omitempty"`
	Message  string    `json:"message"`
}

// Report is the result of validating one configuration.
type Report struct {
	Path           string  `json:"path"`
	IsWARP         bool    `json:"is_warp"`
	WARPConfidence string  `json:"warp_confidence,omitempty"` // "100%", "high" or "none"
	HasAWG         bool    `json:"has_awg"`
	HasWireSock    bool    `json:"has_wiresock"`
	Issues         []Issue `json:"issues"`
	ErrorsCount    int     `json:"errors_count"`
	WarningsCount  int     `json:"warnings_count"`
	InfosCount     int     `json:"infos_count"`
}

// addIssue appends an issue and updates the severity counters.
func (r *Report) addIssue(sev Severity, code ErrorCode, line int, sec, key, msg string) {
	r.Issues = append(r.Issues, Issue{
		Code:     code,
		Severity: sev,
		Line:     line,
		Section:  sec,
		Key:      key,
		Message:  msg,
	})
	switch sev {
	case SevError:
		r.ErrorsCount++
	case SevWarning:
		r.WarningsCount++
	case SevInfo:
		r.InfosCount++
	}
}

// Errors returns only the issues with SevError severity.
func (r *Report) Errors() []Issue {
	var errs []Issue
	for _, iss := range r.Issues {
		if iss.Severity == SevError {
			errs = append(errs, iss)
		}
	}
	return errs
}

// Warnings returns only the issues with SevWarning severity.
func (r *Report) Warnings() []Issue {
	var warns []Issue
	for _, iss := range r.Issues {
		if iss.Severity == SevWarning {
			warns = append(warns, iss)
		}
	}
	return warns
}

// HasWarnings reports whether at least one warning was recorded.
func (r *Report) HasWarnings() bool {
	return r.WarningsCount > 0
}

// HasErrors reports whether at least one error was recorded.
func (r *Report) HasErrors() bool {
	return r.ErrorsCount > 0
}

// Error records a SevError issue.
func (r *Report) Error(code ErrorCode, line int, sec, key string, format string, a ...any) {
	r.addIssue(SevError, code, line, sec, key, fmt.Sprintf(format, a...))
}

// Warn records a SevWarning issue.
func (r *Report) Warn(code ErrorCode, line int, sec, key string, format string, a ...any) {
	r.addIssue(SevWarning, code, line, sec, key, fmt.Sprintf(format, a...))
}

// Info records a SevInfo issue.
func (r *Report) Info(code ErrorCode, line int, sec, key string, format string, a ...any) {
	r.addIssue(SevInfo, code, line, sec, key, fmt.Sprintf(format, a...))
}

// ToJSON renders the report as indented JSON.
func (r *Report) ToJSON() (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	return string(b), err
}

// String renders the report as human-readable text.
//
//goland:noinspection GoUnhandledErrorResult
func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "== Config: %s\n", r.Path)
	if r.IsWARP {
		fmt.Fprintf(&b, "   Profile: Cloudflare WARP (Confidence: %s)\n", r.WARPConfidence)
	}
	if r.HasAWG {
		b.WriteString("   Profile: AmneziaWG Obfuscation Enabled\n")
	}
	if r.HasWireSock {
		b.WriteString("   Features: WireSock Extensions Present\n")
	}

	if len(r.Issues) == 0 {
		b.WriteString("   OK: No issues found.\n")
	} else {
		for _, iss := range r.Issues {
			pos := ""
			if iss.Line > 0 {
				pos = fmt.Sprintf("line %-3d: ", iss.Line)
			}
			fmt.Fprintf(&b, "   %-7s %s[%s] %s\n", iss.Severity, pos, iss.Code, iss.Message)
		}
	}
	fmt.Fprintf(&b, "   Summary: %d error(s), %d warning(s), %d info\n", r.ErrorsCount, r.WarningsCount, r.InfosCount)
	return b.String()
}
