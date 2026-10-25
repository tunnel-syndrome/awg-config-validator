package awgconf

import (
	"fmt"
	"strings"
)

// ParseError describes a fatal syntax problem that prevents the file from being
// interpreted (e.g. a malformed section header).
type ParseError struct {
	Line int       // 1-based line number, 0 when unknown
	Code ErrorCode // machine-readable error code
	Msg  string    // human-readable description
}

// Error implements the error interface.
func (e *ParseError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d [%s]: %s", e.Line, e.Code, e.Msg)
	}
	return e.Msg
}

// RawSection is a parsed INI section that preserves key order and repeated keys.
type RawSection struct {
	Name   string              // section name as written, e.g. "Interface"
	Line   int                 // 1-based line number of the [Section] header (0 for the implicit top-level section)
	Keys   []string            // unique keys in order of first appearance, original casing preserved
	Values map[string][]string // lower-case key -> all values (multi-value keys like Address/DNS)
	Lines  map[string][]int    // lower-case key -> 1-based line numbers of each value
}

// GetFirst returns the first value of key (case-insensitive).
func (s *RawSection) GetFirst(key string) (string, bool) {
	vals := s.Values[strings.ToLower(key)]
	if len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

// GetAll returns every value of key (case-insensitive), for multi-value keys
// such as Address, DNS and AllowedIPs.
func (s *RawSection) GetAll(key string) []string {
	return s.Values[strings.ToLower(key)]
}

// LineOf returns the line number of the first occurrence of key, or the section
// header line when the key is absent.
func (s *RawSection) LineOf(key string) int {
	lines := s.Lines[strings.ToLower(key)]
	if len(lines) == 0 {
		return s.Line
	}
	return lines[0]
}

// ParsedFile is the raw section tree of a config file.
type ParsedFile struct {
	Sections []*RawSection
}

// Section returns the first section with the given name (case-insensitive), or
// nil when it is absent.
func (f *ParsedFile) Section(name string) *RawSection {
	for _, s := range f.Sections {
		if strings.EqualFold(s.Name, name) {
			return s
		}
	}
	return nil
}

// SectionsNamed returns every section with the given name (case-insensitive).
func (f *ParsedFile) SectionsNamed(name string) []*RawSection {
	var out []*RawSection
	for _, s := range f.Sections {
		if strings.EqualFold(s.Name, name) {
			out = append(out, s)
		}
	}
	return out
}

// multiValueKeys lists the wg-quick keys that may legitimately appear several
// times in one section.
var multiValueKeys = map[string]bool{
	"address":    true,
	"dns":        true,
	"allowedips": true,
}

// Parse parses wg-quick style INI content.
//
// It supports "#" and ";" comments (whole-line and trailing), preserves inner
// whitespace of the I1..I5 obfuscation specs, and allows repeated Address, DNS
// and AllowedIPs keys. Unknown sections and keys are kept in the result rather
// than rejected, so custom clients (WireSock, [Socks5], ...) can be inspected
// by the validator.
//
// A *ParseError is returned for unrecoverable syntax problems.
func Parse(content string) (*ParsedFile, error) {
	file := &ParsedFile{}

	// The implicit top-level section holds keys written before any [header].
	var cur = &RawSection{
		Name:   "",
		Values: make(map[string][]string),
		Lines:  make(map[string][]int),
	}
	file.Sections = append(file.Sections, cur)

	lines := strings.Split(content, "\n")
	for i, rawLine := range lines {
		lineNum := i + 1
		line := strings.TrimSuffix(rawLine, "\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		// Section header [Name].
		if strings.HasPrefix(trimmed, "[") {
			end := strings.Index(trimmed, "]")
			if end < 0 {
				return nil, &ParseError{Line: lineNum, Code: CodeSyntaxError, Msg: "unterminated section header"}
			}
			secName := strings.TrimSpace(trimmed[1:end])
			if secName == "" {
				return nil, &ParseError{Line: lineNum, Code: CodeSyntaxError, Msg: "empty section name"}
			}
			// Only a comment may follow the closing bracket.
			tail := strings.TrimSpace(trimmed[end+1:])
			if tail != "" && !strings.HasPrefix(tail, "#") && !strings.HasPrefix(tail, ";") {
				return nil, &ParseError{
					Line: lineNum,
					Code: CodeSyntaxError,
					Msg:  fmt.Sprintf("unexpected trailing characters after section header: %q", tail),
				}
			}

			cur = &RawSection{
				Name:   secName,
				Line:   lineNum,
				Values: make(map[string][]string),
				Lines:  make(map[string][]int),
			}
			file.Sections = append(file.Sections, cur)
			continue
		}

		// Key = Value.
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			return nil, &ParseError{
				Line: lineNum,
				Code: CodeSyntaxError,
				Msg:  fmt.Sprintf("expected Key = Value syntax, got %q", trimmed),
			}
		}
		rawKey := strings.TrimSpace(trimmed[:eq])
		if rawKey == "" {
			return nil, &ParseError{Line: lineNum, Code: CodeSyntaxError, Msg: "empty key before '='"}
		}

		val := trimmed[eq+1:]
		val = stripComment(val)

		lowerKey := strings.ToLower(rawKey)
		// AWG specs preserve inner whitespace, but the single space right
		// after '=' is not part of the value.
		if isSpecialHandshakeKey(rawKey) {
			val = strings.TrimPrefix(val, " ")
			val = strings.TrimPrefix(val, "\t")
			val = strings.TrimRight(val, " \t")
		} else {
			val = strings.TrimSpace(val)
		}

		if _, exists := cur.Values[lowerKey]; exists && !multiValueKeys[lowerKey] {
			return nil, &ParseError{
				Line: lineNum,
				Code: CodeDuplicateKey,
				Msg:  fmt.Sprintf("duplicate key %q in section [%s]", rawKey, cur.Name),
			}
		}

		if len(cur.Values[lowerKey]) == 0 {
			cur.Keys = append(cur.Keys, rawKey)
		}
		cur.Values[lowerKey] = append(cur.Values[lowerKey], val)
		cur.Lines[lowerKey] = append(cur.Lines[lowerKey], lineNum)
	}

	return file, nil
}

// stripComment removes a trailing "#" or ";" comment. The marker must be at the
// start of the value or preceded by whitespace, so values containing '#' (for
// example DNS names or AWG payloads) are not truncated.
func stripComment(v string) string {
	for i := 0; i < len(v); i++ {
		ch := v[i]
		if (ch == '#' || ch == ';') && (i == 0 || v[i-1] == ' ' || v[i-1] == '\t') {
			return v[:i]
		}
	}
	return v
}

// isSpecialHandshakeKey reports whether key is one of the AWG obfuscation
// payload keys, whose internal whitespace must be preserved.
func isSpecialHandshakeKey(key string) bool {
	switch strings.ToUpper(key) {
	case "I1", "I2", "I3", "I4", "I5":
		return true
	}
	return false
}
