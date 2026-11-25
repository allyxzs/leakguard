// Package scanner finds secrets in text content.
package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/allyxzs/leakguard/internal/rules"
)

// Finding is a single detected secret.
type Finding struct {
	RuleID      string         `json:"rule_id"`
	Description string         `json:"description"`
	Severity    rules.Severity `json:"severity"`
	File        string         `json:"file"`
	Line        int            `json:"line"`
	Column      int            `json:"column"`
	Secret      string         `json:"secret"`
	Commit      string         `json:"commit,omitempty"`
	Author      string         `json:"author,omitempty"`
}

// Redacted returns the secret with most characters masked.
func (f Finding) Redacted() string { return Redact(f.Secret) }

// Redact masks a secret, keeping only a short prefix.
func Redact(s string) string {
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	keep := 4
	if len(s) < 12 {
		keep = 2
	}
	return s[:keep] + strings.Repeat("*", min(len(s)-keep, 16))
}

// Scanner holds rules and ignore configuration.
type Scanner struct {
	Rules   []rules.Rule
	Ignores []string // glob patterns
}

// New creates a scanner with default rules, loading .leakguardignore from root if present.
func New(root string) *Scanner {
	s := &Scanner{Rules: rules.Default()}
	s.Ignores = append(s.Ignores, defaultIgnores...)
	if data, err := os.ReadFile(filepath.Join(root, ".leakguardignore")); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				s.Ignores = append(s.Ignores, l)
			}
		}
	}
	return s
}

var defaultIgnores = []string{
	".git/**", "node_modules/**", "vendor/**", "dist/**", "build/**", "target/**",
	"*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.pdf", "*.zip", "*.gz", "*.exe", "*.woff", "*.woff2",
	"*.lock", "go.sum", "package-lock.json",
}

var placeholder = regexp.MustCompile(`(?i)^(?:x+|\*+|\.+|<[^>]*>|\$\{[^}]*\}|\$[A-Z_]+|changeme|example|your[_\-]?.*|placeholder|dummy|test|password|secret|null|none|true|false|redacted|process\.env.*|os\.getenv.*|env\(.*)$`)

// Unquoted calls and indexed values are code expressions, not literal secrets.
// Keep quoted values eligible even when their contents resemble an expression.
var codeExpression = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\([^()]*\)|\[[^\s]+\])$`)

// Ignored reports whether a slash-separated relative path matches an ignore glob.
func (s *Scanner) Ignored(path string) bool {
	path = filepath.ToSlash(path)
	base := filepath.Base(path)
	for _, g := range s.Ignores {
		if strings.HasSuffix(g, "/**") {
			dir := strings.TrimSuffix(g, "/**")
			if path == dir || strings.HasPrefix(path, dir+"/") || strings.Contains(path, "/"+dir+"/") {
				return true
			}
			continue
		}
		if ok, _ := filepath.Match(g, path); ok {
			return true
		}
		if ok, _ := filepath.Match(g, base); ok {
			return true
		}
	}
	return false
}

// ScanContent scans text content attributed to file. lineOffset maps line numbers (nil = identity).
func (s *Scanner) ScanContent(file string, content []byte) []Finding {
	if isBinary(content) {
		return nil
	}
	var out []Finding
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		out = append(out, s.ScanLine(file, ln, sc.Text())...)
	}
	return out
}

// ScanLine scans a single line.
func (s *Scanner) ScanLine(file string, ln int, line string) []Finding {
	if strings.Contains(line, "leakguard:allow") {
		return nil
	}
	var out []Finding
	seen := map[string]bool{}
	for _, r := range s.Rules {
		for _, m := range r.Regex.FindAllStringSubmatchIndex(line, -1) {
			g := r.SecretGroup
			if 2*g+1 >= len(m) || m[2*g] < 0 {
				continue
			}
			secret := line[m[2*g]:m[2*g+1]]
			if seen[secret] {
				continue
			}
			if r.MinEntropy > 0 && ShannonEntropy(secret) < r.MinEntropy {
				continue
			}
			if r.ID == "generic-secret" && placeholder.MatchString(secret) {
				continue
			}
			if r.ID == "generic-secret" && codeExpression.MatchString(secret) {
				start := m[2*g]
				if start == 0 || (line[start-1] != '\'' && line[start-1] != '"' && line[start-1] != '`') {
					continue
				}
			}
			seen[secret] = true
			out = append(out, Finding{RuleID: r.ID, Description: r.Description, Severity: r.Severity,
				File: file, Line: ln, Column: m[2*g] + 1, Secret: secret})
		}
	}
	return out
}

// ScanPath walks a directory (or single file) and scans every non-ignored file.
func (s *Scanner) ScanPath(root string) ([]Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		data, err := os.ReadFile(root)
		if err != nil {
			return nil, err
		}
		return s.scanFile(root, data), nil
	}
	var out []Finding
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		if s.Ignored(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err != nil || fi.Size() > 5*1024*1024 {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		out = append(out, s.scanFile(filepath.ToSlash(rel), data)...)
		return nil
	})
	return out, err
}

func (s *Scanner) scanFile(name string, data []byte) []Finding {
	f := s.ScanContent(name, data)
	if IsEnvFile(name) {
		f = append(f, AnalyzeEnv(name, data, s)...)
	}
	return dedupe(f)
}

func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	lines := map[string]bool{}
	for _, f := range in {
		if f.RuleID != "env-secret" {
			lines[fmt.Sprintf("%s|%d", f.File, f.Line)] = true
		}
	}
	var out []Finding
	for _, f := range in {
		if f.RuleID == "env-secret" && lines[fmt.Sprintf("%s|%d", f.File, f.Line)] {
			continue
		}
		k := f.File + "|" + f.Secret + "|" + f.Commit
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func isBinary(b []byte) bool {
	n := min(len(b), 8000)
	return bytes.IndexByte(b[:n], 0) >= 0
}
