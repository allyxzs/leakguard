package scanner

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/allyxzs/leakguard/internal/rules"
)

// IsEnvFile reports whether the file looks like a dotenv file.
func IsEnvFile(name string) bool {
	b := filepath.Base(name)
	if b == ".env" || strings.HasPrefix(b, ".env.") || strings.HasSuffix(b, ".env") {
		return !IsEnvTemplate(name)
	}
	return false
}

// IsEnvTemplate reports whether the env file is a safe template (.env.example etc).
func IsEnvTemplate(name string) bool {
	b := strings.ToLower(filepath.Base(name))
	for _, s := range []string{"example", "sample", "template", "dist", "defaults"} {
		if strings.Contains(b, s) {
			return true
		}
	}
	return false
}

var (
	envLine      = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$`)
	sensitiveKey = regexp.MustCompile(`(?i)(pass|secret|token|key|auth|credential|private|cert|salt|dsn|database_url|conn)`)
	publicKey    = regexp.MustCompile(`(?i)^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_).*(?:URL|PUBLISHABLE|ANON|SITE)`)
)

// AnalyzeEnv inspects a dotenv file: any non-empty value on a sensitive key is reported.
func AnalyzeEnv(name string, data []byte, s *Scanner) []Finding {
	var out []Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.Contains(line, "leakguard:allow") {
			continue
		}
		m := envLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		val = strings.Trim(val, `"'`)
		if val == "" || placeholder.MatchString(val) || publicKey.MatchString(key) || !sensitiveKey.MatchString(key) {
			continue
		}
		out = append(out, Finding{RuleID: "env-secret", Description: "Sensitive value in .env (" + key + ")",
			Severity: rules.High, File: name, Line: ln, Column: strings.Index(line, val) + 1, Secret: val})
	}
	return out
}
