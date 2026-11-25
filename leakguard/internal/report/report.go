// Package report renders findings as text, JSON or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/allyxzs/leakguard/internal/rules"
	"github.com/allyxzs/leakguard/internal/scanner"
)

var color = os.Getenv("NO_COLOR") == ""

func c(code, s string) string {
	if !color {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

// DisableColor turns ANSI colors off.
func DisableColor() { color = false }

func sevColor(s rules.Severity) string {
	switch s {
	case rules.Critical:
		return c("1;97;41", " "+string(s)+" ")
	case rules.High:
		return c("1;31", string(s))
	case rules.Medium:
		return c("1;33", string(s))
	}
	return c("36", string(s))
}

// Sort orders findings by file and line.
func Sort(f []scanner.Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].File != f[j].File {
			return f[i].File < f[j].File
		}
		return f[i].Line < f[j].Line
	})
}

// Text writes a human-friendly report.
func Text(w io.Writer, f []scanner.Finding, showSecrets bool, title string) {
	fmt.Fprintln(w, c("1;36", "🛡  LeakGuard")+c("2", " — "+title))
	fmt.Fprintln(w)
	if len(f) == 0 {
		fmt.Fprintln(w, c("1;32", "✔ Nenhum segredo encontrado. Pode commitar tranquilo!"))
		return
	}
	counts := map[rules.Severity]int{}
	for _, x := range f {
		counts[x.Severity]++
		secret := x.Redacted()
		if showSecrets {
			secret = x.Secret
		}
		fmt.Fprintf(w, "%s %s\n", sevColor(x.Severity), c("1", x.Description))
		fmt.Fprintf(w, "   %s %s\n", c("2", "arquivo:"), c("4", fmt.Sprintf("%s:%d:%d", x.File, x.Line, x.Column)))
		fmt.Fprintf(w, "   %s %s\n", c("2", "regra:  "), x.RuleID)
		fmt.Fprintf(w, "   %s %s\n", c("2", "segredo:"), c("35", secret))
		if x.Commit != "" {
			fmt.Fprintf(w, "   %s %s %s\n", c("2", "commit: "), c("33", x.Commit[:min(10, len(x.Commit))]), c("2", x.Author))
		}
		fmt.Fprintln(w)
	}
	parts := []string{}
	for _, s := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], strings.ToLower(string(s))))
		}
	}
	fmt.Fprintf(w, "%s %s\n", c("1;31", fmt.Sprintf("✖ %d possível(is) segredo(s) encontrado(s)", len(f))), c("2", "("+strings.Join(parts, ", ")+")"))
}

// JSON writes findings as JSON.
func JSON(w io.Writer, f []scanner.Finding, showSecrets bool) error {
	out := make([]scanner.Finding, len(f))
	for i, x := range f {
		if !showSecrets {
			x.Secret = x.Redacted()
		}
		out[i] = x
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"total": len(out), "findings": out})
}

// SARIF writes a SARIF 2.1.0 log, consumable by GitHub Code Scanning.
func SARIF(w io.Writer, f []scanner.Finding, version string) error {
	ruleIdx := map[string]int{}
	sarifRules := []map[string]any{}
	var results []map[string]any
	for _, x := range f {
		if _, ok := ruleIdx[x.RuleID]; !ok {
			ruleIdx[x.RuleID] = len(sarifRules)
			sarifRules = append(sarifRules, map[string]any{
				"id": x.RuleID, "name": x.RuleID,
				"shortDescription": map[string]string{"text": x.Description},
			})
		}
		level := "warning"
		if x.Severity == rules.Critical || x.Severity == rules.High {
			level = "error"
		}
		results = append(results, map[string]any{
			"ruleId": x.RuleID, "ruleIndex": ruleIdx[x.RuleID], "level": level,
			"message": map[string]string{"text": fmt.Sprintf("%s detectado: %s", x.Description, x.Redacted())},
			"locations": []map[string]any{{"physicalLocation": map[string]any{
				"artifactLocation": map[string]string{"uri": x.File},
				"region":           map[string]int{"startLine": max(1, x.Line), "startColumn": max(1, x.Column)},
			}}},
		})
	}
	if results == nil {
		results = []map[string]any{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "LeakGuard", "version": version, "informationUri": "https://github.com/allyxzs/leakguard", "rules": sarifRules}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
