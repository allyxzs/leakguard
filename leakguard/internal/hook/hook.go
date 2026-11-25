// Package hook installs the Git pre-commit hook.
package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const marker = "# >>> leakguard >>>"

// Script is the pre-commit hook body.
const Script = marker + `
if command -v leakguard >/dev/null 2>&1; then
  leakguard staged || {
    echo ""
    echo "✋ LeakGuard bloqueou este commit: possíveis segredos encontrados."
    echo "   Remova-os, adicione 'leakguard:allow' na linha ou use 'git commit --no-verify' (não recomendado)."
    exit 1
  }
else
  echo "⚠️  leakguard não encontrado no PATH — pulando verificação."
fi
# <<< leakguard <<<
`

// HooksDir resolves the hooks directory, honouring core.hooksPath.
func HooksDir(repoRoot string) string {
	cmd := exec.Command("git", "rev-parse", "--git-path", "hooks")
	cmd.Dir = repoRoot
	if out, err := cmd.Output(); err == nil {
		p := strings.TrimSpace(string(out))
		if !filepath.IsAbs(p) {
			p = filepath.Join(repoRoot, p)
		}
		return p
	}
	return filepath.Join(repoRoot, ".git", "hooks")
}

// Install writes (or appends to) the pre-commit hook of repoRoot.
func Install(repoRoot string, force bool) (string, error) {
	dir := HooksDir(repoRoot)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "pre-commit")
	existing, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(existing), marker) && !force {
		return path, fmt.Errorf("hook já instalado em %s", path)
	}
	content := "#!/bin/sh\n" + Script
	if err == nil && len(existing) > 0 && !strings.Contains(string(existing), marker) {
		content = strings.TrimRight(string(existing), "\n") + "\n\n" + Script
	}
	return path, os.WriteFile(path, []byte(content), 0o755)
}

// Uninstall removes the LeakGuard block from the hook.
func Uninstall(repoRoot string) error {
	path := filepath.Join(HooksDir(repoRoot), "pre-commit")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s := string(data)
	i := strings.Index(s, marker)
	j := strings.Index(s, "# <<< leakguard <<<")
	if i < 0 || j < 0 {
		return fmt.Errorf("hook do leakguard não encontrado")
	}
	rest := strings.TrimSpace(s[:i] + s[j+len("# <<< leakguard <<<"):])
	if rest == "" || rest == "#!/bin/sh" {
		return os.Remove(path)
	}
	return os.WriteFile(path, []byte(rest+"\n"), 0o755)
}
