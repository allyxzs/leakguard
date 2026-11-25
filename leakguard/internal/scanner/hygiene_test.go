package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/allyxzs/leakguard/internal/rules"
)

// This is independent of .leakguardignore and leakguard:allow: test fixtures and
// docs must not contain full provider-shaped credentials in their source bytes.
func TestRepositoryHasNoEmbeddedProviderCredentials(t *testing.T) {
	root := filepath.Join("..", "..")
	checks := rules.Default()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if isBinary(data) {
			return nil
		}
		for _, rule := range checks {
			// Generic assignments require semantic review; source code naturally
			// contains assignments. All provider-specific patterns remain enabled.
			if rule.ID == "generic-secret" {
				continue
			}
			for _, match := range rule.Regex.FindAllSubmatch(data, -1) {
				value := string(match[rule.SecretGroup])
				if rule.MinEntropy > 0 && ShannonEntropy(value) < rule.MinEntropy {
					continue
				}
				t.Errorf("%s contains a full %s pattern; use runtime synthetic fixtures", path, rule.ID)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicExamplesAreClean(t *testing.T) {
	s := New(t.TempDir()) // No repository-specific ignores.
	findings, err := s.ScanPath(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("public examples must contain no credentials: %d findings", len(findings))
	}
}
