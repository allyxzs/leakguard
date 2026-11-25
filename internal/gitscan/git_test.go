package gitscan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/allyxzs/leakguard/internal/scanner"
	"github.com/allyxzs/leakguard/internal/testfixture"
)

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestStagedAndHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	os.WriteFile(filepath.Join(dir, "config.js"), []byte(fmt.Sprintf("const k = %q\n", testfixture.Sample("aws-access-key"))), 0o644)
	run(t, dir, "add", ".")
	s := scanner.New(dir)
	f, err := ScanStaged(dir, s)
	if err != nil || len(f) != 1 {
		t.Fatalf("staged: %v findings=%d", err, len(f))
	}
	run(t, dir, "commit", "-qm", "oops")
	os.WriteFile(filepath.Join(dir, "config.js"), []byte("const k = process.env.KEY\n"), 0o644)
	run(t, dir, "commit", "-qam", "fix")
	h, n, err := ScanHistory(dir, s, 0, "")
	if err != nil || n != 2 || len(h) != 1 || h[0].Commit == "" {
		t.Fatalf("history: %v n=%d findings=%d", err, n, len(h))
	}
}

func TestHistoryCodeExpressionsAndIgnoredFixtures(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".leakguardignore", "*_test.go\n")
	write("source.go", "secret := x.Redacted()\nsecret := line[m[2*g]:m[2*g+1]]\n")
	write("source_test.go", fmt.Sprintf("token = %s\n", testfixture.Sample("github-token")))
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "code and test fixtures")
	s := scanner.New(dir)
	findings, _, err := ScanHistory(dir, s, 0, "")
	if err != nil || len(findings) != 0 {
		t.Fatalf("false positives in history: %v findings=%d", err, len(findings))
	}
	write("config.txt", testfixture.Sample("generic-secret")+"\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "synthetic credential")
	write("config.txt", "token = credentials.AccessToken()\n")
	run(t, dir, "commit", "-qam", "remove credential")
	findings, n, err := ScanHistory(dir, s, 0, "")
	if err != nil || n != 3 || len(findings) != 1 || findings[0].File != "config.txt" || findings[0].Commit == "" {
		t.Fatalf("historical literal must still be detected: %v commits=%d findings=%d", err, n, len(findings))
	}
}

func TestHistoryMarkerInSource(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run(t, dir, "init", "-q")
	content := "// marker __LG_COMMIT__ in source\n" + testfixture.Sample("generic-secret") + "\n// another __LG_COMMIT__ marker\n"
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "marker regression")
	head, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	findings, count, err := ScanHistory(dir, scanner.New(dir), 0, "")
	if err != nil || count != 1 || len(findings) != 1 {
		t.Fatalf("marker changed history parsing: %v commits=%d findings=%d", err, count, len(findings))
	}
	if findings[0].Commit+"\n" != string(head) || findings[0].Line != 2 || findings[0].Author != "t <t@t>" {
		t.Fatal("incorrect commit, line or author attribution")
	}
}
