// Package gitscan scans staged changes and Git history.
package gitscan

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/allyxzs/leakguard/internal/scanner"
)

func git(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// Root returns the repository top-level directory.
func Root(dir string) (string, error) {
	out, err := git(dir, "rev-parse", "--show-toplevel")
	return strings.TrimSpace(string(out)), err
}

var hunk = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)
var commitHeader = regexp.MustCompile(`(?m)^__LG_COMMIT__([0-9a-f]{40,64})\t([^\r\n]*)\r?$`)

// diffOptions restricts output to added lines with no context.
var diffOptions = []string{"--no-color", "--no-ext-diff", "-U0", "--diff-filter=ACMR"}

// ScanStaged scans only lines being added in the index (what the next commit introduces).
func ScanStaged(dir string, s *scanner.Scanner) ([]scanner.Finding, error) {
	out, err := git(dir, append([]string{"diff", "--cached"}, diffOptions...)...)
	if err != nil {
		return nil, err
	}
	f := parseDiff(out, s, "", "")
	// .env files staged at all are a finding by themselves.
	names, _ := git(dir, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	for _, n := range strings.Split(strings.TrimSpace(string(names)), "\n") {
		if n == "" || s.Ignored(n) || !scanner.IsEnvFile(n) {
			continue
		}
		if content, err := git(dir, "show", ":"+n); err == nil {
			f = append(f, scanner.AnalyzeEnv(n, content, s)...)
		}
	}
	return unique(f), nil
}

// ScanHistory walks every commit (optionally limited) and scans the added lines.
func ScanHistory(dir string, s *scanner.Scanner, maxCommits int, rev string) ([]scanner.Finding, int, error) {
	args := []string{"log", "-p", "--no-merges", "--format=__LG_COMMIT__%H%x09%an <%ae>"}
	args = append(args, diffOptions...)
	if maxCommits > 0 {
		args = append(args, "-n", strconv.Itoa(maxCommits))
	}
	if rev != "" {
		args = append(args, rev)
	} else {
		args = append(args, "--all")
	}
	out, err := git(dir, args...)
	if err != nil {
		return nil, 0, err
	}
	var all []scanner.Finding
	headers := commitHeader.FindAllSubmatchIndex(out, -1)
	for i, header := range headers {
		end := len(out)
		if i+1 < len(headers) {
			end = headers[i+1][0]
		}
		commit := string(out[header[2]:header[3]])
		author := string(out[header[4]:header[5]])
		all = append(all, parseDiff(out[header[1]:end], s, commit, author)...)
	}
	return unique(all), len(headers), nil
}

func parseDiff(diff []byte, s *scanner.Scanner, commit, author string) []scanner.Finding {
	var out []scanner.Finding
	file := ""
	line := 0
	sc := bufio.NewScanner(bytes.NewReader(diff))
	sc.Buffer(make([]byte, 1024*1024), 20*1024*1024)
	var envBuf []string
	var envStart []int
	flushEnv := func() {
		if file != "" && scanner.IsEnvFile(file) && len(envBuf) > 0 {
			for _, f := range scanner.AnalyzeEnv(file, []byte(strings.Join(envBuf, "\n")), s) {
				f.Line = envStart[f.Line-1]
				f.Commit, f.Author = commit, author
				out = append(out, f)
			}
		}
		envBuf, envStart = nil, nil
	}
	for sc.Scan() {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "+++ "):
			flushEnv()
			file = strings.TrimPrefix(strings.TrimPrefix(t, "+++ "), "b/")
			if file == "/dev/null" || s.Ignored(file) {
				file = ""
			}
		case strings.HasPrefix(t, "@@"):
			if m := hunk.FindStringSubmatch(t); m != nil {
				line, _ = strconv.Atoi(m[1])
			}
		case strings.HasPrefix(t, "+") && file != "":
			content := t[1:]
			for _, f := range s.ScanLine(file, line, content) {
				f.Commit, f.Author = commit, author
				out = append(out, f)
			}
			envBuf = append(envBuf, content)
			envStart = append(envStart, line)
			line++
		}
	}
	flushEnv()
	return out
}

func unique(in []scanner.Finding) []scanner.Finding {
	seen := map[string]bool{}
	var out []scanner.Finding
	for _, f := range in {
		k := f.File + "|" + f.Secret
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
