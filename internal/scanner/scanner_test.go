package scanner

import (
	"fmt"
	"strings"
	"testing"

	"github.com/allyxzs/leakguard/internal/testfixture"
)

func ids(f []Finding) map[string]bool {
	m := map[string]bool{}
	for _, x := range f {
		m[x.RuleID] = true
	}
	return m
}

func TestDetectsKnownKeys(t *testing.T) {
	s := New(t.TempDir())
	for _, rule := range s.Rules {
		t.Run(rule.ID, func(t *testing.T) {
			if !ids(s.ScanLine("fixture.txt", 1, testfixture.Sample(rule.ID)))[rule.ID] {
				t.Errorf("rule %s did not detect its synthetic input", rule.ID)
			}
		})
	}
}

func TestIgnoresPlaceholdersAndAllow(t *testing.T) {
	s := New(t.TempDir())
	for i, line := range []string{
		`password = "changeme"`,
		`api_key = process.env.API_KEY`,
		`token = "${TOKEN}"`,
		fmt.Sprintf("key = %q // leakguard:allow", testfixture.Sample("aws-access-key")),
		`password = "aaaaaaaaaaaa"`,
	} {
		if f := s.ScanLine("x.go", 1, line); len(f) != 0 {
			t.Errorf("unexpected finding in placeholder case %d (%d findings)", i, len(f))
		}
	}
}

func TestEnvAnalysis(t *testing.T) {
	s := New(t.TempDir())
	env := []byte(fmt.Sprintf("# comment\nDB_PASSWORD=%s\nPORT=3000\nVITE_SUPABASE_URL=https://example.invalid\nAPI_KEY=\nJWT_SECRET=changeme\n", testfixture.Value()))
	f := AnalyzeEnv(".env", env, s)
	if len(f) != 1 || f[0].Line != 2 {
		t.Fatalf("expected one finding on line 2, got %d findings", len(f))
	}
	if IsEnvFile(".env.example") || !IsEnvFile("config/.env.production") {
		t.Fatal("env file detection wrong")
	}
}

func TestRedact(t *testing.T) {
	value := testfixture.Value()
	if got := Redact(value); got != value[:4]+strings.Repeat("*", 16) {
		t.Fatal("redaction did not preserve only the expected prefix")
	}
}

func TestIgnoredPaths(t *testing.T) {
	s := New(t.TempDir())
	if !s.Ignored("node_modules/x/y.js") || !s.Ignored("img/logo.png") || s.Ignored("src/main.go") {
		t.Fatal("ignore matching wrong")
	}
}

func TestGenericSecretCodeExpressions(t *testing.T) {
	s := New(t.TempDir())
	for i, line := range []string{
		`secret := x.Redacted()`,
		`secret := line[m[2*g]:m[2*g+1]]`,
		`token = credentials.AccessToken()`,
		`api_key = settings[API_KEY_NAME]`,
	} {
		if f := s.ScanLine("source.go", 1, line); len(f) != 0 {
			t.Errorf("code expression case %d reported as a secret", i)
		}
	}
	for i, line := range []string{
		fmt.Sprintf("secret = %q", "x.Redacted()"),
		fmt.Sprintf("secret = '%s'", "line[m[2*g]:m[2*g+1]]"),
		testfixture.Sample("generic-secret"),
		fmt.Sprintf("password = %q", testfixture.Value()),
		fmt.Sprintf("token = %s", testfixture.Sample("github-token")),
	} {
		if f := s.ScanLine("config.txt", 1, line); len(f) == 0 {
			t.Errorf("literal credential case %d was missed", i)
		}
	}
}
