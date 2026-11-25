package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/allyxzs/leakguard/internal/rules"
	"github.com/allyxzs/leakguard/internal/scanner"
	"github.com/allyxzs/leakguard/internal/testfixture"
)

func TestSARIFEmptyArrays(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, nil, "1.0.1"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results json.RawMessage `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || string(doc.Runs[0].Tool.Driver.Rules) != "[]" || string(doc.Runs[0].Results) != "[]" {
		t.Fatalf("empty SARIF must contain arrays, not null: %s", b.String())
	}
}

func TestSARIFRedactsAndReusesRule(t *testing.T) {
	secret := testfixture.Value()
	findings := []scanner.Finding{
		{RuleID: "generic-secret", Description: "Synthetic finding", Severity: rules.High, File: "config.go", Line: 3, Column: 12, Secret: secret},
		{RuleID: "generic-secret", Description: "Synthetic finding", Severity: rules.High, File: "config.go", Line: 5, Column: 12, Secret: secret},
	}
	var b bytes.Buffer
	if err := SARIF(&b, findings, "1.0.1"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), secret) {
		t.Fatal("SARIF exposed a complete secret")
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Rules []any }
			}
			Results []struct {
				RuleIndex int
				Level     string
			}
		}
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 || len(run.Results) != 2 {
		t.Fatalf("unexpected rules/results: %s", b.String())
	}
	for _, result := range run.Results {
		if result.RuleIndex != 0 || result.Level != "error" {
			t.Fatalf("invalid result: %+v", result)
		}
	}
}

func TestDefaultReportsDoNotExposeSyntheticInputs(t *testing.T) {
	value := testfixture.Sample("github-token")
	findings := []scanner.Finding{{RuleID: "github-token", Description: "Synthetic input", Severity: rules.Critical, File: "fixture.txt", Line: 1, Column: 1, Secret: value}}
	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			var b bytes.Buffer
			var err error
			switch format {
			case "text":
				Text(&b, findings, false, "synthetic test")
			case "json":
				err = JSON(&b, findings, false)
			case "sarif":
				err = SARIF(&b, findings, "1.0.2")
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(b.String(), value) {
				t.Fatal("report contains an unmasked test input")
			}
		})
	}
}
