// Package rules contains the built-in secret detection rules.
package rules

import "regexp"

// Severity of a finding.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

// Rule describes a pattern that indicates a secret.
type Rule struct {
	ID          string
	Description string
	Severity    Severity
	Regex       *regexp.Regexp
	// SecretGroup is the capture group holding the secret (0 = whole match).
	SecretGroup int
	// MinEntropy, when > 0, requires the captured secret to reach this Shannon entropy.
	MinEntropy float64
}

func r(id, desc string, sev Severity, pattern string, group int, entropy float64) Rule {
	return Rule{id, desc, sev, regexp.MustCompile(pattern), group, entropy}
}

// Default returns the built-in rule set.
func Default() []Rule {
	return []Rule{
		r("aws-access-key", "AWS Access Key ID", Critical, `\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b`, 1, 0),
		r("aws-secret-key", "AWS Secret Access Key", Critical, `(?i)aws.{0,20}?(?:secret|private)?.{0,10}?['"=:\s]+([A-Za-z0-9/+=]{40})\b`, 1, 3.5),
		r("github-token", "GitHub Token", Critical, `\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b`, 1, 0),
		r("github-fine-grained", "GitHub Fine-grained PAT", Critical, `\b(github_pat_[A-Za-z0-9_]{82})\b`, 1, 0),
		r("gitlab-token", "GitLab Personal Access Token", Critical, `\b(glpat-[A-Za-z0-9\-_]{20})\b`, 1, 0),
		r("slack-token", "Slack Token", High, `\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b`, 1, 0),
		r("slack-webhook", "Slack Webhook URL", High, `(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)`, 1, 0),
		r("stripe-key", "Stripe Secret Key", Critical, `\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b`, 1, 0),
		r("google-api-key", "Google API Key", High, `\b(AIza[0-9A-Za-z\-_]{35})\b`, 1, 0),
		r("openai-key", "OpenAI API Key", Critical, `\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b`, 1, 0),
		r("anthropic-key", "Anthropic API Key", Critical, `\b(sk-ant-[A-Za-z0-9_\-]{32,})\b`, 1, 0),
		r("twilio-key", "Twilio API Key", High, `\b(SK[0-9a-fA-F]{32})\b`, 1, 0),
		r("sendgrid-key", "SendGrid API Key", High, `\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`, 1, 0),
		r("npm-token", "npm Access Token", High, `\b(npm_[A-Za-z0-9]{36})\b`, 1, 0),
		r("discord-webhook", "Discord Webhook", Medium, `(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)`, 1, 0),
		r("private-key", "Private Key", Critical, `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`, 0, 0),
		r("jwt", "JSON Web Token", Medium, `\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`, 1, 0),
		r("db-connection-string", "Database URL with credentials", High, `\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/'"]+:([^@\s'"]+)@[^\s'"]+)`, 2, 0),
		r("generic-secret", "Generic secret assignment", Medium, `(?i)\b[\w.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|auth|credential)[\w.\-]*\s*(?:=|:|:=|=>)\s*['"]?([^\s'"#;,]{8,})['"]?`, 1, 3.2),
	}
}
