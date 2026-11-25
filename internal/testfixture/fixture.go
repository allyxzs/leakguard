// Package testfixture builds deterministic, synthetic detector inputs at runtime.
// Nothing here is issued by a service or used to authenticate. Keep full
// credential-shaped strings out of source files, examples and test failure logs.
package testfixture

import "strings"

// Value is a high-entropy-looking local test value, assembled only in memory.
func Value() string {
	return strings.Join([]string{"fixture", "Only", "012345", "AbCdEf"}, "-")
}

// Sample returns an input that exercises a built-in rule without storing a
// complete provider-shaped credential in the repository.
func Sample(rule string) string {
	zeros := func(n int) string { return strings.Repeat("0", n) }
	join := func(parts ...string) string { return strings.Join(parts, "") }
	switch rule {
	case "aws-access-key":
		return join("AK", "IA", zeros(16))
	case "aws-secret-key":
		return join("aws_", "secret", " = ", strings.Repeat("aB3dE6gH9jK2mN5pQ8sT", 2))
	case "github-token":
		return join("gh", "p_", zeros(36))
	case "github-fine-grained":
		return join("github", "_pat_", zeros(82))
	case "gitlab-token":
		return join("gl", "pat-", zeros(20))
	case "slack-token":
		return join("xox", "b-", zeros(12))
	case "slack-webhook":
		return join("https://hooks.slack.com/", "services/", "T", zeros(9), "/B", zeros(9), "/", zeros(24))
	case "stripe-key":
		return join("sk", "_live_", zeros(24))
	case "google-api-key":
		return join("AI", "za", zeros(35))
	case "openai-key":
		return join("sk", "-", zeros(20), "T3Bl", "bkFJ", zeros(20))
	case "anthropic-key":
		return join("sk", "-ant-", zeros(32))
	case "twilio-key":
		return join("S", "K", zeros(32))
	case "sendgrid-key":
		return join("S", "G.", zeros(22), ".", zeros(43))
	case "npm-token":
		return join("np", "m_", zeros(36))
	case "discord-webhook":
		return join("https://discord.com/", "api/webhooks/", zeros(18), "/", zeros(32))
	case "private-key":
		return join("-----", "BEGIN RSA ", "PRIVATE KEY", "-----")
	case "jwt":
		return join("ey", "J", zeros(12), ".ey", "J", zeros(12), ".", zeros(12))
	case "db-connection-string":
		return join("postgres", "://fixture:", Value(), "@localhost:5432/example")
	case "generic-secret":
		return join("token", " = ", Value())
	default:
		panic("missing synthetic fixture for rule: " + rule)
	}
}
