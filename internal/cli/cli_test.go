package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const td = "../../testdata/"

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRun(t *testing.T) {
	acct := td + "account.json"
	full := []string{"--scp", td + "scp-root.json", "--lambda-functions", td + "lambda-functions.json",
		"--ec2-instances", td + "ec2-instances.json", "--codebuild-projects", td + "codebuild-projects.json"}
	tests := []struct {
		name     string
		args     []string
		code     int
		stdout   []string // substrings expected on stdout
		stderr   []string // substrings expected on stderr
		noStdout []string
	}{
		{name: "no args", args: nil, code: ExitUsage, stderr: []string{"Usage:"}},
		{name: "help", args: []string{"help"}, code: ExitOK, stdout: []string{"iampath paths"}},
		{name: "version", args: []string{"version"}, code: ExitOK, stdout: []string{"iampath 0.1.0"}},
		{name: "unknown command", args: []string{"frobnicate"}, code: ExitUsage, stderr: []string{"unknown command"}},
		{name: "paths requires input", args: []string{"paths"}, code: ExitUsage, stderr: []string{"--input is required"}},
		{name: "paths missing file", args: []string{"paths", "-i", "nope.json"}, code: ExitError},
		{name: "paths bad format", args: []string{"paths", "-i", acct, "--format", "xml"}, code: ExitUsage, stderr: []string{"unknown format"}},
		{name: "paths bad k", args: []string{"paths", "-i", acct, "-k", "0"}, code: ExitUsage},
		{name: "paths unknown flag", args: []string{"paths", "--bogus"}, code: ExitUsage},
		{name: "paths flag help", args: []string{"paths", "-h"}, code: ExitOK, stderr: []string{"-fail-on-paths"}},
		{
			name: "paths text", args: []string{"paths", "-i", acct}, code: ExitOK,
			stdout: []string{"user/bob --[STS-001 AssumeRole]--> role/CI-Deployer", "No path to ADMIN", "role/CI-Deployer <-> role/InfraAutomation"},
		},
		{
			name: "paths fail-on-paths", args: []string{"paths", "-i", acct, "--fail-on-paths", "-q"}, code: ExitPathsFound,
			stderr: []string{"can escalate to administrator"},
		},
		{
			name: "paths from no-path principal passes CI gate", args: []string{"paths", "-i", acct, "--from", "grace", "--fail-on-paths"}, code: ExitOK,
			stdout: []string{"0 principals can reach ADMIN"},
		},
		{
			name: "paths from comma list", args: append([]string{"paths", "-i", acct, "--from", "olivia,quinn"}, full...), code: ExitOK,
			stdout: []string{"LAMBDA-003 UpdateFunctionCode", "CB-001 CodeBuild StartBuild"}, noStdout: []string{"user/alice"},
		},
		{name: "paths from unknown principal", args: []string{"paths", "-i", acct, "--from", "mallory"}, code: ExitUsage, stderr: []string{"not found"}},
		{name: "paths unexpected positional", args: []string{"paths", "-i", acct, "extra"}, code: ExitUsage},
		{name: "paths json", args: []string{"paths", "-i", acct, "--format", "json"}, code: ExitOK, stdout: []string{`"accountId": "111122223333"`}},
		{name: "paths dot", args: []string{"paths", "-i", acct, "--format", "dot"}, code: ExitOK, stdout: []string{"digraph iampath"}},
		{name: "paths mermaid", args: []string{"paths", "-i", acct, "--format", "mermaid"}, code: ExitOK, stdout: []string{"flowchart LR"}},
		{name: "paths sarif", args: []string{"paths", "-i", acct, "--format", "sarif"}, code: ExitOK, stdout: []string{`"version": "2.1.0"`}},
		{
			name: "who-can", args: []string{"who-can", "-i", acct, "iam:PassRole", "arn:aws:iam::111122223333:role/service-role/LambdaAdminExec"}, code: ExitOK,
			stdout: []string{"user/carol", "conditional", "user/heidi"},
		},
		{
			name: "who-can flags after positionals", args: []string{"who-can", "iam:CreatePolicyVersion", "arn:aws:iam::111122223333:policy/DeveloperPolicy", "-i", acct}, code: ExitOK,
			stdout: []string{"user/alice", "allow"},
		},
		{
			name: "who-can show denied", args: []string{"who-can", "-i", acct, "--show-denied", "iam:PutUserPolicy", "arn:aws:iam::111122223333:user/erin"}, code: ExitOK,
			stdout: []string{"not allowed by permissions boundary DeveloperBoundary"},
		},
		{name: "who-can missing action", args: []string{"who-can", "-i", acct}, code: ExitUsage},
		{
			name: "explain boundary", args: []string{"explain", "-i", acct, "erin", "iam:PutUserPolicy", "arn:aws:iam::111122223333:user/erin"}, code: ExitOK,
			stdout: []string{"Decision: ImplicitDeny", "permissions boundary", "SelfServiceIAM (inline) stmt ManageOwnUserPolicies: Allow"},
		},
		{
			name: "explain scp", args: []string{"explain", "-i", acct, "--scp", td + "scp-root.json", "frank", "iam:AttachUserPolicy", "arn:aws:iam::111122223333:user/frank"}, code: ExitOK,
			stdout: []string{"Decision: ExplicitDeny", "DenyIAMUserPolicyChanges"},
		},
		{
			name: "explain trust with context override", args: []string{"explain", "-i", acct, "--context", "aws:MultiFactorAuthPresent=true", "dave", "sts:AssumeRole", "arn:aws:iam::111122223333:role/BreakGlassAdmin"}, code: ExitOK,
			stdout: []string{"Decision: Allow", "Trust policy of role/BreakGlassAdmin: trust policy allows (true)"},
		},
		{
			name: "explain trust conditional", args: []string{"explain", "-i", acct, "dave", "sts:AssumeRole", "arn:aws:iam::111122223333:role/BreakGlassAdmin"}, code: ExitOK,
			stdout: []string{"trust policy allows (unknown)", "aws:MultiFactorAuthPresent"},
		},
		{name: "explain bad context", args: []string{"explain", "-i", acct, "--context", "novalue", "dave", "s3:GetObject", "*"}, code: ExitUsage},
		{name: "explain wrong arity", args: []string{"explain", "-i", acct, "dave"}, code: ExitUsage},
		{name: "explain unknown principal", args: []string{"explain", "-i", acct, "zed", "s3:GetObject", "*"}, code: ExitUsage},
		{name: "techniques", args: []string{"techniques"}, code: ExitOK, stdout: []string{"IAM-001", "SSM-002", "needs --ec2-instances"}},
		{name: "techniques markdown", args: []string{"techniques", "--format", "markdown"}, code: ExitOK, stdout: []string{"| ID | Technique |"}},
		{name: "techniques bad format", args: []string{"techniques", "--format", "pdf"}, code: ExitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := run(tt.args...)
			if code != tt.code {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.code, out, errOut)
			}
			for _, s := range tt.stdout {
				if !strings.Contains(out, s) {
					t.Errorf("stdout missing %q\n%s", s, out)
				}
			}
			for _, s := range tt.noStdout {
				if strings.Contains(out, s) {
					t.Errorf("stdout unexpectedly contains %q", s)
				}
			}
			for _, s := range tt.stderr {
				if !strings.Contains(errOut, s) {
					t.Errorf("stderr missing %q\n%s", s, errOut)
				}
			}
		})
	}
}

func TestOutputFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.json")
	code, _, errOut := run("paths", "-i", td+"account.json", "--format", "json", "-o", out)
	if code != ExitOK {
		t.Fatalf("code %d: %s", code, errOut)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Findings []any `json:"findings"`
	}
	if err := json.Unmarshal(b, &v); err != nil || len(v.Findings) == 0 {
		t.Errorf("bad report file: %v", err)
	}
}

func TestTechniquesJSON(t *testing.T) {
	code, out, _ := run("techniques", "--format", "json")
	if code != ExitOK {
		t.Fatal(code)
	}
	var ts []techniqueJSON
	if err := json.Unmarshal([]byte(out), &ts); err != nil {
		t.Fatal(err)
	}
	if len(ts) < 20 {
		t.Errorf("only %d techniques", len(ts))
	}
}

func TestLoaderWarningsPrinted(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "deny.json")
	if err := os.WriteFile(p, []byte(`{"Statement":{"Effect":"Deny","Action":"iam:*","Resource":"*"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, errOut := run("paths", "-i", td+"account.json", "--scp", p)
	if !strings.Contains(errOut, "warning: SCP file") {
		t.Errorf("expected SCP warning, got %q", errOut)
	}
	_, _, errOut = run("paths", "-i", td+"account.json", "--scp", p, "--quiet")
	if strings.Contains(errOut, "warning") {
		t.Errorf("--quiet should suppress warnings")
	}
}
