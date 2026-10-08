package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Opsbreak/iampath/internal/account"
	"github.com/Opsbreak/iampath/internal/escalation"
)

var update = flag.Bool("update", false, "rewrite golden files")

const td = "../../testdata/"

func analyse(t *testing.T, full bool) (*escalation.Result, *account.Account) {
	t.Helper()
	a, err := account.LoadFile(td + "account.json")
	if err != nil {
		t.Fatal(err)
	}
	if full {
		for _, err := range []error{
			a.LoadSCPLevel(td + "scp-root.json"),
			a.LoadLambdaFunctions(td + "lambda-functions.json"),
			a.LoadEC2Instances(td + "ec2-instances.json"),
			a.LoadCodeBuildProjects(td + "codebuild-projects.json"),
		} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return escalation.Analyze(a, escalation.Options{K: 3, MaxHops: 8}), a
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(td, "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run go test ./internal/report -update): %v", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file; run `go test ./internal/report -update` and review the diff.\n--- got ---\n%s", name, got)
	}
}

func TestGolden(t *testing.T) {
	tests := []struct {
		file   string
		format string
		full   bool
	}{
		{"paths-baseline.txt", "text", false},
		{"paths-full.txt", "text", true},
		{"paths-full.json", "json", true},
		{"paths-full.dot", "dot", true},
		{"paths-full.mmd", "mermaid", true},
		{"paths-full.sarif", "sarif", true},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			res, a := analyse(t, tt.full)
			var buf bytes.Buffer
			if err := Write(&buf, tt.format, res, a, Meta{Input: "testdata/account.json"}); err != nil {
				t.Fatal(err)
			}
			golden(t, tt.file, buf.Bytes())
		})
	}
}

func TestJSONIsValid(t *testing.T) {
	res, a := analyse(t, true)
	for _, f := range []string{"json", "sarif"} {
		var buf bytes.Buffer
		if err := Write(&buf, f, res, a, Meta{}); err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
			t.Errorf("%s output is not valid JSON: %v", f, err)
		}
	}
	r := BuildJSON(res, Meta{acct: a})
	if r.Summary.PrincipalsWithPaths != len(res.Findings) || r.Summary.Admins != len(res.Admins) {
		t.Errorf("summary mismatch: %+v", r.Summary)
	}
}

func TestSARIFStructure(t *testing.T) {
	res, a := analyse(t, true)
	var buf bytes.Buffer
	if err := SARIF(&buf, res, Meta{acct: a, Input: `testdata\account.json`}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad SARIF header")
	}
	rules := map[string]bool{}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		rules[r.ID] = true
	}
	levels := map[string]int{}
	for _, r := range log.Runs[0].Results {
		if !rules[r.RuleID] {
			t.Errorf("result references undefined rule %s", r.RuleID)
		}
		levels[r.Level]++
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "testdata/account.json" {
			t.Errorf("uri = %q", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
	}
	if len(log.Runs[0].Results) != len(res.Findings) || levels["warning"] == 0 || levels["error"] == 0 {
		t.Errorf("results=%d levels=%v", len(log.Runs[0].Results), levels)
	}
}

func TestRenderPath(t *testing.T) {
	res, a := analyse(t, false)
	for _, f := range res.Findings {
		if f.Principal.Name != "bob" {
			continue
		}
		got := RenderPath(a, f.Principal, f.Paths[0])
		want := "user/bob --[STS-001 AssumeRole]--> role/CI-Deployer --[STS-001 AssumeRole]--> role/InfraAutomation --[STS-001 AssumeRole]--> role/OrgAdmin ==> ADMIN"
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
		return
	}
	t.Fatal("bob not found")
}

func TestUnknownFormat(t *testing.T) {
	res, a := analyse(t, false)
	if err := Write(&bytes.Buffer{}, "xml", res, a, Meta{}); err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("err = %v", err)
	}
}

func TestEmptyResult(t *testing.T) {
	res := &escalation.Result{AccountID: "1"}
	for _, f := range Formats {
		var buf bytes.Buffer
		if err := Write(&buf, f, res, nil, Meta{}); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%s: empty output", f)
		}
	}
}
