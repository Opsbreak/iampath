package escalation

import (
	"strings"
	"testing"

	"github.com/Opsbreak/iampath/internal/account"
)

const td = "../../testdata/"

func loadFixture(t testing.TB, full bool) *account.Account {
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
	return a
}

func techniqueIDs(p Path) string {
	var ids []string
	for _, h := range p.Hops {
		ids = append(ids, h.Technique.ID)
	}
	return strings.Join(ids, ",")
}

func TestFixtureAdmins(t *testing.T) {
	res := Analyze(loadFixture(t, true), Options{K: 3})
	var got []string
	for _, a := range res.Admins {
		got = append(got, a.Principal.ShortName())
	}
	want := "role/BreakGlassAdmin,role/EC2-AdminInstance,role/OrgAdmin,role/CodeBuildDeployRole,role/LambdaAdminExec,user/heidi"
	if strings.Join(got, ",") != want {
		t.Errorf("admins = %s\nwant    %s", strings.Join(got, ","), want)
	}
}

// TestFixturePaths checks the best path for every principal in the
// fixture, with and without the optional inputs (SCPs and inventories).
func TestFixturePaths(t *testing.T) {
	tests := []struct {
		principal string
		full      bool
		// techniques is the comma-separated technique sequence of the best
		// path, or "" when no path is expected.
		techniques  string
		cost        int
		conditional bool
	}{
		{"alice", false, "IAM-001", 1, false},
		{"bob", false, "STS-001,STS-001,STS-001,ADMIN", 3, false},
		{"carol", false, "LAMBDA-001,ADMIN", 2, false},
		{"dave", false, "STS-001,ADMIN", 4, true},
		{"erin", false, "", 0, false}, // blocked by permissions boundary
		{"frank", false, "IAM-003", 1, false},
		{"frank", true, "", 0, false}, // blocked by SCP
		{"grace", false, "", 0, false},
		{"ivan", false, "IAM-010,ADMIN", 1, false},
		{"judy", false, "IAM-009", 1, false},
		{"ken", false, "", 0, false}, // PassRole limited to lambda.amazonaws.com
		{"ken", true, "SSM-001,ADMIN", 5, true},
		{"olivia", false, "", 0, false},
		{"olivia", true, "LAMBDA-003,ADMIN", 2, false},
		{"peggy", false, "IAM-002", 1, false},
		{"peggy", true, "IAM-002", 1, false},
		{"quinn", false, "", 0, false},
		{"quinn", true, "CB-001,ADMIN", 2, false},
		{"trent", false, "IAM-013,ADMIN", 2, false},
		{"svc-backup", true, "", 0, false},
		{"role/CI-Deployer", false, "STS-001,STS-001,ADMIN", 2, false},
		{"role/InfraAutomation", false, "STS-001,ADMIN", 1, false},
		{"role/EC2-AppServer", false, "STS-001,ADMIN", 4, true},
		{"role/EC2-AppServer", true, "SSM-001,ADMIN", 2, false},
		{"role/LambdaThumbnailer", true, "", 0, false},
		{"role/ReadOnlyAuditor", true, "", 0, false},
		{"role/GlueETLRole", true, "", 0, false},
	}
	results := map[bool]*Result{}
	for _, full := range []bool{false, true} {
		results[full] = Analyze(loadFixture(t, full), Options{K: 3, MaxHops: 8})
	}
	for _, tt := range tests {
		name := tt.principal
		if tt.full {
			name += "/full"
		}
		t.Run(name, func(t *testing.T) {
			res := results[tt.full]
			var f *Finding
			for i := range res.Findings {
				if strings.EqualFold(res.Findings[i].Principal.Name, strings.TrimPrefix(strings.TrimPrefix(tt.principal, "role/"), "user/")) {
					f = &res.Findings[i]
				}
			}
			if tt.techniques == "" {
				if f != nil {
					t.Fatalf("expected no path, got %s", techniqueIDs(f.Paths[0]))
				}
				found := false
				for _, p := range res.NoPath {
					if strings.HasSuffix(tt.principal, p.Name) {
						found = true
					}
				}
				if !found {
					t.Errorf("principal not listed in NoPath")
				}
				return
			}
			if f == nil {
				t.Fatalf("expected path %s, got none", tt.techniques)
			}
			best := f.Paths[0]
			if got := techniqueIDs(best); got != tt.techniques {
				t.Errorf("techniques = %s, want %s", got, tt.techniques)
			}
			if best.Cost != tt.cost {
				t.Errorf("cost = %d, want %d", best.Cost, tt.cost)
			}
			if best.Conditional != tt.conditional {
				t.Errorf("conditional = %v, want %v", best.Conditional, tt.conditional)
			}
			for _, p := range f.Paths {
				if p.Hops[len(p.Hops)-1].To != AdminNode {
					t.Errorf("path does not end at ADMIN")
				}
				if p.Cost < best.Cost {
					t.Errorf("paths not ordered by cost")
				}
			}
		})
	}
}

func TestFixtureSummary(t *testing.T) {
	tests := []struct {
		full             bool
		findings, noPath int
	}{
		{false, 12, 9},
		{true, 14, 7},
	}
	for _, tt := range tests {
		res := Analyze(loadFixture(t, tt.full), Options{K: 3})
		if len(res.Findings) != tt.findings || len(res.NoPath) != tt.noPath {
			t.Errorf("full=%v findings=%d noPath=%d, want %d/%d", tt.full, len(res.Findings), len(res.NoPath), tt.findings, tt.noPath)
		}
		if len(res.Cycles) != 1 || len(res.Cycles[0]) != 2 {
			t.Errorf("cycles = %v", res.Cycles)
		}
	}
}

func TestFixtureMultiplePaths(t *testing.T) {
	a := loadFixture(t, false)
	ivan, _ := a.Find("ivan")
	res := Analyze(a, Options{K: 3, From: []*account.Principal{ivan}})
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Findings))
	}
	ps := res.Findings[0].Paths
	if len(ps) != 3 {
		t.Fatalf("paths = %d, want 3", len(ps))
	}
	seen := map[string]bool{}
	for _, p := range ps {
		k := techniqueIDs(p) + p.Hops[0].To
		if seen[k] {
			t.Errorf("duplicate path %s", k)
		}
		seen[k] = true
	}
	if ps[0].Cost != 1 || ps[1].Cost != 2 || ps[2].Cost != 2 {
		t.Errorf("costs = %d,%d,%d", ps[0].Cost, ps[1].Cost, ps[2].Cost)
	}
}

func TestFixtureMaxHops(t *testing.T) {
	a := loadFixture(t, false)
	bob, _ := a.Find("bob")
	// The final "already admin" pseudo hop does not count as a step.
	if res := Analyze(a, Options{K: 1, MaxHops: 2, From: []*account.Principal{bob}}); len(res.Findings) != 0 {
		t.Errorf("bob's 3-step path should exceed max-hops 2")
	}
	if res := Analyze(a, Options{K: 1, MaxHops: 3, From: []*account.Principal{bob}}); len(res.Findings) != 1 {
		t.Errorf("expected bob's path with max-hops 3")
	}
}

func TestPassRoleEdgeRespectsConditions(t *testing.T) {
	a := loadFixture(t, false)
	an := NewAnalyzer(a)
	ken, _ := a.Find("ken")
	for _, e := range an.becomeEdges(ken) {
		if e.Technique.Category == CategoryPassRole {
			t.Errorf("unexpected PassRole edge %s -> %s", e.Technique.ID, e.To)
		}
	}
	carol, _ := a.Find("carol")
	var targets []string
	for _, e := range an.becomeEdges(carol) {
		if e.Technique.ID == "LAMBDA-001" {
			targets = append(targets, e.To)
		}
	}
	if strings.Join(targets, ",") != "arn:aws:iam::111122223333:role/service-role/LambdaAdminExec,arn:aws:iam::111122223333:role/service-role/LambdaThumbnailer" {
		t.Errorf("carol LAMBDA-001 targets = %v", targets)
	}
}
