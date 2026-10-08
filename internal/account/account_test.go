package account

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Opsbreak/iampath/internal/policy"
)

const fixture = "../../testdata/account.json"

func load(t *testing.T) *Account {
	t.Helper()
	a, err := LoadFile(fixture)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	return a
}

func TestLoadFixture(t *testing.T) {
	a := load(t)
	if a.ID != "111122223333" {
		t.Errorf("account id = %q", a.ID)
	}
	if len(a.Users) != 16 || len(a.Roles) != 12 || len(a.Groups) != 3 {
		t.Errorf("users=%d roles=%d groups=%d", len(a.Users), len(a.Roles), len(a.Groups))
	}
	if len(a.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", a.Warnings)
	}
	for i := 1; i < len(a.Principals); i++ {
		if a.Principals[i-1].ARN > a.Principals[i].ARN {
			t.Fatal("principals not sorted by ARN")
		}
	}
}

func TestPrincipalModel(t *testing.T) {
	a := load(t)
	tests := []struct {
		ref        string
		kind       PrincipalKind
		identity   int
		boundary   bool
		groups     int
		profiles   int
		svcLinked  bool
		trust      bool
		attachedMP int
	}{
		{ref: "alice", kind: KindUser, identity: 2, groups: 1, attachedMP: 1},
		{ref: "user/carol", kind: KindUser, identity: 2, groups: 1, attachedMP: 2},
		{ref: "erin", kind: KindUser, identity: 2, groups: 1, boundary: true, attachedMP: 1},
		{ref: "heidi", kind: KindUser, identity: 1, groups: 1, attachedMP: 1},
		{ref: "svc-backup", kind: KindUser, identity: 1},
		{ref: "role/EC2-AppServer", kind: KindRole, identity: 2, profiles: 1, trust: true, attachedMP: 2},
		{ref: "arn:aws:iam::111122223333:role/service-role/LambdaAdminExec", kind: KindRole, identity: 1, trust: true, attachedMP: 1},
		{ref: "AWSServiceRoleForSupport", kind: KindRole, identity: 1, trust: true, svcLinked: true, attachedMP: 1},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			p, err := a.Find(tt.ref)
			if err != nil {
				t.Fatal(err)
			}
			if p.Kind != tt.kind {
				t.Errorf("kind = %s", p.Kind)
			}
			if n := len(p.IdentityPolicies()); n != tt.identity {
				t.Errorf("identity policies = %d, want %d", n, tt.identity)
			}
			if (p.BoundaryPolicy() != nil) != tt.boundary {
				t.Errorf("boundary = %v", p.BoundaryPolicy())
			}
			if len(p.Groups) != tt.groups {
				t.Errorf("groups = %d", len(p.Groups))
			}
			if len(p.InstanceProfiles) != tt.profiles {
				t.Errorf("profiles = %d", len(p.InstanceProfiles))
			}
			if p.ServiceLinked != tt.svcLinked {
				t.Errorf("service linked = %v", p.ServiceLinked)
			}
			if (p.Trust != nil) != tt.trust {
				t.Errorf("trust = %v", p.Trust != nil)
			}
			if n := len(p.AttachedManagedPolicies()); n != tt.attachedMP {
				t.Errorf("attached managed = %d, want %d", n, tt.attachedMP)
			}
		})
	}
}

func TestFind(t *testing.T) {
	a := load(t)
	tests := []struct {
		ref, want, err string
	}{
		{ref: "bob", want: "arn:aws:iam::111122223333:user/bob"},
		{ref: "BOB", want: "arn:aws:iam::111122223333:user/bob"},
		{ref: "role/OrgAdmin", want: "arn:aws:iam::111122223333:role/OrgAdmin"},
		{ref: "arn:aws:iam::111122223333:user/service/svc-backup", want: "arn:aws:iam::111122223333:user/service/svc-backup"},
		{ref: "user/OrgAdmin", err: "not found"},
		{ref: "mallory", err: "not found"},
	}
	for _, tt := range tests {
		p, err := a.Find(tt.ref)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("Find(%q) err = %v, want %q", tt.ref, err, tt.err)
			}
			continue
		}
		if err != nil || p.ARN != tt.want {
			t.Errorf("Find(%q) = %v, %v; want %s", tt.ref, p, err, tt.want)
		}
	}
}

func TestPolicyVersions(t *testing.T) {
	a := load(t)
	mp := a.Policies["arn:aws:iam::111122223333:policy/ReportingAnalystPolicy"]
	if mp == nil || len(mp.Versions) != 2 {
		t.Fatalf("expected 2 versions, got %+v", mp)
	}
	def := 0
	for _, v := range mp.Versions {
		if v.IsDefault {
			def++
			if v.ID != "v2" {
				t.Errorf("default version = %s", v.ID)
			}
		}
	}
	if def != 1 || mp.Default == nil {
		t.Errorf("default versions = %d", def)
	}
	if mp.IsAWSManaged() {
		t.Error("customer policy reported as AWS managed")
	}
	if !a.Policies["arn:aws:iam::aws:policy/AdministratorAccess"].IsAWSManaged() {
		t.Error("AdministratorAccess not AWS managed")
	}
}

func TestRequestContext(t *testing.T) {
	a := load(t)
	alice, _ := a.Find("alice")
	ctx := a.RequestContext(alice)
	if v, st := ctx.Get("aws:username"); st != policy.KeyPresent || v[0] != "alice" {
		t.Errorf("aws:username = %v %v", v, st)
	}
	if v, _ := ctx.Get("aws:PrincipalTag/team"); len(v) != 1 || v[0] != "platform" {
		t.Errorf("principal tag = %v", v)
	}
	if _, st := ctx.Get("aws:PrincipalTag/cost-center"); st != policy.KeyAbsent {
		t.Errorf("missing principal tag should be absent, got %v", st)
	}
	if _, st := ctx.Get("aws:SourceIp"); st != policy.KeyUnknown {
		t.Errorf("source ip should be unknown")
	}
	role, _ := a.Find("role/OrgAdmin")
	if _, st := a.RequestContext(role).Get("aws:username"); st != policy.KeyAbsent {
		t.Errorf("aws:username should be absent for roles")
	}
}

func TestLoadRawAPIEncodedDocuments(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	enc := url.QueryEscape(doc)
	raw := map[string]any{
		"UserDetailList": []any{map[string]any{
			"UserName": "u", "Arn": "arn:aws:iam::123456789012:user/u", "Path": "/",
			"UserPolicyList":          []any{map[string]any{"PolicyName": "p", "PolicyDocument": enc}},
			"AttachedManagedPolicies": []any{map[string]any{"PolicyName": "Missing", "PolicyArn": "arn:aws:iam::123456789012:policy/Missing"}},
			"GroupList":               []any{"NoSuchGroup"},
		}},
	}
	b, _ := json.Marshal(raw)
	a, err := Load(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := a.Find("u")
	if len(u.Inline) != 1 || u.Inline[0].Doc.Statement[0].Action[0] != "s3:*" {
		t.Fatalf("inline policy not decoded: %+v", u.Inline)
	}
	if len(a.Warnings) != 2 {
		t.Errorf("expected 2 warnings (missing policy, missing group), got %v", a.Warnings)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(strings.NewReader(`{}`)); err == nil {
		t.Error("expected error for empty details")
	}
	if _, err := Load(strings.NewReader(`not json`)); err == nil {
		t.Error("expected error for invalid json")
	}
	if _, err := LoadFile("does-not-exist.json"); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseSCPs(t *testing.T) {
	full := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	content, _ := json.Marshal(full)
	describe := `{"Policy":{"PolicySummary":{"Name":"FullAWSAccess","Arn":"arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess"},"Content":` + string(content) + `}}`
	tests := []struct {
		name  string
		in    string
		n     int
		first string
	}{
		{"single document", full, 1, "x.json#0"},
		{"array of documents", "[" + full + "," + full + "]", 2, "x.json#0"},
		{"describe-policy output", describe, 1, "FullAWSAccess"},
		{"array of describe-policy", "[" + describe + "]", 1, "FullAWSAccess"},
		{"named document", `{"Name":"Root","Document":` + full + `}`, 1, "Root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps, err := ParseSCPs([]byte(tt.in), "x.json")
			if err != nil {
				t.Fatal(err)
			}
			if len(ps) != tt.n || ps[0].Name != tt.first || ps[0].Kind != policy.KindSCP {
				t.Errorf("got %d policies, first %q", len(ps), ps[0].Name)
			}
		})
	}
	if _, err := ParseSCPs([]byte(" "), "x"); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestLoadSCPLevelWarnsWithoutAllow(t *testing.T) {
	a := load(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "deny-only.json")
	if err := os.WriteFile(p, []byte(`{"Statement":{"Effect":"Deny","Action":"iam:*","Resource":"*"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadSCPLevel(p); err != nil {
		t.Fatal(err)
	}
	if len(a.SCPLevels) != 1 || len(a.Warnings) != 1 || !strings.Contains(a.Warnings[0], "FullAWSAccess") {
		t.Errorf("levels=%d warnings=%v", len(a.SCPLevels), a.Warnings)
	}
	svc, _ := a.Find("AWSServiceRoleForSupport")
	if a.PolicyInput(svc).SCPLevels != nil {
		t.Error("SCPs must not apply to service-linked roles")
	}
}

func TestInventories(t *testing.T) {
	a := load(t)
	if err := a.LoadSCPLevel("../../testdata/scp-root.json"); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadLambdaFunctions("../../testdata/lambda-functions.json"); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadEC2Instances("../../testdata/ec2-instances.json"); err != nil {
		t.Fatal(err)
	}
	if err := a.LoadCodeBuildProjects("../../testdata/codebuild-projects.json"); err != nil {
		t.Fatal(err)
	}
	if len(a.SCPLevels) != 1 || len(a.SCPLevels[0]) != 2 {
		t.Errorf("scp levels = %v", a.SCPLevels)
	}
	if len(a.Lambdas) != 2 || a.Lambdas[0].RoleARN != "arn:aws:iam::111122223333:role/service-role/LambdaAdminExec" {
		t.Errorf("lambdas = %+v", a.Lambdas)
	}
	if len(a.Instances) != 2 || a.Instances[0].ARN != "arn:aws:ec2:ca-central-1:111122223333:instance/i-0a1b2c3d4e5f60718" {
		t.Errorf("instances = %+v", a.Instances)
	}
	if r := a.RoleForInstanceProfile(a.Instances[0].InstanceProfileARN); r == nil || r.Name != "EC2-AdminInstance" {
		t.Errorf("instance profile role = %v", r)
	}
	if len(a.CodeBuild) != 1 || a.CodeBuild[0].ServiceRoleARN == "" {
		t.Errorf("codebuild = %+v", a.CodeBuild)
	}
	for _, f := range []func(string) error{a.LoadLambdaFunctions, a.LoadEC2Instances, a.LoadCodeBuildProjects, a.LoadSCPLevel} {
		if err := f("missing.json"); err == nil {
			t.Error("expected error for missing file")
		}
	}
}
