package escalation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Opsbreak/iampath/internal/account"
)

const acct = "123456789012"

type roleSpec struct {
	name     string
	trust    string // JSON principal object, e.g. {"Service":"lambda.amazonaws.com"}
	policy   string // JSON statement array
	profile  bool
	boundary string // policy name of a managed boundary
}

type env struct {
	attacker       string // JSON statement array for user "attacker"
	attackerGroups []string
	groups         map[string]string // group name -> statements
	roles          []roleSpec
	users          map[string]string // extra users -> statements
	boundaries     map[string]string // managed policy name -> statements
}

func stmts(s string) map[string]any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		panic(s + ": " + err.Error())
	}
	return map[string]any{"Version": "2012-10-17", "Statement": v}
}

func (e env) build(t *testing.T) *account.Account {
	t.Helper()
	inl := func(name, s string) []any {
		if s == "" {
			return []any{}
		}
		return []any{map[string]any{"PolicyName": name, "PolicyDocument": stmts(s)}}
	}
	users := []any{map[string]any{
		"UserName": "attacker", "Path": "/", "UserId": "AIDAATTACKER", "Arn": "arn:aws:iam::" + acct + ":user/attacker",
		"UserPolicyList": inl("attacker-policy", e.attacker), "GroupList": e.attackerGroups,
	}}
	for name, s := range e.users {
		users = append(users, map[string]any{
			"UserName": name, "Path": "/", "Arn": "arn:aws:iam::" + acct + ":user/" + name,
			"UserPolicyList": inl(name+"-policy", s),
		})
	}
	var groups []any
	for name, s := range e.groups {
		groups = append(groups, map[string]any{
			"GroupName": name, "Path": "/", "Arn": "arn:aws:iam::" + acct + ":group/" + name,
			"GroupPolicyList": inl(name+"-policy", s),
		})
	}
	var policies []any
	for name, s := range e.boundaries {
		policies = append(policies, map[string]any{
			"PolicyName": name, "Arn": "arn:aws:iam::" + acct + ":policy/" + name, "DefaultVersionId": "v1",
			"PolicyVersionList": []any{map[string]any{"VersionId": "v1", "IsDefaultVersion": true, "Document": stmts(s)}},
		})
	}
	var roles []any
	for _, r := range e.roles {
		var trust any
		_ = json.Unmarshal([]byte(r.trust), &trust)
		rm := map[string]any{
			"RoleName": r.name, "Path": "/", "Arn": "arn:aws:iam::" + acct + ":role/" + r.name,
			"AssumeRolePolicyDocument": map[string]any{"Version": "2012-10-17", "Statement": []any{
				map[string]any{"Effect": "Allow", "Principal": trust, "Action": "sts:AssumeRole"}}},
			"RolePolicyList": inl(r.name+"-policy", r.policy),
		}
		if r.profile {
			rm["InstanceProfileList"] = []any{map[string]any{"InstanceProfileName": r.name, "Arn": "arn:aws:iam::" + acct + ":instance-profile/" + r.name}}
		}
		if r.boundary != "" {
			rm["PermissionsBoundary"] = map[string]any{"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::" + acct + ":policy/" + r.boundary}
		}
		roles = append(roles, rm)
	}
	b, err := json.Marshal(map[string]any{"UserDetailList": users, "GroupDetailList": groups, "RoleDetailList": roles, "Policies": policies})
	if err != nil {
		t.Fatal(err)
	}
	a, err := account.Load(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const adminStmt = `[{"Effect":"Allow","Action":"*","Resource":"*"}]`

func svc(s string) string { return `{"Service":"` + s + `"}` }

// TestTechniques exercises each technique against a minimal account and
// checks the first hop of the best path from user "attacker".
func TestTechniques(t *testing.T) {
	admin := func(name, service string) roleSpec {
		return roleSpec{name: name, trust: svc(service), policy: adminStmt}
	}
	tests := []struct {
		name string
		env  env
		want string // first technique ID, "" for no path
		cond bool
	}{
		{
			name: "LAMBDA-001",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "lambda.amazonaws.com")}},
			want: "LAMBDA-001",
		},
		{
			name: "LAMBDA-002 via event source mapping",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction","lambda:CreateEventSourceMapping"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "lambda.amazonaws.com")}},
			want: "LAMBDA-002",
		},
		{
			name: "Lambda without a way to invoke",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "lambda.amazonaws.com")}},
		},
		{
			name: "EC2-001 with instance profile",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}]`,
				roles: []roleSpec{{name: "Target", trust: svc("ec2.amazonaws.com"), policy: adminStmt, profile: true}}},
			want: "EC2-001",
		},
		{
			name: "EC2 role without instance profile",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "ec2.amazonaws.com")}},
		},
		{
			name: "CFN-001",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","cloudformation:CreateStack"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "cloudformation.amazonaws.com")}},
			want: "CFN-001",
		},
		{
			name: "GLUE-001",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","glue:CreateDevEndpoint"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "glue.amazonaws.com")}},
			want: "GLUE-001",
		},
		{
			name: "GLUE-002",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","glue:CreateJob","glue:StartJobRun"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "glue.amazonaws.com")}},
			want: "GLUE-002",
		},
		{
			name: "DP-001",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","datapipeline:CreatePipeline","datapipeline:PutPipelineDefinition","datapipeline:ActivatePipeline"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "datapipeline.amazonaws.com")}},
			want: "DP-001",
		},
		{
			name: "SM-001",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","sagemaker:CreateNotebookInstance","sagemaker:CreatePresignedNotebookInstanceUrl"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "sagemaker.amazonaws.com")}},
			want: "SM-001",
		},
		{
			name: "ECS-001",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","ecs:RegisterTaskDefinition","ecs:RunTask"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "ecs-tasks.amazonaws.com")}},
			want: "ECS-001",
		},
		{
			name: "CB-002",
			env: env{attacker: `[{"Effect":"Allow","Action":["iam:PassRole","codebuild:CreateProject","codebuild:StartBuild"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "codebuild.amazonaws.com")}},
			want: "CB-002",
		},
		{
			name: "PassRole restricted to another service",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}},{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "lambda.amazonaws.com")}},
		},
		{
			name: "PassRole restricted to another role",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/Other"},{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "lambda.amazonaws.com")}},
		},
		{
			name: "PassRole with unknown condition is conditional",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"ca-central-1"}}},{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "lambda.amazonaws.com")}},
			want: "LAMBDA-001", cond: true,
		},
		{
			name: "IAM-003 AttachUserPolicy self",
			env:  env{attacker: `[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"arn:aws:iam::123456789012:user/attacker"}]`},
			want: "IAM-003",
		},
		{
			name: "IAM-003 limited by iam:PolicyARN",
			env:  env{attacker: `[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*","Condition":{"ArnEquals":{"iam:PolicyARN":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}}]`},
		},
		{
			name: "IAM-003 allowed by iam:PolicyARN",
			env:  env{attacker: `[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*","Condition":{"ArnLike":{"iam:PolicyARN":"arn:aws:iam::aws:policy/Admin*"}}}]`},
			want: "IAM-003",
		},
		{
			name: "IAM-004 AttachGroupPolicy on own group",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:AttachGroupPolicy","Resource":"arn:aws:iam::123456789012:group/devs"}]`,
				attackerGroups: []string{"devs"}, groups: map[string]string{"devs": `[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]`}},
			want: "IAM-004",
		},
		{
			name: "IAM-006 PutUserPolicy self",
			env:  env{attacker: `[{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"arn:aws:iam::*:user/${aws:username}"}]`},
			want: "IAM-006",
		},
		{
			name: "IAM-007 PutGroupPolicy on own group",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:PutGroupPolicy","Resource":"*"}]`,
				attackerGroups: []string{"devs"}, groups: map[string]string{"devs": `[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]`}},
			want: "IAM-007",
		},
		{
			name: "IAM-008 PutRolePolicy on assumable role (composite)",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"arn:aws:iam::123456789012:role/Dev"}]`,
				roles: []roleSpec{{name: "Dev", trust: `{"AWS":"arn:aws:iam::123456789012:user/attacker"}`, policy: `[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]`}}},
			want: "IAM-008",
		},
		{
			name: "IAM-005 AttachRolePolicy on role not assumable",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]`,
				roles: []roleSpec{{name: "Dev", trust: svc("ec2.amazonaws.com"), policy: `[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]`}}},
		},
		{
			name: "IAM-009 AddUserToGroup admin group",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:AddUserToGroup","Resource":"*"}]`,
				groups: map[string]string{"admins": adminStmt, "readers": `[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]`}},
			want: "IAM-009",
		},
		{
			name: "IAM-009 only non-admin groups",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:AddUserToGroup","Resource":"arn:aws:iam::123456789012:group/readers"}]`,
				groups: map[string]string{"admins": adminStmt, "readers": `[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]`}},
		},
		{
			name: "IAM-010 CreateAccessKey on admin user",
			env:  env{attacker: `[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*"}]`, users: map[string]string{"boss": adminStmt}},
			want: "IAM-010",
		},
		{
			name: "IAM-011 CreateLoginProfile on admin user",
			env:  env{attacker: `[{"Effect":"Allow","Action":"iam:CreateLoginProfile","Resource":"arn:aws:iam::123456789012:user/boss"}]`, users: map[string]string{"boss": adminStmt}},
			want: "IAM-011",
		},
		{
			name: "IAM-012 UpdateLoginProfile on admin user",
			env:  env{attacker: `[{"Effect":"Allow","Action":"iam:UpdateLoginProfile","Resource":"*"}]`, users: map[string]string{"boss": adminStmt}},
			want: "IAM-012",
		},
		{
			name: "IAM-013 UpdateAssumeRolePolicy",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy","Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "ec2.amazonaws.com")}},
			want: "IAM-013",
		},
		{
			name: "IAM-013 blocked by explicit deny on AssumeRole",
			env: env{attacker: `[{"Effect":"Allow","Action":"iam:UpdateAssumeRolePolicy","Resource":"*"},{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}]`,
				roles: []roleSpec{admin("Target", "ec2.amazonaws.com")}},
		},
		{
			name: "STS-001 trust names user directly (no identity policy needed)",
			env:  env{attacker: `[]`, roles: []roleSpec{{name: "Target", trust: `{"AWS":"arn:aws:iam::123456789012:user/attacker"}`, policy: adminStmt}}},
			want: "STS-001",
		},
		{
			name: "STS-001 trust names account but no identity permission",
			env:  env{attacker: `[]`, roles: []roleSpec{{name: "Target", trust: `{"AWS":"arn:aws:iam::123456789012:root"}`, policy: adminStmt}}},
		},
		{
			name: "STS-001 trust names account with identity permission",
			env: env{attacker: `[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::123456789012:role/Target"}]`,
				roles: []roleSpec{{name: "Target", trust: `{"AWS":"123456789012"}`, policy: adminStmt}}},
			want: "STS-001",
		},
		{
			name: "STS-001 wildcard trust",
			env:  env{attacker: `[]`, roles: []roleSpec{{name: "Target", trust: `"*"`, policy: adminStmt}}},
			want: "STS-001",
		},
		{
			name: "STS-001 direct trust blocked by explicit deny",
			env: env{attacker: `[{"Effect":"Deny","Action":"sts:*","Resource":"*"}]`,
				roles: []roleSpec{{name: "Target", trust: `{"AWS":"arn:aws:iam::123456789012:user/attacker"}`, policy: adminStmt}}},
		},
		{
			name: "role chain blocked by role permissions boundary",
			env: env{attacker: `[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::123456789012:role/Hop"}]`,
				roles: []roleSpec{
					{name: "Hop", trust: `{"AWS":"arn:aws:iam::123456789012:root"}`, policy: `[]`, boundary: "S3Only"},
					{name: "Target", trust: `{"AWS":"arn:aws:iam::123456789012:role/Hop"}`, policy: adminStmt},
				},
				boundaries: map[string]string{"S3Only": `[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]`}},
		},
		{
			name: "role chain without boundary",
			env: env{attacker: `[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::123456789012:role/Hop"}]`,
				roles: []roleSpec{
					{name: "Hop", trust: `{"AWS":"arn:aws:iam::123456789012:root"}`, policy: `[]`},
					{name: "Target", trust: `{"AWS":"arn:aws:iam::123456789012:role/Hop"}`, policy: adminStmt},
				}},
			want: "STS-001",
		},
		{
			name: "PowerUserAccess is not admin and has no path",
			env:  env{attacker: `[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"}]`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.env.build(t)
			attacker, err := a.Find("attacker")
			if err != nil {
				t.Fatal(err)
			}
			res := Analyze(a, Options{K: 1, From: []*account.Principal{attacker}})
			if tt.want == "" {
				if len(res.Findings) != 0 {
					t.Fatalf("expected no path, got %s", techniqueIDs(res.Findings[0].Paths[0]))
				}
				return
			}
			if len(res.Findings) != 1 {
				t.Fatalf("expected a path starting with %s, got none", tt.want)
			}
			p := res.Findings[0].Paths[0]
			if p.Hops[0].Technique.ID != tt.want {
				t.Errorf("first technique = %s (path %s), want %s", p.Hops[0].Technique.ID, techniqueIDs(p), tt.want)
			}
			if p.Conditional != tt.cond {
				t.Errorf("conditional = %v, want %v", p.Conditional, tt.cond)
			}
		})
	}
}

func TestAdminDetection(t *testing.T) {
	tests := []struct {
		name  string
		stmts string
		admin bool
	}{
		{"star on star", adminStmt, true},
		{"iam star", `[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]`, true},
		{"iam star on scoped resource", `[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::123456789012:user/*"}]`, false},
		{"enumerated iam writes are not wildcard", `[{"Effect":"Allow","Action":["iam:AttachUserPolicy","iam:PutUserPolicy"],"Resource":"*"}]`, false},
		{"star with mfa condition", `[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]`, false},
		{"star with deny on iam star", `[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]`, false},
		{"star with narrow deny stays admin", `[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:DeleteUser","Resource":"*"}]`, true},
		{"poweruser", `[{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"}]`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := env{attacker: tt.stmts}.build(t)
			p, _ := a.Find("attacker")
			if got := NewAnalyzer(a).Admin(p).Admin; got != tt.admin {
				t.Errorf("admin = %v, want %v", got, tt.admin)
			}
		})
	}
}

func TestTechniqueCatalog(t *testing.T) {
	ts := Techniques()
	if len(ts) < 20 {
		t.Fatalf("only %d techniques", len(ts))
	}
	seen := map[string]bool{}
	for _, tc := range ts {
		if seen[tc.ID] {
			t.Errorf("duplicate id %s", tc.ID)
		}
		seen[tc.ID] = true
		if tc.Name == "" || tc.Description == "" || tc.Exploitation == "" || tc.Remediation == "" || len(tc.Permissions) == 0 || tc.Weight <= 0 {
			t.Errorf("technique %s is incomplete", tc.ID)
		}
		if tc.Category == CategoryPassRole && (tc.Service == "" || passRoleSteps(tc.ID, acct) == nil) {
			t.Errorf("PassRole technique %s lacks service or steps", tc.ID)
		}
		if TechniqueByID(tc.ID) != tc {
			t.Errorf("TechniqueByID(%s) mismatch", tc.ID)
		}
	}
	if TechniqueByID("ADMIN") != AdminTechnique || TechniqueByID("NOPE") != nil {
		t.Error("TechniqueByID special cases")
	}
}

func TestMergeEdges(t *testing.T) {
	t1, t2 := TechniqueByID("SSM-001"), TechniqueByID("SSM-002")
	edges := []*Edge{
		{From: "b", To: "c", Technique: t2, Weight: 2},
		{From: "a", To: "c", Technique: t1, Weight: 5, Conditional: true},
		{From: "a", To: "c", Technique: t2, Weight: 2},
	}
	m := MergeEdges(edges)
	if len(m) != 2 || m[0].From != "a" || m[0].Technique != t2 || len(m[0].Alternatives) != 1 {
		t.Fatalf("unexpected merge result: %+v", m[0])
	}
}
