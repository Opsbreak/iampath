package policy

import (
	"strings"
	"testing"
)

func np(kind Kind, name, doc string) NamedPolicy {
	return NamedPolicy{Name: name, Kind: kind, Doc: MustParse(doc)}
}

const fullAWSAccess = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// TestEvaluate mirrors examples from the AWS IAM documentation ("Policy
// evaluation logic", "Permissions boundaries", "Example IAM
// identity-based policies" and the SCP examples).
func TestEvaluate(t *testing.T) {
	aliceCtx := func() *Context {
		return NewContext().
			Set("aws:username", "alice").
			Set("aws:PrincipalArn", "arn:aws:iam::111122223333:user/alice").
			Set("aws:PrincipalAccount", "111122223333")
	}
	tests := []struct {
		name        string
		in          Input
		req         Request
		want        Decision
		conditional bool
		deniedBy    string
	}{
		{
			name: "identity allow",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "s3", `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}}`)}},
			req:  Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::bucket/key"},
			want: DecisionAllow,
		},
		{
			name:     "implicit deny when nothing matches",
			in:       Input{Identity: []NamedPolicy{np(KindIdentity, "s3", `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}}`)}},
			req:      Request{Action: "s3:PutObject", Resource: "arn:aws:s3:::bucket/key"},
			want:     DecisionImplicitDeny,
			deniedBy: "identity",
		},
		{
			name: "explicit deny overrides allow",
			in: Input{Identity: []NamedPolicy{
				np(KindIdentity, "admin", fullAWSAccess),
				np(KindIdentity, "deny-iam", `{"Statement":{"Effect":"Deny","Action":"iam:*","Resource":"*"}}`),
			}},
			req:      Request{Action: "iam:CreateUser", Resource: "arn:aws:iam::111122223333:user/x"},
			want:     DecisionExplicitDeny,
			deniedBy: "explicit",
		},
		{
			name:     "NotAction allow (PowerUserAccess) excludes iam",
			in:       Input{Identity: []NamedPolicy{np(KindIdentity, "power", `{"Statement":{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"}}`)}},
			req:      Request{Action: "iam:AttachUserPolicy", Resource: "arn:aws:iam::111122223333:user/x"},
			want:     DecisionImplicitDeny,
			deniedBy: "identity",
		},
		{
			name: "NotAction allow (PowerUserAccess) includes others",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "power", `{"Statement":{"Effect":"Allow","NotAction":["iam:*","organizations:*","account:*"],"Resource":"*"}}`)}},
			req:  Request{Action: "lambda:CreateFunction", Resource: "arn:aws:lambda:ca-central-1:111122223333:function:f"},
			want: DecisionAllow,
		},
		{
			// Permissions boundaries doc: effective permissions are the
			// intersection of identity policy and boundary.
			name: "boundary blocks action allowed by identity",
			in: Input{
				Identity: []NamedPolicy{np(KindIdentity, "iam", `{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}`)},
				Boundary: &NamedPolicy{Name: "boundary", Kind: KindBoundary, Doc: MustParse(`{"Statement":{"Effect":"Allow","Action":["s3:*","cloudwatch:*","ec2:*"],"Resource":"*"}}`)},
			},
			req:      Request{Action: "iam:CreateUser", Resource: "arn:aws:iam::111122223333:user/x"},
			want:     DecisionImplicitDeny,
			deniedBy: "boundary",
		},
		{
			name: "boundary does not grant on its own",
			in: Input{
				Identity: []NamedPolicy{np(KindIdentity, "s3", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)},
				Boundary: &NamedPolicy{Name: "boundary", Kind: KindBoundary, Doc: MustParse(fullAWSAccess)},
			},
			req:      Request{Action: "ec2:RunInstances", Resource: "*"},
			want:     DecisionImplicitDeny,
			deniedBy: "identity",
		},
		{
			name: "boundary and identity both allow",
			in: Input{
				Identity: []NamedPolicy{np(KindIdentity, "s3", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)},
				Boundary: &NamedPolicy{Name: "boundary", Kind: KindBoundary, Doc: MustParse(`{"Statement":{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}}`)},
			},
			req:  Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/k"},
			want: DecisionAllow,
		},
		{
			name: "deny in boundary is an explicit deny",
			in: Input{
				Identity: []NamedPolicy{np(KindIdentity, "admin", fullAWSAccess)},
				Boundary: &NamedPolicy{Name: "boundary", Kind: KindBoundary, Doc: MustParse(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`)},
			},
			req:      Request{Action: "iam:PutUserPolicy", Resource: "*"},
			want:     DecisionExplicitDeny,
			deniedBy: "explicit",
		},
		{
			name: "SCP deny overrides administrator",
			in: Input{
				Identity:  []NamedPolicy{np(KindIdentity, "admin", fullAWSAccess)},
				SCPLevels: [][]NamedPolicy{{np(KindSCP, "FullAWSAccess", fullAWSAccess), np(KindSCP, "DenyLeave", `{"Statement":{"Effect":"Deny","Action":"organizations:LeaveOrganization","Resource":"*"}}`)}},
			},
			req:      Request{Action: "organizations:LeaveOrganization", Resource: "*"},
			want:     DecisionExplicitDeny,
			deniedBy: "explicit",
		},
		{
			name: "SCP allow-list without the service",
			in: Input{
				Identity:  []NamedPolicy{np(KindIdentity, "admin", fullAWSAccess)},
				SCPLevels: [][]NamedPolicy{{np(KindSCP, "AllowEC2S3", `{"Statement":{"Effect":"Allow","Action":["ec2:*","s3:*"],"Resource":"*"}}`)}},
			},
			req:      Request{Action: "iam:CreateUser", Resource: "*"},
			want:     DecisionImplicitDeny,
			deniedBy: "scp",
		},
		{
			name: "SCP every level must allow",
			in: Input{
				Identity: []NamedPolicy{np(KindIdentity, "admin", fullAWSAccess)},
				SCPLevels: [][]NamedPolicy{
					{np(KindSCP, "root", fullAWSAccess)},
					{np(KindSCP, "ou", `{"Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`)},
				},
			},
			req:      Request{Action: "s3:GetObject", Resource: "*"},
			want:     DecisionImplicitDeny,
			deniedBy: "scp",
		},
		{
			name: "SCP does not grant permissions",
			in: Input{
				SCPLevels: [][]NamedPolicy{{np(KindSCP, "root", fullAWSAccess)}},
			},
			req:      Request{Action: "s3:GetObject", Resource: "*"},
			want:     DecisionImplicitDeny,
			deniedBy: "identity",
		},
		{
			name: "SCP deny with ArnNotLike exemption applies to others",
			in: Input{
				Identity: []NamedPolicy{np(KindIdentity, "self", `{"Statement":{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"arn:aws:iam::111122223333:user/${aws:username}"}}`)},
				SCPLevels: [][]NamedPolicy{{np(KindSCP, "root", fullAWSAccess),
					np(KindSCP, "deny", `{"Statement":{"Effect":"Deny","Action":"iam:AttachUserPolicy","Resource":"*","Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/OrgAdmin"}}}}`)}},
			},
			req:      Request{Action: "iam:AttachUserPolicy", Resource: "arn:aws:iam::111122223333:user/alice", Context: aliceCtx()},
			want:     DecisionExplicitDeny,
			deniedBy: "explicit",
		},
		{
			// "Allows IAM users to manage their own credentials".
			name: "aws:username policy variable matches own user",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "self", `{"Statement":{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:UpdateAccessKey"],"Resource":"arn:aws:iam::*:user/${aws:username}"}}`)}},
			req:  Request{Action: "iam:CreateAccessKey", Resource: "arn:aws:iam::111122223333:user/alice", Context: aliceCtx()},
			want: DecisionAllow,
		},
		{
			name:     "aws:username policy variable does not match other user",
			in:       Input{Identity: []NamedPolicy{np(KindIdentity, "self", `{"Statement":{"Effect":"Allow","Action":["iam:CreateAccessKey"],"Resource":"arn:aws:iam::*:user/${aws:username}"}}`)}},
			req:      Request{Action: "iam:CreateAccessKey", Resource: "arn:aws:iam::111122223333:user/bob", Context: aliceCtx()},
			want:     DecisionImplicitDeny,
			deniedBy: "identity",
		},
		{
			// "Allows access based on MFA" - MFA is unknown offline.
			name:        "allow with MFA condition is conditional",
			in:          Input{Identity: []NamedPolicy{np(KindIdentity, "mfa", `{"Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`)}},
			req:         Request{Action: "ec2:StopInstances", Resource: "*"},
			want:        DecisionAllow,
			conditional: true,
		},
		{
			// "Denies access to AWS based on the source IP".
			name: "deny on source IP is conditional",
			in: Input{Identity: []NamedPolicy{
				np(KindIdentity, "admin", fullAWSAccess),
				np(KindIdentity, "ip", `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":["192.0.2.0/24","203.0.113.0/24"]},"Bool":{"aws:ViaAWSService":"false"}}}}`),
			}},
			req:         Request{Action: "s3:GetObject", Resource: "*"},
			want:        DecisionAllow,
			conditional: true,
		},
		{
			name: "deny on source IP resolved with context",
			in: Input{Identity: []NamedPolicy{
				np(KindIdentity, "admin", fullAWSAccess),
				np(KindIdentity, "ip", `{"Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":["192.0.2.0/24"]}}}}`),
			}},
			req:      Request{Action: "s3:GetObject", Resource: "*", Context: NewContext().Set("aws:SourceIp", "198.51.100.7")},
			want:     DecisionExplicitDeny,
			deniedBy: "explicit",
		},
		{
			name:     "NotResource deny excludes listed resource",
			in:       Input{Identity: []NamedPolicy{np(KindIdentity, "admin", fullAWSAccess), np(KindIdentity, "nr", `{"Statement":{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::allowed","arn:aws:s3:::allowed/*"]}}`)}},
			req:      Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::other/k"},
			want:     DecisionExplicitDeny,
			deniedBy: "explicit",
		},
		{
			name: "NotResource deny does not apply to excluded resource",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "admin", fullAWSAccess), np(KindIdentity, "nr", `{"Statement":{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::allowed","arn:aws:s3:::allowed/*"]}}`)}},
			req:  Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::allowed/k"},
			want: DecisionAllow,
		},
		{
			name: "attacker-chosen resource name intersects allow",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "dev", `{"Statement":{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"arn:aws:lambda:*:111122223333:function:dev-*"}}`)}},
			req:  Request{Action: "lambda:CreateFunction", Resource: "arn:aws:lambda:*:111122223333:function:*", ResourcePattern: true},
			want: DecisionAllow,
		},
		{
			name: "partial deny does not block attacker-chosen name",
			in: Input{Identity: []NamedPolicy{
				np(KindIdentity, "all", `{"Statement":{"Effect":"Allow","Action":"lambda:*","Resource":"*"}}`),
				np(KindIdentity, "deny", `{"Statement":{"Effect":"Deny","Action":"lambda:CreateFunction","Resource":"arn:aws:lambda:*:111122223333:function:prod-*"}}`),
			}},
			req:  Request{Action: "lambda:CreateFunction", Resource: "arn:aws:lambda:*:111122223333:function:*", ResourcePattern: true},
			want: DecisionAllow,
		},
		{
			name:     "attacker-chosen name in another account",
			in:       Input{Identity: []NamedPolicy{np(KindIdentity, "dev", `{"Statement":{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"arn:aws:lambda:*:999999999999:function:*"}}`)}},
			req:      Request{Action: "lambda:CreateFunction", Resource: "arn:aws:lambda:*:111122223333:function:*", ResourcePattern: true},
			want:     DecisionImplicitDeny,
			deniedBy: "identity",
		},
		{
			name: "PassRole with PassedToService condition",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "pass", `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/app-*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}}`)}},
			req:  Request{Action: "iam:PassRole", Resource: "arn:aws:iam::111122223333:role/app-fn", Context: NewContext().Set("iam:PassedToService", "lambda.amazonaws.com")},
			want: DecisionAllow,
		},
		{
			name:     "PassRole to a different service is denied",
			in:       Input{Identity: []NamedPolicy{np(KindIdentity, "pass", `{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::111122223333:role/app-*","Condition":{"StringEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}}}`)}},
			req:      Request{Action: "iam:PassRole", Resource: "arn:aws:iam::111122223333:role/app-fn", Context: NewContext().Set("iam:PassedToService", "ec2.amazonaws.com")},
			want:     DecisionImplicitDeny,
			deniedBy: "identity",
		},
		{
			name: "case-insensitive action in policy",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "x", `{"Statement":{"Effect":"Allow","Action":"IAM:put*POLICY","Resource":"*"}}`)}},
			req:  Request{Action: "iam:PutRolePolicy", Resource: "arn:aws:iam::111122223333:role/r"},
			want: DecisionAllow,
		},
		{
			name: "resource matching is case-sensitive",
			in:   Input{Identity: []NamedPolicy{np(KindIdentity, "x", `{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::Bucket/*"}}`)}},
			req:  Request{Action: "s3:GetObject", Resource: "arn:aws:s3:::bucket/k"},
			want: DecisionImplicitDeny, deniedBy: "identity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := tt.in
			req := tt.req
			got := Evaluate(&in, &req)
			if got.Decision != tt.want {
				t.Fatalf("decision = %s (%s), want %s", got.Decision, got.Reason, tt.want)
			}
			if got.Conditional != tt.conditional {
				t.Errorf("conditional = %v, want %v (%s)", got.Conditional, tt.conditional, got.Reason)
			}
			if got.DeniedBy != tt.deniedBy {
				t.Errorf("deniedBy = %q, want %q", got.DeniedBy, tt.deniedBy)
			}
			if got.Reason == "" {
				t.Error("empty reason")
			}
		})
	}
}

func TestEvaluateTrace(t *testing.T) {
	in := &Input{Identity: []NamedPolicy{
		{Name: "Dev", Source: "group:Developers", Kind: KindIdentity, Doc: MustParse(`{"Statement":[{"Sid":"S3","Effect":"Allow","Action":"s3:*","Resource":"*"},{"Sid":"Other","Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`)},
	}}
	r := Evaluate(in, &Request{Action: "s3:ListBucket", Resource: "arn:aws:s3:::b"})
	if len(r.Trace) != 1 || r.Trace[0].Sid != "S3" {
		t.Fatalf("trace = %+v", r.Trace)
	}
	if !strings.Contains(r.Reason, "Dev (group:Developers)") {
		t.Errorf("reason %q does not name the policy", r.Reason)
	}
}

func TestMayAllow(t *testing.T) {
	ps := []NamedPolicy{np(KindIdentity, "x", `{"Statement":[{"Effect":"Allow","Action":"iam:Pass*","Resource":"arn:aws:iam::1:role/x"},{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`)}
	if !MayAllow(ps, "iam:PassRole") {
		t.Error("expected MayAllow iam:PassRole")
	}
	if MayAllow(ps, "s3:GetObject") {
		t.Error("deny statements must not count")
	}
}
