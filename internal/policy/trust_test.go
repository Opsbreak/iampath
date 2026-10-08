package policy

import "testing"

func TestEvaluateTrust(t *testing.T) {
	alice := Caller{ARN: "arn:aws:iam::111122223333:user/alice", Account: "111122223333"}
	role := Caller{ARN: "arn:aws:iam::111122223333:role/ci", Account: "111122223333"}
	other := Caller{ARN: "arn:aws:iam::444455556666:user/eve", Account: "444455556666"}
	lambda := Caller{Service: "lambda.amazonaws.com"}
	ctx := func(c Caller) *Context {
		x := NewContext()
		if c.ARN != "" {
			x.Set("aws:PrincipalArn", c.ARN).Set("aws:PrincipalAccount", c.Account)
		}
		return x
	}
	tests := []struct {
		name         string
		trust        string
		caller       Caller
		want         Tri
		needIdentity bool
	}{
		{"direct user ARN", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole"}}`, alice, True, false},
		{"other user ARN", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/bob"},"Action":"sts:AssumeRole"}}`, alice, False, false},
		{"account root requires identity", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}}`, alice, True, true},
		{"bare account id", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"111122223333"},"Action":"sts:AssumeRole"}}`, role, True, true},
		{"different account root", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"}}`, other, False, false},
		{"wildcard principal", `{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`, other, True, false},
		{"wildcard principal restricted by account condition", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalAccount":"111122223333"}}}}`, other, False, false},
		{"wildcard with PrincipalArn condition", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::111122223333:role/c*"}}}}`, role, True, false},
		{"MFA condition is unknown", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`, alice, Unknown, true},
		{"ExternalId condition is unknown", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"x"}}}}`, alice, Unknown, false},
		{"service principal", `{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`, lambda, True, false},
		{"service principal list", `{"Statement":{"Effect":"Allow","Principal":{"Service":["ec2.amazonaws.com","lambda.amazonaws.com"]},"Action":"sts:AssumeRole"}}`, lambda, True, false},
		{"service principal does not match user", `{"Statement":{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}}`, alice, False, false},
		{"web identity action is not AssumeRole", `{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity"}}`, alice, False, false},
		{"explicit deny in trust", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole"}]}`, alice, False, false},
		{"NotPrincipal deny excludes caller", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:*"},{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole"}]}`, alice, True, true},
		{"NotPrincipal deny hits others", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:*"},{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole"}]}`, role, False, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateTrust(MustParse(tt.trust), "r", "sts:AssumeRole", tt.caller, ctx(tt.caller))
			if got.Allowed != tt.want {
				t.Fatalf("allowed = %v (%s), want %v", got.Allowed, got.Reason, tt.want)
			}
			if got.Allowed != False && got.RequiresIdentityPermission != tt.needIdentity {
				t.Errorf("requiresIdentity = %v, want %v", got.RequiresIdentityPermission, tt.needIdentity)
			}
		})
	}
}

func TestEvaluateTrustNil(t *testing.T) {
	if r := EvaluateTrust(nil, "r", "sts:AssumeRole", Caller{}, nil); r.Allowed != False {
		t.Errorf("nil trust policy should not allow")
	}
}
