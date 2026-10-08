package policy

import (
	"encoding/json"
	"testing"
)

func cond(t *testing.T, s string) ConditionBlock {
	t.Helper()
	var cb ConditionBlock
	if err := json.Unmarshal([]byte(s), &cb); err != nil {
		t.Fatalf("bad condition %s: %v", s, err)
	}
	return cb
}

func TestEvaluateConditions(t *testing.T) {
	ctx := NewContext().
		Set("aws:username", "alice").
		Set("aws:PrincipalArn", "arn:aws:iam::111122223333:user/alice").
		Set("aws:PrincipalTag/team", "platform").
		Set("aws:TagKeys", "team", "env").
		Set("aws:SecureTransport", "true").
		Set("aws:SourceIp", "203.0.113.25").
		Set("iam:PassedToService", "lambda.amazonaws.com").
		SetAbsent("aws:MultiFactorAuthPresent").
		SetAbsent("aws:RequestTag/owner")
	tests := []struct {
		name string
		cond string
		want Tri
	}{
		{"StringEquals match", `{"StringEquals":{"aws:username":"alice"}}`, True},
		{"StringEquals no match", `{"StringEquals":{"aws:username":"bob"}}`, False},
		{"StringEquals values are OR-ed", `{"StringEquals":{"aws:username":["bob","alice"]}}`, True},
		{"keys are AND-ed", `{"StringEquals":{"aws:username":"alice","aws:PrincipalTag/team":"web"}}`, False},
		{"operators are AND-ed", `{"StringEquals":{"aws:username":"alice"},"Bool":{"aws:SecureTransport":"true"}}`, True},
		{"key names are case-insensitive", `{"StringEquals":{"AWS:USERNAME":"alice"}}`, True},
		{"StringEquals is case-sensitive", `{"StringEquals":{"aws:username":"ALICE"}}`, False},
		{"StringEqualsIgnoreCase", `{"StringEqualsIgnoreCase":{"aws:username":"ALICE"}}`, True},
		{"StringNotEquals", `{"StringNotEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}`, True},
		{"StringNotEquals matching value", `{"StringNotEquals":{"iam:PassedToService":"lambda.amazonaws.com"}}`, False},
		{"StringLike wildcard", `{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/a*"}}`, True},
		{"StringNotLike", `{"StringNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/*"}}`, True},
		{"ArnLike", `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::111122223333:user/*"}}`, True},
		{"ArnEquals behaves like ArnLike", `{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::*:user/alice"}}`, True},
		{"ArnNotLike", `{"ArnNotLike":{"aws:PrincipalArn":["arn:aws:iam::*:role/OrgAdmin"]}}`, True},
		{"Bool true", `{"Bool":{"aws:SecureTransport":"true"}}`, True},
		{"Bool false", `{"Bool":{"aws:SecureTransport":false}}`, False},
		{"IpAddress in range", `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`, True},
		{"IpAddress out of range", `{"IpAddress":{"aws:SourceIp":"198.51.100.0/24"}}`, False},
		{"IpAddress single ip", `{"IpAddress":{"aws:SourceIp":"203.0.113.25"}}`, True},
		{"NotIpAddress", `{"NotIpAddress":{"aws:SourceIp":["10.0.0.0/8","192.168.0.0/16"]}}`, True},
		{"policy variable in value", `{"StringEquals":{"aws:PrincipalArn":"arn:aws:iam::111122223333:user/${aws:username}"}}`, True},
		// Missing keys (AWS: "the condition returns false" unless IfExists
		// or a negated operator).
		{"absent key positive op", `{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`, False},
		{"absent key IfExists", `{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}`, True},
		{"absent key negated op", `{"StringNotEquals":{"aws:RequestTag/owner":"x"}}`, True},
		{"absent key ForAllValues is vacuously true", `{"ForAllValues:StringEquals":{"aws:RequestTag/owner":"x"}}`, True},
		{"absent key ForAnyValue is false", `{"ForAnyValue:StringEquals":{"aws:RequestTag/owner":"x"}}`, False},
		{"Null true on absent", `{"Null":{"aws:MultiFactorAuthPresent":"true"}}`, True},
		{"Null false on present", `{"Null":{"aws:username":"false"}}`, True},
		{"Null true on present", `{"Null":{"aws:username":"true"}}`, False},
		// Multi-valued keys.
		{"ForAnyValue match", `{"ForAnyValue:StringEquals":{"aws:TagKeys":["env","cost"]}}`, True},
		{"ForAnyValue none", `{"ForAnyValue:StringEquals":{"aws:TagKeys":["cost"]}}`, False},
		{"ForAllValues subset", `{"ForAllValues:StringEquals":{"aws:TagKeys":["team","env","cost"]}}`, True},
		{"ForAllValues not subset", `{"ForAllValues:StringEquals":{"aws:TagKeys":["team"]}}`, False},
		{"ForAllValues StringLike", `{"ForAllValues:StringLike":{"aws:TagKeys":["t*","e*"]}}`, True},
		// Unknown keys and operators are reported as Unknown.
		{"unknown key", `{"StringEquals":{"aws:RequestedRegion":"ca-central-1"}}`, Unknown},
		{"unsupported operator", `{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}`, Unknown},
		{"unsupported numeric operator", `{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}`, Unknown},
		{"false dominates unknown", `{"StringEquals":{"aws:username":"bob","aws:RequestedRegion":"x"}}`, False},
		{"unknown with true", `{"StringEquals":{"aws:username":"alice","aws:RequestedRegion":"x"}}`, Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateConditions(cond(t, tt.cond), ctx)
			if got.Result != tt.want {
				t.Errorf("got %v (unresolved %v), want %v", got.Result, got.Unresolved, tt.want)
			}
			if got.Result == Unknown && len(got.Unresolved) == 0 {
				t.Errorf("unknown result without explanation")
			}
		})
	}
}

func TestIsSupportedOperator(t *testing.T) {
	for _, op := range []string{"StringEquals", "ForAnyValue:StringLike", "ForAllValues:ArnLike", "BoolIfExists", "Null", "IpAddress", "StringNotEqualsIfExists"} {
		if !IsSupportedOperator(op) {
			t.Errorf("%s should be supported", op)
		}
	}
	for _, op := range []string{"DateLessThan", "NumericEquals", "BinaryEquals"} {
		if IsSupportedOperator(op) {
			t.Errorf("%s should not be supported", op)
		}
	}
}

func TestContextClone(t *testing.T) {
	c := NewContext().Set("a", "1").SetAbsent("b").SetAbsentPrefix("tag/")
	d := c.Clone()
	d.Set("a", "2")
	if v, _ := c.Get("a"); v[0] != "1" {
		t.Error("clone shares values")
	}
	if _, st := d.Get("b"); st != KeyAbsent {
		t.Error("clone lost absent key")
	}
	if _, st := d.Get("TAG/x"); st != KeyAbsent {
		t.Error("clone lost absent prefix")
	}
	if _, st := d.Get("other"); st != KeyUnknown {
		t.Error("expected unknown")
	}
	if ks := NewContext().Set("aws:PrincipalArn", "x").Set("AWS:PRINCIPALARN", "y").Set("aws:a", "z").Keys(); len(ks) != 2 || ks[0] != "aws:a" || ks[1] != "aws:PrincipalArn" {
		t.Errorf("Keys() = %v", ks)
	}
}
