package policy

import "testing"

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"", "", true},
		{"", "a", false},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a*c", "ac", true},
		{"a*c", "abbbbc", true},
		{"a*c", "abbbbd", false},
		{"*Policy", "PutUserPolicy", true},
		{"Put*Policy", "PutRolePolicy", true},
		{"Put*Policy", "PutRolePolicyX", false},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b/c", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket2/a", false},
		{"a*b*c", "aXbYbZc", true},
		{"a**", "a", true},
		{"ABC", "abc", false},
	}
	for _, tt := range tests {
		if got := WildcardMatch(tt.pattern, tt.s); got != tt.want {
			t.Errorf("WildcardMatch(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestMatchAction(t *testing.T) {
	tests := []struct {
		pattern, action string
		want            bool
	}{
		{"iam:PutUserPolicy", "iam:putuserpolicy", true},
		{"IAM:*", "iam:CreateUser", true},
		{"iam:Put*", "iam:PutRolePolicy", true},
		{"iam:Put*", "iam:AttachRolePolicy", false},
		{"s3:Get*", "s3:GetObject", true},
		{"s3:?etObject", "s3:GetObject", true},
		{"*", "kms:Decrypt", true},
		{"ec2:*", "ec2messages:GetMessages", false},
	}
	for _, tt := range tests {
		if got := MatchAction(tt.pattern, tt.action); got != tt.want {
			t.Errorf("MatchAction(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
		}
	}
}

func TestGlobsIntersect(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"*", "arn:aws:lambda:*:1:function:*", true},
		{"arn:aws:lambda:*:1:function:dev-*", "arn:aws:lambda:*:1:function:*", true},
		{"arn:aws:lambda:us-east-1:1:function:x", "arn:aws:lambda:*:1:function:*", true},
		// Generic globs: a star may span colons, so these intersect
		// (e.g. "arn:aws:lambda:x:2:function:y:1:function:z").
		{"arn:aws:lambda:*:2:function:*", "arn:aws:lambda:*:1:function:*", true},
		{"arn:aws:s3:::bucket/*", "arn:aws:lambda:*:1:function:*", false},
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"a?c", "a*", true},
		{"a*z", "*b*", true},
		{"x*", "y*", false},
		{"", "*", true},
	}
	for _, tt := range tests {
		if got := GlobsIntersect(tt.a, tt.b); got != tt.want {
			t.Errorf("GlobsIntersect(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
		if got := GlobsIntersect(tt.b, tt.a); got != tt.want {
			t.Errorf("GlobsIntersect(%q, %q) (swapped) = %v, want %v", tt.b, tt.a, got, tt.want)
		}
	}
}

func TestResourcePatternIntersects(t *testing.T) {
	req := "arn:aws:lambda:*:111122223333:function:*"
	tests := []struct {
		policy string
		want   bool
	}{
		{"*", true},
		{"arn:aws:lambda:*:111122223333:function:dev-*", true},
		{"arn:aws:lambda:ca-central-1:111122223333:function:x", true},
		{"arn:aws:lambda:*:999999999999:function:*", false},
		{"arn:aws:lambda:*:*:function:*", true},
		// Policy stars keep AWS semantics and may span components.
		{"arn:aws:*:111122223333:function:*", true},
		{"arn:aws:lambda:*", true},
		{"arn:aws:s3:::bucket/*", false},
		// The request's function-name star cannot produce a colon.
		{"arn:aws:lambda:*:111122223333:function:a:b", false},
		{"arn:aws:lambda:*:111122223333:function:?", true},
	}
	for _, tt := range tests {
		if got := ResourcePatternIntersects(tt.policy, req); got != tt.want {
			t.Errorf("ResourcePatternIntersects(%q) = %v, want %v", tt.policy, got, tt.want)
		}
	}
}

func TestArnLike(t *testing.T) {
	tests := []struct {
		pattern, arn string
		want         bool
	}{
		{"arn:aws:iam::*:role/OrgAdmin", "arn:aws:iam::111122223333:role/OrgAdmin", true},
		{"arn:aws:iam::*:role/OrgAdmin", "arn:aws:iam::111122223333:role/Other", false},
		{"arn:aws:iam::111122223333:role/*", "arn:aws:iam::111122223333:role/path/x", true},
		// A wildcard in one component cannot span a colon.
		{"arn:aws:iam::1*3:user/a", "arn:aws:iam::1:2:3:user/a", false},
		{"arn:aws:sts::111122223333:assumed-role/Dev/*", "arn:aws:sts::111122223333:assumed-role/Dev/alice", true},
		{"*", "arn:aws:s3:::x", true},
	}
	for _, tt := range tests {
		if got := ArnLike(tt.pattern, tt.arn); got != tt.want {
			t.Errorf("ArnLike(%q, %q) = %v, want %v", tt.pattern, tt.arn, got, tt.want)
		}
	}
}

func TestSubstituteVariables(t *testing.T) {
	ctx := NewContext().Set("aws:username", "alice").SetAbsent("aws:PrincipalTag/team")
	tests := []struct {
		in      string
		want    string
		ok      bool
		unknown bool
	}{
		{"arn:aws:iam::1:user/${aws:username}", "arn:aws:iam::1:user/alice", true, false},
		{"arn:aws:s3:::home/${AWS:UserName}/*", "arn:aws:s3:::home/alice/*", true, false},
		{"literal-${*}-${?}-${$}", "literal-*-?-$", true, false},
		{"tag/${aws:PrincipalTag/team}", "tag/", false, false},
		{"tag/${aws:PrincipalTag/team, 'none'}", "tag/none", true, false},
		{"src/${aws:SourceIp}", "src/", false, true},
		{"no variables", "no variables", true, false},
	}
	for _, tt := range tests {
		got, ok, unk := SubstituteVariables(tt.in, ctx)
		if ok != tt.ok || unk != tt.unknown || (ok && got != tt.want) {
			t.Errorf("SubstituteVariables(%q) = %q, %v, %v; want %q, %v, %v", tt.in, got, ok, unk, tt.want, tt.ok, tt.unknown)
		}
	}
}
