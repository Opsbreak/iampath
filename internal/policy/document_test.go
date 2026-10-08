package policy

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestStringListUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want StringList
		err  bool
	}{
		{"single string", `"s3:GetObject"`, StringList{"s3:GetObject"}, false},
		{"array", `["a","b"]`, StringList{"a", "b"}, false},
		{"bool", `true`, StringList{"true"}, false},
		{"number", `3600`, StringList{"3600"}, false},
		{"mixed array", `["x", false, 12]`, StringList{"x", "false", "12"}, false},
		{"null", `null`, nil, false},
		{"object rejected", `{"a":1}`, nil, true},
		{"nested array rejected", `[["a"]]`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s StringList
			err := json.Unmarshal([]byte(tt.in), &s)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v, want err %v", err, tt.err)
			}
			if !tt.err && !reflect.DeepEqual(s, tt.want) {
				t.Errorf("got %#v, want %#v", s, tt.want)
			}
		})
	}
}

func TestParseDocument(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		statements int
		err        string
		check      func(t *testing.T, d *Document)
	}{
		{
			name:       "statement as object",
			in:         `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`,
			statements: 1,
		},
		{
			name:       "statement as array",
			in:         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":"*"},{"Effect":"Deny","NotAction":"iam:*","NotResource":"arn:aws:s3:::x"}]}`,
			statements: 2,
			check: func(t *testing.T, d *Document) {
				if d.Statement[1].Effect != Deny || d.Statement[1].NotAction[0] != "iam:*" {
					t.Errorf("unexpected second statement %+v", d.Statement[1])
				}
			},
		},
		{
			name:       "effect is case-normalised",
			in:         `{"Statement":[{"Effect":"allow","Action":"*","Resource":"*"}]}`,
			statements: 1,
			check: func(t *testing.T, d *Document) {
				if d.Statement[0].Effect != Allow {
					t.Errorf("effect = %q", d.Statement[0].Effect)
				}
			},
		},
		{
			name:       "principal wildcard string",
			in:         `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
			statements: 1,
			check: func(t *testing.T, d *Document) {
				if !d.Statement[0].Principal.Wildcard {
					t.Error("expected wildcard principal")
				}
			},
		},
		{
			name:       "principal map with string and array",
			in:         `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:root","444455556666"],"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
			statements: 1,
			check: func(t *testing.T, d *Document) {
				p := d.Statement[0].Principal
				if len(p.AWS) != 2 || p.Service[0] != "lambda.amazonaws.com" || p.Wildcard {
					t.Errorf("unexpected principal %+v", p)
				}
			},
		},
		{
			name:       "principal AWS star is wildcard",
			in:         `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
			statements: 1,
			check: func(t *testing.T, d *Document) {
				if !d.Statement[0].Principal.Wildcard {
					t.Error("expected wildcard")
				}
			},
		},
		{
			name:       "NotPrincipal",
			in:         `{"Statement":[{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:user/admin"},"Action":"*","Resource":"*"}]}`,
			statements: 1,
			check: func(t *testing.T, d *Document) {
				if d.Statement[0].NotPrincipal == nil {
					t.Error("expected NotPrincipal")
				}
			},
		},
		{
			name:       "condition with bool and number values",
			in:         `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":true},"NumericLessThan":{"s3:max-keys":10}}}]}`,
			statements: 1,
			check: func(t *testing.T, d *Document) {
				c := d.Statement[0].Condition
				if c["Bool"]["aws:SecureTransport"][0] != "true" || c["NumericLessThan"]["s3:max-keys"][0] != "10" {
					t.Errorf("unexpected condition %+v", c)
				}
			},
		},
		{name: "invalid effect", in: `{"Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`, err: "invalid Effect"},
		{name: "action and notaction", in: `{"Statement":[{"Effect":"Allow","Action":"*","NotAction":"iam:*","Resource":"*"}]}`, err: "both Action and NotAction"},
		{name: "resource and notresource", in: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","NotResource":"x"}]}`, err: "both Resource and NotResource"},
		{name: "bad principal string", in: `{"Statement":[{"Effect":"Allow","Principal":"bob","Action":"*"}]}`, err: "invalid principal"},
		{name: "unknown principal type", in: `{"Statement":[{"Effect":"Allow","Principal":{"Robot":"x"},"Action":"*"}]}`, err: "unknown principal type"},
		{name: "empty", in: ``, err: "empty policy document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := Parse([]byte(tt.in))
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want containing %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(d.Statement) != tt.statements {
				t.Fatalf("statements = %d, want %d", len(d.Statement), tt.statements)
			}
			if tt.check != nil {
				tt.check(t, d)
			}
		})
	}
}

func TestParseEncodedDocument(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	// The raw IAM API returns URL-encoded documents.
	enc, _ := json.Marshal(url.QueryEscape(raw))
	d, err := Parse(enc)
	if err != nil {
		t.Fatalf("url-encoded: %v", err)
	}
	if d.Statement[0].Resource[0] != "arn:aws:s3:::b/*" {
		t.Errorf("resource = %q", d.Statement[0].Resource[0])
	}
	// A JSON string containing plain JSON is also accepted.
	plain, _ := json.Marshal(raw)
	if _, err := Parse(plain); err != nil {
		t.Fatalf("json string: %v", err)
	}
}
