// Package policy implements an offline AWS IAM policy evaluation engine:
// parsing of policy documents, action/resource matching, a subset of the
// condition operators and the AWS policy evaluation order for identity
// policies, permission boundaries, service control policies and role trust
// policies.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Effect is the effect of a policy statement.
type Effect string

// Statement effects.
const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// StringList is a JSON value that may be encoded either as a single scalar
// or as an array of scalars. Booleans and numbers are converted to their
// canonical string form, which is how AWS compares condition values.
type StringList []string

// UnmarshalJSON implements json.Unmarshaler.
func (s *StringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*s = nil
		return nil
	}
	if b[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		out := make(StringList, 0, len(raw))
		for _, r := range raw {
			v, err := scalarString(r)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		*s = out
		return nil
	}
	v, err := scalarString(b)
	if err != nil {
		return err
	}
	*s = StringList{v}
	return nil
}

func scalarString(b []byte) (string, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return "", fmt.Errorf("empty value")
	}
	switch b[0] {
	case '"':
		var v string
		err := json.Unmarshal(b, &v)
		return v, err
	case 't', 'f':
		var v bool
		if err := json.Unmarshal(b, &v); err != nil {
			return "", err
		}
		return strconv.FormatBool(v), nil
	case '{', '[':
		return "", fmt.Errorf("expected scalar, got %s", string(b))
	default:
		var n json.Number
		if err := json.Unmarshal(b, &n); err != nil {
			return "", err
		}
		return n.String(), nil
	}
}

// Principal is the Principal or NotPrincipal element of a statement.
type Principal struct {
	// Wildcard is true for "Principal": "*" (or {"AWS": "*"}).
	Wildcard      bool
	AWS           StringList
	Service       StringList
	Federated     StringList
	CanonicalUser StringList
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *Principal) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		if v != "*" {
			return fmt.Errorf("invalid principal string %q (only \"*\" is allowed)", v)
		}
		p.Wildcard = true
		return nil
	}
	var m map[string]StringList
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("principal: %w", err)
	}
	for k, v := range m {
		switch strings.ToLower(k) {
		case "aws":
			p.AWS = append(p.AWS, v...)
		case "service":
			p.Service = append(p.Service, v...)
		case "federated":
			p.Federated = append(p.Federated, v...)
		case "canonicaluser":
			p.CanonicalUser = append(p.CanonicalUser, v...)
		default:
			return fmt.Errorf("unknown principal type %q", k)
		}
	}
	for _, a := range p.AWS {
		if a == "*" {
			p.Wildcard = true
		}
	}
	return nil
}

// ConditionBlock maps operator -> condition key -> values.
type ConditionBlock map[string]map[string]StringList

// Statement is a single policy statement.
type Statement struct {
	Sid          string         `json:"Sid,omitempty"`
	Effect       Effect         `json:"Effect"`
	Principal    *Principal     `json:"Principal,omitempty"`
	NotPrincipal *Principal     `json:"NotPrincipal,omitempty"`
	Action       StringList     `json:"Action,omitempty"`
	NotAction    StringList     `json:"NotAction,omitempty"`
	Resource     StringList     `json:"Resource,omitempty"`
	NotResource  StringList     `json:"NotResource,omitempty"`
	Condition    ConditionBlock `json:"Condition,omitempty"`
}

// Document is an IAM policy document.
type Document struct {
	Version   string      `json:"Version,omitempty"`
	ID        string      `json:"Id,omitempty"`
	Statement []Statement `json:"Statement"`
}

// UnmarshalJSON implements json.Unmarshaler. Statement may be a single
// object or an array of objects.
func (d *Document) UnmarshalJSON(b []byte) error {
	var raw struct {
		Version   string          `json:"Version"`
		ID        string          `json:"Id"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	d.Version = raw.Version
	d.ID = raw.ID
	d.Statement = nil
	st := bytes.TrimSpace(raw.Statement)
	if len(st) == 0 || bytes.Equal(st, []byte("null")) {
		return nil
	}
	if st[0] == '{' {
		var s Statement
		if err := json.Unmarshal(st, &s); err != nil {
			return fmt.Errorf("statement: %w", err)
		}
		d.Statement = []Statement{s}
	} else {
		if err := json.Unmarshal(st, &d.Statement); err != nil {
			return fmt.Errorf("statement: %w", err)
		}
	}
	for i := range d.Statement {
		if err := d.Statement[i].validate(); err != nil {
			return fmt.Errorf("statement %d: %w", i, err)
		}
	}
	return nil
}

func (s *Statement) validate() error {
	switch strings.ToLower(string(s.Effect)) {
	case "allow":
		s.Effect = Allow
	case "deny":
		s.Effect = Deny
	default:
		return fmt.Errorf("invalid Effect %q", s.Effect)
	}
	if len(s.Action) > 0 && len(s.NotAction) > 0 {
		return fmt.Errorf("both Action and NotAction present")
	}
	if len(s.Resource) > 0 && len(s.NotResource) > 0 {
		return fmt.Errorf("both Resource and NotResource present")
	}
	if s.Principal != nil && s.NotPrincipal != nil {
		return fmt.Errorf("both Principal and NotPrincipal present")
	}
	return nil
}

// Parse parses a policy document. It accepts a JSON object, or a JSON
// string containing the (optionally URL-encoded) document as returned by
// the raw IAM API.
func Parse(b []byte) (*Document, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty policy document")
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		if strings.HasPrefix(strings.TrimSpace(s), "%7B") || strings.Contains(s, "%22") {
			dec, err := url.QueryUnescape(s)
			if err != nil {
				return nil, fmt.Errorf("url-decoding policy document: %w", err)
			}
			s = dec
		}
		b = []byte(s)
	}
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// MustParse is like Parse but panics on error. Intended for tests and
// static data.
func MustParse(s string) *Document {
	d, err := Parse([]byte(s))
	if err != nil {
		panic(err)
	}
	return d
}
