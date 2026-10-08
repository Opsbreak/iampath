package policy

import (
	"fmt"
	"strings"
)

// Caller identifies who is making a request against a resource-based
// policy such as a role trust policy.
type Caller struct {
	// ARN of the IAM user or role (not the STS session ARN).
	ARN string
	// Account is the 12-digit account ID of the caller.
	Account string
	// Service is set when the caller is an AWS service principal such as
	// "lambda.amazonaws.com".
	Service string
}

// PrincipalMatch describes how a Principal element matched a caller.
type PrincipalMatch int8

// Principal match kinds.
const (
	// NoMatch means the principal element does not name the caller.
	NoMatch PrincipalMatch = iota
	// MatchDirect means the caller (or "*") is named directly: no
	// identity-based permission is required for same-account role
	// assumption.
	MatchDirect
	// MatchAccount means the caller's account is named: the caller also
	// needs an identity-based policy allowing the action.
	MatchAccount
)

// MatchPrincipal reports whether p names c.
func MatchPrincipal(p *Principal, c Caller) PrincipalMatch {
	if p == nil {
		return NoMatch
	}
	if p.Wildcard {
		return MatchDirect
	}
	if c.Service != "" {
		for _, s := range p.Service {
			if strings.EqualFold(s, c.Service) {
				return MatchDirect
			}
		}
		return NoMatch
	}
	best := NoMatch
	for _, a := range p.AWS {
		switch {
		case a == "*":
			return MatchDirect
		case strings.EqualFold(a, c.ARN):
			return MatchDirect
		case a == c.Account || a == "arn:aws:iam::"+c.Account+":root":
			best = MatchAccount
		}
	}
	return best
}

// TrustResult is the result of evaluating a trust policy.
type TrustResult struct {
	// Allowed is True if the trust policy grants the action to the caller,
	// Unknown if only conditionally.
	Allowed Tri
	// RequiresIdentityPermission is true when the grant is via the account
	// principal, meaning the caller's own policies must also allow it.
	RequiresIdentityPermission bool
	Trace                      []TraceEntry
	Reason                     string
}

// EvaluateTrust evaluates a role trust policy (a resource-based policy) for
// action (normally "sts:AssumeRole") by caller.
func EvaluateTrust(doc *Document, roleName string, action string, c Caller, ctx *Context) TrustResult {
	tr := TrustResult{Allowed: False}
	if doc == nil {
		tr.Reason = "role has no trust policy"
		return tr
	}
	if ctx == nil {
		ctx = NewContext()
	}
	allow, deny := False, False
	direct := false
	for i := range doc.Statement {
		st := &doc.Statement[i]
		var pm PrincipalMatch
		switch {
		case st.Principal != nil:
			pm = MatchPrincipal(st.Principal, c)
		case st.NotPrincipal != nil:
			if MatchPrincipal(st.NotPrincipal, c) == NoMatch {
				pm = MatchDirect
			}
		}
		if pm == NoMatch {
			continue
		}
		if !actionMatches(st, action) {
			continue
		}
		m := True
		var why []string
		if len(st.Condition) > 0 {
			cr := EvaluateConditions(st.Condition, ctx)
			m, why = cr.Result, cr.Unresolved
		}
		if m == False {
			continue
		}
		tr.Trace = append(tr.Trace, TraceEntry{Kind: KindTrust, Policy: "trust policy of " + roleName,
			Sid: st.Sid, Index: i, Effect: st.Effect, Outcome: m, Unresolve: why})
		if st.Effect == Deny {
			deny = or(deny, m)
			continue
		}
		if pm == MatchDirect {
			direct = true
		}
		allow = or(allow, m)
	}
	switch {
	case deny == True:
		tr.Allowed = False
		tr.Reason = "explicitly denied by trust policy"
	case allow == False:
		tr.Reason = "trust policy does not name the caller"
	default:
		tr.Allowed = allow
		if deny == Unknown {
			tr.Allowed = Unknown
		}
		tr.RequiresIdentityPermission = !direct
		tr.Reason = fmt.Sprintf("trust policy allows (%s)", allow)
	}
	return tr
}
