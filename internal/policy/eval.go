package policy

import (
	"fmt"
	"strings"
)

// Kind identifies the role a policy plays in evaluation.
type Kind string

// Policy kinds.
const (
	KindIdentity Kind = "identity"
	KindBoundary Kind = "boundary"
	KindSCP      Kind = "scp"
	KindTrust    Kind = "trust"
)

// NamedPolicy is a policy document with provenance information used in
// evaluation traces.
type NamedPolicy struct {
	Name string
	ARN  string
	// Source describes how the policy reaches the principal, e.g.
	// "inline", "managed", "group:Developers".
	Source string
	Kind   Kind
	Doc    *Document
}

// Label returns a human readable identifier for the policy.
func (p NamedPolicy) Label() string {
	n := p.Name
	if n == "" {
		n = p.ARN
	}
	if p.Source != "" {
		return fmt.Sprintf("%s (%s)", n, p.Source)
	}
	return n
}

// Request is a single authorization question.
type Request struct {
	Action   string
	Resource string
	// ResourcePattern indicates that Resource contains wildcards describing
	// a resource whose name the caller is free to choose (for example a new
	// Lambda function). Allow statements match if any concrete resource
	// matches both; Deny statements only apply if they cover the whole
	// pattern.
	ResourcePattern bool
	Context         *Context
}

// Decision is the final authorization decision.
type Decision string

// Decisions.
const (
	DecisionAllow        Decision = "Allow"
	DecisionExplicitDeny Decision = "ExplicitDeny"
	DecisionImplicitDeny Decision = "ImplicitDeny"
)

// TraceEntry records how a single statement contributed to a decision.
type TraceEntry struct {
	Kind      Kind
	Policy    string
	Sid       string
	Index     int
	Effect    Effect
	Outcome   Tri
	Unresolve []string
}

func (t TraceEntry) String() string {
	sid := t.Sid
	if sid == "" {
		sid = fmt.Sprintf("#%d", t.Index)
	}
	s := fmt.Sprintf("[%s] %s stmt %s: %s", t.Kind, t.Policy, sid, t.Effect)
	if t.Outcome == Unknown {
		s += " (conditional: " + strings.Join(t.Unresolve, "; ") + ")"
	}
	return s
}

// Result is the outcome of Evaluate.
type Result struct {
	Decision Decision
	// Conditional is true when the decision depends on conditions that
	// could not be resolved offline.
	Conditional bool
	// Reason is a one-line explanation.
	Reason string
	// Trace lists every statement that matched (fully or conditionally).
	Trace []TraceEntry
	// Layers summarises each evaluation layer.
	Layers []LayerResult
	// DeniedBy names the layer responsible for a deny: "explicit", "scp",
	// "identity" or "boundary".
	DeniedBy string
}

// Allowed reports whether the decision is Allow (possibly conditional).
func (r Result) Allowed() bool { return r.Decision == DecisionAllow }

// LayerResult describes the result of a single evaluation layer.
type LayerResult struct {
	Name   string
	Result Tri
	Note   string
}

// Input groups the policies that apply to a principal.
type Input struct {
	Identity []NamedPolicy
	// Boundary is the permissions boundary, or nil if none is attached.
	Boundary *NamedPolicy
	// SCPLevels holds the SCPs at each level of the organization hierarchy
	// (root, OUs, account). Every level must allow the action. Within a
	// level, any SCP may allow it. Empty means no SCPs are in effect.
	SCPLevels [][]NamedPolicy
}

// StatementMatch evaluates whether a statement applies to req.
func StatementMatch(st *Statement, req *Request) (Tri, []string) {
	if !actionMatches(st, req.Action) {
		return False, nil
	}
	rm, why := resourceMatches(st, req)
	if rm == False {
		return False, nil
	}
	if len(st.Condition) == 0 {
		return rm, why
	}
	cr := EvaluateConditions(st.Condition, req.Context)
	return and(rm, cr.Result), append(why, cr.Unresolved...)
}

func actionMatches(st *Statement, action string) bool {
	if len(st.NotAction) > 0 {
		for _, p := range st.NotAction {
			if MatchAction(p, action) {
				return false
			}
		}
		return true
	}
	for _, p := range st.Action {
		if MatchAction(p, action) {
			return true
		}
	}
	return false
}

// matchResourcePattern reports whether the policy pattern matches the
// request resource, handling policy variables.
func matchResourcePattern(pattern string, req *Request, forDeny bool) (Tri, string) {
	p, ok, unknown := SubstituteVariables(pattern, req.Context)
	if unknown {
		return Unknown, fmt.Sprintf("resource %q uses a policy variable not known offline", pattern)
	}
	if !ok {
		return False, ""
	}
	if p == "*" {
		return True, ""
	}
	if req.ResourcePattern {
		if forDeny {
			// A deny only blocks the attacker if it covers every
			// name they could choose.
			if WildcardMatch(p, req.Resource) {
				return True, ""
			}
			return False, ""
		}
		if ResourcePatternIntersects(p, req.Resource) {
			return True, ""
		}
		return False, ""
	}
	if WildcardMatch(p, req.Resource) {
		return True, ""
	}
	return False, ""
}

func resourceMatches(st *Statement, req *Request) (Tri, []string) {
	forDeny := st.Effect == Deny
	if len(st.NotResource) > 0 {
		res := True
		var why []string
		for _, p := range st.NotResource {
			// For NotResource the roles flip: an allow applies to an
			// attacker-chosen resource unless the exclusion covers the
			// whole pattern.
			m, w := matchResourcePattern(p, req, !forDeny)
			if m == True {
				return False, nil
			}
			if m == Unknown {
				res = Unknown
				why = append(why, w)
			}
		}
		return res, why
	}
	if len(st.Resource) == 0 {
		// Trust policies and SCPs may omit Resource.
		return True, nil
	}
	res := False
	var why []string
	for _, p := range st.Resource {
		m, w := matchResourcePattern(p, req, forDeny)
		if m == True {
			return True, nil
		}
		if m == Unknown {
			res = Unknown
			why = append(why, w)
		}
	}
	return res, why
}

type layerEval struct {
	allow Tri
	deny  Tri
	trace []TraceEntry
}

func evalPolicies(ps []NamedPolicy, req *Request) layerEval {
	le := layerEval{allow: False, deny: False}
	for _, p := range ps {
		if p.Doc == nil {
			continue
		}
		for i := range p.Doc.Statement {
			st := &p.Doc.Statement[i]
			m, why := StatementMatch(st, req)
			if m == False {
				continue
			}
			le.trace = append(le.trace, TraceEntry{
				Kind: p.Kind, Policy: p.Label(), Sid: st.Sid, Index: i,
				Effect: st.Effect, Outcome: m, Unresolve: why,
			})
			if st.Effect == Deny {
				le.deny = or(le.deny, m)
			} else {
				le.allow = or(le.allow, m)
			}
		}
	}
	return le
}

// Evaluate evaluates req against the policies in in following the AWS
// policy evaluation logic for a request within a single account:
//
//  1. An explicit Deny in any SCP, permissions boundary or identity policy
//     denies the request.
//  2. If SCPs are in effect, every level of the hierarchy must allow it.
//  3. An identity-based policy must allow it.
//  4. If a permissions boundary is attached, it must also allow it.
//
// Resource-based policies and session policies are not considered.
func Evaluate(in *Input, req *Request) Result {
	if req.Context == nil {
		req.Context = NewContext()
	}
	var res Result
	conditional := false
	var condNotes []string

	idEval := evalPolicies(in.Identity, req)
	var bEval *layerEval
	if in.Boundary != nil {
		b := evalPolicies([]NamedPolicy{*in.Boundary}, req)
		bEval = &b
	}
	scpEvals := make([]layerEval, len(in.SCPLevels))
	for i, lvl := range in.SCPLevels {
		scpEvals[i] = evalPolicies(lvl, req)
	}

	res.Trace = append(res.Trace, idEval.trace...)
	if bEval != nil {
		res.Trace = append(res.Trace, bEval.trace...)
	}
	for _, s := range scpEvals {
		res.Trace = append(res.Trace, s.trace...)
	}

	// 1. Explicit deny.
	deny := idEval.deny
	if bEval != nil {
		deny = or(deny, bEval.deny)
	}
	for _, s := range scpEvals {
		deny = or(deny, s.deny)
	}
	res.Layers = append(res.Layers, LayerResult{Name: "explicit deny", Result: deny})
	if deny == True {
		res.Decision = DecisionExplicitDeny
		res.DeniedBy = "explicit"
		res.Reason = "explicitly denied by " + firstTrace(res.Trace, Deny, True)
		return res
	}
	if deny == Unknown {
		conditional = true
		condNotes = append(condNotes, "a Deny statement may apply depending on conditions ("+firstTrace(res.Trace, Deny, Unknown)+")")
	}

	// 2. SCPs.
	for i, s := range scpEvals {
		res.Layers = append(res.Layers, LayerResult{Name: fmt.Sprintf("scp level %d", i+1), Result: s.allow})
		if s.allow == False {
			res.Decision = DecisionImplicitDeny
			res.DeniedBy = "scp"
			res.Reason = fmt.Sprintf("not allowed by any service control policy at level %d", i+1)
			return res
		}
		if s.allow == Unknown {
			conditional = true
			condNotes = append(condNotes, fmt.Sprintf("SCP level %d allows only conditionally", i+1))
		}
	}

	// 3. Identity policies.
	res.Layers = append(res.Layers, LayerResult{Name: "identity", Result: idEval.allow})
	if idEval.allow == False {
		res.Decision = DecisionImplicitDeny
		res.DeniedBy = "identity"
		res.Reason = "no identity-based policy allows the action"
		return res
	}
	if idEval.allow == Unknown {
		conditional = true
		condNotes = append(condNotes, "identity allow is conditional ("+firstTraceKind(res.Trace, KindIdentity, Allow, Unknown)+")")
	}

	// 4. Permissions boundary.
	if bEval != nil {
		res.Layers = append(res.Layers, LayerResult{Name: "permissions boundary", Result: bEval.allow})
		if bEval.allow == False {
			res.Decision = DecisionImplicitDeny
			res.DeniedBy = "boundary"
			res.Reason = "not allowed by permissions boundary " + in.Boundary.Label()
			return res
		}
		if bEval.allow == Unknown {
			conditional = true
			condNotes = append(condNotes, "permissions boundary allows only conditionally")
		}
	}

	res.Decision = DecisionAllow
	res.Conditional = conditional
	if conditional {
		res.Reason = "allowed conditionally: " + strings.Join(condNotes, "; ")
	} else {
		res.Reason = "allowed by " + firstTraceKind(res.Trace, KindIdentity, Allow, True)
	}
	return res
}

func firstTrace(tr []TraceEntry, eff Effect, out Tri) string {
	for _, t := range tr {
		if t.Effect == eff && t.Outcome == out {
			return t.String()
		}
	}
	return "?"
}

func firstTraceKind(tr []TraceEntry, k Kind, eff Effect, out Tri) string {
	for _, t := range tr {
		if t.Kind == k && t.Effect == eff && t.Outcome == out {
			return t.String()
		}
	}
	return "?"
}

// MayAllow is a fast pre-filter: it reports whether any Allow statement in
// ps could match action regardless of resource and conditions.
func MayAllow(ps []NamedPolicy, action string) bool {
	for _, p := range ps {
		if p.Doc == nil {
			continue
		}
		for i := range p.Doc.Statement {
			st := &p.Doc.Statement[i]
			if st.Effect == Allow && actionMatches(st, action) {
				return true
			}
		}
	}
	return false
}
