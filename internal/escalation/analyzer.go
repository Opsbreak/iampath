package escalation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Opsbreak/iampath/internal/account"
	"github.com/Opsbreak/iampath/internal/policy"
)

// AdminNode is the name of the virtual graph node representing
// administrator-equivalent access.
const AdminNode = "ADMIN"

// ConditionalPenalty is added to the weight of edges that depend on
// conditions that could not be evaluated offline, so that unconditional
// paths rank first.
const ConditionalPenalty = 3

// AdministratorAccessARN is the AWS managed AdministratorAccess policy.
const AdministratorAccessARN = "arn:aws:iam::aws:policy/AdministratorAccess"

// Edge is a privilege-escalation step from one principal to another (or to
// the ADMIN node).
type Edge struct {
	From      string
	To        string
	Technique *Technique
	// Resource is the primary resource the technique acts on.
	Resource string
	// Via carries extra detail, e.g. the role a composite step goes
	// through or the policy version restored.
	Via         string
	Conditional bool
	// Notes lists the conditions that could not be resolved offline.
	Notes  []string
	Weight int
	// Alternatives lists other techniques connecting the same pair of
	// nodes (only set on merged edges).
	Alternatives []*Edge
}

// AdminStatus describes whether a principal is administrator-equivalent.
type AdminStatus struct {
	Admin  bool
	Reason string
}

// Probe actions used to decide administrator equivalence. They are
// synthetic action names that only a wildcard grant ("*", "iam:*",
// "sts:*") can allow, so a principal is admin-equivalent when its
// effective policy grants the wildcard, even if an SCP or explicit deny
// removes a handful of specific actions.
var (
	fullAdminProbe = []string{"iampathprobe:SyntheticAction", "iam:IampathSyntheticAction", "sts:IampathSyntheticAction"}
	iamAdminProbe  = []string{"iam:IampathSyntheticAction"}
	allowAllDoc    = policy.MustParse(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
)

type check struct {
	ok    bool
	cond  bool
	notes []string
	res   policy.Result
}

type trustIndex struct {
	wildcard bool
	arns     map[string]bool
	accounts map[string]bool
	services map[string]policy.TrustResult
}

// Analyzer computes escalation edges for an account.
type Analyzer struct {
	Acct *account.Account

	inputs        map[*account.Principal]*policy.Input
	ctxs          map[*account.Principal]*policy.Context
	admin         map[*account.Principal]AdminStatus
	fullGrant     map[*account.Principal]bool
	mayAllow      map[*account.Principal]map[string]bool
	trust         map[*account.Principal]*trustIndex
	adminPolicies []string
}

// NewAnalyzer prepares an analyzer for acct.
func NewAnalyzer(acct *account.Account) *Analyzer {
	an := &Analyzer{
		Acct:      acct,
		inputs:    map[*account.Principal]*policy.Input{},
		ctxs:      map[*account.Principal]*policy.Context{},
		admin:     map[*account.Principal]AdminStatus{},
		fullGrant: map[*account.Principal]bool{},
		mayAllow:  map[*account.Principal]map[string]bool{},
		trust:     map[*account.Principal]*trustIndex{},
	}
	an.adminPolicies = []string{AdministratorAccessARN}
	arns := make([]string, 0, len(acct.Policies))
	for arn := range acct.Policies {
		arns = append(arns, arn)
	}
	sort.Strings(arns)
	for _, arn := range arns {
		mp := acct.Policies[arn]
		if arn == AdministratorAccessARN || mp.Default == nil {
			continue
		}
		in := &policy.Input{Identity: []policy.NamedPolicy{{Name: mp.Name, Kind: policy.KindIdentity, Doc: mp.Default}}}
		if ok, _ := probeAdmin(in, policy.NewContext()); ok {
			an.adminPolicies = append(an.adminPolicies, arn)
		}
	}
	return an
}

// Input returns the evaluation input for p.
func (an *Analyzer) Input(p *account.Principal) *policy.Input {
	if in, ok := an.inputs[p]; ok {
		return in
	}
	in := an.Acct.PolicyInput(p)
	an.inputs[p] = in
	return in
}

// Context returns the request context for p.
func (an *Analyzer) Context(p *account.Principal) *policy.Context {
	if c, ok := an.ctxs[p]; ok {
		return c
	}
	c := an.Acct.RequestContext(p)
	an.ctxs[p] = c
	return c
}

func (an *Analyzer) may(p *account.Principal, action string) bool {
	m := an.mayAllow[p]
	if m == nil {
		m = map[string]bool{}
		an.mayAllow[p] = m
	}
	if v, ok := m[action]; ok {
		return v
	}
	v := policy.MayAllow(an.Input(p).Identity, action)
	m[action] = v
	return v
}

// Can evaluates whether p may perform action on resource.
func (an *Analyzer) Can(p *account.Principal, action, resource string, pattern bool, mod func(*policy.Context)) policy.Result {
	ctx := an.Context(p)
	if mod != nil {
		ctx = ctx.Clone()
		mod(ctx)
	}
	return policy.Evaluate(an.Input(p), &policy.Request{Action: action, Resource: resource, ResourcePattern: pattern, Context: ctx})
}

func (an *Analyzer) can(p *account.Principal, action, resource string, pattern bool, mod func(*policy.Context)) check {
	if !an.may(p, action) {
		return check{res: policy.Result{Decision: policy.DecisionImplicitDeny, DeniedBy: "identity"}}
	}
	r := an.Can(p, action, resource, pattern, mod)
	c := check{ok: r.Allowed(), cond: r.Conditional, res: r}
	if c.ok && c.cond {
		c.notes = conditionNotes(r, action)
	}
	return c
}

func conditionNotes(r policy.Result, action string) []string {
	var out []string
	for _, t := range r.Trace {
		if t.Outcome == policy.Unknown {
			for _, u := range t.Unresolve {
				out = append(out, action+": "+u)
			}
		}
	}
	return out
}

// all combines checks; all must be ok.
func all(cs ...check) check {
	out := check{ok: true}
	for _, c := range cs {
		if !c.ok {
			return check{}
		}
		out.cond = out.cond || c.cond
		out.notes = append(out.notes, c.notes...)
	}
	return out
}

func probeAdmin(in *policy.Input, ctx *policy.Context) (bool, string) {
	allowed := func(actions []string) bool {
		for _, a := range actions {
			r := policy.Evaluate(in, &policy.Request{Action: a, Resource: "*", Context: ctx})
			if !r.Allowed() || r.Conditional {
				return false
			}
		}
		return true
	}
	if allowed(fullAdminProbe) {
		return true, "effective policy allows * on *"
	}
	if allowed(iamAdminProbe) {
		return true, "effective policy allows iam:* on *"
	}
	return false, ""
}

// Admin reports whether p is administrator-equivalent.
func (an *Analyzer) Admin(p *account.Principal) AdminStatus {
	if s, ok := an.admin[p]; ok {
		return s
	}
	var s AdminStatus
	s.Admin, s.Reason = probeAdmin(an.Input(p), an.Context(p))
	an.admin[p] = s
	return s
}

// wouldBeAdmin reports whether p would be admin if extra policies were
// added and/or a managed policy's default document replaced.
func (an *Analyzer) wouldBeAdmin(p *account.Principal, extra []policy.NamedPolicy, replaceARN string, replaceDoc *policy.Document) bool {
	base := an.Input(p)
	in := &policy.Input{Boundary: base.Boundary, SCPLevels: base.SCPLevels}
	for _, np := range base.Identity {
		if replaceARN != "" && np.ARN == replaceARN {
			np.Doc = replaceDoc
		}
		in.Identity = append(in.Identity, np)
	}
	in.Identity = append(in.Identity, extra...)
	ok, _ := probeAdmin(in, an.Context(p))
	return ok
}

// grantable reports whether granting AdministratorAccess to p would make
// it admin (false when a permissions boundary or SCP caps it).
func (an *Analyzer) grantable(p *account.Principal) bool {
	if v, ok := an.fullGrant[p]; ok {
		return v
	}
	v := an.wouldBeAdmin(p, []policy.NamedPolicy{{Name: "AdministratorAccess", Kind: policy.KindIdentity, Doc: allowAllDoc}}, "", nil)
	an.fullGrant[p] = v
	return v
}

func (an *Analyzer) trustOf(role *account.Principal) *trustIndex {
	if ti, ok := an.trust[role]; ok {
		return ti
	}
	ti := &trustIndex{arns: map[string]bool{}, accounts: map[string]bool{}, services: map[string]policy.TrustResult{}}
	if role.Trust != nil {
		for _, st := range role.Trust.Statement {
			for _, pr := range []*policy.Principal{st.Principal, st.NotPrincipal} {
				if pr == nil {
					continue
				}
				if st.NotPrincipal != nil || pr.Wildcard {
					ti.wildcard = true
				}
				for _, a := range pr.AWS {
					switch {
					case a == "*":
						ti.wildcard = true
					case strings.HasSuffix(a, ":root"):
						ti.accounts[account.AccountFromARN(a)] = true
					case len(a) == 12 && !strings.Contains(a, ":"):
						ti.accounts[a] = true
					default:
						ti.arns[strings.ToLower(a)] = true
					}
				}
			}
		}
	}
	an.trust[role] = ti
	return ti
}

func (an *Analyzer) serviceTrust(role *account.Principal, service string) policy.TrustResult {
	ti := an.trustOf(role)
	if tr, ok := ti.services[service]; ok {
		return tr
	}
	tr := policy.EvaluateTrust(role.Trust, role.Name, "sts:AssumeRole", policy.Caller{Service: service}, policy.NewContext())
	ti.services[service] = tr
	return tr
}

func newEdge(from, to string, t *Technique, resource string, c check) *Edge {
	w := t.Weight
	if c.cond {
		w += ConditionalPenalty
	}
	return &Edge{From: from, To: to, Technique: t, Resource: resource, Conditional: c.cond, Notes: dedupe(c.notes), Weight: w}
}

func dedupe(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// directGrant evaluates a request that a resource-based policy (here: a
// role trust policy) grants to the principal's own ARN in the same account.
// No identity-based Allow is needed, but explicit denies and SCPs still
// apply, and so does the permissions boundary of a role: AWS documents
// that resource-based grants to an IAM user ARN are not limited by the
// user's boundary, while grants to a role ARN are.
func (an *Analyzer) directGrant(p *account.Principal, action, resource string) check {
	base := an.Input(p)
	in := &policy.Input{SCPLevels: base.SCPLevels}
	in.Identity = append(in.Identity, base.Identity...)
	in.Identity = append(in.Identity, policy.NamedPolicy{Name: "resource-based grant", Kind: policy.KindIdentity, Doc: allowAllDoc})
	if p.Kind == account.KindRole {
		in.Boundary = base.Boundary
	}
	r := policy.Evaluate(in, &policy.Request{Action: action, Resource: resource, Context: an.Context(p)})
	c := check{ok: r.Allowed(), cond: r.Conditional, res: r}
	if c.ok && c.cond {
		c.notes = conditionNotes(r, action)
	}
	return c
}

// assumeEdge evaluates STS-001 for s -> role.
func (an *Analyzer) assumeEdge(s, role *account.Principal) *Edge {
	ti := an.trustOf(role)
	acct := account.AccountFromARN(s.ARN)
	if !ti.wildcard && !ti.arns[strings.ToLower(s.ARN)] && !ti.accounts[acct] {
		return nil
	}
	tr := policy.EvaluateTrust(role.Trust, role.Name, "sts:AssumeRole", policy.Caller{ARN: s.ARN, Account: acct}, an.Context(s))
	if tr.Allowed == policy.False {
		return nil
	}
	var c check
	if tr.RequiresIdentityPermission {
		c = an.can(s, "sts:AssumeRole", role.ARN, false, nil)
		if !c.ok {
			return nil
		}
	} else {
		c = an.directGrant(s, "sts:AssumeRole", role.ARN)
		if !c.ok {
			return nil
		}
	}
	if tr.Allowed == policy.Unknown {
		c.cond = true
		for _, t := range tr.Trace {
			for _, u := range t.Unresolve {
				c.notes = append(c.notes, "trust policy: "+u)
			}
		}
	}
	return newEdge(s.ARN, role.ARN, TechniqueByID("STS-001"), role.ARN, c)
}

type passRoleReq struct {
	action, resource string
}

// passRoleSteps lists the service actions (besides iam:PassRole) needed by
// each PassRole technique. Resources use attacker-chosen name patterns.
func passRoleSteps(id, acct string) []passRoleReq {
	switch id {
	case "LAMBDA-001":
		fn := "arn:aws:lambda:*:" + acct + ":function:*"
		return []passRoleReq{{"lambda:CreateFunction", fn}, {"lambda:InvokeFunction", fn}}
	case "LAMBDA-002":
		fn := "arn:aws:lambda:*:" + acct + ":function:*"
		return []passRoleReq{{"lambda:CreateFunction", fn}, {"lambda:CreateEventSourceMapping", "*"}}
	case "EC2-001":
		return []passRoleReq{{"ec2:RunInstances", "arn:aws:ec2:*:" + acct + ":instance/*"}}
	case "CFN-001":
		return []passRoleReq{{"cloudformation:CreateStack", "arn:aws:cloudformation:*:" + acct + ":stack/*/*"}}
	case "GLUE-001":
		return []passRoleReq{{"glue:CreateDevEndpoint", "arn:aws:glue:*:" + acct + ":devEndpoint/*"}}
	case "GLUE-002":
		job := "arn:aws:glue:*:" + acct + ":job/*"
		return []passRoleReq{{"glue:CreateJob", job}, {"glue:StartJobRun", job}}
	case "DP-001":
		pl := "arn:aws:datapipeline:*:" + acct + ":pipeline/*"
		return []passRoleReq{{"datapipeline:CreatePipeline", pl}, {"datapipeline:PutPipelineDefinition", pl}, {"datapipeline:ActivatePipeline", pl}}
	case "SM-001":
		nb := "arn:aws:sagemaker:*:" + acct + ":notebook-instance/*"
		return []passRoleReq{{"sagemaker:CreateNotebookInstance", nb}, {"sagemaker:CreatePresignedNotebookInstanceUrl", nb}}
	case "ECS-001":
		return []passRoleReq{{"ecs:RegisterTaskDefinition", "*"}, {"ecs:RunTask", "arn:aws:ecs:*:" + acct + ":task-definition/*"}}
	case "CB-002":
		pr := "arn:aws:codebuild:*:" + acct + ":project/*"
		return []passRoleReq{{"codebuild:CreateProject", pr}, {"codebuild:StartBuild", pr}}
	}
	return nil
}

// becomeEdges returns edges from s to principals whose credentials or
// sessions s can obtain.
func (an *Analyzer) becomeEdges(s *account.Principal) []*Edge {
	var out []*Edge
	acct := account.AccountFromARN(s.ARN)
	mayPass := an.may(s, "iam:PassRole")
	for _, role := range an.Acct.Roles {
		if role == s || role.ServiceLinked {
			continue
		}
		e := an.assumeEdge(s, role)
		if e != nil {
			out = append(out, e)
		}
		if e == nil || e.Conditional {
			if an.may(s, "iam:UpdateAssumeRolePolicy") {
				c := an.can(s, "iam:UpdateAssumeRolePolicy", role.ARN, false, nil)
				if c.ok {
					// After rewriting the trust policy to name s
					// directly, only denies, SCPs and (for roles) the
					// boundary can stop the assumption.
					if d := an.directGrant(s, "sts:AssumeRole", role.ARN); d.ok {
						out = append(out, newEdge(s.ARN, role.ARN, TechniqueByID("IAM-013"), role.ARN, all(c, d)))
					}
				}
			}
		}
		if !mayPass {
			continue
		}
		for _, t := range techniques {
			if t.Category != CategoryPassRole {
				continue
			}
			if t.ID == "EC2-001" && len(role.InstanceProfiles) == 0 {
				continue
			}
			tr := an.serviceTrust(role, t.Service)
			if tr.Allowed == policy.False {
				continue
			}
			svc := t.Service
			checks := []check{an.can(s, "iam:PassRole", role.ARN, false, func(c *policy.Context) {
				c.Set("iam:PassedToService", svc)
			})}
			if !checks[0].ok {
				continue
			}
			for _, st := range passRoleSteps(t.ID, acct) {
				checks = append(checks, an.can(s, st.action, st.resource, true, nil))
			}
			c := all(checks...)
			if !c.ok {
				continue
			}
			if tr.Allowed == policy.Unknown {
				c.cond = true
				c.notes = append(c.notes, "service trust is conditional")
			}
			e := newEdge(s.ARN, role.ARN, t, role.ARN, c)
			if t.ID == "EC2-001" {
				e.Via = "instance profile " + role.InstanceProfiles[0]
			}
			out = append(out, e)
		}
	}
	for _, u := range an.Acct.Users {
		if u == s {
			continue
		}
		for _, id := range []string{"IAM-010", "IAM-011", "IAM-012"} {
			t := TechniqueByID(id)
			c := an.can(s, t.Permissions[0], u.ARN, false, nil)
			if c.ok {
				out = append(out, newEdge(s.ARN, u.ARN, t, u.ARN, c))
			}
		}
	}
	// Inventory-based techniques.
	if an.may(s, "lambda:UpdateFunctionCode") {
		for _, f := range an.Acct.Lambdas {
			role := an.Acct.ByARN(f.RoleARN)
			if role == nil || role == s {
				continue
			}
			c := an.can(s, "lambda:UpdateFunctionCode", f.ARN, false, nil)
			if c.ok {
				e := newEdge(s.ARN, role.ARN, TechniqueByID("LAMBDA-003"), f.ARN, c)
				e.Via = "function " + f.Name
				out = append(out, e)
			}
		}
	}
	for _, inst := range an.Acct.Instances {
		if inst.InstanceProfileARN == "" || inst.State == "terminated" || inst.State == "shutting-down" {
			continue
		}
		role := an.Acct.RoleForInstanceProfile(inst.InstanceProfileARN)
		if role == nil || role == s {
			continue
		}
		tags := inst.Tags
		mod := func(c *policy.Context) {
			for k, v := range tags {
				c.Set("aws:ResourceTag/"+k, v)
				c.Set("ssm:resourceTag/"+k, v)
				c.Set("ec2:ResourceTag/"+k, v)
			}
			c.SetAbsentPrefix("aws:ResourceTag/")
			c.SetAbsentPrefix("ssm:resourceTag/")
			c.SetAbsentPrefix("ec2:ResourceTag/")
		}
		for _, id := range []string{"SSM-001", "SSM-002"} {
			t := TechniqueByID(id)
			c := an.can(s, t.Permissions[0], inst.ARN, false, mod)
			if c.ok {
				e := newEdge(s.ARN, role.ARN, t, inst.ARN, c)
				e.Via = "instance " + inst.ID
				if inst.State != "running" {
					e.Notes = append(e.Notes, "instance is "+inst.State)
				}
				out = append(out, e)
			}
		}
	}
	for _, pr := range an.Acct.CodeBuild {
		role := an.Acct.ByARN(pr.ServiceRoleARN)
		if role == nil || role == s {
			continue
		}
		c := an.can(s, "codebuild:StartBuild", pr.ARN, false, nil)
		if c.ok {
			e := newEdge(s.ARN, role.ARN, TechniqueByID("CB-001"), pr.ARN, c)
			e.Via = "project " + pr.Name
			out = append(out, e)
		}
	}
	return out
}

// grantEdges returns edges by which s can make target administrator
// (target == s for direct self-escalation). The edges lead to ADMIN.
func (an *Analyzer) grantEdges(s, target *account.Principal) []*Edge {
	if !an.grantable(target) {
		return nil
	}
	var out []*Edge
	add := func(id, resource, via string, c check) {
		if !c.ok {
			return
		}
		e := newEdge(s.ARN, AdminNode, TechniqueByID(id), resource, c)
		e.Via = via
		out = append(out, e)
	}
	attachMod := func(arn string) func(*policy.Context) {
		return func(c *policy.Context) { c.Set("iam:PolicyARN", arn) }
	}
	// tryAttach checks an Attach*Policy action for each candidate admin
	// policy, honouring iam:PolicyARN conditions.
	tryAttach := func(action, resource string) (check, string) {
		if !an.may(s, action) {
			return check{}, ""
		}
		var best check
		bestARN := ""
		for _, arn := range an.adminPolicies {
			c := an.can(s, action, resource, false, attachMod(arn))
			if c.ok && (!best.ok || (best.cond && !c.cond)) {
				best, bestARN = c, arn
				if !c.cond {
					break
				}
			}
		}
		return best, bestARN
	}
	for _, ap := range target.AttachedManagedPolicies() {
		mp := ap.Policy
		if mp.IsAWSManaged() {
			continue
		}
		if an.may(s, "iam:CreatePolicyVersion") {
			add("IAM-001", mp.ARN, "", an.can(s, "iam:CreatePolicyVersion", mp.ARN, false, nil))
		}
		if an.may(s, "iam:SetDefaultPolicyVersion") {
			for _, v := range mp.Versions {
				if v.IsDefault || v.Doc == nil {
					continue
				}
				if an.wouldBeAdmin(target, nil, mp.ARN, v.Doc) {
					add("IAM-002", mp.ARN, "restore version "+v.ID, an.can(s, "iam:SetDefaultPolicyVersion", mp.ARN, false, nil))
					break
				}
			}
		}
	}
	if target.Kind == account.KindUser {
		if c, arn := tryAttach("iam:AttachUserPolicy", target.ARN); c.ok {
			add("IAM-003", target.ARN, "attach "+arn, c)
		}
		if an.may(s, "iam:PutUserPolicy") {
			add("IAM-006", target.ARN, "", an.can(s, "iam:PutUserPolicy", target.ARN, false, nil))
		}
		for _, g := range target.Groups {
			if c, arn := tryAttach("iam:AttachGroupPolicy", g.ARN); c.ok {
				add("IAM-004", g.ARN, "attach "+arn+" to group "+g.Name, c)
			}
			if an.may(s, "iam:PutGroupPolicy") {
				add("IAM-007", g.ARN, "group "+g.Name, an.can(s, "iam:PutGroupPolicy", g.ARN, false, nil))
			}
		}
		if an.may(s, "iam:AddUserToGroup") {
			member := map[*account.Group]bool{}
			for _, g := range target.Groups {
				member[g] = true
			}
			names := make([]string, 0, len(an.Acct.Groups))
			for n := range an.Acct.Groups {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				g := an.Acct.Groups[n]
				if member[g] {
					continue
				}
				var extra []policy.NamedPolicy
				for _, mp := range g.Managed {
					extra = append(extra, policy.NamedPolicy{Name: mp.Name, ARN: mp.ARN, Kind: policy.KindIdentity, Doc: mp.Default})
				}
				extra = append(extra, g.Inline...)
				if !an.wouldBeAdmin(target, extra, "", nil) {
					continue
				}
				c := an.can(s, "iam:AddUserToGroup", g.ARN, false, nil)
				if c.ok {
					add("IAM-009", g.ARN, "join group "+g.Name, c)
					break
				}
			}
		}
	} else {
		if c, arn := tryAttach("iam:AttachRolePolicy", target.ARN); c.ok {
			add("IAM-005", target.ARN, "attach "+arn, c)
		}
		if an.may(s, "iam:PutRolePolicy") {
			add("IAM-008", target.ARN, "", an.can(s, "iam:PutRolePolicy", target.ARN, false, nil))
		}
	}
	return out
}

// BuildEdges computes every escalation edge in the account.
func (an *Analyzer) BuildEdges() []*Edge {
	var edges []*Edge
	for _, s := range an.Acct.Principals {
		if s.ServiceLinked {
			continue
		}
		if st := an.Admin(s); st.Admin {
			edges = append(edges, &Edge{From: s.ARN, To: AdminNode, Technique: AdminTechnique, Via: st.Reason})
			continue
		}
		become := an.becomeEdges(s)
		edges = append(edges, become...)
		edges = append(edges, an.grantEdges(s, s)...)
		// Composite: modify the permissions of a principal s can become,
		// then become it.
		seen := map[string]bool{}
		for _, b := range become {
			if seen[b.To] {
				continue
			}
			seen[b.To] = true
			t := an.Acct.ByARN(b.To)
			if t == nil || an.Admin(t).Admin {
				continue
			}
			for _, g := range an.grantEdges(s, t) {
				g.Via = strings.TrimSpace(fmt.Sprintf("%s; then act as %s via %s", g.Via, t.ShortName(), b.Technique.Name))
				g.Via = strings.TrimPrefix(g.Via, "; ")
				g.Weight += b.Weight
				g.Conditional = g.Conditional || b.Conditional
				g.Notes = append(g.Notes, b.Notes...)
				edges = append(edges, g)
			}
		}
	}
	return edges
}

// MergeEdges collapses parallel edges between the same pair of nodes into
// the best one (lowest weight, unconditional first) and records the others
// as alternatives.
func MergeEdges(edges []*Edge) []*Edge {
	type pair struct{ from, to string }
	groups := map[pair][]*Edge{}
	var order []pair
	for _, e := range edges {
		k := pair{e.From, e.To}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], e)
	}
	out := make([]*Edge, 0, len(order))
	for _, k := range order {
		g := groups[k]
		sort.SliceStable(g, func(i, j int) bool {
			if g[i].Weight != g[j].Weight {
				return g[i].Weight < g[j].Weight
			}
			if g[i].Conditional != g[j].Conditional {
				return !g[i].Conditional
			}
			return g[i].Technique.ID < g[j].Technique.ID
		})
		best := *g[0]
		best.Alternatives = nil
		for _, alt := range g[1:] {
			a := *alt
			best.Alternatives = append(best.Alternatives, &a)
		}
		out = append(out, &best)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}
