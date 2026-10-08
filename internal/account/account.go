// Package account loads the output of `aws iam
// get-account-authorization-details` (and optional inventories) into a
// principal model suitable for policy evaluation.
package account

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Opsbreak/iampath/internal/policy"
)

// Raw JSON shapes of get-account-authorization-details.

type rawAttached struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

type rawInline struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

type rawBoundary struct {
	PermissionsBoundaryType string `json:"PermissionsBoundaryType"`
	PermissionsBoundaryArn  string `json:"PermissionsBoundaryArn"`
}

type rawTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

type rawUser struct {
	Path                    string        `json:"Path"`
	UserName                string        `json:"UserName"`
	UserID                  string        `json:"UserId"`
	Arn                     string        `json:"Arn"`
	GroupList               []string      `json:"GroupList"`
	AttachedManagedPolicies []rawAttached `json:"AttachedManagedPolicies"`
	UserPolicyList          []rawInline   `json:"UserPolicyList"`
	PermissionsBoundary     *rawBoundary  `json:"PermissionsBoundary"`
	Tags                    []rawTag      `json:"Tags"`
}

type rawGroup struct {
	Path                    string        `json:"Path"`
	GroupName               string        `json:"GroupName"`
	GroupID                 string        `json:"GroupId"`
	Arn                     string        `json:"Arn"`
	GroupPolicyList         []rawInline   `json:"GroupPolicyList"`
	AttachedManagedPolicies []rawAttached `json:"AttachedManagedPolicies"`
}

type rawInstanceProfile struct {
	InstanceProfileName string `json:"InstanceProfileName"`
	Arn                 string `json:"Arn"`
}

type rawRole struct {
	Path                     string               `json:"Path"`
	RoleName                 string               `json:"RoleName"`
	RoleID                   string               `json:"RoleId"`
	Arn                      string               `json:"Arn"`
	AssumeRolePolicyDocument json.RawMessage      `json:"AssumeRolePolicyDocument"`
	InstanceProfileList      []rawInstanceProfile `json:"InstanceProfileList"`
	RolePolicyList           []rawInline          `json:"RolePolicyList"`
	AttachedManagedPolicies  []rawAttached        `json:"AttachedManagedPolicies"`
	PermissionsBoundary      *rawBoundary         `json:"PermissionsBoundary"`
	Tags                     []rawTag             `json:"Tags"`
}

type rawPolicyVersion struct {
	Document         json.RawMessage `json:"Document"`
	VersionID        string          `json:"VersionId"`
	IsDefaultVersion bool            `json:"IsDefaultVersion"`
}

type rawPolicy struct {
	PolicyName        string             `json:"PolicyName"`
	PolicyID          string             `json:"PolicyId"`
	Arn               string             `json:"Arn"`
	Path              string             `json:"Path"`
	DefaultVersionID  string             `json:"DefaultVersionId"`
	PolicyVersionList []rawPolicyVersion `json:"PolicyVersionList"`
}

type rawDetails struct {
	UserDetailList  []rawUser   `json:"UserDetailList"`
	GroupDetailList []rawGroup  `json:"GroupDetailList"`
	RoleDetailList  []rawRole   `json:"RoleDetailList"`
	Policies        []rawPolicy `json:"Policies"`
}

// PolicyVersion is one version of a managed policy.
type PolicyVersion struct {
	ID        string
	IsDefault bool
	Doc       *policy.Document
}

// ManagedPolicy is a customer or AWS managed policy.
type ManagedPolicy struct {
	Name     string
	ARN      string
	Versions []PolicyVersion
	// Default is the default version document (may be nil if the export
	// did not include the policy body).
	Default *policy.Document
}

// IsAWSManaged reports whether the policy is owned by AWS.
func (m *ManagedPolicy) IsAWSManaged() bool {
	return strings.HasPrefix(m.ARN, "arn:aws:iam::aws:") || strings.Contains(m.ARN, ":iam::aws:policy/")
}

// Group is an IAM group.
type Group struct {
	Name    string
	ARN     string
	Managed []*ManagedPolicy
	Inline  []policy.NamedPolicy
	Members []*Principal
}

// PrincipalKind distinguishes users from roles.
type PrincipalKind string

// Principal kinds.
const (
	KindUser PrincipalKind = "user"
	KindRole PrincipalKind = "role"
)

// Principal is an IAM user or role.
type Principal struct {
	Kind     PrincipalKind
	Name     string
	ARN      string
	ID       string
	Path     string
	Groups   []*Group
	Managed  []*ManagedPolicy
	Inline   []policy.NamedPolicy
	Boundary *ManagedPolicy
	// Trust is the role trust policy (roles only).
	Trust *policy.Document
	// InstanceProfiles lists instance profile ARNs containing the role.
	InstanceProfiles []string
	Tags             map[string]string
	// ServiceLinked is true for roles under /aws-service-role/.
	ServiceLinked bool
}

// ShortName returns "user/alice" or "role/Admin".
func (p *Principal) ShortName() string { return string(p.Kind) + "/" + p.Name }

// Account is the loaded authorization model.
type Account struct {
	ID         string
	Users      []*Principal
	Roles      []*Principal
	Groups     map[string]*Group // by lower-case name
	Policies   map[string]*ManagedPolicy
	Principals []*Principal // users then roles, sorted by ARN
	byARN      map[string]*Principal
	byName     map[string][]*Principal
	// Warnings collects non-fatal problems found while loading.
	Warnings []string

	SCPLevels        [][]policy.NamedPolicy
	Lambdas          []LambdaFunction
	Instances        []EC2Instance
	CodeBuild        []CodeBuildProject
	instanceProfiles map[string]*Principal
}

// LoadFile reads an authorization-details JSON file.
func LoadFile(path string) (*Account, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// Load parses an authorization-details JSON document.
func Load(r io.Reader) (*Account, error) {
	var raw rawDetails
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing authorization details: %w", err)
	}
	if len(raw.UserDetailList) == 0 && len(raw.RoleDetailList) == 0 {
		return nil, fmt.Errorf("authorization details contain no users or roles (is this the output of `aws iam get-account-authorization-details`?)")
	}
	a := &Account{
		Groups:           map[string]*Group{},
		Policies:         map[string]*ManagedPolicy{},
		byARN:            map[string]*Principal{},
		byName:           map[string][]*Principal{},
		instanceProfiles: map[string]*Principal{},
	}
	for _, rp := range raw.Policies {
		mp := &ManagedPolicy{Name: rp.PolicyName, ARN: rp.Arn}
		for _, v := range rp.PolicyVersionList {
			if len(v.Document) == 0 {
				continue
			}
			doc, err := policy.Parse(v.Document)
			if err != nil {
				a.warnf("policy %s version %s: %v (ignored)", rp.Arn, v.VersionID, err)
				continue
			}
			isDef := v.IsDefaultVersion || (rp.DefaultVersionID != "" && v.VersionID == rp.DefaultVersionID)
			mp.Versions = append(mp.Versions, PolicyVersion{ID: v.VersionID, IsDefault: isDef, Doc: doc})
			if isDef {
				mp.Default = doc
			}
		}
		a.Policies[rp.Arn] = mp
	}
	resolve := func(owner string, att []rawAttached) []*ManagedPolicy {
		var out []*ManagedPolicy
		for _, at := range att {
			mp, ok := a.Policies[at.PolicyArn]
			if !ok || mp.Default == nil {
				a.warnf("%s: attached policy %s not present in export; its permissions are ignored", owner, at.PolicyArn)
				if !ok {
					mp = &ManagedPolicy{Name: at.PolicyName, ARN: at.PolicyArn}
					a.Policies[at.PolicyArn] = mp
				}
			}
			out = append(out, mp)
		}
		return out
	}
	inline := func(owner string, src string, list []rawInline) []policy.NamedPolicy {
		var out []policy.NamedPolicy
		for _, il := range list {
			doc, err := policy.Parse(il.PolicyDocument)
			if err != nil {
				a.warnf("%s inline policy %s: %v (ignored)", owner, il.PolicyName, err)
				continue
			}
			out = append(out, policy.NamedPolicy{Name: il.PolicyName, Source: src, Kind: policy.KindIdentity, Doc: doc})
		}
		return out
	}
	boundary := func(owner string, b *rawBoundary) *ManagedPolicy {
		if b == nil || b.PermissionsBoundaryArn == "" {
			return nil
		}
		mp, ok := a.Policies[b.PermissionsBoundaryArn]
		if !ok || mp.Default == nil {
			a.warnf("%s: permissions boundary %s not present in export; treating boundary as allowing nothing", owner, b.PermissionsBoundaryArn)
			if !ok {
				mp = &ManagedPolicy{ARN: b.PermissionsBoundaryArn, Name: lastSegment(b.PermissionsBoundaryArn)}
				a.Policies[mp.ARN] = mp
			}
		}
		return mp
	}

	for _, rg := range raw.GroupDetailList {
		g := &Group{Name: rg.GroupName, ARN: rg.Arn}
		g.Managed = resolve("group "+rg.GroupName, rg.AttachedManagedPolicies)
		g.Inline = inline("group "+rg.GroupName, "group:"+rg.GroupName+" inline", rg.GroupPolicyList)
		a.Groups[strings.ToLower(rg.GroupName)] = g
	}
	for _, ru := range raw.UserDetailList {
		p := &Principal{Kind: KindUser, Name: ru.UserName, ARN: ru.Arn, ID: ru.UserID, Path: ru.Path, Tags: tags(ru.Tags)}
		p.Managed = resolve("user "+ru.UserName, ru.AttachedManagedPolicies)
		p.Inline = inline("user "+ru.UserName, "inline", ru.UserPolicyList)
		p.Boundary = boundary("user "+ru.UserName, ru.PermissionsBoundary)
		for _, gn := range ru.GroupList {
			g, ok := a.Groups[strings.ToLower(gn)]
			if !ok {
				a.warnf("user %s: group %s not present in export", ru.UserName, gn)
				continue
			}
			p.Groups = append(p.Groups, g)
			g.Members = append(g.Members, p)
		}
		a.Users = append(a.Users, p)
	}
	for _, rr := range raw.RoleDetailList {
		p := &Principal{Kind: KindRole, Name: rr.RoleName, ARN: rr.Arn, ID: rr.RoleID, Path: rr.Path, Tags: tags(rr.Tags)}
		p.ServiceLinked = strings.HasPrefix(rr.Path, "/aws-service-role/")
		p.Managed = resolve("role "+rr.RoleName, rr.AttachedManagedPolicies)
		p.Inline = inline("role "+rr.RoleName, "inline", rr.RolePolicyList)
		p.Boundary = boundary("role "+rr.RoleName, rr.PermissionsBoundary)
		if len(rr.AssumeRolePolicyDocument) > 0 {
			doc, err := policy.Parse(rr.AssumeRolePolicyDocument)
			if err != nil {
				a.warnf("role %s trust policy: %v (role treated as not assumable)", rr.RoleName, err)
			} else {
				p.Trust = doc
			}
		}
		for _, ip := range rr.InstanceProfileList {
			p.InstanceProfiles = append(p.InstanceProfiles, ip.Arn)
			a.instanceProfiles[ip.Arn] = p
		}
		a.Roles = append(a.Roles, p)
	}
	a.index()
	return a, nil
}

func (a *Account) index() {
	a.Principals = a.Principals[:0]
	a.Principals = append(a.Principals, a.Users...)
	a.Principals = append(a.Principals, a.Roles...)
	sort.SliceStable(a.Principals, func(i, j int) bool { return a.Principals[i].ARN < a.Principals[j].ARN })
	for _, p := range a.Principals {
		a.byARN[strings.ToLower(p.ARN)] = p
		a.byName[strings.ToLower(p.Name)] = append(a.byName[strings.ToLower(p.Name)], p)
		if a.ID == "" {
			a.ID = AccountFromARN(p.ARN)
		}
	}
}

func (a *Account) warnf(format string, args ...any) {
	a.Warnings = append(a.Warnings, fmt.Sprintf(format, args...))
}

// ByARN returns the principal with the given ARN.
func (a *Account) ByARN(arn string) *Principal { return a.byARN[strings.ToLower(arn)] }

// RoleForInstanceProfile returns the role contained in an instance profile.
func (a *Account) RoleForInstanceProfile(arn string) *Principal { return a.instanceProfiles[arn] }

// Find resolves a principal reference: a full ARN, "user/NAME",
// "role/NAME" or a bare name (which must be unambiguous).
func (a *Account) Find(ref string) (*Principal, error) {
	if p := a.ByARN(ref); p != nil {
		return p, nil
	}
	kind, name := "", ref
	if i := strings.IndexByte(ref, '/'); i > 0 {
		kind, name = strings.ToLower(ref[:i]), ref[i+1:]
	}
	var matches []*Principal
	for _, p := range a.byName[strings.ToLower(name)] {
		if kind == "" || string(p.Kind) == kind {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("principal %q not found", ref)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("principal %q is ambiguous; use user/NAME, role/NAME or the full ARN", ref)
	}
}

// IdentityPolicies returns every identity-based policy that applies to p:
// attached managed policies, inline policies and those of its groups.
func (p *Principal) IdentityPolicies() []policy.NamedPolicy {
	var out []policy.NamedPolicy
	for _, mp := range p.Managed {
		out = append(out, policy.NamedPolicy{Name: mp.Name, ARN: mp.ARN, Source: "managed", Kind: policy.KindIdentity, Doc: mp.Default})
	}
	out = append(out, p.Inline...)
	for _, g := range p.Groups {
		for _, mp := range g.Managed {
			out = append(out, policy.NamedPolicy{Name: mp.Name, ARN: mp.ARN, Source: "group:" + g.Name, Kind: policy.KindIdentity, Doc: mp.Default})
		}
		out = append(out, g.Inline...)
	}
	return out
}

// BoundaryPolicy returns the permissions boundary as a NamedPolicy, or nil.
func (p *Principal) BoundaryPolicy() *policy.NamedPolicy {
	if p.Boundary == nil {
		return nil
	}
	return &policy.NamedPolicy{Name: p.Boundary.Name, ARN: p.Boundary.ARN, Source: "permissions boundary", Kind: policy.KindBoundary, Doc: p.Boundary.Default}
}

// AttachedManagedPolicies returns every managed policy attached to p
// directly or through a group, with the attachment source.
func (p *Principal) AttachedManagedPolicies() []AttachedPolicy {
	var out []AttachedPolicy
	for _, mp := range p.Managed {
		out = append(out, AttachedPolicy{Policy: mp, Via: ""})
	}
	for _, g := range p.Groups {
		for _, mp := range g.Managed {
			out = append(out, AttachedPolicy{Policy: mp, Via: g.Name})
		}
	}
	return out
}

// AttachedPolicy is a managed policy and the group it comes through ("" if
// attached directly).
type AttachedPolicy struct {
	Policy *ManagedPolicy
	Via    string
}

// AccountFromARN extracts the account ID from an ARN.
func AccountFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

func lastSegment(arn string) string {
	if i := strings.LastIndexByte(arn, '/'); i >= 0 {
		return arn[i+1:]
	}
	return arn
}

func tags(ts []rawTag) map[string]string {
	if len(ts) == 0 {
		return nil
	}
	m := make(map[string]string, len(ts))
	for _, t := range ts {
		m[t.Key] = t.Value
	}
	return m
}

// RequestContext builds the request context for a request made by p.
// Global keys that are knowable from the export are set; everything else
// is left unknown.
func (a *Account) RequestContext(p *Principal) *policy.Context {
	ctx := policy.NewContext()
	ctx.Set("aws:PrincipalArn", p.ARN)
	ctx.Set("aws:PrincipalAccount", AccountFromARN(p.ARN))
	ctx.Set("aws:userid", p.ID)
	if p.Kind == KindUser {
		ctx.Set("aws:username", p.Name)
		ctx.Set("aws:PrincipalType", "User")
	} else {
		ctx.SetAbsent("aws:username")
		ctx.Set("aws:PrincipalType", "AssumedRole")
	}
	ctx.Set("aws:PrincipalIsAWSService", "false")
	// The export includes every tag on the principal, so any other
	// aws:PrincipalTag/* key is known to be absent.
	ctx.SetAbsentPrefix("aws:PrincipalTag/")
	for k, v := range p.Tags {
		ctx.Set("aws:PrincipalTag/"+k, v)
	}
	return ctx
}

// PolicyInput builds the evaluation input for p, including SCPs.
func (a *Account) PolicyInput(p *Principal) *policy.Input {
	return &policy.Input{Identity: p.IdentityPolicies(), Boundary: p.BoundaryPolicy(), SCPLevels: a.scpFor(p)}
}

func (a *Account) scpFor(p *Principal) [][]policy.NamedPolicy {
	if p.ServiceLinked {
		// SCPs do not affect service-linked roles.
		return nil
	}
	return a.SCPLevels
}
