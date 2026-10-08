package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Tri is a three-valued logic result used for offline evaluation: some
// condition keys (source IP, MFA, request time, tags on resources that are
// not in the export...) cannot be known ahead of time.
type Tri int8

// Tri values.
const (
	False Tri = iota
	True
	Unknown
)

func (t Tri) String() string {
	switch t {
	case True:
		return "true"
	case False:
		return "false"
	default:
		return "unknown"
	}
}

// and combines two Tri values with three-valued AND.
func and(a, b Tri) Tri {
	if a == False || b == False {
		return False
	}
	if a == Unknown || b == Unknown {
		return Unknown
	}
	return True
}

// or combines two Tri values with three-valued OR.
func or(a, b Tri) Tri {
	if a == True || b == True {
		return True
	}
	if a == Unknown || b == Unknown {
		return Unknown
	}
	return False
}

// KeyState describes what is known about a condition key.
type KeyState int8

// Key states.
const (
	KeyUnknown KeyState = iota
	KeyPresent
	KeyAbsent
)

// Context is the request context used to evaluate conditions and policy
// variables. Keys are case-insensitive. Keys that were neither set nor
// marked absent are "unknown" and make dependent conditions evaluate to
// Unknown.
type Context struct {
	values         map[string][]string
	names          map[string]string // lower-case key -> key as first set
	absent         map[string]bool
	absentPrefixes []string
}

// NewContext returns an empty context.
func NewContext() *Context {
	return &Context{values: map[string][]string{}, names: map[string]string{}, absent: map[string]bool{}}
}

// Set sets a key to one or more values.
func (c *Context) Set(key string, vals ...string) *Context {
	k := strings.ToLower(key)
	c.values[k] = append([]string(nil), vals...)
	if _, ok := c.names[k]; !ok {
		c.names[k] = key
	}
	delete(c.absent, k)
	return c
}

// SetAbsent marks a key as definitely absent from the request.
func (c *Context) SetAbsent(key string) *Context {
	k := strings.ToLower(key)
	delete(c.values, k)
	c.absent[k] = true
	return c
}

// Get returns the values and state of a key.
func (c *Context) Get(key string) ([]string, KeyState) {
	if c == nil {
		return nil, KeyUnknown
	}
	k := strings.ToLower(key)
	if v, ok := c.values[k]; ok {
		return v, KeyPresent
	}
	if c.absent[k] {
		return nil, KeyAbsent
	}
	for _, pfx := range c.absentPrefixes {
		if strings.HasPrefix(k, pfx) {
			return nil, KeyAbsent
		}
	}
	return nil, KeyUnknown
}

// SetAbsentPrefix marks every key starting with prefix that is not
// explicitly set as absent (e.g. "aws:PrincipalTag/" when all principal
// tags are known).
func (c *Context) SetAbsentPrefix(prefix string) *Context {
	c.absentPrefixes = append(c.absentPrefixes, strings.ToLower(prefix))
	return c
}

// Clone returns a deep copy of the context.
func (c *Context) Clone() *Context {
	n := NewContext()
	if c == nil {
		return n
	}
	for k, v := range c.values {
		n.values[k] = append([]string(nil), v...)
	}
	for k, v := range c.names {
		n.names[k] = v
	}
	for k := range c.absent {
		n.absent[k] = true
	}
	n.absentPrefixes = append(n.absentPrefixes, c.absentPrefixes...)
	return n
}

// Keys returns the keys that are present, in their original spelling,
// sorted case-insensitively.
func (c *Context) Keys() []string {
	var ks []string
	for k := range c.values {
		ks = append(ks, c.names[k])
	}
	sort.Slice(ks, func(i, j int) bool { return strings.ToLower(ks[i]) < strings.ToLower(ks[j]) })
	return ks
}

// baseOperators lists the supported operators and whether they are negated.
var baseOperators = map[string]bool{
	"stringequals":              false,
	"stringnotequals":           true,
	"stringequalsignorecase":    false,
	"stringnotequalsignorecase": true,
	"stringlike":                false,
	"stringnotlike":             true,
	"arnequals":                 false,
	"arnlike":                   false,
	"arnnotequals":              true,
	"arnnotlike":                true,
	"bool":                      false,
	"ipaddress":                 false,
	"notipaddress":              true,
}

// IsSupportedOperator reports whether the condition operator (including
// IfExists and ForAnyValue/ForAllValues qualifiers) can be evaluated.
func IsSupportedOperator(op string) bool {
	base, _, _, _ := splitOperator(op)
	if base == "null" {
		return true
	}
	_, ok := baseOperators[base]
	return ok
}

func splitOperator(op string) (base string, ifExists bool, anyValue bool, allValues bool) {
	o := strings.ToLower(strings.TrimSpace(op))
	switch {
	case strings.HasPrefix(o, "foranyvalue:"):
		anyValue = true
		o = strings.TrimPrefix(o, "foranyvalue:")
	case strings.HasPrefix(o, "forallvalues:"):
		allValues = true
		o = strings.TrimPrefix(o, "forallvalues:")
	}
	if strings.HasSuffix(o, "ifexists") {
		ifExists = true
		o = strings.TrimSuffix(o, "ifexists")
	}
	return o, ifExists, anyValue, allValues
}

// ConditionResult is the outcome of evaluating a Condition block.
type ConditionResult struct {
	Result Tri
	// Unresolved lists human-readable reasons for Unknown results.
	Unresolved []string
}

// EvaluateConditions evaluates a condition block against ctx. All operators
// and all keys must be satisfied (logical AND); multiple values for one key
// are OR-ed.
func EvaluateConditions(cb ConditionBlock, ctx *Context) ConditionResult {
	res := ConditionResult{Result: True}
	ops := make([]string, 0, len(cb))
	for op := range cb {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		keys := make([]string, 0, len(cb[op]))
		for k := range cb[op] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			r, why := evalOne(op, key, cb[op][key], ctx)
			if r == Unknown {
				res.Unresolved = append(res.Unresolved, why)
			}
			res.Result = and(res.Result, r)
		}
	}
	if res.Result != Unknown {
		res.Unresolved = nil
	}
	return res
}

func evalOne(op, key string, policyVals StringList, ctx *Context) (Tri, string) {
	base, ifExists, anyValue, allValues := splitOperator(op)
	negated, supported := baseOperators[base]
	if base == "null" {
		supported = true
	}
	if !supported {
		return Unknown, fmt.Sprintf("unsupported operator %s on %s", op, key)
	}
	reqVals, state := ctx.Get(key)
	if state == KeyUnknown {
		return Unknown, fmt.Sprintf("%s %s=%v (key not known offline)", op, key, []string(policyVals))
	}
	if base == "null" {
		want := len(policyVals) > 0 && strings.EqualFold(policyVals[0], "true")
		isNull := state == KeyAbsent
		if want == isNull {
			return True, ""
		}
		return False, ""
	}
	if state == KeyAbsent || len(reqVals) == 0 {
		switch {
		case ifExists:
			return True, ""
		case allValues:
			return True, ""
		case anyValue:
			return False, ""
		case negated:
			return True, ""
		default:
			return False, ""
		}
	}
	// Substitute policy variables in the policy values.
	vals := make([]string, 0, len(policyVals))
	for _, pv := range policyVals {
		s, ok, unk := SubstituteVariables(pv, ctx)
		if unk {
			return Unknown, fmt.Sprintf("%s %s uses a policy variable not known offline", op, key)
		}
		if ok {
			vals = append(vals, s)
		}
	}
	match := func(rv string) bool {
		for _, pv := range vals {
			if baseMatch(base, pv, rv) {
				return true
			}
		}
		return false
	}
	pred := func(rv string) bool {
		m := match(rv)
		if negated {
			return !m
		}
		return m
	}
	switch {
	case anyValue:
		for _, rv := range reqVals {
			if pred(rv) {
				return True, ""
			}
		}
		return False, ""
	case allValues:
		for _, rv := range reqVals {
			if !pred(rv) {
				return False, ""
			}
		}
		return True, ""
	case negated:
		for _, rv := range reqVals {
			if match(rv) {
				return False, ""
			}
		}
		return True, ""
	default:
		for _, rv := range reqVals {
			if match(rv) {
				return True, ""
			}
		}
		return False, ""
	}
}

func baseMatch(base, pv, rv string) bool {
	switch base {
	case "stringequals", "stringnotequals":
		return pv == rv
	case "stringequalsignorecase", "stringnotequalsignorecase":
		return strings.EqualFold(pv, rv)
	case "stringlike", "stringnotlike":
		return WildcardMatch(pv, rv)
	case "arnequals", "arnlike", "arnnotequals", "arnnotlike":
		return ArnLike(pv, rv)
	case "bool":
		return strings.EqualFold(pv, rv)
	case "ipaddress", "notipaddress":
		return ipMatch(pv, rv)
	}
	return false
}

func ipMatch(cidr, ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	c := strings.TrimSpace(cidr)
	if !strings.Contains(c, "/") {
		a, err := netip.ParseAddr(c)
		return err == nil && a == addr
	}
	pfx, err := netip.ParsePrefix(c)
	if err != nil {
		return false
	}
	return pfx.Contains(addr)
}
