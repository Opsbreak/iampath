package policy

import "strings"

// WildcardMatch reports whether s matches pattern, where '*' matches any
// sequence of characters (including none) and '?' matches exactly one
// character. Matching is case-sensitive.
func WildcardMatch(pattern, s string) bool {
	p, i := 0, 0
	starP, starI := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			starP, starI = p, i
			p++
		case starP >= 0:
			p = starP + 1
			starI++
			i = starI
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// MatchAction reports whether an IAM action pattern (e.g. "iam:Put*Policy")
// matches action. Action matching is case-insensitive in AWS.
func MatchAction(pattern, action string) bool {
	if pattern == "*" {
		return true
	}
	return WildcardMatch(strings.ToLower(pattern), strings.ToLower(action))
}

// GlobsIntersect reports whether there exists at least one string matched by
// both wildcard patterns a and b.
func GlobsIntersect(a, b string) bool { return globsIntersect(a, b, false) }

// ResourcePatternIntersects reports whether a policy resource pattern
// allows at least one concrete resource described by an attacker-chosen
// request pattern such as "arn:aws:lambda:*:111122223333:function:*". The
// wildcards in the request pattern stand for single ARN components (a
// region, a function name) and therefore never produce ':'; wildcards in
// the policy pattern keep full AWS semantics and may span colons.
func ResourcePatternIntersects(policyPattern, requestPattern string) bool {
	return globsIntersect(policyPattern, requestPattern, true)
}

func globsIntersect(a, b string, bNoColon bool) bool {
	memo := make([]int8, (len(a)+1)*(len(b)+1))
	var f func(i, j int) bool
	f = func(i, j int) bool {
		k := i*(len(b)+1) + j
		if memo[k] != 0 {
			return memo[k] == 1
		}
		res := false
		switch {
		case i == len(a) && j == len(b):
			res = true
		case i < len(a) && a[i] == '*':
			// a's star produces nothing more, or absorbs whatever b
			// produces at position j.
			res = f(i+1, j) || (j < len(b) && f(i, j+1))
		case j < len(b) && b[j] == '*':
			// b's star produces nothing more, or produces the next
			// character that a requires.
			res = f(i, j+1) || (i < len(a) && !(bNoColon && a[i] == ':') && f(i+1, j))
		case i == len(a) || j == len(b):
			res = false
		case b[j] == '?':
			res = !(bNoColon && a[i] == ':') && f(i+1, j+1)
		case a[i] == '?' || a[i] == b[j]:
			res = f(i+1, j+1)
		}
		if res {
			memo[k] = 1
		} else {
			memo[k] = 2
		}
		return res
	}
	return f(0, 0)
}

// ArnLike implements the ArnLike/ArnEquals condition operators: each of the
// six colon-delimited ARN components is matched separately and may contain
// '*' and '?' wildcards.
func ArnLike(pattern, arn string) bool {
	if pattern == "*" {
		return true
	}
	pp := strings.SplitN(pattern, ":", 6)
	ap := strings.SplitN(arn, ":", 6)
	if len(pp) != 6 || len(ap) != 6 {
		return WildcardMatch(pattern, arn)
	}
	for i := range pp {
		if !WildcardMatch(pp[i], ap[i]) {
			return false
		}
	}
	return true
}

// SubstituteVariables replaces IAM policy variables such as
// ${aws:username} in s using values from ctx. The special variables ${*},
// ${?} and ${$} produce the literal characters. A default value may be
// supplied with ${key, 'default'}. The second return value is false when a
// referenced key is missing from the request context and has no default, in
// which case AWS treats the element as non-matching. The third return value
// is true when the key's presence could not be determined offline.
func SubstituteVariables(s string, ctx *Context) (out string, ok bool, unknown bool) {
	if !strings.Contains(s, "${") {
		return s, true, false
	}
	var sb strings.Builder
	ok = true
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			sb.WriteString(s)
			break
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			sb.WriteString(s)
			break
		}
		sb.WriteString(s[:i])
		expr := s[i+2 : i+j]
		s = s[i+j+1:]
		key, def, hasDef := expr, "", false
		if c := strings.IndexByte(expr, ','); c >= 0 {
			key = strings.TrimSpace(expr[:c])
			def = strings.Trim(strings.TrimSpace(expr[c+1:]), "'")
			hasDef = true
		}
		switch key {
		case "*", "?", "$":
			sb.WriteString(key)
			continue
		}
		vals, state := ctx.Get(key)
		switch {
		case state == KeyPresent && len(vals) > 0:
			sb.WriteString(vals[0])
		case hasDef:
			sb.WriteString(def)
		case state == KeyUnknown:
			ok, unknown = false, true
		default:
			ok = false
		}
	}
	return sb.String(), ok, unknown
}
