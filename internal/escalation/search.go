package escalation

import (
	"sort"

	"github.com/Opsbreak/iampath/internal/account"
	"github.com/Opsbreak/iampath/internal/graph"
)

// Options control path search.
type Options struct {
	// K is the maximum number of distinct paths reported per source.
	K int
	// MaxHops discards paths with more steps (0 = unlimited).
	MaxHops int
	// From restricts sources to these principals (nil = all non-admins).
	From []*account.Principal
}

// Path is an escalation path from a source principal to ADMIN.
type Path struct {
	Hops        []*Edge
	Cost        int
	Conditional bool
}

// Steps returns the number of real escalation steps (excluding the final
// "already admin" pseudo hop).
func (p Path) Steps() int {
	n := 0
	for _, h := range p.Hops {
		if h.Technique != AdminTechnique {
			n++
		}
	}
	return n
}

// Finding groups the paths found for one source principal.
type Finding struct {
	Principal *account.Principal
	Paths     []Path
}

// AdminEntry is an administrator-equivalent principal.
type AdminEntry struct {
	Principal *account.Principal
	Reason    string
}

// Result is the outcome of a full analysis.
type Result struct {
	AccountID  string
	Principals int
	Admins     []AdminEntry
	Findings   []Finding
	// NoPath lists analysed sources without any path.
	NoPath []*account.Principal
	// Cycles lists groups of principals that can reach each other.
	Cycles [][]*account.Principal
	// Edges are the merged escalation edges (excluding ADMIN pseudo
	// edges).
	Edges    []*Edge
	Warnings []string
	Options  Options
}

// Analyze runs the full analysis.
func Analyze(acct *account.Account, opts Options) *Result {
	if opts.K <= 0 {
		opts.K = 3
	}
	an := NewAnalyzer(acct)
	edges := MergeEdges(an.BuildEdges())
	g := graph.New()
	admin := g.Node(AdminNode)
	for _, p := range acct.Principals {
		g.Node(p.ARN)
	}
	for i, e := range edges {
		g.AddEdge(g.Node(e.From), g.Node(e.To), e.Weight, i)
	}

	res := &Result{AccountID: acct.ID, Principals: len(acct.Principals), Warnings: acct.Warnings, Options: opts}
	for _, e := range edges {
		if e.Technique != AdminTechnique {
			res.Edges = append(res.Edges, e)
		}
	}
	for _, p := range acct.Principals {
		if st := an.Admin(p); st.Admin {
			res.Admins = append(res.Admins, AdminEntry{Principal: p, Reason: st.Reason})
		}
	}

	sources := opts.From
	if sources == nil {
		for _, p := range acct.Principals {
			if !p.ServiceLinked {
				sources = append(sources, p)
			}
		}
	}
	for _, p := range sources {
		if an.Admin(p).Admin {
			continue
		}
		src, _ := g.Lookup(p.ARN)
		// The graph hop limit includes the final ADMIN pseudo hop; the
		// user-facing limit counts real steps only and is applied below.
		graphHops := 0
		if opts.MaxHops > 0 {
			graphHops = opts.MaxHops + 1
		}
		f := Finding{Principal: p}
		for _, pp := range g.KShortestPaths(src, admin, opts.K, graphHops) {
			path := Path{Cost: pp.Cost}
			for _, eid := range pp.Edges {
				e := edges[g.Edge(eid).Payload]
				path.Hops = append(path.Hops, e)
				path.Conditional = path.Conditional || e.Conditional
			}
			if opts.MaxHops > 0 && path.Steps() > opts.MaxHops {
				continue
			}
			f.Paths = append(f.Paths, path)
		}
		if len(f.Paths) == 0 {
			res.NoPath = append(res.NoPath, p)
			continue
		}
		res.Findings = append(res.Findings, f)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i].Paths[0], res.Findings[j].Paths[0]
		if a.Conditional != b.Conditional {
			return !a.Conditional
		}
		if a.Cost != b.Cost {
			return a.Cost < b.Cost
		}
		return res.Findings[i].Principal.ARN < res.Findings[j].Principal.ARN
	})

	for _, comp := range g.SCCs(func(n int) bool { return n == admin }) {
		var c []*account.Principal
		for _, n := range comp {
			if p := acct.ByARN(g.Name(n)); p != nil {
				c = append(c, p)
			}
		}
		if len(c) > 0 {
			res.Cycles = append(res.Cycles, c)
		}
	}
	return res
}
