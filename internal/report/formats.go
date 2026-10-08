package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Opsbreak/iampath/internal/escalation"
	"github.com/Opsbreak/iampath/internal/version"
)

// JSONHop is a hop in the JSON report.
type JSONHop struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	Technique     string   `json:"technique"`
	TechniqueName string   `json:"techniqueName"`
	Resource      string   `json:"resource,omitempty"`
	Via           string   `json:"via,omitempty"`
	Conditional   bool     `json:"conditional"`
	Notes         []string `json:"notes,omitempty"`
	Alternatives  []string `json:"alternatives,omitempty"`
}

// JSONPath is a path in the JSON report.
type JSONPath struct {
	Steps       int       `json:"steps"`
	Cost        int       `json:"cost"`
	Conditional bool      `json:"conditional"`
	Rendered    string    `json:"rendered"`
	Hops        []JSONHop `json:"hops"`
}

// JSONFinding is a finding in the JSON report.
type JSONFinding struct {
	Principal string     `json:"principal"`
	ARN       string     `json:"arn"`
	Paths     []JSONPath `json:"paths"`
}

// JSONAdmin is an admin entry in the JSON report.
type JSONAdmin struct {
	Principal string `json:"principal"`
	ARN       string `json:"arn"`
	Reason    string `json:"reason"`
}

// JSONReport is the machine-readable report.
type JSONReport struct {
	Tool      string `json:"tool"`
	Version   string `json:"version"`
	AccountID string `json:"accountId"`
	Summary   struct {
		Principals             int `json:"principals"`
		Edges                  int `json:"edges"`
		Admins                 int `json:"adminEquivalent"`
		PrincipalsWithPaths    int `json:"principalsWithPaths"`
		UnconditionalPaths     int `json:"principalsWithUnconditionalPaths"`
		PrincipalsWithoutPaths int `json:"principalsWithoutPaths"`
	} `json:"summary"`
	Admins   []JSONAdmin   `json:"admins"`
	Findings []JSONFinding `json:"findings"`
	NoPath   []string      `json:"noPath"`
	Cycles   [][]string    `json:"cycles"`
	Warnings []string      `json:"warnings"`
}

func hopJSON(meta Meta, e *escalation.Edge) JSONHop {
	h := JSONHop{
		From: nodeName(meta.acct, e.From), To: nodeName(meta.acct, e.To),
		Technique: e.Technique.ID, TechniqueName: e.Technique.Name,
		Resource: e.Resource, Via: e.Via, Conditional: e.Conditional, Notes: e.Notes,
	}
	for _, a := range e.Alternatives {
		h.Alternatives = append(h.Alternatives, a.Technique.ID+" "+a.Technique.Name)
	}
	return h
}

// BuildJSON converts a result to the JSON report structure.
func BuildJSON(res *escalation.Result, meta Meta) *JSONReport {
	r := &JSONReport{Tool: version.Name, Version: version.Version, AccountID: res.AccountID}
	r.Summary.Principals = res.Principals
	r.Summary.Edges = len(res.Edges)
	r.Summary.Admins = len(res.Admins)
	r.Summary.PrincipalsWithPaths = len(res.Findings)
	r.Summary.PrincipalsWithoutPaths = len(res.NoPath)
	r.Admins = []JSONAdmin{}
	r.Findings = []JSONFinding{}
	r.NoPath = []string{}
	r.Cycles = [][]string{}
	r.Warnings = append([]string{}, res.Warnings...)
	for _, a := range res.Admins {
		r.Admins = append(r.Admins, JSONAdmin{Principal: a.Principal.ShortName(), ARN: a.Principal.ARN, Reason: a.Reason})
	}
	for _, f := range res.Findings {
		jf := JSONFinding{Principal: f.Principal.ShortName(), ARN: f.Principal.ARN}
		if !f.Paths[0].Conditional {
			r.Summary.UnconditionalPaths++
		}
		for _, p := range f.Paths {
			jp := JSONPath{Steps: p.Steps(), Cost: p.Cost, Conditional: p.Conditional, Rendered: RenderPath(meta.acct, f.Principal, p)}
			for _, h := range p.Hops {
				jp.Hops = append(jp.Hops, hopJSON(meta, h))
			}
			jf.Paths = append(jf.Paths, jp)
		}
		r.Findings = append(r.Findings, jf)
	}
	for _, p := range res.NoPath {
		r.NoPath = append(r.NoPath, p.ShortName())
	}
	sort.Strings(r.NoPath)
	for _, c := range res.Cycles {
		var names []string
		for _, p := range c {
			names = append(names, p.ShortName())
		}
		r.Cycles = append(r.Cycles, names)
	}
	return r
}

// JSON renders the JSON report.
func JSON(w io.Writer, res *escalation.Result, meta Meta) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(BuildJSON(res, meta))
}

// pathEdges returns the unique edges that appear on reported paths, in a
// deterministic order.
func pathEdges(res *escalation.Result) []*escalation.Edge {
	seen := map[*escalation.Edge]bool{}
	var out []*escalation.Edge
	for _, f := range res.Findings {
		for _, p := range f.Paths {
			for _, h := range p.Hops {
				if !seen[h] {
					seen[h] = true
					out = append(out, h)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func dotEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
}

// DOT renders the union of all reported paths as a Graphviz digraph.
func DOT(w io.Writer, res *escalation.Result, meta Meta) error {
	ew := &errWriter{w: w}
	edges := pathEdges(res)
	admins := map[string]bool{}
	for _, a := range res.Admins {
		admins[a.Principal.ARN] = true
	}
	nodes := map[string]bool{}
	for _, e := range edges {
		nodes[e.From], nodes[e.To] = true, true
	}
	names := make([]string, 0, len(nodes))
	for n := range nodes {
		names = append(names, n)
	}
	sort.Strings(names)
	ew.printf("digraph iampath {\n")
	ew.printf("  rankdir=LR;\n  node [fontname=\"Helvetica\", fontsize=10];\n  edge [fontname=\"Helvetica\", fontsize=9];\n")
	for _, n := range names {
		label := nodeName(meta.acct, n)
		attrs := "shape=ellipse"
		switch {
		case n == escalation.AdminNode:
			attrs = "shape=doubleoctagon, style=filled, fillcolor=\"#d62728\", fontcolor=white"
		case strings.HasPrefix(label, "role/"):
			attrs = "shape=box"
		}
		if admins[n] {
			attrs += ", color=\"#d62728\", penwidth=2"
		}
		ew.printf("  \"%s\" [label=\"%s\", %s];\n", dotEscape(n), dotEscape(label), attrs)
	}
	for _, e := range edges {
		label := e.Technique.ID
		if e.Technique != escalation.AdminTechnique {
			label += " " + e.Technique.Name
		}
		style := ""
		if e.Conditional {
			style = ", style=dashed"
		}
		ew.printf("  \"%s\" -> \"%s\" [label=\"%s\"%s];\n", dotEscape(e.From), dotEscape(e.To), dotEscape(label), style)
	}
	ew.printf("}\n")
	return ew.err
}

// Mermaid renders the union of all reported paths as a Mermaid flowchart.
func Mermaid(w io.Writer, res *escalation.Result, meta Meta) error {
	ew := &errWriter{w: w}
	edges := pathEdges(res)
	ids := map[string]string{}
	var order []string
	id := func(n string) string {
		if v, ok := ids[n]; ok {
			return v
		}
		v := fmt.Sprintf("n%d", len(ids))
		ids[n] = v
		order = append(order, n)
		return v
	}
	for _, e := range edges {
		id(e.From)
		id(e.To)
	}
	admins := map[string]bool{}
	for _, a := range res.Admins {
		admins[a.Principal.ARN] = true
	}
	ew.printf("flowchart LR\n")
	for _, n := range order {
		label := strings.ReplaceAll(nodeName(meta.acct, n), `"`, "'")
		switch {
		case n == escalation.AdminNode:
			ew.printf("  %s{{\"%s\"}}\n", ids[n], label)
		case strings.HasPrefix(label, "role/"):
			ew.printf("  %s[\"%s\"]\n", ids[n], label)
		default:
			ew.printf("  %s([\"%s\"])\n", ids[n], label)
		}
	}
	for _, e := range edges {
		label := e.Technique.ID
		if e.Technique != escalation.AdminTechnique {
			label += " " + e.Technique.Name
		}
		label = strings.NewReplacer(`"`, "'", "|", "/").Replace(label)
		arrow := "-->"
		if e.Conditional {
			arrow = "-.->"
		}
		ew.printf("  %s %s|\"%s\"| %s\n", ids[e.From], arrow, label, ids[e.To])
	}
	ew.printf("  classDef admin fill:#d62728,color:#fff,stroke:#8c1c1c\n")
	var adminIDs []string
	for _, n := range order {
		if n == escalation.AdminNode || admins[n] {
			adminIDs = append(adminIDs, ids[n])
		}
	}
	if len(adminIDs) > 0 {
		ew.printf("  class %s admin\n", strings.Join(adminIDs, ","))
	}
	return ew.err
}

// SARIF renders findings as a SARIF 2.1.0 log.
func SARIF(w io.Writer, res *escalation.Result, meta Meta) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		FullDescription  msg            `json:"fullDescription"`
		Help             msg            `json:"help"`
		Properties       map[string]any `json:"properties,omitempty"`
	}
	type logical struct {
		Name               string `json:"name"`
		FullyQualifiedName string `json:"fullyQualifiedName"`
		Kind               string `json:"kind"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
		LogicalLocations []logical `json:"logicalLocations"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             msg               `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
		Properties          map[string]any    `json:"properties"`
	}
	used := map[string]*escalation.Technique{}
	var results []result
	uri := strings.ReplaceAll(meta.Input, `\`, "/")
	if uri == "" {
		uri = "account-authorization-details.json"
	}
	for _, f := range res.Findings {
		best := f.Paths[0]
		first := best.Hops[0].Technique
		for _, p := range f.Paths {
			for _, h := range p.Hops {
				if h.Technique != escalation.AdminTechnique {
					used[h.Technique.ID] = h.Technique
				}
			}
		}
		level := "error"
		if best.Conditional {
			level = "warning"
		}
		var rendered []string
		for _, p := range f.Paths {
			rendered = append(rendered, RenderPath(meta.acct, f.Principal, p))
		}
		sum := sha256.Sum256([]byte(f.Principal.ARN + "|" + rendered[0]))
		var loc location
		loc.PhysicalLocation.ArtifactLocation.URI = uri
		loc.LogicalLocations = []logical{{Name: f.Principal.ShortName(), FullyQualifiedName: f.Principal.ARN, Kind: string(f.Principal.Kind)}}
		cond := ""
		if best.Conditional {
			cond = " (conditional: depends on request conditions that could not be evaluated offline)"
		}
		results = append(results, result{
			RuleID: first.ID,
			Level:  level,
			Message: msg{Text: fmt.Sprintf("%s can escalate to administrator in %s%s: %s",
				f.Principal.ShortName(), plural(best.Steps(), "step"), cond, rendered[0])},
			Locations:           []location{loc},
			PartialFingerprints: map[string]string{"iampathPath/v1": hex.EncodeToString(sum[:16])},
			Properties: map[string]any{
				"principalArn": f.Principal.ARN,
				"steps":        best.Steps(),
				"cost":         best.Cost,
				"conditional":  best.Conditional,
				"paths":        rendered,
			},
		})
	}
	var rules []rule
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := used[id]
		rules = append(rules, rule{
			ID: t.ID, Name: strings.NewReplacer(" ", "", "+", "And", "(", "", ")", "").Replace(t.Name),
			ShortDescription: msg{Text: t.Description},
			FullDescription:  msg{Text: t.Exploitation},
			Help:             msg{Text: "Remediation: " + t.Remediation},
			Properties:       map[string]any{"requiredPermissions": t.Permissions, "category": string(t.Category), "tags": []string{"security", "aws", "iam"}},
		})
	}
	if rules == nil {
		rules = []rule{}
	}
	if results == nil {
		results = []result{}
	}
	log := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": version.Name, "version": version.Version, "informationUri": version.URL, "rules": rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}
