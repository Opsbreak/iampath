// Package report renders analysis results as text, JSON, Graphviz DOT,
// Mermaid and SARIF.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Opsbreak/iampath/internal/account"
	"github.com/Opsbreak/iampath/internal/escalation"
	"github.com/Opsbreak/iampath/internal/version"
)

// Formats lists the supported output formats.
var Formats = []string{"text", "json", "dot", "mermaid", "sarif"}

// Meta carries information about the inputs used for a report.
type Meta struct {
	// Input is the path of the authorization-details file as given by the
	// user (used for SARIF artifact locations).
	Input string
	acct  *account.Account
}

// Write renders res in the given format.
func Write(w io.Writer, format string, res *escalation.Result, acct *account.Account, meta Meta) error {
	meta.acct = acct
	switch format {
	case "text", "":
		return Text(w, res, meta)
	case "json":
		return JSON(w, res, meta)
	case "dot":
		return DOT(w, res, meta)
	case "mermaid":
		return Mermaid(w, res, meta)
	case "sarif":
		return SARIF(w, res, meta)
	}
	return fmt.Errorf("unknown format %q (want one of %s)", format, strings.Join(Formats, ", "))
}

// nodeName returns a short display name for a graph node.
func nodeName(acct *account.Account, arn string) string {
	if arn == escalation.AdminNode {
		return escalation.AdminNode
	}
	if acct != nil {
		if p := acct.ByARN(arn); p != nil {
			return p.ShortName()
		}
	}
	return arn
}

// HopLabel renders the label of a single hop, e.g.
// "IAM-001 CreatePolicyVersion on arn:aws:iam::111122223333:policy/X".
func HopLabel(e *escalation.Edge) string {
	var sb strings.Builder
	sb.WriteString(e.Technique.ID)
	sb.WriteString(" ")
	sb.WriteString(e.Technique.Name)
	if e.Resource != "" && e.Resource != e.To {
		sb.WriteString(" on ")
		sb.WriteString(e.Resource)
	}
	if e.Via != "" {
		sb.WriteString(" (")
		sb.WriteString(e.Via)
		sb.WriteString(")")
	}
	if e.Conditional {
		sb.WriteString(" [conditional]")
	}
	return sb.String()
}

// RenderPath renders a path on one line:
// user/a --[...]--> role/b --[...]--> ADMIN.
func RenderPath(acct *account.Account, src *account.Principal, p escalation.Path) string {
	var sb strings.Builder
	sb.WriteString(src.ShortName())
	for _, h := range p.Hops {
		if h.Technique == escalation.AdminTechnique {
			sb.WriteString(" ==> ADMIN")
			continue
		}
		sb.WriteString(" --[")
		sb.WriteString(HopLabel(h))
		sb.WriteString("]--> ")
		sb.WriteString(nodeName(acct, h.To))
	}
	return sb.String()
}

func plural(n int, s string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, s)
	}
	return fmt.Sprintf("%d %ss", n, s)
}

// Text renders a human-friendly report.
func Text(w io.Writer, res *escalation.Result, meta Meta) error {
	acct := meta.acct
	ew := &errWriter{w: w}
	ew.printf("%s %s - offline IAM privilege-escalation analysis\n", version.Name, version.Version)
	ew.printf("Account %s: %s, %s, %s.\n\n", res.AccountID, plural(res.Principals, "principal"),
		plural(len(res.Edges), "escalation edge"), plural(len(res.Admins), "admin-equivalent principal"))

	ew.printf("Administrator-equivalent principals:\n")
	if len(res.Admins) == 0 {
		ew.printf("  (none)\n")
	}
	width := 0
	for _, a := range res.Admins {
		if l := len(a.Principal.ShortName()); l > width {
			width = l
		}
	}
	for _, a := range res.Admins {
		ew.printf("  %-*s  %s\n", width, a.Principal.ShortName(), a.Reason)
	}
	ew.printf("\n")

	unconditional := 0
	for _, f := range res.Findings {
		if !f.Paths[0].Conditional {
			unconditional++
		}
	}
	ew.printf("Escalation paths: %s can reach ADMIN (%d unconditionally, %d only conditionally).\n",
		plural(len(res.Findings), "principal"), unconditional, len(res.Findings)-unconditional)
	for i, f := range res.Findings {
		best := f.Paths[0]
		tag := ""
		if best.Conditional {
			tag = ", CONDITIONAL"
		}
		ew.printf("\n[%d] %s  (%s, cost %d%s)\n", i+1, f.Principal.ShortName(), plural(best.Steps(), "step"), best.Cost, tag)
		for j, p := range f.Paths {
			prefix := "    "
			if len(f.Paths) > 1 {
				ew.printf("    path %d (%s, cost %d):\n", j+1, plural(p.Steps(), "step"), p.Cost)
				prefix = "      "
			}
			ew.printf("%s%s\n", prefix, RenderPath(acct, f.Principal, p))
			for _, h := range p.Hops {
				for _, n := range h.Notes {
					ew.printf("%s  ! %s\n", prefix, n)
				}
			}
		}
	}
	ew.printf("\n")

	if len(res.NoPath) > 0 {
		names := make([]string, 0, len(res.NoPath))
		for _, p := range res.NoPath {
			names = append(names, p.ShortName())
		}
		sort.Strings(names)
		ew.printf("No path to ADMIN (%d): %s\n\n", len(names), strings.Join(names, ", "))
	}
	if len(res.Cycles) > 0 {
		ew.printf("Cycles (principals that can reach each other):\n")
		for _, c := range res.Cycles {
			names := make([]string, 0, len(c))
			for _, p := range c {
				names = append(names, p.ShortName())
			}
			ew.printf("  %s\n", strings.Join(names, " <-> "))
		}
		ew.printf("\n")
	}
	if len(res.Warnings) > 0 {
		ew.printf("Warnings:\n")
		for _, wn := range res.Warnings {
			ew.printf("  - %s\n", wn)
		}
		ew.printf("\n")
	}
	return ew.err
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}
