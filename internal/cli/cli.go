// Package cli implements the iampath command-line interface.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Opsbreak/iampath/internal/account"
	"github.com/Opsbreak/iampath/internal/escalation"
	"github.com/Opsbreak/iampath/internal/policy"
	"github.com/Opsbreak/iampath/internal/report"
	"github.com/Opsbreak/iampath/internal/version"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitError      = 1
	ExitUsage      = 2
	ExitPathsFound = 3
)

const usage = `iampath - offline AWS IAM privilege-escalation path finder

Usage:
  iampath paths     -i account.json [flags]            find escalation paths to admin
  iampath who-can   -i account.json [flags] ACTION [RESOURCE]
  iampath explain   -i account.json [flags] PRINCIPAL ACTION RESOURCE
  iampath techniques [--format text|json|markdown]      list modelled techniques
  iampath version

Input flags (paths, who-can, explain):
  -i, --input FILE              output of 'aws iam get-account-authorization-details' (required)
  --scp FILE                    SCPs for one level of the org hierarchy (repeatable; one file per level)
  --lambda-functions FILE       output of 'aws lambda list-functions'
  --ec2-instances FILE          output of 'aws ec2 describe-instances'
  --codebuild-projects FILE     output of 'aws codebuild batch-get-projects'
  -q, --quiet                   do not print loader warnings to stderr

Run 'iampath COMMAND -h' for command-specific flags.

Exit codes: 0 ok, 1 error, 2 usage error, 3 paths found (with --fail-on-paths).
`

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := ExitOK
	switch cmd {
	case "paths", "analyze":
		code, err = runPaths(rest, stdout, stderr)
	case "who-can":
		err = runWhoCan(rest, stdout, stderr)
	case "explain":
		err = runExplain(rest, stdout, stderr)
	case "techniques":
		err = runTechniques(rest, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%s %s\n", version.Name, version.Version)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "iampath: unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "iampath %s: %v\n", cmd, err)
			return ExitUsage
		}
		fmt.Fprintf(stderr, "iampath %s: %v\n", cmd, err)
		return ExitError
	}
	return code
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type inputFlags struct {
	input     string
	scps      multiFlag
	lambdas   string
	instances string
	codebuild string
	quiet     bool
}

func (f *inputFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.input, "input", "", "authorization details JSON file")
	fs.StringVar(&f.input, "i", "", "shorthand for --input")
	fs.Var(&f.scps, "scp", "SCP file for one hierarchy level (repeatable)")
	fs.StringVar(&f.lambdas, "lambda-functions", "", "output of 'aws lambda list-functions'")
	fs.StringVar(&f.instances, "ec2-instances", "", "output of 'aws ec2 describe-instances'")
	fs.StringVar(&f.codebuild, "codebuild-projects", "", "output of 'aws codebuild batch-get-projects'")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress loader warnings")
	fs.BoolVar(&f.quiet, "q", false, "shorthand for --quiet")
}

func (f *inputFlags) load(stderr io.Writer, printWarnings bool) (*account.Account, error) {
	if f.input == "" {
		return nil, usagef("--input is required")
	}
	acct, err := account.LoadFile(f.input)
	if err != nil {
		return nil, err
	}
	for _, s := range f.scps {
		if err := acct.LoadSCPLevel(s); err != nil {
			return nil, err
		}
	}
	if f.lambdas != "" {
		if err := acct.LoadLambdaFunctions(f.lambdas); err != nil {
			return nil, err
		}
	}
	if f.instances != "" {
		if err := acct.LoadEC2Instances(f.instances); err != nil {
			return nil, err
		}
	}
	if f.codebuild != "" {
		if err := acct.LoadCodeBuildProjects(f.codebuild); err != nil {
			return nil, err
		}
	}
	if printWarnings && !f.quiet {
		for _, w := range acct.Warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
	}
	return acct, nil
}

// parse parses flags allowing them to be interspersed with positional
// arguments, and returns the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError{err.Error()}
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func newFlagSet(name string, stderr io.Writer, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: iampath %s\n\nFlags:\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

func runPaths(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("paths", stderr, "paths -i account.json [--from PRINCIPAL] [-k N] [--format FORMAT] [--fail-on-paths]")
	var in inputFlags
	in.register(fs)
	var from multiFlag
	fs.Var(&from, "from", "only analyse paths from this principal (name, user/NAME, role/NAME or ARN; repeatable or comma-separated)")
	k := fs.Int("k", 3, "maximum number of distinct paths per source principal")
	maxHops := fs.Int("max-hops", 8, "ignore paths with more steps than this (0 = unlimited)")
	format := fs.String("format", "text", "output format: "+strings.Join(report.Formats, ", "))
	out := fs.String("output", "", "write output to FILE instead of stdout")
	fs.StringVar(out, "o", "", "shorthand for --output")
	failOnPaths := fs.Bool("fail-on-paths", false, "exit with status 3 if any escalation path is found (for CI)")
	pos, err := parse(fs, args)
	if err != nil {
		return ExitUsage, err
	}
	if len(pos) > 0 {
		return ExitUsage, usagef("unexpected arguments: %s", strings.Join(pos, " "))
	}
	if *k < 1 {
		return ExitUsage, usagef("-k must be >= 1")
	}
	if !validFormat(*format) {
		return ExitUsage, usagef("unknown format %q (want one of %s)", *format, strings.Join(report.Formats, ", "))
	}
	acct, err := in.load(stderr, true)
	if err != nil {
		return ExitError, err
	}
	opts := escalation.Options{K: *k, MaxHops: *maxHops}
	for _, f := range from {
		for _, ref := range strings.Split(f, ",") {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			p, err := acct.Find(ref)
			if err != nil {
				return ExitUsage, usageError{err.Error()}
			}
			opts.From = append(opts.From, p)
		}
	}
	res := escalation.Analyze(acct, opts)
	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return ExitError, err
		}
		defer f.Close()
		w = f
	}
	if err := report.Write(w, *format, res, acct, report.Meta{Input: in.input}); err != nil {
		return ExitError, err
	}
	if *failOnPaths && len(res.Findings) > 0 {
		fmt.Fprintf(stderr, "iampath: %d principal(s) can escalate to administrator\n", len(res.Findings))
		return ExitPathsFound, nil
	}
	return ExitOK, nil
}

func validFormat(f string) bool {
	for _, x := range report.Formats {
		if x == f {
			return true
		}
	}
	return false
}

func runWhoCan(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("who-can", stderr, "who-can -i account.json [--pattern] [--show-denied] ACTION [RESOURCE]")
	var in inputFlags
	in.register(fs)
	pattern := fs.Bool("pattern", false, "treat wildcards in RESOURCE as 'any resource matching this pattern'")
	showDenied := fs.Bool("show-denied", false, "also list principals that are denied, with the reason")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || len(pos) > 2 {
		return usagef("expected ACTION [RESOURCE]")
	}
	action, resource := pos[0], "*"
	if len(pos) == 2 {
		resource = pos[1]
	}
	acct, err := in.load(stderr, true)
	if err != nil {
		return err
	}
	an := escalation.NewAnalyzer(acct)
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "PRINCIPAL\tDECISION\tDETAIL\n")
	allowed, conditional := 0, 0
	for _, p := range acct.Principals {
		r := an.Can(p, action, resource, *pattern, nil)
		switch {
		case r.Allowed() && !r.Conditional:
			allowed++
			fmt.Fprintf(tw, "%s\tallow\t%s\n", p.ShortName(), r.Reason)
		case r.Allowed():
			conditional++
			fmt.Fprintf(tw, "%s\tconditional\t%s\n", p.ShortName(), r.Reason)
		case *showDenied:
			fmt.Fprintf(tw, "%s\t%s\t%s\n", p.ShortName(), strings.ToLower(string(r.Decision)), r.Reason)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\n%d principal(s) allowed, %d conditionally, for %s on %s.\n", allowed, conditional, action, resource)
	return nil
}

func runExplain(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("explain", stderr, "explain -i account.json [--context key=value] [--pattern] PRINCIPAL ACTION RESOURCE")
	var in inputFlags
	in.register(fs)
	var ctxFlags multiFlag
	fs.Var(&ctxFlags, "context", "set a request context key, e.g. aws:MultiFactorAuthPresent=true (repeatable)")
	pattern := fs.Bool("pattern", false, "treat wildcards in RESOURCE as 'any resource matching this pattern'")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 3 {
		return usagef("expected PRINCIPAL ACTION RESOURCE")
	}
	acct, err := in.load(stderr, true)
	if err != nil {
		return err
	}
	p, err := acct.Find(pos[0])
	if err != nil {
		return usageError{err.Error()}
	}
	action, resource := pos[1], pos[2]
	an := escalation.NewAnalyzer(acct)
	extra := map[string]string{}
	for _, kv := range ctxFlags {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			return usagef("--context expects key=value, got %q", kv)
		}
		extra[kv[:i]] = kv[i+1:]
	}
	mod := func(c *policy.Context) {
		for k, v := range extra {
			c.Set(k, strings.Split(v, ",")...)
		}
	}
	ctx := an.Context(p).Clone()
	mod(ctx)
	r := an.Can(p, action, resource, *pattern, mod)
	return writeExplain(stdout, acct, an, p, action, resource, ctx, r)
}

func writeExplain(w io.Writer, acct *account.Account, an *escalation.Analyzer, p *account.Principal,
	action, resource string, ctx *policy.Context, r policy.Result) error {
	in := an.Input(p)
	fmt.Fprintf(w, "Principal: %s (%s)\n", p.ShortName(), p.ARN)
	fmt.Fprintf(w, "Request:   %s on %s\n", action, resource)
	var kv []string
	for _, k := range ctx.Keys() {
		v, _ := ctx.Get(k)
		kv = append(kv, k+"="+strings.Join(v, ","))
	}
	fmt.Fprintf(w, "Context:   %s\n", strings.Join(kv, " "))
	fmt.Fprintf(w, "           (other condition keys are unknown offline)\n\n")

	fmt.Fprintf(w, "Policies evaluated:\n")
	for _, np := range in.Identity {
		state := ""
		if np.Doc == nil {
			state = " [document missing from export]"
		}
		fmt.Fprintf(w, "  identity  %s%s\n", np.Label(), state)
	}
	if in.Boundary != nil {
		fmt.Fprintf(w, "  boundary  %s\n", in.Boundary.Name)
	} else {
		fmt.Fprintf(w, "  boundary  (none)\n")
	}
	if len(in.SCPLevels) == 0 {
		fmt.Fprintf(w, "  scp       (none supplied)\n")
	}
	for i, lvl := range in.SCPLevels {
		var names []string
		for _, s := range lvl {
			names = append(names, s.Name)
		}
		fmt.Fprintf(w, "  scp L%d    %s\n", i+1, strings.Join(names, ", "))
	}

	fmt.Fprintf(w, "\nMatching statements:\n")
	if len(r.Trace) == 0 {
		fmt.Fprintf(w, "  (none)\n")
	}
	for _, t := range r.Trace {
		fmt.Fprintf(w, "  %s\n", t.String())
	}
	fmt.Fprintf(w, "\nEvaluation (AWS order):\n")
	for _, l := range r.Layers {
		fmt.Fprintf(w, "  %-22s %s\n", l.Name, l.Result)
	}
	dec := string(r.Decision)
	if r.Conditional {
		dec += " (conditional)"
	}
	fmt.Fprintf(w, "\nDecision: %s\n  %s\n", dec, r.Reason)

	// For role assumption also show the trust policy decision.
	if strings.EqualFold(action, "sts:AssumeRole") {
		if role := acct.ByARN(resource); role != nil && role.Kind == account.KindRole {
			tr := policy.EvaluateTrust(role.Trust, role.Name, "sts:AssumeRole",
				policy.Caller{ARN: p.ARN, Account: account.AccountFromARN(p.ARN)}, ctx)
			fmt.Fprintf(w, "\nTrust policy of %s: %s\n", role.ShortName(), tr.Reason)
			for _, t := range tr.Trace {
				fmt.Fprintf(w, "  %s\n", t.String())
			}
			if tr.Allowed != policy.False {
				if tr.RequiresIdentityPermission {
					fmt.Fprintf(w, "  trust names the account: the identity decision above must also be Allow\n")
				} else {
					fmt.Fprintf(w, "  trust names the principal directly: an identity-policy Allow is not required in the same account\n")
				}
			}
		}
	}
	return nil
}

func runTechniques(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("techniques", stderr, "techniques [--format text|json|markdown]")
	format := fs.String("format", "text", "output format: text, json or markdown")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ts := escalation.Techniques()
	switch *format {
	case "text":
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintf(tw, "ID\tNAME\tCATEGORY\tPERMISSIONS\n")
		for _, t := range ts {
			perms := strings.Join(t.Permissions, ", ")
			if t.Inventory != "" {
				perms += "  (needs " + t.Inventory + ")"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Category, perms)
		}
		return tw.Flush()
	case "markdown":
		fmt.Fprintf(stdout, "| ID | Technique | Required permissions | Remediation |\n|---|---|---|---|\n")
		for _, t := range ts {
			perms := "`" + strings.Join(t.Permissions, "` + `") + "`"
			if t.Service != "" {
				perms += " (role trusts `" + t.Service + "`)"
			}
			if t.Inventory != "" {
				perms += " (needs `" + t.Inventory + "`)"
			}
			fmt.Fprintf(stdout, "| %s | %s | %s | %s |\n", t.ID, t.Name, perms, t.Remediation)
		}
		return nil
	case "json":
		return writeTechniquesJSON(stdout, ts)
	}
	return usagef("unknown format %q", *format)
}
