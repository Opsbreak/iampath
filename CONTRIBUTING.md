# Contributing to iampath

Thanks for helping make IAM privilege escalation easier to find and fix.

## Ground rules

- **Never commit real account data.** Fixtures must be synthetic. Use the
  account IDs from the AWS documentation (`111122223333`, `444455556666`,
  `123456789012`) or the generator in `internal/synth`.
- Report security issues privately, as described in [SECURITY.md](SECURITY.md).
  Don't open public issues for them.
- iampath stays offline and read-only. Changes must not add network calls or
  require AWS credentials.

## Development

You need Go 1.22 or newer. The project uses only the standard library.

```sh
go build ./...
go test ./...            # unit, table-driven and golden-file tests
go test -race ./...
go vet ./...
gofmt -l .               # must print nothing
go test -run '^$' -bench . -benchmem ./internal/...   # benchmarks
```

### Golden files

Tests compare report output against the files in `testdata/golden/`. If you
change the output on purpose, regenerate the golden files and review the
diff:

```sh
go test ./internal/report -update
```

Then re-run the commands shown in `README.md` and `examples/README.md` and
update the example output there.

## Adding an escalation technique

1. Add a `Technique` to `internal/escalation/techniques.go`. Give it an ID,
   the required permissions, a description, exploitation notes written for
   defenders, a remediation and a weight (1 = trivial, higher = more steps or
   more noise).
2. Build its edges in `internal/escalation/analyzer.go`:
   - **become** edges (`becomeEdges`) go from a principal to another principal
     whose credentials or session it can obtain.
   - **grant** edges (`grantEdges`) go to `ADMIN` when a principal can give
     administrator permissions to itself or to a principal it can become.

   For a PassRole technique it's usually enough to add the service actions to
   `passRoleSteps`.
3. Add positive and negative cases to `TestTechniques` in
   `internal/escalation/techniques_test.go`.
4. Regenerate the technique table in `README.md` with
   `go run ./cmd/iampath techniques --format markdown`.

## Extending the evaluation engine

Policy semantics live in `internal/policy`. Every change in behaviour needs a
table-driven test, ideally one that mirrors an example from the AWS
documentation and cites it. If a feature can't be evaluated precisely
offline, return `Unknown` so the path is reported as conditional. Never
silently allow or deny.

## Pull requests

- Keep each PR focused, and describe why you made the change and how you
  tested it.
- CI must pass: gofmt, `go vet`, `go test -race`, and cross-compilation for
  Linux, macOS and Windows.
- Add a line to the `Unreleased` section of `CHANGELOG.md`.

By contributing, you agree to license your contributions under the MIT
License.
