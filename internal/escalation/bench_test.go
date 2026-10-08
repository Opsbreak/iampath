package escalation

import (
	"bytes"
	"testing"

	"github.com/Opsbreak/iampath/internal/account"
	"github.com/Opsbreak/iampath/internal/synth"
)

func synthAccount(tb testing.TB, n int) *account.Account {
	tb.Helper()
	a, err := account.Load(bytes.NewReader(synth.Generate(n, 42)))
	if err != nil {
		tb.Fatal(err)
	}
	return a
}

func TestSyntheticScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	a := synthAccount(t, 500)
	res := Analyze(a, Options{K: 3, MaxHops: 8})
	if len(res.Admins) == 0 || len(res.Findings) == 0 || len(res.NoPath) == 0 {
		t.Errorf("synthetic account should have admins (%d), findings (%d) and principals without paths (%d)",
			len(res.Admins), len(res.Findings), len(res.NoPath))
	}
	for _, f := range res.Findings {
		for _, p := range f.Paths {
			if len(p.Hops) == 0 || p.Hops[len(p.Hops)-1].To != AdminNode {
				t.Fatalf("invalid path for %s", f.Principal.ARN)
			}
		}
	}
}

// BenchmarkAnalyze2000 measures the full pipeline (edge construction,
// admin detection, K=3 path search from every principal) on a generated
// account with 2,000 principals.
func BenchmarkAnalyze2000(b *testing.B) {
	a := synthAccount(b, 2000)
	b.ResetTimer()
	var res *Result
	for i := 0; i < b.N; i++ {
		res = Analyze(a, Options{K: 3, MaxHops: 8})
	}
	b.ReportMetric(float64(len(res.Edges)), "edges")
	b.ReportMetric(float64(len(res.Findings)), "findings")
}

// BenchmarkBuildEdges2000 measures edge construction only.
func BenchmarkBuildEdges2000(b *testing.B) {
	a := synthAccount(b, 2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewAnalyzer(a).BuildEdges()
	}
}

// BenchmarkLoad2000 measures parsing the generated JSON document.
func BenchmarkLoad2000(b *testing.B) {
	data := synth.Generate(2000, 42)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := account.Load(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
