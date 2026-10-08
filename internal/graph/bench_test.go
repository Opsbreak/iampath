package graph

import (
	"fmt"
	"math/rand"
	"testing"
)

// randomGraph builds a graph with n principal nodes plus a sink, ~deg
// out-edges per node and ~2% of nodes connected to the sink.
func randomGraph(n, deg int) (*Graph, int) {
	r := rand.New(rand.NewSource(1))
	g := New()
	sink := g.Node("ADMIN")
	for i := 0; i < n; i++ {
		g.Node(fmt.Sprintf("p%d", i))
	}
	for i := 1; i <= n; i++ {
		for d := 0; d < deg; d++ {
			if r.Intn(3) == 0 {
				g.AddEdge(i, 1+r.Intn(n), 1+r.Intn(3), 0)
			}
		}
		if r.Intn(50) == 0 {
			g.AddEdge(i, sink, 0, 0)
		}
	}
	return g, sink
}

// BenchmarkKShortestPaths2000 runs K=3 Yen searches from every node of a
// 2,000-node graph to the sink.
func BenchmarkKShortestPaths2000(b *testing.B) {
	g, sink := randomGraph(2000, 6)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for src := 1; src < g.NumNodes(); src++ {
			g.KShortestPaths(src, sink, 3, 9)
		}
	}
}
