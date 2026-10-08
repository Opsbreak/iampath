package graph

import (
	"reflect"
	"testing"
)

// build creates a graph from "from>to:weight" edge specs.
func build(t *testing.T, edges [][3]any) *Graph {
	t.Helper()
	g := New()
	for i, e := range edges {
		g.AddEdge(g.Node(e[0].(string)), g.Node(e[1].(string)), e[2].(int), i)
	}
	return g
}

func names(g *Graph, p Path, src int) []string {
	var out []string
	for _, n := range g.Nodes(p, src) {
		out = append(out, g.Name(n))
	}
	return out
}

func TestShortestPath(t *testing.T) {
	g := build(t, [][3]any{
		{"a", "b", 1}, {"b", "c", 1}, {"c", "d", 1},
		{"a", "d", 5},
		{"a", "e", 1}, {"e", "d", 1},
	})
	a, _ := g.Lookup("a")
	d, _ := g.Lookup("d")
	p, ok := g.ShortestPath(a, d)
	if !ok || p.Cost != 2 {
		t.Fatalf("cost = %d ok=%v", p.Cost, ok)
	}
	if got := names(g, p, a); !reflect.DeepEqual(got, []string{"a", "e", "d"}) {
		t.Errorf("path = %v", got)
	}
	x := g.Node("x")
	if _, ok := g.ShortestPath(a, x); ok {
		t.Error("expected no path to isolated node")
	}
	if p, ok := g.ShortestPath(a, a); !ok || len(p.Edges) != 0 {
		t.Error("path to self should be empty")
	}
}

func TestShortestPathPrefersFewerHopsOnTie(t *testing.T) {
	g := build(t, [][3]any{
		{"s", "a", 1}, {"a", "b", 0}, {"b", "t", 1},
		{"s", "c", 1}, {"c", "t", 1},
	})
	s, _ := g.Lookup("s")
	tt, _ := g.Lookup("t")
	p, _ := g.ShortestPath(s, tt)
	if p.Cost != 2 || len(p.Edges) != 2 {
		t.Errorf("cost=%d hops=%d, want 2 hops", p.Cost, len(p.Edges))
	}
}

func TestKShortestPaths(t *testing.T) {
	// Classic Yen example graph (C -> H).
	g := build(t, [][3]any{
		{"C", "D", 3}, {"C", "E", 2}, {"D", "F", 4}, {"E", "D", 1},
		{"E", "F", 2}, {"E", "G", 3}, {"F", "G", 2}, {"F", "H", 1}, {"G", "H", 2},
	})
	c, _ := g.Lookup("C")
	h, _ := g.Lookup("H")
	tests := []struct {
		k, maxHops int
		wantCosts  []int
	}{
		{1, 0, []int{5}},
		{3, 0, []int{5, 7, 8}},
		{10, 0, []int{5, 7, 8, 8, 8, 11, 11}},
		{3, 3, []int{5, 7, 8}},
		{10, 2, nil},
	}
	for _, tt := range tests {
		ps := g.KShortestPaths(c, h, tt.k, tt.maxHops)
		var costs []int
		for _, p := range ps {
			costs = append(costs, p.Cost)
			if tt.maxHops > 0 && len(p.Edges) > tt.maxHops {
				t.Errorf("path exceeds maxHops: %v", names(g, p, c))
			}
		}
		if !reflect.DeepEqual(costs, tt.wantCosts) {
			t.Errorf("k=%d maxHops=%d costs = %v, want %v", tt.k, tt.maxHops, costs, tt.wantCosts)
		}
	}
	first := g.KShortestPaths(c, h, 1, 0)[0]
	if got := names(g, first, c); !reflect.DeepEqual(got, []string{"C", "E", "F", "H"}) {
		t.Errorf("first path = %v", got)
	}
}

func TestKShortestPathsLoopless(t *testing.T) {
	g := build(t, [][3]any{
		{"a", "b", 1}, {"b", "a", 1}, {"b", "c", 1}, {"a", "c", 3},
	})
	a, _ := g.Lookup("a")
	c, _ := g.Lookup("c")
	for _, p := range g.KShortestPaths(a, c, 5, 0) {
		seen := map[int]bool{}
		for _, n := range g.Nodes(p, a) {
			if seen[n] {
				t.Fatalf("path revisits node: %v", names(g, p, a))
			}
			seen[n] = true
		}
	}
	if n := len(g.KShortestPaths(a, c, 5, 0)); n != 2 {
		t.Errorf("expected 2 loopless paths, got %d", n)
	}
}

func TestSCCs(t *testing.T) {
	g := build(t, [][3]any{
		{"a", "b", 1}, {"b", "c", 1}, {"c", "a", 1}, // cycle a-b-c
		{"c", "d", 1},
		{"d", "e", 1}, {"e", "d", 1}, // cycle d-e
		{"f", "f", 1}, // self loop
		{"g", "h", 1},
	})
	var got [][]string
	for _, comp := range g.SCCs(nil) {
		var c []string
		for _, n := range comp {
			c = append(c, g.Name(n))
		}
		got = append(got, c)
	}
	want := [][]string{{"a", "b", "c"}, {"d", "e"}, {"f"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SCCs = %v, want %v", got, want)
	}
	skipE := func(n int) bool { return g.Name(n) == "e" }
	if n := len(g.SCCs(skipE)); n != 2 {
		t.Errorf("with e skipped expected 2 components, got %d", n)
	}
}

func TestNegativeWeightPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic")
		}
	}()
	g := New()
	g.AddEdge(g.Node("a"), g.Node("b"), -1, 0)
}
