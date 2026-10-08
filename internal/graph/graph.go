// Package graph provides a small weighted directed graph with Dijkstra
// shortest paths, Yen's K-shortest loopless paths and Tarjan's strongly
// connected components.
package graph

import (
	"container/heap"
	"sort"
)

// Edge is a directed weighted edge. Payload is an opaque caller value.
type Edge struct {
	From, To int
	Weight   int
	Payload  int
}

// Graph is a directed multigraph with non-negative integer weights.
type Graph struct {
	names []string
	index map[string]int
	edges []Edge
	out   [][]int
}

// New returns an empty graph.
func New() *Graph { return &Graph{index: map[string]int{}} }

// Node returns the index of the node with the given name, creating it if
// needed.
func (g *Graph) Node(name string) int {
	if i, ok := g.index[name]; ok {
		return i
	}
	i := len(g.names)
	g.names = append(g.names, name)
	g.index[name] = i
	g.out = append(g.out, nil)
	return i
}

// Lookup returns the index of name and whether it exists.
func (g *Graph) Lookup(name string) (int, bool) {
	i, ok := g.index[name]
	return i, ok
}

// Name returns the name of node i.
func (g *Graph) Name(i int) string { return g.names[i] }

// NumNodes returns the number of nodes.
func (g *Graph) NumNodes() int { return len(g.names) }

// NumEdges returns the number of edges.
func (g *Graph) NumEdges() int { return len(g.edges) }

// AddEdge adds an edge and returns its index.
func (g *Graph) AddEdge(from, to, weight, payload int) int {
	if weight < 0 {
		panic("graph: negative weight")
	}
	id := len(g.edges)
	g.edges = append(g.edges, Edge{From: from, To: to, Weight: weight, Payload: payload})
	g.out[from] = append(g.out[from], id)
	return id
}

// Edge returns edge id.
func (g *Graph) Edge(id int) Edge { return g.edges[id] }

// Out returns the ids of edges leaving node n.
func (g *Graph) Out(n int) []int { return g.out[n] }

// Path is a sequence of edge ids.
type Path struct {
	Edges []int
	Cost  int
}

// Nodes returns the node sequence of p starting at src.
func (g *Graph) Nodes(p Path, src int) []int {
	ns := []int{src}
	for _, e := range p.Edges {
		ns = append(ns, g.edges[e].To)
	}
	return ns
}

type pqItem struct {
	node, dist int
}

type pq []pqItem

func (q pq) Len() int { return len(q) }
func (q pq) Less(i, j int) bool {
	if q[i].dist != q[j].dist {
		return q[i].dist < q[j].dist
	}
	return q[i].node < q[j].node
}
func (q pq) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *pq) Push(x any)   { *q = append(*q, x.(pqItem)) }
func (q *pq) Pop() any {
	old := *q
	it := old[len(old)-1]
	*q = old[:len(old)-1]
	return it
}

// workspace holds Dijkstra buffers so that repeated searches (Yen's
// algorithm runs one per spur node) do not allocate.
type workspace struct {
	dist, hops, prev []int
	done             []bool
	touched          []int
	q                pq
}

const inf = int(^uint(0) >> 1)

func newWorkspace(n int) *workspace {
	w := &workspace{dist: make([]int, n), hops: make([]int, n), prev: make([]int, n), done: make([]bool, n)}
	for i := range w.dist {
		w.dist[i] = inf
		w.prev[i] = -1
	}
	return w
}

func (w *workspace) reset() {
	for _, v := range w.touched {
		w.dist[v], w.hops[v], w.prev[v], w.done[v] = inf, 0, -1, false
	}
	w.touched = w.touched[:0]
	w.q = w.q[:0]
}

// shortest runs Dijkstra from src to dst avoiding banned nodes/edges. Ties
// are broken deterministically by fewer hops, then lower node index.
func (g *Graph) shortest(w *workspace, src, dst int, bannedNode []bool, bannedEdge map[int]bool) (Path, bool) {
	w.reset()
	dist, hops, prev, done := w.dist, w.hops, w.prev, w.done
	dist[src] = 0
	w.touched = append(w.touched, src)
	w.q = append(w.q, pqItem{node: src})
	q := &w.q
	for q.Len() > 0 {
		it := heap.Pop(q).(pqItem)
		u := it.node
		if done[u] {
			continue
		}
		done[u] = true
		if u == dst {
			break
		}
		for _, eid := range g.out[u] {
			if bannedEdge[eid] {
				continue
			}
			e := g.edges[eid]
			if bannedNode != nil && bannedNode[e.To] {
				continue
			}
			nd := dist[u] + e.Weight
			if dist[e.To] == inf {
				w.touched = append(w.touched, e.To)
			}
			if nd < dist[e.To] || (nd == dist[e.To] && hops[u]+1 < hops[e.To]) {
				dist[e.To] = nd
				hops[e.To] = hops[u] + 1
				prev[e.To] = eid
				heap.Push(q, pqItem{node: e.To, dist: nd})
			}
		}
	}
	if dist[dst] == inf {
		return Path{}, false
	}
	n := 0
	for v := dst; v != src; v = g.edges[prev[v]].From {
		n++
	}
	p := Path{Cost: dist[dst], Edges: make([]int, n)}
	for v := dst; v != src; v = g.edges[prev[v]].From {
		n--
		p.Edges[n] = prev[v]
	}
	return p, true
}

// ShortestPath returns the minimum-weight path from src to dst.
func (g *Graph) ShortestPath(src, dst int) (Path, bool) {
	if src == dst {
		return Path{}, true
	}
	return g.shortest(newWorkspace(len(g.names)), src, dst, nil, nil)
}

// KShortestPaths returns up to k loopless paths from src to dst in order of
// increasing cost (Yen's algorithm). Paths longer than maxHops edges are
// discarded when maxHops > 0.
func (g *Graph) KShortestPaths(src, dst, k, maxHops int) []Path {
	if k <= 0 || src == dst {
		return nil
	}
	w := newWorkspace(len(g.names))
	first, ok := g.shortest(w, src, dst, nil, nil)
	if !ok {
		return nil
	}
	A := []Path{first}
	var B []Path
	seen := map[string]bool{key(first): true}
	banned := make([]bool, len(g.names))
	bannedEdge := map[int]bool{}
	for len(A) < k+4*k && countWithin(A, maxHops) < k {
		last := A[len(A)-1]
		nodes := g.Nodes(last, src)
		for i := 0; i < len(last.Edges); i++ {
			spur := nodes[i]
			rootEdges := last.Edges[:i]
			clear(bannedEdge)
			for _, p := range A {
				if len(p.Edges) > i && equalPrefix(p.Edges, rootEdges) {
					bannedEdge[p.Edges[i]] = true
				}
			}
			for _, n := range nodes[:i] {
				banned[n] = true
			}
			sp, ok := g.shortest(w, spur, dst, banned, bannedEdge)
			for _, n := range nodes[:i] {
				banned[n] = false
			}
			if !ok {
				continue
			}
			cost := sp.Cost
			for _, e := range rootEdges {
				cost += g.edges[e].Weight
			}
			cand := Path{Edges: append(append([]int(nil), rootEdges...), sp.Edges...), Cost: cost}
			kk := key(cand)
			if seen[kk] {
				continue
			}
			seen[kk] = true
			B = append(B, cand)
		}
		if len(B) == 0 {
			break
		}
		sort.SliceStable(B, func(i, j int) bool {
			if B[i].Cost != B[j].Cost {
				return B[i].Cost < B[j].Cost
			}
			return len(B[i].Edges) < len(B[j].Edges)
		})
		A = append(A, B[0])
		B = B[1:]
	}
	var out []Path
	for _, p := range A {
		if maxHops > 0 && len(p.Edges) > maxHops {
			continue
		}
		out = append(out, p)
		if len(out) == k {
			break
		}
	}
	return out
}

func countWithin(ps []Path, maxHops int) int {
	if maxHops <= 0 {
		return len(ps)
	}
	n := 0
	for _, p := range ps {
		if len(p.Edges) <= maxHops {
			n++
		}
	}
	return n
}

func equalPrefix(a, prefix []int) bool {
	if len(a) < len(prefix) {
		return false
	}
	for i := range prefix {
		if a[i] != prefix[i] {
			return false
		}
	}
	return true
}

func key(p Path) string {
	b := make([]byte, 0, len(p.Edges)*4)
	for _, e := range p.Edges {
		b = append(b, byte(e>>24), byte(e>>16), byte(e>>8), byte(e))
	}
	return string(b)
}

// SCCs returns the strongly connected components with more than one node,
// or a single node with a self-loop, using an iterative Tarjan algorithm.
// Nodes for which skip returns true are ignored.
func (g *Graph) SCCs(skip func(int) bool) [][]int {
	n := len(g.names)
	index := make([]int, n)
	low := make([]int, n)
	onStack := make([]bool, n)
	for i := range index {
		index[i] = -1
	}
	var stack []int
	var out [][]int
	next := 0
	type frame struct{ v, ei int }
	for s := 0; s < n; s++ {
		if index[s] != -1 || (skip != nil && skip(s)) {
			continue
		}
		call := []frame{{v: s}}
		index[s], low[s] = next, next
		next++
		stack = append(stack, s)
		onStack[s] = true
		for len(call) > 0 {
			f := &call[len(call)-1]
			v := f.v
			if f.ei < len(g.out[v]) {
				e := g.edges[g.out[v][f.ei]]
				f.ei++
				w := e.To
				if skip != nil && skip(w) {
					continue
				}
				if index[w] == -1 {
					index[w], low[w] = next, next
					next++
					stack = append(stack, w)
					onStack[w] = true
					call = append(call, frame{v: w})
				} else if onStack[w] && index[w] < low[v] {
					low[v] = index[w]
				}
				continue
			}
			if low[v] == index[v] {
				var comp []int
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp = append(comp, w)
					if w == v {
						break
					}
				}
				if len(comp) > 1 || g.hasSelfLoop(v) {
					sort.Ints(comp)
					out = append(out, comp)
				}
			}
			call = call[:len(call)-1]
			if len(call) > 0 {
				p := call[len(call)-1].v
				if low[v] < low[p] {
					low[p] = low[v]
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

func (g *Graph) hasSelfLoop(v int) bool {
	for _, eid := range g.out[v] {
		if g.edges[eid].To == v {
			return true
		}
	}
	return false
}
