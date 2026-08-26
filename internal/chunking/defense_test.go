package chunking

import "testing"

// TestGridDefensive: a Grid built directly from wire fields must not
// divide-by-zero or overflow on crafted values.
func TestGridDefensive(t *testing.T) {
	cases := []Grid{
		{Size: 1, ChunkSize: 0},               // div-by-zero
		{Size: 1 << 40, ChunkSize: 0},         // div-by-zero, large
		{Size: 1<<63 - 1, ChunkSize: 4 << 20}, // overflow numerator
		{Size: -5, ChunkSize: 4 << 20},        // negative size
		{Size: 100, ChunkSize: -1},            // negative chunk
	}
	for i, g := range cases {
		if n := g.Count(); n != 0 { // all should degrade to 0, never panic
			t.Errorf("case %d: Count=%d, want 0 (no panic)", i, n)
		}
	}
	// a valid grid still works
	g := Grid{Size: 10 << 20, ChunkSize: 4 << 20}
	if g.Count() != 3 {
		t.Fatalf("valid grid Count=%d, want 3", g.Count())
	}
}
