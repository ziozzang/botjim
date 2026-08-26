package relay

import "testing"

// TestPickerRarestFirst: the scarcest chunk is handed out first.
func TestPickerRarestFirst(t *testing.T) {
	tasks := []chunkTask{{0, 0}, {0, 1}, {0, 2}}
	pk := newPicker(tasks)
	// chunk 1 is rarest (held by nobody), chunk 0 by 3 peers, chunk 2 by 1
	rarity := map[rarityKey]int{{0, 0}: 3, {0, 1}: 0, {0, 2}: 1}
	got, ok, _ := pk.pick(rarity)
	if !ok || got.chunk != 1 {
		t.Fatalf("expected rarest chunk 1, got %+v ok=%v", got, ok)
	}
}

// TestPickerEndgameAndRetry: a failed fetch is retried; when pending is
// empty but a piece is in flight, pick duplicates it (endgame).
func TestPickerEndgameAndRetry(t *testing.T) {
	pk := newPicker([]chunkTask{{0, 0}, {0, 1}})
	r := map[rarityKey]int{}
	a, ok, _ := pk.pick(r)
	if !ok {
		t.Fatal("pick 1 failed")
	}
	b, ok, _ := pk.pick(r)
	if !ok {
		t.Fatal("pick 2 failed")
	}
	// both in flight, pending empty → endgame duplicates one of them
	c, ok, endgame := pk.pick(r)
	if !ok || !endgame {
		t.Fatalf("expected endgame duplicate, ok=%v endgame=%v", ok, endgame)
	}
	if c != a && c != b {
		t.Fatalf("endgame pick %+v is neither in-flight task", c)
	}
	// complete a: first completion wins
	if !pk.complete(a) {
		t.Fatal("first complete should win")
	}
	// the endgame duplicate of a (if c==a) loses
	if c == a && pk.complete(a) {
		t.Fatal("duplicate completion should lose")
	}
	// fail b a few times → retried, not fatal until the ceiling
	for i := 0; i < pk.maxFails-1; i++ {
		if pk.fail(b) {
			t.Fatalf("fatal too early at attempt %d", i)
		}
		// after a non-fatal fail, b returns to pending
		bb, ok, _ := pk.pick(r)
		if !ok || bb != b {
			t.Fatalf("retried chunk not re-picked: %+v ok=%v", bb, ok)
		}
	}
	if !pk.fail(b) {
		t.Fatal("should be fatal after maxFails")
	}
}

// TestPickerAllDone: pick returns ok=false once everything completes.
func TestPickerAllDone(t *testing.T) {
	pk := newPicker([]chunkTask{{0, 0}})
	r := map[rarityKey]int{}
	tk, ok, _ := pk.pick(r)
	if !ok {
		t.Fatal("pick failed")
	}
	pk.complete(tk)
	if !pk.allDone() {
		t.Fatal("should be all done")
	}
	if _, ok, _ := pk.pick(r); ok {
		t.Fatal("pick should return false when all done")
	}
}
