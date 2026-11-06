package db

import "testing"

func TestLLMUsageByIntentUsesPerCallLedger(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("intent usage", "per-intent exact usage")
	if err != nil { t.Fatal(err) }
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary":"high-value investigation"}, 5, nil, "planner")
	if err != nil { t.Fatal(err) }
	unusedID, err := store.AddIntent(map[string]any{"summary":"not yet executed"}, 1, nil, "planner")
	if err != nil { t.Fatal(err) }

	for _, usage := range []*LLMUsage{
		{ExplorationID:expID, IntentID:intentID, Worker:"worker", InputTokens:100, OutputTokens:20, CacheRead:70, CacheWrite:5, LatencyMs:1000, Status:"ok"},
		{ExplorationID:expID, IntentID:intentID, Worker:"worker", InputTokens:200, OutputTokens:30, CacheRead:150, CacheWrite:10, LatencyMs:2000, Status:"error"},
	} {
		if err := d.InsertLLMUsage(usage); err != nil { t.Fatal(err) }
	}

	items, err := store.LLMUsageByIntent()
	if err != nil { t.Fatal(err) }
	if len(items) != 2 { t.Fatalf("got %d intent rows, want 2: %+v", len(items), items) }
	var measured, unused *IntentUsageSummary
	for i := range items {
		switch items[i].IntentID {
		case intentID: measured = &items[i]
		case unusedID: unused = &items[i]
		}
	}
	if measured == nil || measured.Calls != 2 || measured.InputTokens != 300 ||
		measured.OutputTokens != 50 || measured.CacheReadTokens != 220 ||
		measured.CacheWriteTokens != 15 || measured.LatencyMs != 3000 {
		t.Fatalf("unexpected exact usage aggregate: %+v", measured)
	}
	if unused == nil || unused.Calls != 0 || unused.InputTokens != 0 {
		t.Fatalf("unexecuted intent should remain visible with zero usage: %+v", unused)
	}
}
