package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestAddIntentToolDeduplicatesSameCoordinatedWorkUnit(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("PostgreSQL DSN unavailable: %v", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	defer d.Close()

	task, err := d.CreateTask("intent coordinator tool", "deduplicate equivalent work", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	tools := NewToolSet(d.Exploration(task.ExplorationID), "planner")
	result, err := tools.addIntent().Call(context.Background(), json.RawMessage(`{
		"intents": [
			{"summary":"Review object authorization on endpoint A","coordination_key":"endpoint-a|authorization|object-read"},
			{"summary":"Check the same object-read authorization boundary","coordination_key":"endpoint-a|authorization|object-read"}
		]
	}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		IDs          []int64          `json:"ids"`
		Deduplicated map[string]int64 `json:"deduplicated"`
	}
	if err := json.Unmarshal([]byte(result.Flatten()), &out); err != nil {
		t.Fatalf("decode tool result %q: %v", result.Flatten(), err)
	}
	if len(out.IDs) != 2 || out.IDs[0] <= 0 || out.IDs[0] != out.IDs[1] {
		t.Fatalf("expected both submissions to resolve to the same intent: %+v", out)
	}
	if out.Deduplicated["1"] != out.IDs[0] {
		t.Fatalf("second item should be marked deduplicated: %+v", out)
	}
	nodes, err := d.Exploration(task.ExplorationID).ListByKind(db.KindIntent, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("intent count=%d, want 1", len(nodes))
	}
}
