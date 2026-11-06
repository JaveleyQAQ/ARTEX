package db

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestAddIntentCoordinatedAdmitsOnlyOneConcurrentActiveWorkUnit(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("PostgreSQL DSN unavailable: %v", err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("intent coordinator", "concurrent duplicate admission")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)

	const contenders = 12
	var created atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	ids := make(chan int64, contenders)
	errs := make(chan error, contenders)
	for range contenders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			id, wasCreated, addErr := store.AddIntentCoordinated(
				map[string]any{"summary": "same investigation"},
				5, []int64{}, "planner", "v1|assets=|work=authz:object-read",
			)
			if addErr != nil {
				errs <- addErr
				return
			}
			if wasCreated {
				created.Add(1)
			}
			ids <- id
		}()
	}
	close(start)
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var first int64
	for id := range ids {
		if first == 0 {
			first = id
		} else if id != first {
			t.Fatalf("concurrent admissions created different intents: first=%d got=%d", first, id)
		}
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("created count=%d, want exactly 1", got)
	}
	nodes, err := store.ListByKind(KindIntent, 100)
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, node := range nodes {
		if node.State == "open" || node.State == "running" {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active intents=%d, want 1", active)
	}
}

func TestAddIntentCoordinatedAllowsDistinctWorkAndReopensAfterTerminal(t *testing.T) {
	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("PostgreSQL DSN unavailable: %v", err)
	}
	d, err := Open(dsn)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("intent coordinator lifecycle", "distinct keys and terminal retry")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	store := d.Exploration(expID)

	first, created, err := store.AddIntentCoordinated(map[string]any{"summary": "same asset, dimension A"}, 5, nil, "planner", "v1|assets=|work=dimension-a")
	if err != nil || !created {
		t.Fatalf("first admission: id=%d created=%v err=%v", first, created, err)
	}
	second, created, err := store.AddIntentCoordinated(map[string]any{"summary": "same asset, dimension B"}, 5, nil, "planner", "v1|assets=|work=dimension-b")
	if err != nil || !created || second == first {
		t.Fatalf("distinct work admission: id=%d created=%v err=%v", second, created, err)
	}
	if err := store.SetNodeState(first, "done"); err != nil {
		t.Fatal(err)
	}
	retry, created, err := store.AddIntentCoordinated(map[string]any{"summary": "new attempt after completion"}, 5, nil, "planner", "v1|assets=|work=dimension-a")
	if err != nil || !created || retry == first {
		t.Fatalf("terminal key should be reusable: id=%d created=%v err=%v", retry, created, err)
	}
}
