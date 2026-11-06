package db

import (
	"context"
	"strings"
	"testing"
)

func TestRecordFindingDeduplicatesSameTaskRootCauseAndPreservesEvidence(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()

	task, err := d.CreateTask("finding dedup", "task-local root cause merge", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)

	intent1, err := store.AddIntent(map[string]any{"summary": "first verification"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	intent2, err := store.AddIntent(map[string]any{"summary": "independent corroboration"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}

	base := RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, IntentID: intent1,
		VulnClass: "AUTHZ", Name: "Object ownership check missing", Severity: "high",
		Summary: "Non-owner can read the same object", Evidence: "owner/non-owner differential observed",
		Worker: "work#1", RootCauseKey: "GET /api/orders/{id} | missing object ownership check",
	}
	first, err := store.RecordFinding(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if first.Deduplicated || first.FindingID <= 0 || first.NodeID <= 0 {
		t.Fatalf("first report should create a finding: %+v", first)
	}

	secondInput := base
	secondInput.IntentID = intent2
	secondInput.Worker = "work#2"
	secondInput.Evidence = "second independent session reproduced the same authorization gap"
	secondInput.Summary = "Same object authorization gap reproduced independently"
	second, err := store.RecordFinding(context.Background(), secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deduplicated || second.FindingID != first.FindingID || second.NodeID != first.NodeID {
		t.Fatalf("same root cause should resolve to the existing finding: first=%+v second=%+v", first, second)
	}

	findings, err := d.ListFindings(100)
	if err != nil {
		t.Fatal(err)
	}
	taskFindings := 0
	var mergedEvidence string
	for _, finding := range findings {
		if finding.TaskID != nil && *finding.TaskID == task.ID {
			taskFindings++
			mergedEvidence = finding.Evidence
		}
	}
	if taskFindings != 1 {
		t.Fatalf("task findings=%d, want exactly 1", taskFindings)
	}
	if !strings.Contains(mergedEvidence, base.Evidence) || !strings.Contains(mergedEvidence, secondInput.Evidence) {
		t.Fatalf("merged finding lost corroborating evidence: %q", mergedEvidence)
	}

	facts, err := store.ListByKind(KindFact, 100)
	if err != nil {
		t.Fatal(err)
	}
	corroborationFound := false
	for _, fact := range facts {
		if strings.Contains(string(fact.Payload), "duplicate_of_finding_id") {
			corroborationFound = true
			break
		}
	}
	if !corroborationFound {
		t.Fatal("deduplicated report should preserve a corroboration fact in the second intent lineage")
	}

	distinct := base
	distinct.IntentID = intent2
	distinct.RootCauseKey = "GET /api/orders/{id} | missing tenant isolation"
	distinct.Evidence = "different root cause evidence"
	third, err := store.RecordFinding(context.Background(), distinct)
	if err != nil {
		t.Fatal(err)
	}
	if third.Deduplicated || third.FindingID == first.FindingID {
		t.Fatalf("different root causes must remain separate: first=%+v third=%+v", first, third)
	}

	noKey := base
	noKey.IntentID = intent2
	noKey.RootCauseKey = ""
	noKey.Evidence = "legacy report without a stable root cause key"
	fourth, err := store.RecordFinding(context.Background(), noKey)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Deduplicated {
		t.Fatalf("missing root_cause_key must not trigger heuristic merging: %+v", fourth)
	}
}
