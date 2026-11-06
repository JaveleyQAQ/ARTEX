package agent

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestCoverageSeparatesObservedAssetsFromSecurityTestedAssets(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTask("coverage semantics", "distinguish observation from security testing", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	domain := fmt.Sprintf("coverage-%d.example.test", time.Now().UnixNano())
	if _, err := d.Assets().RegisterTaskAssetScopes(task.ID, []db.ScopeInput{{Kind: "domain", Value: domain}}); err != nil {
		t.Fatal(err)
	}
	assets, err := d.Assets().QueryByTask(task.ID, "", 10, 0)
	if err != nil || len(assets) != 1 {
		t.Fatalf("scoped assets=%+v err=%v", assets, err)
	}
	assetID := assets[0].ID
	t.Cleanup(func() { _, _ = d.Assets().DeleteByIDs([]int64{assetID}) })

	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "inspect scoped asset"}, 5, []int64{assetID}, "planner")
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(store, "worker")

	observedID, err := tools.recordOneFact(factItem{
		Summary: "Identified the service and response fingerprint",
		Evidence: "GET / returned HTTP 200",
		Confidence: "observed",
		AssetIDs: []json.RawMessage{mustJSONRaw(assetID)},
		IntentID: mustJSONRaw(intentID),
	}, intentID)
	if err != nil {
		t.Fatal(err)
	}
	_ = observedID

	coverage, err := d.Assets().TaskCoverageWithSources(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Denominator != 1 || coverage.Tested != 1 || coverage.SecurityTested != 0 {
		t.Fatalf("observation must not count as security-tested: %+v", coverage)
	}

	if _, err := tools.recordOneFact(factItem{
		Summary: "Completed an evidence-backed security test attempt",
		Evidence: "controlled test request returned the observed policy response",
		TestStatus: "tested",
		Confidence: "observed",
		AssetIDs: []json.RawMessage{mustJSONRaw(assetID)},
		IntentID: mustJSONRaw(intentID),
	}, intentID); err != nil {
		t.Fatal(err)
	}

	coverage, err = d.Assets().TaskCoverageWithSources(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Denominator != 1 || coverage.Tested != 1 || coverage.SecurityTested != 1 {
		t.Fatalf("explicit security test should count once without inflating observed assets: %+v", coverage)
	}
	if coverage.SecurityTestedPct == nil || *coverage.SecurityTestedPct != 1 {
		t.Fatalf("security_tested_pct=%v, want 1", coverage.SecurityTestedPct)
	}
}

func TestRecordFactCannotClaimTestedWithoutDirectEvidence(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("coverage evidence guard", "require evidence for tested status", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	tools := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	_, err = tools.recordOneFact(factItem{
		Summary: "unsupported test claim",
		TestStatus: "tested",
		Confidence: "observed",
	}, 0)
	if err == nil {
		t.Fatal("test_status=tested without evidence must be rejected")
	}
}
