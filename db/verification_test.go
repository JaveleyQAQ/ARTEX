package db

import (
 "encoding/json"
 "errors"
 "testing"
 "time"
)

func TestFindingVerificationLifecycle(t *testing.T) {
 d, err := Open(testDSN(t))
	if err != nil { t.Skipf("postgres unavailable: %v", err) }
	defer d.Close()
 task,err:=d.CreateTask("verification lifecycle","fixture",nil,0,0); if err!=nil{t.Fatal(err)}; defer d.DeleteTask(task.ID)
 store:=d.Exploration(task.ExplorationID)
 intentID,err:=store.AddIntent(map[string]any{"summary":"fixture intent"},5,nil,"planner");if err!=nil{t.Fatal(err)}
 recorded,err:=store.RecordFinding(t.Context(),RecordFindingInput{TaskID:task.ID,IntentID:intentID,VulnClass:"TEST",Severity:SeverityLow,Summary:"candidate finding",Evidence:"observed fixture response",Worker:"worker-1"});if err!=nil{t.Fatal(err)}
 node,err:=store.GetNode(recorded.NodeID);if err!=nil||node==nil||node.State!="confirmed"{t.Fatalf("candidate node=%+v err=%v",node,err)}
	nodes:=[]*Node{node}
	if err:=store.PopulateFindingTrafficIDs(nodes);err!=nil||node.FindingStatus!=FindingPending{t.Fatalf("candidate finding status=%q err=%v",node.FindingStatus,err)}

 finding,err:=d.GetFinding(recorded.FindingID);if err!=nil||finding==nil||finding.Status!=FindingPending{t.Fatalf("candidate finding=%+v err=%v",finding,err)}
 confirmedIDs,pendingIDs,err:=store.FindingVerificationOverview()
 if err!=nil||len(confirmedIDs)!=0||len(pendingIDs)!=1||pendingIDs[0]!=recorded.NodeID{t.Fatalf("candidate overview confirmed=%v pending=%v err=%v",confirmedIDs,pendingIDs,err)}

 pending, err := d.ListPendingFindingVerificationRuns(t.Context(), 200)
	foundPending := false
	for _, candidate := range pending {
		if candidate.FindingID == recorded.FindingID {
			foundPending = true
			break
		}
	}
	if err != nil || !foundPending {
		t.Fatalf("candidate missing from pending queue (queue size %d), err=%v", len(pending), err)
	}
	runs, err := d.ListFindingVerificationRuns(t.Context(), recorded.FindingID)
	if err != nil || len(runs) != 1 || runs[0].Status != FindingVerificationPending {
		t.Fatalf("initial runs = %+v, err=%v", runs, err)
	}
 run,err:=d.ClaimFindingVerificationRun(t.Context(),runs[0].ID,"independent-reviewer");if err!=nil||run.Status!=FindingVerificationRunning||run.Attempts!=1{t.Fatalf("claim=%+v err=%v",run,err)}
 if _,err=d.ClaimFindingVerificationRun(t.Context(),run.ID,"second-reviewer");!errors.Is(err,ErrVerificationRunUnavailable){t.Fatalf("second claim should fail, got %v",err)}
 completed,err:=d.CompleteFindingVerificationRun(t.Context(),run.ID,"independent-reviewer",FindingVerdictConfirmed,"independent evidence review passed",json.RawMessage(`[{"kind":"response","observation":"fixture marker"}]`))
 if err!=nil||completed.Status!=FindingVerificationComplete||completed.Verdict!=FindingVerdictConfirmed{t.Fatalf("complete=%+v err=%v",completed,err)}
 finding,err=d.GetFinding(recorded.FindingID);if err!=nil||finding.Status!=FindingConfirmed{t.Fatalf("confirmed finding=%+v err=%v",finding,err)}
 node,err=store.GetNode(recorded.NodeID);if err!=nil||node.State!="confirmed"{t.Fatalf("confirmed node=%+v err=%v",node,err)}
	nodes=[]*Node{node}
	if err:=store.PopulateFindingTrafficIDs(nodes);err!=nil||node.FindingStatus!=FindingConfirmed{t.Fatalf("confirmed finding status=%q err=%v",node.FindingStatus,err)}

 confirmedIDs,pendingIDs,err=store.FindingVerificationOverview()
 if err!=nil||len(confirmedIDs)!=1||confirmedIDs[0]!=recorded.NodeID||len(pendingIDs)!=0{t.Fatalf("confirmed overview confirmed=%v pending=%v err=%v",confirmedIDs,pendingIDs,err)}

}

func TestRequeueStaleFindingVerificationRuns(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil { t.Skipf("postgres unavailable: %v", err) }
	defer d.Close()
	task, err := d.CreateTask("stale verification", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	recorded, err := store.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, VulnClass: "TEST", Severity: SeverityLow,
		Summary: "stale candidate", Evidence: "fixture evidence", Worker: "worker",
	})
	if err != nil {
	defer func() { _, _ = d.DeleteFinding(recorded.FindingID) }()
		t.Fatal(err)
	}
	runs, err := d.ListFindingVerificationRuns(t.Context(), recorded.FindingID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	if _, err := d.ClaimFindingVerificationRun(t.Context(), runs[0].ID, "crashed-reviewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE finding_verification_runs SET started_at=now()-interval '10 minutes' WHERE id=$1`, runs[0].ID); err != nil {
		t.Fatal(err)
	}
	requeued, err := d.RequeueStaleFindingVerificationRuns(t.Context(), time.Minute)
	if err != nil || requeued != 1 {
		t.Fatalf("requeued=%d err=%v", requeued, err)
	}
	recovered, err := d.GetFindingVerificationRun(t.Context(), runs[0].ID)
	if err != nil || recovered.Status != FindingVerificationPending || recovered.Verifier != "" {
		t.Fatalf("recovered run=%+v err=%v", recovered, err)
	}
}


func TestRejectedFindingVerificationKeepsHumanTriagePending(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	task, err := d.CreateTask("rejected verification", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	recorded, err := store.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, VulnClass: "TEST", Severity: SeverityLow,
		Summary: "rejected candidate", Evidence: "contradictory fixture evidence", Worker: "worker",
	})
	if err != nil {
	defer func() { _, _ = d.DeleteFinding(recorded.FindingID) }()
		t.Fatal(err)
	}
	runs, err := d.ListFindingVerificationRuns(t.Context(), recorded.FindingID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	run, err := d.ClaimFindingVerificationRun(t.Context(), runs[0].ID, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CompleteFindingVerificationRun(t.Context(), run.ID, "reviewer",
		FindingVerdictRejected, "证据直接反证候选主张",
		json.RawMessage(`[{"quote":"contradictory fixture evidence","reason":"与候选主张相矛盾"}]`)); err != nil {
		t.Fatal(err)
	}
	finding, err := d.GetFinding(recorded.FindingID)
	if err != nil || finding.Status != FindingPending {
		t.Fatalf("rejected finding must remain pending for human triage: %+v err=%v", finding, err)
	}
	node, err := store.GetNode(recorded.NodeID)
	if err != nil || node.State != "confirmed" {
		t.Fatalf("rejected candidate graph node=%+v err=%v", node, err)
	}
	confirmed, pending, err := store.FindingVerificationOverview()
	if err != nil || len(confirmed) != 0 || len(pending) != 1 || pending[0] != recorded.NodeID {
		t.Fatalf("rejected overview confirmed=%v pending=%v err=%v", confirmed, pending, err)
	}
}

func TestQueueFindingVerificationRunAllowsOnlyPendingWithoutActiveRun(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()
	task, err := d.CreateTask("manual retry", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	recorded, err := store.RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, VulnClass: "TEST", Severity: SeverityLow,
		Summary: "manual retry candidate", Evidence: "retry fixture", Worker: "worker",
	})
	if err != nil {
	defer func() { _, _ = d.DeleteFinding(recorded.FindingID) }()
		t.Fatal(err)
	}
	if _, err := d.QueueFindingVerificationRun(t.Context(), recorded.FindingID); !errors.Is(err, ErrFindingNotReviewable) {
		t.Fatalf("active run must block duplicate queueing, got %v", err)
	}
	runs, err := d.ListFindingVerificationRuns(t.Context(), recorded.FindingID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
	claimed, err := d.ClaimFindingVerificationRun(t.Context(), runs[0].ID, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CompleteFindingVerificationRun(t.Context(), claimed.ID, "reviewer",
		FindingVerdictInconclusive, "evidence is insufficient", json.RawMessage("[]")); err != nil {
		t.Fatal(err)
	}
	retry, err := d.QueueFindingVerificationRun(t.Context(), recorded.FindingID)
	if err != nil || retry.Status != FindingVerificationPending {
		t.Fatalf("manual retry=%+v err=%v", retry, err)
	}
	if _, err := d.SetFindingStatus(recorded.FindingID, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	if _, err := d.QueueFindingVerificationRun(t.Context(), recorded.FindingID); !errors.Is(err, ErrFindingNotReviewable) {
		t.Fatalf("human-confirmed finding must not be requeued, got %v", err)
	}
}
