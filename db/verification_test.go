package db

import (
 "encoding/json"
 "errors"
 "testing"
)

func TestFindingVerificationLifecycle(t *testing.T) {
 d:=testDB(t); defer d.Close()
 task,err:=d.CreateTask("verification lifecycle","fixture",nil,0,0); if err!=nil{t.Fatal(err)}; defer d.DeleteTask(task.ID)
 store:=d.Exploration(task.ExplorationID)
 intentID,err:=store.AddIntent(map[string]any{"summary":"fixture intent"},5,nil,"planner");if err!=nil{t.Fatal(err)}
 recorded,err:=store.RecordFinding(t.Context(),RecordFindingInput{TaskID:task.ID,IntentID:intentID,VulnClass:"TEST",Severity:SeverityLow,Summary:"candidate finding",Evidence:"observed fixture response",Worker:"worker-1"});if err!=nil{t.Fatal(err)}
 node,err:=store.GetNode(recorded.NodeID);if err!=nil||node==nil||node.State!="pending_verification"{t.Fatalf("candidate node=%+v err=%v",node,err)}
 finding,err:=d.GetFinding(recorded.FindingID);if err!=nil||finding==nil||finding.Status!=FindingPending{t.Fatalf("candidate finding=%+v err=%v",finding,err)}
 pending, err := d.ListPendingFindingVerificationRuns(t.Context(), 10)
	if err != nil || len(pending) != 1 || pending[0].FindingID != recorded.FindingID {
		t.Fatalf("pending queue = %+v, err=%v", pending, err)
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
}

func TestRequeueStaleFindingVerificationRuns(t *testing.T) {
	d := testDB(t)
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
