package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/evidence"
)

type failingFindingRecorder struct{}

func (failingFindingRecorder) Record(context.Context, db.RecordFindingInput, []db.TrafficRef) (*db.RecordedFinding, error) {
	return nil, errors.New("fixture persistence failed")
}

func TestReportFindingOptionalTrafficWithoutCapture(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("TCP evidence", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts, ts.taskID = d.Exploration(task.ExplorationID), task.ID
	ts.SetFindingRecorder(evidence.New(d, nil, t.TempDir()))
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	for _, refs := range []string{"", `,"traffic_refs":[]`, `,"traffic_refs":null`} {
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(`{"vulnclass":"TCP","severity":"low","summary":"verified TCP fixture","evidence":"command output proves the finding"`+refs+`}`), nil)
		if err != nil || !strings.HasPrefix(res.Flatten(), "finding recorded: ") {
			t.Fatalf("optional traffic rejected: %v %s", err, res.Flatten())
		}
		var out db.RecordedFinding
		if err := json.Unmarshal([]byte(strings.SplitN(res.Flatten(), "\n", 2)[1]), &out); err != nil {
			t.Fatal(err)
		}
		f, err := d.GetFinding(out.FindingID)
		if err != nil || f == nil || len(out.Traffic.Bindings) != 0 || f.Evidence != "command output proves the finding" {
			t.Fatalf("lost non-HTTP evidence: %+v %v", f, err)
		}
	}
	if notices != 3 {
		t.Fatalf("successful reports notified %d times", notices)
	}
}

func TestReportFindingAtomicContract(t *testing.T) {
	old := FindingTrafficBindingEnabled
	FindingTrafficBindingEnabled = func() bool { return true }
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("report contract", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(nil, "")
	ts.ts = d.Exploration(task.ExplorationID)
	ts.taskID = task.ID
	ts.worker = "fixture"
	notices := 0
	ts.notifyFinding = func(int64, string) { notices++ }
	call := func(body string) string {
		t.Helper()
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	ts.SetFindingRecorder(failingFindingRecorder{})
	if got := call(`{"vulnclass":"TEST","summary":"fail","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "persistence failed") {
		t.Fatal(got)
	}
	if notices != 0 || ts.writes.Findings != 0 {
		t.Fatal("notified before commit")
	}
	ts.SetFindingRecorder(nil)
	got := call(`{"vulnclass":"TEST","summary":"legacy report","severity":"low"}`)
	lines := strings.SplitN(got, "\n", 2)
	if len(lines) != 2 {
		t.Fatal(got)
	}
	var out db.RecordedFinding
	if err = json.Unmarshal([]byte(lines[1]), &out); err != nil {
		t.Fatal(err)
	}
	if lines[0] != fmt.Sprintf("finding recorded: %d", out.NodeID) || out.FindingID <= 0 || notices != 1 {
		t.Fatal(got)
	}
	f, err := d.GetFinding(out.FindingID)
	if err != nil || f == nil || f.NodeID == nil || *f.NodeID != out.NodeID {
		t.Fatalf("wrong finding/node mapping: %+v %v", f, err)
	}
	if got = call(`{"vulnclass":"TEST","summary":"no storage","severity":"low","traffic_refs":[{"traffic_id":"x"}]}`); !strings.Contains(got, "未登记") {
		t.Fatal(got)
	}
	if notices != 1 {
		t.Fatal("failed tool triggered reporter")
	}
}


func TestFindingVerificationReadinessNeverClaimsIndependentVerification(t *testing.T) {
	tests := []struct {
		name        string
		evidence    string
		intentValid bool
		want        string
	}{
		{name: "no evidence", intentValid: true, want: "review_required"},
		{name: "no intent provenance", evidence: "observed response", want: "review_required"},
		{name: "evidence and intent", evidence: "observed response", intentValid: true, want: "pending_independent_review"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, note := findingVerificationReadiness(tt.evidence, tt.intentValid)
			if got != tt.want {
				t.Fatalf("status = %q, want %q", got, tt.want)
			}
			if strings.Contains(strings.ToLower(note), "verified") && got != "pending_independent_review" {
				t.Fatalf("review-required note must not imply verification: %q", note)
			}
			if got == "pending_independent_review" && !strings.Contains(note, "尚未经过独立验证") {
				t.Fatalf("pending status must explicitly require independent review: %q", note)
			}
		})
	}
}

func TestReportFindingValidatesSeverityAndIntentProvenance(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("finding validation", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "local fixture intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	ts := NewToolSet(store, "fixture")
	ts.SetTaskID(task.ID)

	call := func(body string) string {
		t.Helper()
		res, err := ts.addFinding().Call(t.Context(), json.RawMessage(body), nil)
		if err != nil {
			t.Fatal(err)
		}
		return res.Flatten()
	}
	if got := call(`{"vulnclass":"TEST","summary":"bad severity","severity":"urgent","evidence":"observed"}`); !strings.Contains(got, "severity 必须") {
		t.Fatalf("invalid severity was accepted: %s", got)
	}
	if got := call(fmt.Sprintf(`{"vulnclass":"TEST","summary":"foreign intent","severity":"low","intent_id":%d,"evidence":"observed"}`, intentID+999999)); !strings.Contains(got, "有效意图节点") {
		t.Fatalf("invalid intent provenance was accepted: %s", got)
	}
	got := call(fmt.Sprintf(`{"vulnclass":"TEST","summary":"candidate","severity":" LOW ","intent_id":%d,"evidence":"Observed response: fixture marker"}`, intentID))
	lines := strings.SplitN(got, "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("finding was not recorded: %s", got)
	}
	var result struct {
		VerificationStatus string `json:"verification_status"`
		VerificationNote   string `json:"verification_note"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &result); err != nil {
		t.Fatal(err)
	}
	if result.VerificationStatus != "pending_independent_review" || !strings.Contains(result.VerificationNote, "尚未经过独立验证") {
		t.Fatalf("submission was incorrectly treated as verified: %+v", result)
	}
}
