package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRecordHypothesisResultPersistsOutcomeAndEvidence(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("hypothesis result", "verify a scoped test hypothesis", nil, 0, 0)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func(){ _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{
		"summary":"verify object ownership on endpoint",
		"hypothesis":map[string]any{
			"pattern_id":int64(7),
			"verification_steps":[]string{"read object as owner","read same object as another test user"},
			"expected_evidence":[]string{"different authorization outcome for same object"},
			"acceptance_criteria":[]string{"owner can read the object and non-owner cannot"},
		},
	}, 8, nil, "planner")
	if err != nil { t.Fatal(err) }
	tools := NewToolSet(store, "worker")
	tools.SetTaskID(task.ID)
	tools.SetOwnerNode(intentID)
	tool := tools.recordHypothesisResult()
	result, err := tool.Call(context.Background(), json.RawMessage(`{
		"intent_id":`+hypothesisFixtureJSONNumber(intentID)+`,
		"outcome":"inconclusive",
		"summary":"second test identity could not be provisioned",
		"evidence":"HTTP 403 from identity bootstrap; no cross-user object request was made",
		"supporting_evidence":[],
		"contradicting_evidence":["Identity bootstrap was denied; the cross-user condition remains untested"],
		"acceptance_criteria_met":false,
		"limitations":["second identity unavailable"]
	}`), nil)
	if err != nil { t.Fatal(err) }
	var out map[string]any
	if err := json.Unmarshal([]byte(result.Flatten()), &out); err != nil { t.Fatalf("decode result %q: %v",result.Flatten(),err) }
	if out["outcome"] != "inconclusive" || out["finding_required"] != false { t.Fatalf("unexpected tool result: %#v",out) }
	factID := int64(out["fact_id"].(float64))
	fact, err := store.GetNode(factID)
	if err != nil || fact == nil || fact.Kind != db.KindFact { t.Fatalf("fact=%+v err=%v",fact,err) }
	var payload map[string]any
	if err := json.Unmarshal(fact.Payload,&payload); err != nil { t.Fatal(err) }
	if payload["hypothesis_outcome"]!="inconclusive" || payload["evidence"]=="" || payload["pattern_id"]!=float64(7) || payload["acceptance_criteria_met"]!=false || payload["test_status"]!="tested" || len(payload["contradicting_evidence"].([]any))!=1 {
		t.Fatalf("hypothesis evidence not persisted: %#v",payload)
	}
	edges, err := store.Edges(100)
	if err != nil { t.Fatal(err) }
	linked:=false
	for _, edge := range edges { if edge.From==intentID && edge.To==factID && edge.Rel==db.RelYields { linked=true } }
	if !linked { t.Fatalf("result fact %d is not linked to intent %d",factID,intentID) }
	hasHypothesis, status, outcome, err := store.IntentHypothesisLifecycle(intentID)
	if err != nil || !hasHypothesis || status != "recorded" || outcome != "inconclusive" {
		t.Fatalf("unexpected lifecycle: has=%v status=%q outcome=%q err=%v", hasHypothesis, status, outcome, err)
	}
	if err := store.SetIntentHypothesisLifecycle(intentID, "recorded", "inconclusive", factID); err != nil {
		t.Fatal(err)
	}
	finding, err := tools.addFinding().Call(context.Background(), json.RawMessage(`{
		"vulnclass":"AUTHZ","severity":"high","summary":"must not report an inconclusive hypothesis",
		"intent_id":`+hypothesisFixtureJSONNumber(intentID)+`,
		"evidence":"inconclusive result is not a confirmed vulnerability"
	}`), nil)
	if err != nil { t.Fatal(err) }
	if !strings.Contains(finding.Flatten(), "必须先提交 outcome=confirmed") {
		t.Fatalf("expected finding gate for inconclusive hypothesis, got %q", finding.Flatten())
	}
}

func TestRecordHypothesisResultRequiresStructuredHypothesisAndEvidence(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("hypothesis validation", "reject incomplete hypothesis", nil, 0, 0)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func(){ _ = d.DeleteTask(task.ID) })
	store:=d.Exploration(task.ExplorationID)
	intentID,err:=store.AddIntent(map[string]any{"summary":"ordinary exploration"},5,nil,"planner")
	if err!=nil { t.Fatal(err) }
	tool:=NewToolSet(store,"worker").recordHypothesisResult()
	call:=func(input string) string { r,e:=tool.Call(context.Background(),json.RawMessage(input),nil); if e!=nil {t.Fatal(e)}; return r.Flatten() }
	if got:=call(`{"intent_id":`+hypothesisFixtureJSONNumber(intentID)+`,"outcome":"confirmed","summary":"claimed","evidence":"observed"}`); !strings.Contains(got,"没有结构化 hypothesis") {
		t.Fatalf("expected structured-hypothesis guard, got %q",got)
	}
	hypID,err:=store.AddIntent(map[string]any{"summary":"hypothesis","hypothesis":map[string]any{"verification_steps":[]string{"check"},"expected_evidence":[]string{"response"},"acceptance_criteria":[]string{"response matches expected control"}}},5,nil,"planner")
	if err!=nil {t.Fatal(err)}
	if got:=call(`{"intent_id":`+hypothesisFixtureJSONNumber(hypID)+`,"outcome":"confirmed","summary":"claimed","evidence":""}`); !strings.Contains(got,"evidence 不能为空") {
		t.Fatalf("expected evidence guard, got %q",got)
	}
	if got:=call(`{"intent_id":`+hypothesisFixtureJSONNumber(hypID)+`,"outcome":"confirmed","summary":"claimed","evidence":"observed","supporting_evidence":["response matched"],"contradicting_evidence":[],"acceptance_criteria_met":false}`); !strings.Contains(got,"必须明确满足全部 acceptance_criteria") {
		t.Fatalf("expected acceptance criteria guard, got %q",got)
	}
	if got:=call(`{"intent_id":`+hypothesisFixtureJSONNumber(hypID)+`,"outcome":"confirmed","summary":"criteria met","evidence":"reproducible response","supporting_evidence":["same controlled input produced the expected response"],"contradicting_evidence":[],"acceptance_criteria_met":true}`); !strings.Contains(got,"finding_required") {
		t.Fatalf("expected confirmed hypothesis result, got %q",got)
	}
}

func hypothesisFixtureJSONNumber(id int64) string { b,_:=json.Marshal(id); return string(b) }
