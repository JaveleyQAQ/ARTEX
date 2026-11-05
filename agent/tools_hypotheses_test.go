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
		},
	}, 8, nil, "planner")
	if err != nil { t.Fatal(err) }
	tools := NewToolSet(store, "worker")
	tools.SetTaskID(task.ID)
	tool := tools.recordHypothesisResult()
	result, err := tool.Call(context.Background(), json.RawMessage(`{
		"intent_id":`+hypothesisFixtureJSONNumber(intentID)+`,
		"outcome":"inconclusive",
		"summary":"second test identity could not be provisioned",
		"evidence":"HTTP 403 from identity bootstrap; no cross-user object request was made",
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
	if payload["hypothesis_outcome"]!="inconclusive" || payload["evidence"]=="" || payload["pattern_id"]!=float64(7) {
		t.Fatalf("hypothesis evidence not persisted: %#v",payload)
	}
	edges, err := store.Edges(100)
	if err != nil { t.Fatal(err) }
	linked:=false
	for _, edge := range edges { if edge.From==intentID && edge.To==factID && edge.Rel==db.RelYields { linked=true } }
	if !linked { t.Fatalf("result fact %d is not linked to intent %d",factID,intentID) }
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
	hypID,err:=store.AddIntent(map[string]any{"summary":"hypothesis","hypothesis":map[string]any{"verification_steps":[]string{"check"},"expected_evidence":[]string{"response"}}},5,nil,"planner")
	if err!=nil {t.Fatal(err)}
	if got:=call(`{"intent_id":`+hypothesisFixtureJSONNumber(hypID)+`,"outcome":"confirmed","summary":"claimed","evidence":""}`); !strings.Contains(got,"evidence 不能为空") {
		t.Fatalf("expected evidence guard, got %q",got)
	}
}

func hypothesisFixtureJSONNumber(id int64) string { b,_:=json.Marshal(id); return string(b) }
