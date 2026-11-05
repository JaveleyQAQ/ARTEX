package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSummarizeIntentExecutionFeedbackSeparatesEvidenceFromToolFailure(t *testing.T) {
	intent := &db.Node{
		ID: 42, Kind: db.KindIntent, State: "exhausted",
		Payload: json.RawMessage(`{
			"summary":"review the fixture endpoint",
			"hypothesis":"the fixture exposes a role check gap",
			"expected_observation":"a lower-privilege fixture identity sees the protected marker",
			"success_criteria":"capture the request, identity role and returned marker"
		}`),
	}
	activities := []db.Activity{
		{Kind: "tool", Tool: "http_request", Summary: "request timed out", IsError: true},
		{Kind: "tool", Tool: "record_fact", Summary: "saved observation", IsError: false},
		{Kind: "tool", Tool: "http_request", Summary: "connection refused", IsError: true},
	}
	got := summarizeIntentExecutionFeedback(intent, activities, []int64{101})
	for _, want := range []string{
		"Intent #42 终态：exhausted",
		"原假设：the fixture exposes a role check gap",
		"预期观察：a lower-privilege fixture identity",
		"工具调用：3；工具错误：2",
		"http_request×2",
		"request timed out",
		"本轮写回事实：#101",
		"不得把工具失败当作反证",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("feedback missing %q: %s", want, got)
		}
	}
}

func TestSummarizeIntentExecutionFeedbackHandlesLegacyIntentAndNoFacts(t *testing.T) {
	intent := &db.Node{ID: 7, Kind: db.KindIntent, State: "done", Payload: json.RawMessage(`{"summary":"legacy intent"}`)}
	got := summarizeIntentExecutionFeedback(intent, nil, nil)
	for _, want := range []string{"Intent #7 终态：done", "工具调用：0；工具错误：0", "本轮写回事实：无"} {
		if !strings.Contains(got, want) {
			t.Errorf("feedback missing %q: %s", want, got)
		}
	}
	if summarizeIntentExecutionFeedback(nil, nil, nil) != "" {
		t.Fatal("nil intent should produce no feedback")
	}
}

func TestIsDuplicateActiveIntentIsConservative(t *testing.T) {
	existing := &db.Node{
		ID: 12, Kind: db.KindIntent, State: "open",
		Payload: json.RawMessage(`{"summary":"Review /api/profile","hypothesis":"role check is missing","asset_ids":[3,9]}`),
	}
	proposed := intentItem{
		Summary: " review /api/profile ",
		Hypothesis: "role check is missing",
	}
	if !isDuplicateActiveIntent(existing, proposed, []int64{9, 3}) {
		t.Fatal("same active direction with punctuation/asset ordering differences should be blocked")
	}
	proposed.Hypothesis = "a different authorization condition is present"
	if isDuplicateActiveIntent(existing, proposed, []int64{3, 9}) {
		t.Fatal("materially different hypothesis must remain eligible")
	}
	proposed.Hypothesis = "role check is missing"
	if isDuplicateActiveIntent(existing, proposed, []int64{3, 10}) {
		t.Fatal("different asset set must remain eligible")
	}
	existing.State = "done"
	if isDuplicateActiveIntent(existing, proposed, []int64{3, 9}) {
		t.Fatal("completed direction may be revisited after new evidence")
	}
}

func TestCompactIntentsPreservesPlanningContract(t *testing.T) {
	node := &db.Node{
		ID: 88, Kind: db.KindIntent, State: "open", Priority: 9,
		Payload: json.RawMessage(`{
			"summary":"inspect the fixture authorization boundary",
			"hypothesis":"the role check may be missing",
			"expected_observation":"a fixture user can read the protected marker",
			"success_criteria":"capture a reproducible request and response",
			"stop_conditions":"stop at the local fixture boundary",
			"priority_reason":"high goal relevance and low verification cost",
			"planner_review":{"outcome":"supported","reason":"the fixture marker was observed","evidence_ids":[101]}
		}`),
	}
	got := compactIntents([]*db.Node{node}, nil, nil)
	if len(got) != 1 {
		t.Fatalf("compact intents length=%d", len(got))
	}
	for key, want := range map[string]any{
		"priority": 9,
		"hypothesis": "the role check may be missing",
		"expected_observation": "a fixture user can read the protected marker",
		"success_criteria": "capture a reproducible request and response",
		"stop_conditions": "stop at the local fixture boundary",
		"priority_reason": "high goal relevance and low verification cost",
	} {
		if got[0][key] != want {
			t.Errorf("%s=%#v want %#v", key, got[0][key], want)
		}
	}
	review, ok := got[0]["planner_review"].(map[string]any)
	if !ok || review["outcome"] != "supported" || review["reason"] != "the fixture marker was observed" {
		t.Fatalf("planner review missing from compact intent: %#v", got[0]["planner_review"])
	}
	review, ok := got[0]["planner_review"].(map[string]any)
	if !ok || review["outcome"] != "supported" || review["reason"] != "the fixture marker was observed" {
		t.Fatalf("planner review missing from compact intent: %#v", got[0]["planner_review"])
	}
}
