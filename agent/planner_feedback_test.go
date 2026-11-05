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
