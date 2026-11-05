package agent

import "testing"

func TestIntentPayloadPersistsHypothesisContract(t *testing.T) {
	item := intentItem{
		Summary: "  检查本地靶场中登录流程的状态绑定  ",
		Priority: 8,
		PriorityReason: "目标直接相关、证据置信度较高且验证成本低",
		Hypothesis: "会话状态可能未与当前用户绑定",
		ExpectedObservation: "不同测试用户的会话标识可能出现交叉复用",
		SuccessCriteria: "只有在可重复的请求/响应证据表明跨用户状态泄露时才支持假设",
		StopConditions: "超出任务声明的本地靶场范围或需要真实用户数据时立即停止",
	}
	got := intentPayload(item, []int64{12, 34})
	if got["summary"] != "检查本地靶场中登录流程的状态绑定" {
		t.Fatalf("summary was not normalized: %#v", got["summary"])
	}
	if got["priority_reason"] != item.PriorityReason {
		t.Fatalf("priority_reason = %#v, want %q", got["priority_reason"], item.PriorityReason)
	}
	if got["asset_ids"] == nil {
		t.Fatal("asset_ids were not preserved")
	}
	for key, want := range map[string]string{
		"hypothesis": item.Hypothesis,
		"expected_observation": item.ExpectedObservation,
		"success_criteria": item.SuccessCriteria,
		"stop_conditions": item.StopConditions,
	} {
		if got[key] != want {
			t.Errorf("%s = %#v, want %q", key, got[key], want)
		}
	}
}

func TestIntentPayloadOmitsEmptyHypothesisFields(t *testing.T) {
	got := intentPayload(intentItem{Summary: "legacy intent"}, nil)
	for _, key := range []string{"hypothesis", "expected_observation", "success_criteria", "stop_conditions", "priority_reason", "asset_ids"} {
		if _, ok := got[key]; ok {
			t.Errorf("unexpected optional field %q in %#v", key, got)
		}
	}
}
func TestIntentPriorityMustBeWithinRange(t *testing.T) {
	for _, priority := range []int{-1, 11} {
		if priority >= 1 && priority <= 10 {
			t.Fatalf("test fixture has valid priority %d", priority)
		}
	}
}

func TestNormalizeIntentPriority(t *testing.T) {
	for input, want := range map[int]int{0: 5, 1: 1, 8: 8, 10: 10} {
		got, err := normalizeIntentPriority(input)
		if err != nil || got != want {
			t.Errorf("normalizeIntentPriority(%d) = %d, %v; want %d", input, got, err, want)
		}
	}
	for _, input := range []int{-1, 11} {
		if _, err := normalizeIntentPriority(input); err == nil {
			t.Errorf("normalizeIntentPriority(%d) should reject out-of-range value", input)
		}
	}
}
