package agent

import "testing"

func TestIntentPayloadPersistsHypothesisContract(t *testing.T) {
	item := intentItem{
		Summary: "  检查本地靶场中登录流程的状态绑定  ",
		Hypothesis: "会话状态可能未与当前用户绑定",
		ExpectedObservation: "不同测试用户的会话标识可能出现交叉复用",
		SuccessCriteria: "只有在可重复的请求/响应证据表明跨用户状态泄露时才支持假设",
		StopConditions: "超出任务声明的本地靶场范围或需要真实用户数据时立即停止",
	}
	got := intentPayload(item, []int64{12, 34})
	if got["summary"] != "检查本地靶场中登录流程的状态绑定" {
		t.Fatalf("summary was not normalized: %#v", got["summary"])
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
	for _, key := range []string{"hypothesis", "expected_observation", "success_criteria", "stop_conditions", "asset_ids"} {
		if _, ok := got[key]; ok {
			t.Errorf("unexpected optional field %q in %#v", key, got)
		}
	}
}