package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRenderIntentHypothesisContract(t *testing.T) {
	intent := &db.Node{Payload: []byte(`{
		"summary":"核对本地靶场的会话隔离",
		"hypothesis":"会话标识可能未绑定当前测试用户",
		"expected_observation":"若成立，两个隔离测试用户可能读取到彼此会话状态",
		"success_criteria":"必须有可重复的跨用户请求与响应证据",
		"stop_conditions":"超出本地靶场或需要真实用户数据时停止"
	}`)}
	got := renderIntentHypothesisContract(intent)
	for _, want := range []string{
		"本意图的假设验证契约",
		"会话标识可能未绑定当前测试用户",
		"两个隔离测试用户可能读取到彼此会话状态",
		"可重复的跨用户请求与响应证据",
		"超出本地靶场或需要真实用户数据时停止",
		"observed",
		"inferred",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("contract missing %q: %s", want, got)
		}
	}
}

func TestRenderIntentHypothesisContractIsBackwardCompatible(t *testing.T) {
	for name, intent := range map[string]*db.Node{
		"nil": nil,
		"legacy payload": {Payload: []byte(`{"summary":"legacy intent","asset_ids":[1]}`)},
		"malformed payload": {Payload: []byte(`not-json`)},
	} {
		if got := renderIntentHypothesisContract(intent); got != "" {
			t.Errorf("%s: expected empty contract, got %q", name, got)
		}
	}
}

func TestRenderIntentTaskIncludesContractAndIntentID(t *testing.T) {
	intent := &db.Node{ID: 42, Payload: []byte(`{"summary":"local task","hypothesis":"test hypothesis"}`)}
	got := renderIntentTask(intent)
	if !strings.Contains(got, "test hypothesis") || !strings.Contains(got, "意图 id: 42") {
		t.Fatalf("rendered task missing hypothesis or intent id: %s", got)
	}
}