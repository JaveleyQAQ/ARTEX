package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// recordHypothesisResult persists an evidence-backed outcome for a structured
// vulnerability hypothesis. A confirmed hypothesis is still not a Finding:
// the worker must separately call report_finding with reproducible evidence.
func (t *ToolSet) recordHypothesisResult() actool.CoreTool {
	return t.writeExpTool("record_hypothesis_result",
		"记录本意图中结构化漏洞假设的验证结果。必须提供真实观察到的 evidence；outcome 只能是 confirmed/rejected/inconclusive/blocked。该工具只记录验证结论，不会自动创建漏洞 Finding。outcome=confirmed 时，只有达到假设 acceptance_criteria 且证据可复现，才另行调用 report_finding；模式匹配本身不是漏洞证据。",
		obj(map[string]any{
			"intent_id": idp("当前 Worker 领取的意图 ID"),
			"outcome": map[string]any{"type":"string","enum":[]string{"confirmed","rejected","inconclusive","blocked"},"description":"验证结论"},
			"summary": str("本轮验证的简明结论"),
			"evidence": str("实际观察到的关键证据，包含请求/命令与关键响应；不得编造"),
			"limitations": stringArraySchema("验证限制、未覆盖条件或潜在误判原因"),
		}, "intent_id","outcome","summary","evidence"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID int64 `json:"intent_id"`
				Outcome string `json:"outcome"`
				Summary string `json:"summary"`
				Evidence string `json:"evidence"`
				Limitations []string `json:"limitations"`
			}
			if err := json.Unmarshal(in, &a); err != nil { return actool.Errorf(err.Error()), nil }
			a.Outcome = strings.ToLower(strings.TrimSpace(a.Outcome))
			if a.IntentID <= 0 { return actool.Errorf("intent_id 必须为正数"), nil }
			if t.ownerNode > 0 && a.IntentID != t.ownerNode {
				return actool.Errorf("Worker 只能为自己当前领取的意图记录假设结果"), nil
			}
			switch a.Outcome {
			case "confirmed","rejected","inconclusive","blocked":
			default: return actool.Errorf("outcome 必须是 confirmed/rejected/inconclusive/blocked"), nil
			}
			if strings.TrimSpace(a.Summary)=="" || strings.TrimSpace(a.Evidence)=="" {
				return actool.Errorf("summary 和 evidence 不能为空；只记录真实观察"), nil
			}
			intent, err := t.ts.GetNode(a.IntentID)
			if err != nil || intent == nil || intent.Kind != db.KindIntent {
				return actool.Errorf("intent_id 必须是本任务的意图节点"), nil
			}
			var payload map[string]any
			if err := json.Unmarshal(intent.Payload, &payload); err != nil { return actool.Errorf("意图 payload 无效"), nil }
			hypothesis, ok := payload["hypothesis"].(map[string]any)
			if !ok || hypothesis == nil { return actool.Errorf("该意图没有结构化 hypothesis，不能记录假设验证结果"), nil }
			result := map[string]any{
				"summary": a.Summary, "hypothesis_outcome": a.Outcome,
				"evidence": a.Evidence, "hypothesis_intent_id": a.IntentID,
				"confidence": "observed",
			}
			if patternID, ok := hypothesis["pattern_id"]; ok { result["pattern_id"] = patternID }
			if len(a.Limitations)>0 { result["limitations"] = a.Limitations }
			factID, err := t.ts.AddNode(db.KindFact, result, 5, "confirmed", t.worker, intentAssetIDs(intent))
			if err != nil { return actool.Errorf(fmt.Sprintf("保存验证结果失败: %v",err)), nil }
			if err := t.ts.Link(a.IntentID, db.RelYields, factID); err != nil {
				return actool.Errorf(fmt.Sprintf("验证结果已保存为 fact %d，但建立血缘失败: %v",factID,err)), nil
			}
			t.writes.Facts++
			return jsonResult(map[string]any{"fact_id":factID,"intent_id":a.IntentID,"outcome":a.Outcome,"finding_required":a.Outcome=="confirmed","note":"验证结论已保存；confirmed 仍需独立 report_finding，不能仅凭假设或模式匹配报告漏洞。"})
		})
}
