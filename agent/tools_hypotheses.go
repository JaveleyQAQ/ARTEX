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
			"evidence": str("对本轮验证的简明证据摘要，必须真实、可复核"),
			"supporting_evidence": stringArraySchema("支持假设成立的实际观察；没有则传空数组"),
			"contradicting_evidence": stringArraySchema("反对假设成立或削弱结论的实际观察；没有则传空数组"),
			"acceptance_criteria_met": map[string]any{"type":"boolean","description":"只有逐项满足 hypothesis.acceptance_criteria 且证据可复核时才为 true；confirmed 必须为 true"},
			"limitations": stringArraySchema("验证限制、未覆盖条件或潜在误判原因"),
			"test_performed": map[string]any{"type":"boolean","description":"可选。是否实际执行了安全测试尝试。confirmed/rejected 默认为 true；inconclusive 默认为 false，若确实执行过测试可显式传 true；blocked 必须为 false。未执行测试不能计入安全测试覆盖率。"},
		}, "intent_id","outcome","summary","evidence","supporting_evidence","contradicting_evidence","acceptance_criteria_met"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID int64 `json:"intent_id"`
				Outcome string `json:"outcome"`
				Summary string `json:"summary"`
				Evidence string `json:"evidence"`
				SupportingEvidence []string `json:"supporting_evidence"`
				ContradictingEvidence []string `json:"contradicting_evidence"`
				AcceptanceCriteriaMet *bool `json:"acceptance_criteria_met"`
				Limitations []string `json:"limitations"`
				TestPerformed *bool `json:"test_performed"`
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
			if a.SupportingEvidence == nil || a.ContradictingEvidence == nil || a.AcceptanceCriteriaMet == nil {
				return actool.Errorf("必须明确提交 supporting_evidence、contradicting_evidence（无则空数组）和 acceptance_criteria_met"), nil
			}
			if a.Outcome == "confirmed" && !*a.AcceptanceCriteriaMet {
				return actool.Errorf("confirmed 必须明确满足全部 acceptance_criteria；否则应记录 inconclusive 或 rejected"), nil
			}
			if a.Outcome != "confirmed" && *a.AcceptanceCriteriaMet {
				return actool.Errorf("只有 outcome=confirmed 才能将 acceptance_criteria_met 设为 true"), nil
			}
			testPerformed := a.Outcome == "confirmed" || a.Outcome == "rejected"
			if a.TestPerformed != nil {
				testPerformed = *a.TestPerformed
			}
			if a.Outcome == "blocked" && testPerformed {
				return actool.Errorf("outcome=blocked 不能标记为已执行安全测试"), nil
			}
			if (a.Outcome == "confirmed" || a.Outcome == "rejected") && !testPerformed {
				return actool.Errorf("confirmed/rejected 必须基于实际执行的安全测试；未执行应记录 inconclusive/blocked"), nil
			}
			_, lifecycle, _, lifecycleErr := t.ts.IntentHypothesisLifecycle(a.IntentID)
			if lifecycleErr != nil { return actool.Errorf(fmt.Sprintf("读取假设生命周期失败: %v", lifecycleErr)), nil }
			if lifecycle == "recorded" { return actool.Errorf("该意图的假设结果已经提交；请勿重复写入"), nil }
			result := map[string]any{
				"summary": a.Summary, "hypothesis_outcome": a.Outcome,
				"evidence": a.Evidence, "hypothesis_intent_id": a.IntentID,
				"supporting_evidence": a.SupportingEvidence,
				"contradicting_evidence": a.ContradictingEvidence,
				"acceptance_criteria_met": *a.AcceptanceCriteriaMet,
				"confidence": "observed",
				"test_status": map[bool]string{true: "tested", false: "observed"}[testPerformed],
			}
			if patternID, ok := hypothesis["pattern_id"]; ok { result["pattern_id"] = patternID }
			if len(a.Limitations)>0 { result["limitations"] = a.Limitations }
			factID, err := t.ts.RecordIntentHypothesisResult(a.IntentID, result, t.worker, intentAssetIDs(intent))
			if err != nil { return actool.Errorf(fmt.Sprintf("保存验证结果失败: %v", err)), nil }
			t.writes.Facts++
			return jsonResult(map[string]any{"fact_id":factID,"intent_id":a.IntentID,"outcome":a.Outcome,"finding_required":a.Outcome=="confirmed" && *a.AcceptanceCriteriaMet,"note":"验证结论已保存；confirmed 仍需独立 report_finding，不能仅凭假设或模式匹配报告漏洞。"})
		})
}
