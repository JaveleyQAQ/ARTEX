package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func stringArraySchema(description string) map[string]any {
	return map[string]any{
		"type": "array",
		"description": description,
		"items": map[string]any{"type": "string"},
	}
}

// searchVulnerabilityPatterns exposes only reviewed/verified knowledge to agents.
// Draft entries are deliberately excluded from this retrieval path.
func (t *ToolSet) searchVulnerabilityPatterns() actool.CoreTool {
	return t.readExpTool("search_vulnerability_patterns",
		"检索已审核的漏洞模式知识。默认只返回 reviewed/verified 模式；用于结合当前资产、业务特征形成待验证假设，不得把模式匹配当成漏洞结论。",
		obj(map[string]any{
			"query": str("可选：业务特征、漏洞模式或验证条件关键词"),
			"vulnclass": str("可选：漏洞类别，如 IDOR、SQLi、XSS、AUTHZ"),
			"asset_type": str("可选：资产类型，如 endpoint、service、app"),
			"limit": map[string]any{"type":"integer","description":"返回条数，默认 10，最大 20"},
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Query string `json:"query"`
				VulnClass string `json:"vulnclass"`
				AssetType string `json:"asset_type"`
				Limit int `json:"limit"`
			}
			if err := json.Unmarshal(in, &a); err != nil { return actool.Errorf(err.Error()), nil }
			if a.Limit <= 0 || a.Limit > 20 { a.Limit = 10 }
			items, err := t.ts.ListVulnerabilityPatterns(db.VulnerabilityPatternFilter{
				Query:a.Query, VulnClass:a.VulnClass, AssetType:a.AssetType, Limit:a.Limit,
			})
			if err != nil { return actool.Errorf(err.Error()), nil }
			return jsonResult(map[string]any{"patterns":items, "count":len(items), "note":"模式是测试线索，不是目标存在漏洞的证据。"})
		})
}

// proposeVulnerabilityPattern stores a reusable candidate as draft. It never
// promotes model-authored knowledge into the trusted retrieval set.
func (t *ToolSet) proposeVulnerabilityPattern() actool.CoreTool {
	return t.writeExpTool("propose_vulnerability_pattern",
		"把已记录 Finding 中可复用的漏洞成因/业务模式提议为知识条目。新条目一律 draft，需人工或独立审核后才能被常规检索。不要写入未经证实的漏洞结论；provenance 应引用 Finding/探索节点等来源 ID。",
		obj(map[string]any{
			"pattern_key": str("稳定且唯一的模式键，如 authz.object-ownership-gap.v1"),
			"vulnclass": str("漏洞类别"),
			"title": str("模式名称"),
			"description": str("模式描述与适用业务上下文"),
			"preconditions": stringArraySchema("成立前置条件"),
			"indicators": stringArraySchema("值得关注的业务或技术特征"),
			"validation_guidance": str("授权测试环境中的验证思路及所需证据"),
			"limitations": stringArraySchema("适用限制、容易误判的情况"),
			"asset_types": stringArraySchema("适用资产类型"),
			"provenance": stringArraySchema("来源引用，如 finding_id:123、exploration_node_id:456"),
			"confidence": str("low / medium / high；描述知识来源可信程度，不代表目标漏洞已确认"),
		}, "pattern_key","vulnclass","title"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				PatternKey string `json:"pattern_key"`
				VulnClass string `json:"vulnclass"`
				Title string `json:"title"`
				Description string `json:"description"`
				Preconditions []string `json:"preconditions"`
				Indicators []string `json:"indicators"`
				ValidationGuidance string `json:"validation_guidance"`
				Limitations []string `json:"limitations"`
				AssetTypes []string `json:"asset_types"`
				Provenance []string `json:"provenance"`
				Confidence string `json:"confidence"`
			}
			if err := json.Unmarshal(in, &a); err != nil { return actool.Errorf(err.Error()), nil }
			p, err := t.ts.CreateVulnerabilityPattern(db.VulnerabilityPatternInput{
				PatternKey:a.PatternKey, VulnClass:a.VulnClass, Title:a.Title, Description:a.Description,
				Preconditions:a.Preconditions, Indicators:a.Indicators, ValidationGuidance:a.ValidationGuidance,
				Limitations:a.Limitations, AssetTypes:a.AssetTypes, Provenance:a.Provenance,
				Confidence:a.Confidence, Status:db.PatternDraft,
			})
			if err != nil { return actool.Errorf(err.Error()), nil }
			return jsonResult(map[string]any{"pattern":p,"status":"draft","note":"该模式尚未进入 Agent 默认检索，审核通过后再设为 reviewed 或 verified。"})
		})
}

func (t *ToolSet) linkFindingPattern() actool.CoreTool {
	return t.writeExpTool("link_finding_pattern",
		"将本任务中已登记的 Finding 关联到漏洞模式，建立可追溯知识来源。relation 只能是 supports、derived_from 或 related；关联不代表模式已审核。",
		obj(map[string]any{
			"finding_id": map[string]any{"type":"integer","description":"report_finding 返回的独立 finding_id"},
			"pattern_id": map[string]any{"type":"integer","description":"search_vulnerability_patterns 或模式提议返回的 pattern ID"},
			"relation": str("supports / derived_from / related"),
			"rationale": str("为什么该 Finding 与模式有关，引用实际证据"),
			"confidence": str("low / medium / high"),
		}, "finding_id","pattern_id","relation","rationale"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				FindingID int64 `json:"finding_id"`
				PatternID int64 `json:"pattern_id"`
				Relation string `json:"relation"`
				Rationale string `json:"rationale"`
				Confidence string `json:"confidence"`
			}
			if err := json.Unmarshal(in, &a); err != nil { return actool.Errorf(err.Error()), nil }
			if err := t.ts.LinkFindingPattern(a.FindingID,a.PatternID,a.Relation,a.Rationale,a.Confidence); err != nil { return actool.Errorf(err.Error()), nil }
			return actool.Text(fmt.Sprintf("finding %d linked to pattern %d (%s)",a.FindingID,a.PatternID,strings.TrimSpace(a.Relation))),nil
		})
}

func (t *ToolSet) listFindingPatternLinks() actool.CoreTool {
	return t.readExpTool("list_finding_pattern_links",
		"列出指定 Finding 已关联的漏洞模式及关联理由。",
		obj(map[string]any{"finding_id":map[string]any{"type":"integer","description":"独立 finding_id"}},"finding_id"),
		func(_ context.Context,in json.RawMessage)(actool.Result,error){
			var a struct{ FindingID int64 `json:"finding_id"` }
			if err:=json.Unmarshal(in,&a);err!=nil{return actool.Errorf(err.Error()),nil}
			if a.FindingID<=0{return actool.Errorf("finding_id 必须为正数"),nil}
			links,err:=t.ts.ListFindingPatternLinks(a.FindingID)
			if err!=nil{return actool.Errorf(err.Error()),nil}
			return jsonResult(map[string]any{"links":links,"count":len(links)})
		})
}
