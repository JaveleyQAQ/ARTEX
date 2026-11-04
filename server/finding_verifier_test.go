package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestParseFindingVerifierOutput(t *testing.T) {
	got, err := parseFindingVerifierOutput(`{"verdict":"confirmed","summary":"有直接证据","evidence":[{"quote":"HTTP/1.1 200 OK","reason":"实际响应片段"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != db.FindingVerdictConfirmed || len(got.Evidence) != 1 {
		t.Fatalf("unexpected verifier output: %+v", got)
	}
}

func TestParseFindingVerifierOutputRejectsUnsupportedClaims(t *testing.T) {
	cases := []string{
		`{"verdict":"confirmed","summary":"没有引用证据","evidence":[]}`,
		`{"verdict":"guess","summary":"unsupported","evidence":[{"quote":"x","reason":"y"}]}`,
		`{"verdict":"rejected","summary":"缺少引用","evidence":[{"quote":" ","reason":"no quote"}]}`,
	}
	for _, raw := range cases {
		if _, err := parseFindingVerifierOutput(raw); err == nil {
			t.Errorf("expected invalid response to fail: %s", raw)
		}
	}
}

func TestFindingVerifierPromptTreatsEvidenceAsUntrusted(t *testing.T) {
	for _, marker := range []string{"没有工具", "不可信数据", "不得尝试访问目标", "不能把模型猜测当事实"} {
		if !strings.Contains(findingVerifierSystemPrompt, marker) {
			t.Errorf("verifier safety prompt missing %q", marker)
		}
	}
}
