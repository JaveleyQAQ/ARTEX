package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// intentCoordinationLabel is the human-readable part of the work-unit identity.
// It is shown back to Planner so later rounds can reuse the same key verbatim.
func intentCoordinationLabel(it intentItem) string {
	work := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.CoordinationKey)), " "))
	if work != "" {
		return work
	}
	parts := []string{
		strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.Summary)), " ")),
	}
	if it.Hypothesis != nil {
		parts = append(parts, strings.ToLower(strings.TrimSpace(it.Hypothesis.PatternKey)))
		parts = append(parts, strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.Hypothesis.AssetRef)), " ")))
	}
	return strings.Join(parts, "|")
}

// intentCoordinationKey builds a stable, task-local identity for one unit of work.
// A Planner-provided key distinguishes different investigation dimensions on the
// same asset; the fallback is deliberately conservative and only collapses exact
// normalized summaries with the same asset set and hypothesis family.
func intentCoordinationKey(it intentItem, assetIDs []int64) string {
	assets := append([]int64(nil), assetIDs...)
	sort.Slice(assets, func(i, j int) bool { return assets[i] < assets[j] })
	assetParts := make([]string, 0, len(assets)+1)
	last := int64(0)
	for _, id := range assets {
		if id <= 0 || (len(assetParts) > 0 && id == last) {
			continue
		}
		assetParts = append(assetParts, strconv.FormatInt(id, 10))
		last = id
	}
	if it.Hypothesis != nil {
		assetRef := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.Hypothesis.AssetRef)), " "))
		if assetRef != "" {
			assetParts = append(assetParts, "ref:"+assetRef)
		}
	}
	canonical := "v1|assets=" + strings.Join(assetParts, ",") + "|work=" + intentCoordinationLabel(it)
	if len(canonical) > 240 {
		sum := sha256.Sum256([]byte(canonical))
		return "v1:" + hex.EncodeToString(sum[:])
	}
	return canonical
}
