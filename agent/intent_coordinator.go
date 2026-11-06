package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// intentCoordinationKey builds a stable, task-local identity for one unit of work.
// A Planner-provided key distinguishes different investigation dimensions on the
// same asset; the fallback is deliberately conservative and only collapses exact
// normalized summaries with the same asset set and hypothesis family.
func intentCoordinationKey(it intentItem, assetIDs []int64) string {
	assets := append([]int64(nil), assetIDs...)
	sort.Slice(assets, func(i, j int) bool { return assets[i] < assets[j] })
	assetParts := make([]string, 0, len(assets))
	last := int64(0)
	for _, id := range assets {
		if id <= 0 || (len(assetParts) > 0 && id == last) {
			continue
		}
		assetParts = append(assetParts, stringInt64(id))
		last = id
	}
	if it.Hypothesis != nil {
		assetRef := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.Hypothesis.AssetRef)), " "))
		if assetRef != "" {
			assetParts = append(assetParts, "ref:"+assetRef)
		}
	}
	assetScope := strings.Join(assetParts, ",")
	work := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.CoordinationKey)), " "))
	if work == "" {
		parts := []string{
			strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.Summary)), " ")),
		}
		if it.Hypothesis != nil {
			parts = append(parts, strings.ToLower(strings.TrimSpace(it.Hypothesis.PatternKey)))
			parts = append(parts, strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(it.Hypothesis.AssetRef)), " ")))
		}
		work = strings.Join(parts, "|")
	}
	canonical := "v1|assets=" + assetScope + "|work=" + work
	if len(canonical) > 240 {
		sum := sha256.Sum256([]byte(canonical))
		return "v1:" + hex.EncodeToString(sum[:])
	}
	return canonical
}

func stringInt64(v int64) string {
	// strconv.FormatInt is kept behind this helper to keep key construction local.
	return strconv.FormatInt(v, 10)
}
