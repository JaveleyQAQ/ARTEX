package db

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// FindingFingerprint returns a conservative task-local identity for one root
// cause. Empty RootCauseKey deliberately disables deduplication: merging based
// only on severity, vulnclass, or a vague title risks hiding distinct findings.
func FindingFingerprint(in RecordFindingInput) string {
	rootCause := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(in.RootCauseKey)), " "))
	vulnClass := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(in.VulnClass)), " "))
	if rootCause == "" || vulnClass == "" {
		return ""
	}
	assets := append([]int64(nil), in.AssetIDs...)
	sort.Slice(assets, func(i, j int) bool { return assets[i] < assets[j] })
	unique := assets[:0]
	var last int64
	for _, id := range assets {
		if id <= 0 || (len(unique) > 0 && id == last) {
			continue
		}
		unique = append(unique, id)
		last = id
	}
	parts := make([]string, len(unique))
	for i, id := range unique {
		parts[i] = strconv.FormatInt(id, 10)
	}
	canonical := "v1|class=" + vulnClass + "|assets=" + strings.Join(parts, ",") + "|root=" + rootCause
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
