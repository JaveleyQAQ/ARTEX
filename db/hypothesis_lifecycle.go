package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// IntentHypothesisLifecycle reports whether an intent has a structured
// hypothesis and whether its worker persisted a terminal evidence-backed result.
func (s *ExplorationStore) IntentHypothesisLifecycle(intentID int64) (hasHypothesis bool, status, outcome string, err error) {
	err = s.db.QueryRow(`
SELECT payload ? 'hypothesis',
       COALESCE(payload->>'hypothesis_status', 'pending'),
       COALESCE(payload->>'hypothesis_outcome', '')
FROM exploration_nodes
WHERE id=$1 AND exploration_id=$2 AND kind='intent'`, intentID, s.expID).Scan(&hasHypothesis, &status, &outcome)
	if err == sql.ErrNoRows {
		return false, "", "", fmt.Errorf("intent %d not found", intentID)
	}
	return
}

// SetIntentHypothesisLifecycle records the lifecycle marker on the intent itself.
// The evidence remains in its yielded fact; this marker is the compact state
// consumed by the Engine when deciding whether a hypothesis-bearing intent is done.
func (s *ExplorationStore) SetIntentHypothesisLifecycle(intentID int64, status, outcome string, factID int64) error {
	res, err := s.db.Exec(`
UPDATE exploration_nodes
SET payload = payload || jsonb_build_object(
	'hypothesis_status', $1::text,
	'hypothesis_outcome', NULLIF($2::text, ''),
	'hypothesis_result_fact_id', NULLIF($3::bigint, 0)
), content_version=content_version+1
WHERE id=$4 AND exploration_id=$5 AND kind='intent' AND payload ? 'hypothesis'`,
		status, outcome, factID, intentID, s.expID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("intent %d has no structured hypothesis or no longer exists", intentID)
	}
	return nil
}


// RecordIntentHypothesisResult atomically writes the evidence fact, its yields
// edge, and the lifecycle marker. The row lock makes duplicate submissions safe
// even if a resumed Worker retries the same tool call.
func (s *ExplorationStore) RecordIntentHypothesisResult(intentID int64, result map[string]any, worker string, anchors []int64) (int64, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var intentPayload []byte
	if err := tx.QueryRow(`
SELECT payload FROM exploration_nodes
WHERE id=$1 AND exploration_id=$2 AND kind='intent'
FOR UPDATE`, intentID, s.expID).Scan(&intentPayload); err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("intent %d not found", intentID)
		}
		return 0, err
	}
	var payload map[string]any
	if err := json.Unmarshal(intentPayload, &payload); err != nil {
		return 0, err
	}
	if payload["hypothesis"] == nil {
		return 0, fmt.Errorf("intent %d has no structured hypothesis", intentID)
	}
	if payload["hypothesis_status"] == "recorded" {
		return 0, fmt.Errorf("intent %d hypothesis result already recorded", intentID)
	}

	var factID int64
	if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1, 'fact', $2, 5, 'confirmed', $3)
RETURNING id`, s.expID, string(raw), worker).Scan(&factID); err != nil {
		return 0, err
	}
	for _, assetID := range anchors {
		if assetID <= 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, factID, assetID); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`
INSERT INTO exploration_edges(exploration_id, src_id, rel, dst_id)
VALUES ($1,$2,'yields',$3)
ON CONFLICT (exploration_id, src_id, rel, dst_id) DO NOTHING`, s.expID, intentID, factID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`
UPDATE exploration_nodes
SET payload = payload || jsonb_build_object(
	'hypothesis_status', 'recorded',
	'hypothesis_outcome', $1::text,
	'hypothesis_result_fact_id', $2::bigint
), content_version=content_version+1
WHERE id=$3 AND exploration_id=$4 AND kind='intent'`, result["hypothesis_outcome"], factID, intentID, s.expID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return factID, nil
}
