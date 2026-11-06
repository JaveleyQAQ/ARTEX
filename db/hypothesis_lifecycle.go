package db

import (
	"database/sql"
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
