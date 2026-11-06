package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// AddIntentCoordinated atomically admits an intent for one coordination key.
// Only open/running intents reserve a key: once work reaches a terminal state,
// a genuinely new attempt may be admitted. The transaction-scoped advisory lock
// serializes competing planners/workers for this exploration, so two concurrent
// callers cannot both pass the active-work check.
func (s *ExplorationStore) AddIntentCoordinated(payload map[string]any, priority int, anchors []int64, origin, coordinationKey string) (int64, bool, error) {
	if coordinationKey == "" {
		return 0, false, fmt.Errorf("coordination_key 不能为空")
	}
	if origin == "" {
		origin = "planner"
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	// Exploration IDs are unique within this database and provide a stable
	// per-task lock namespace. The lock is released automatically on commit/rollback.
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, -s.expID); err != nil {
		return 0, false, fmt.Errorf("lock intent coordinator: %w", err)
	}

	var existingID int64
	err = tx.QueryRow(`
SELECT id
FROM exploration_nodes
WHERE exploration_id=$1
  AND kind='intent'
  AND state IN ('open','running')
  AND COALESCE(payload->>'coordination_key','') <> ''
  AND payload->>'coordination_key'=$2
ORDER BY id
LIMIT 1
FOR UPDATE`, s.expID, coordinationKey).Scan(&existingID)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return 0, false, err
		}
		return existingID, false, nil
	}
	if err != sql.ErrNoRows {
		return 0, false, err
	}

	payloadCopy := make(map[string]any, len(payload)+1)
	for key, value := range payload {
		payloadCopy[key] = value
	}
	payloadCopy["coordination_key"] = coordinationKey
	raw, err := json.Marshal(payloadCopy)
	if err != nil {
		return 0, false, fmt.Errorf("marshal intent payload: %w", err)
	}

	var id int64
	if err := tx.QueryRow(`
INSERT INTO exploration_nodes(exploration_id, kind, payload, priority, state, origin)
VALUES ($1, 'intent', $2, $3, 'open', $4)
RETURNING id`, s.expID, string(raw), priority, origin).Scan(&id); err != nil {
		return 0, false, err
	}
	for _, assetID := range anchors {
		if _, err := tx.Exec(`INSERT INTO exploration_anchors(node_id, asset_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, id, assetID); err != nil {
			return 0, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return id, true, nil
}
