package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const (
	FindingVerificationPending  = "pending"
	FindingVerificationRunning  = "running"
	FindingVerificationComplete = "completed"

	FindingVerdictConfirmed    = "confirmed"
	FindingVerdictRejected     = "rejected"
	FindingVerdictInconclusive = "inconclusive"
)

var ErrVerificationRunUnavailable = errors.New("finding verification run is unavailable or already claimed")

type FindingVerificationRun struct {
	ID         int64           `json:"id"`
	FindingID  int64           `json:"finding_id"`
	TaskID     *int64          `json:"task_id,omitempty"`
	IntentID   *int64          `json:"intent_id,omitempty"`
	Status     string          `json:"status"`
	Verdict    string          `json:"verdict"`
	Verifier   string          `json:"verifier"`
	Summary    string          `json:"summary"`
	Evidence   json.RawMessage `json:"evidence"`
	CreatedAt  time.Time       `json:"created_at"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Attempts   int    `json:"attempts"`
	LastError  string `json:"last_error,omitempty"`
}

const findingVerificationColumns = `id,finding_id,task_id,intent_id,status,verdict,verifier,summary,evidence,created_at,started_at,finished_at,attempts,last_error`

func scanFindingVerificationRun(row interface{ Scan(...any) error }) (*FindingVerificationRun, error) {
	var run FindingVerificationRun
	err := row.Scan(
		&run.ID, &run.FindingID, &run.TaskID, &run.IntentID, &run.Status,
		&run.Verdict, &run.Verifier, &run.Summary, &run.Evidence,
		&run.CreatedAt, &run.StartedAt, &run.FinishedAt, &run.Attempts, &run.LastError,
	)
	if err != nil {
		return nil, err
	}
	return &run, nil
}

// ListPendingFindingVerificationRuns returns the oldest unclaimed reviews first.
// ClaimFindingVerificationRun remains the concurrency-safe ownership boundary.
func (d *DB) ListPendingFindingVerificationRuns(ctx context.Context, limit int) ([]*FindingVerificationRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := d.QueryContext(ctx, `SELECT `+findingVerificationColumns+`
FROM finding_verification_runs WHERE status='pending' ORDER BY id ASC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FindingVerificationRun
	for rows.Next() {
		run, err := scanFindingVerificationRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

// RequeueStaleFindingVerificationRuns recovers claims abandoned by a process crash.
// Runs that exhaust the retry budget are closed as inconclusive rather than blocking
// the candidate forever.
func (d *DB) RequeueStaleFindingVerificationRuns(ctx context.Context, age time.Duration) (int64, error) {
	if age <= 0 {
		age = 5 * time.Minute
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	cutoff := time.Now().Add(-age)
	if _, err := tx.ExecContext(ctx, `
UPDATE finding_verification_runs
SET status='completed', verdict='inconclusive',
    summary='复核进程异常退出且自动重试次数已耗尽，需人工复核',
    last_error='stale verifier claim exhausted retry budget', finished_at=now()
WHERE status='running' AND started_at < $1 AND attempts >= 3`, cutoff); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE finding_verification_runs
SET status='pending', verifier='', started_at=NULL,
    last_error='stale verifier claim recovered after worker restart'
WHERE status='running' AND started_at < $1 AND attempts < 3`, cutoff)
	if err != nil {
		return 0, err
	}
	requeued, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return requeued, nil
}

// ClaimFindingVerificationRun atomically leases a pending review to one reviewer.
// This persistence API does not grant target-execution or network-probing capabilities.
func (d *DB) ClaimFindingVerificationRun(ctx context.Context, runID int64, verifier string) (*FindingVerificationRun, error) {
	verifier = strings.TrimSpace(verifier)
	if runID <= 0 || verifier == "" {
		return nil, errors.New("run id and verifier are required")
	}
	run, err := scanFindingVerificationRun(d.QueryRowContext(ctx, `
UPDATE finding_verification_runs
SET status='running', verifier=$2, started_at=now(), attempts=attempts+1
WHERE id=$1 AND status='pending'
RETURNING `+findingVerificationColumns, runID, verifier))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVerificationRunUnavailable
	}
	return run, err
}

// ReleaseFindingVerificationRun returns a transiently failed claim to the queue.
// The attempt counter is retained so the worker can enforce a bounded retry policy.
func (d *DB) ReleaseFindingVerificationRun(ctx context.Context, runID int64, verifier, reason string) error {
	verifier, reason = strings.TrimSpace(verifier), strings.TrimSpace(reason)
	if runID <= 0 || verifier == "" {
		return errors.New("run id and verifier are required")
	}
	result, err := d.ExecContext(ctx, `
UPDATE finding_verification_runs
SET status='pending', verifier='', started_at=NULL, last_error=$3
WHERE id=$1 AND verifier=$2 AND status='running'`, runID, verifier, reason)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrVerificationRunUnavailable
	}
	return nil
}

// CompleteFindingVerificationRun records a reviewer verdict. Automated status
// changes apply only while human triage is still pending and never overwrite it.
func (d *DB) CompleteFindingVerificationRun(ctx context.Context, runID int64, verifier, verdict, summary string, evidence json.RawMessage) (*FindingVerificationRun, error) {
	verifier, summary = strings.TrimSpace(verifier), strings.TrimSpace(summary)
	if runID <= 0 || verifier == "" || summary == "" {
		return nil, errors.New("run id, verifier and summary are required")
	}
	switch verdict {
	case FindingVerdictConfirmed, FindingVerdictRejected, FindingVerdictInconclusive:
	default:
		return nil, errors.New("verdict must be confirmed, rejected or inconclusive")
	}
	if len(evidence) == 0 {
		evidence = json.RawMessage("[]")
	}
	if !json.Valid(evidence) {
		return nil, errors.New("verification evidence must be valid JSON")
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var findingID int64
	err = tx.QueryRowContext(ctx, `
UPDATE finding_verification_runs
SET status='completed', verdict=$3, summary=$4, evidence=$5, finished_at=now(), last_error=''
WHERE id=$1 AND verifier=$2 AND status='running'
RETURNING finding_id`, runID, verifier, verdict, summary, string(evidence)).Scan(&findingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrVerificationRunUnavailable
	}
	if err != nil {
		return nil, err
	}

	if verdict == FindingVerdictConfirmed || verdict == FindingVerdictRejected {
		findingStatus := FindingConfirmed
		if verdict == FindingVerdictRejected {
			findingStatus = FindingFalsePositive
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE findings SET status=$2 WHERE id=$1 AND status='pending'`, findingID, findingStatus)
		if updateErr != nil {
			return nil, updateErr
		}
		updated, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return nil, rowsErr
		}
		// The graph node starts in its legacy-compatible "confirmed" state.
		// Only a rejected candidate is transitioned to the allowed "dismissed"
		// graph state, and only if this verifier actually changed the pending row.
		if updated > 0 && verdict == FindingVerdictRejected {
			if _, err = tx.ExecContext(ctx, `UPDATE exploration_nodes
SET state='dismissed'
WHERE id=(SELECT node_id FROM findings WHERE id=$1) AND state='confirmed'`, findingID); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return d.GetFindingVerificationRun(ctx, runID)
}

func (d *DB) GetFindingVerificationRun(ctx context.Context, runID int64) (*FindingVerificationRun, error) {
	return scanFindingVerificationRun(d.QueryRowContext(ctx,
		`SELECT `+findingVerificationColumns+` FROM finding_verification_runs WHERE id=$1`, runID))
}

func (d *DB) ListFindingVerificationRuns(ctx context.Context, findingID int64) ([]*FindingVerificationRun, error) {
	rows, err := d.QueryContext(ctx,
		`SELECT `+findingVerificationColumns+` FROM finding_verification_runs WHERE finding_id=$1 ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*FindingVerificationRun
	for rows.Next() {
		run, err := scanFindingVerificationRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}


// FindingVerificationOverview returns validated and pending candidate node ids.
// The standalone findings table is authoritative; graph-node state alone is not
// a verification signal because legacy nodes predate this lifecycle.
func (s *ExplorationStore) FindingVerificationOverview() (confirmed, pending []int64, err error) {
	rows, err := s.db.Query(`
SELECT f.node_id, f.status
FROM findings f
JOIN exploration_nodes en ON en.id=f.node_id
WHERE en.exploration_id=$1
ORDER BY f.id DESC`, s.expID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nodeID int64
		var status string
		if err := rows.Scan(&nodeID, &status); err != nil {
			return nil, nil, err
		}
		switch status {
		case FindingConfirmed, FindingResolved, FindingFixed, FindingRiskAccepted:
			confirmed = append(confirmed, nodeID)
		case FindingPending, FindingInProgress:
			pending = append(pending, nodeID)
		}
	}
	return confirmed, pending, rows.Err()
}


var ErrFindingNotReviewable = errors.New("finding is not eligible for independent verification")

// QueueFindingVerificationRun manually requeues a pending candidate after an
// inconclusive/failed review. The partial unique index is the concurrency guard.
func (d *DB) QueueFindingVerificationRun(ctx context.Context, findingID int64) (*FindingVerificationRun, error) {
	if findingID <= 0 {
		return nil, errors.New("finding id is required")
	}
	run, err := scanFindingVerificationRun(d.QueryRowContext(ctx, `
INSERT INTO finding_verification_runs(finding_id,task_id,intent_id,status,evidence)
SELECT f.id, f.task_id,
       (SELECT previous.intent_id FROM finding_verification_runs previous
        WHERE previous.finding_id=f.id ORDER BY previous.id DESC LIMIT 1),
       'pending',
       jsonb_build_array(jsonb_build_object('kind','manual_retry','requested_at',now()))
FROM findings f
WHERE f.id=$1 AND f.status='pending' AND f.task_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM finding_verification_runs active
      WHERE active.finding_id=f.id AND active.status IN ('pending','running')
  )
ON CONFLICT (finding_id) WHERE status IN ('pending','running') DO NOTHING
RETURNING `+findingVerificationColumns, findingID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrFindingNotReviewable
	}
	return run, err
}
