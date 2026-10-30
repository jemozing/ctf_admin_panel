package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

type Record struct {
	ID        domain.ID       `json:"id"`
	ServiceID domain.ID       `json:"service_id"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	Digest    domain.Digest   `json:"digest"`
	CreatedAt time.Time       `json:"created_at"`
}

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (s *Store) PutImmutable(ctx context.Context, kind string, id, serviceID domain.ID, value any) error {
	if !kindPattern.MatchString(kind) {
		return fmt.Errorf("invalid record kind")
	}
	for _, v := range []domain.ID{id, serviceID} {
		if err := v.Validate(); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	digest := domain.Hash(payload)
	result, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO records(kind,id,service_id,payload,digest,created_at) VALUES(?,?,?,?,?,?)", kind, id, serviceID, payload, digest, time.Now().UnixNano())
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		return nil
	}
	var existingDigest domain.Digest
	var existingService domain.ID
	if err := s.db.QueryRowContext(ctx, "SELECT digest,service_id FROM records WHERE kind=? AND id=?", kind, id).Scan(&existingDigest, &existingService); err != nil {
		return err
	}
	if existingDigest != digest || existingService != serviceID {
		return ErrImmutable
	}
	return nil
}

func (s *Store) Get(ctx context.Context, kind string, id domain.ID, out any) error {
	var payload []byte
	var digest domain.Digest
	if err := s.db.QueryRowContext(ctx, "SELECT payload,digest FROM records WHERE kind=? AND id=?", kind, id).Scan(&payload, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if domain.Hash(payload) != digest {
		return fmt.Errorf("stored record integrity mismatch")
	}
	return json.Unmarshal(payload, out)
}

func (s *Store) List(ctx context.Context, kind string, serviceID domain.ID) ([]Record, error) {
	query := "SELECT id,service_id,kind,payload,digest,created_at FROM records WHERE kind=?"
	args := []any{kind}
	if serviceID != "" {
		query += " AND service_id=?"
		args = append(args, serviceID)
	}
	query += " ORDER BY created_at,id"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Record{}
	for rows.Next() {
		var r Record
		var at int64
		if err := rows.Scan(&r.ID, &r.ServiceID, &r.Kind, &r.Payload, &r.Digest, &at); err != nil {
			return nil, err
		}
		if domain.Hash(r.Payload) != r.Digest {
			return nil, fmt.Errorf("stored record integrity mismatch")
		}
		r.CreatedAt = time.Unix(0, at).UTC()
		result = append(result, r)
	}
	return result, rows.Err()
}

// Proposal includes the immutable normalized configuration digest. Confirmation
// of only a Service ID could otherwise approve a replaced Compose configuration.
type Proposal struct {
	ID                  domain.ID      `json:"id"`
	Service             domain.Service `json:"service"`
	ConfigurationDigest domain.Digest  `json:"configuration_digest"`
	Actor               domain.ID      `json:"actor"`
	CreatedAt           time.Time      `json:"created_at"`
	Digest              domain.Digest  `json:"digest"`
}

func proposalPayload(p Proposal) ([]byte, error) {
	type content struct {
		ID                  domain.ID      `json:"id"`
		Service             domain.Service `json:"service"`
		ConfigurationDigest domain.Digest  `json:"configuration_digest"`
		Actor               domain.ID      `json:"actor"`
		CreatedAt           time.Time      `json:"created_at"`
	}
	return json.Marshal(content{p.ID, p.Service, p.ConfigurationDigest, p.Actor, p.CreatedAt.UTC()})
}

func (s *Store) CreateProposal(ctx context.Context, id domain.ID, service domain.Service, configurationDigest domain.Digest, actor domain.ID, at time.Time) (Proposal, error) {
	for _, v := range []domain.ID{id, actor} {
		if err := v.Validate(); err != nil {
			return Proposal{}, err
		}
	}
	if err := service.Validate(); err != nil {
		return Proposal{}, err
	}
	if err := configurationDigest.Validate(); err != nil {
		return Proposal{}, err
	}
	if at.IsZero() {
		return Proposal{}, fmt.Errorf("proposal timestamp required")
	}
	p := Proposal{ID: id, Service: service, ConfigurationDigest: configurationDigest, Actor: actor, CreatedAt: at.UTC()}
	payload, err := proposalPayload(p)
	if err != nil {
		return Proposal{}, err
	}
	p.Digest = domain.Hash(payload)
	result, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO proposals(id,service_id,digest,payload,actor,created_at) VALUES(?,?,?,?,?,?)", id, service.ID, p.Digest, payload, actor, at.UnixNano())
	if err != nil {
		return Proposal{}, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Proposal{}, err
	}
	if inserted == 0 {
		existing, err := s.GetProposal(ctx, id)
		if err != nil {
			return Proposal{}, err
		}
		if existing.Digest != p.Digest {
			return Proposal{}, ErrImmutable
		}
		return existing, nil
	}
	return s.GetProposal(ctx, id)
}

func (s *Store) GetProposal(ctx context.Context, id domain.ID) (Proposal, error) {
	var payload []byte
	var digest domain.Digest
	if err := s.db.QueryRowContext(ctx, "SELECT payload,digest FROM proposals WHERE id=?", id).Scan(&payload, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Proposal{}, ErrNotFound
		}
		return Proposal{}, err
	}
	return decodeProposal(payload, digest)
}

func decodeProposal(payload []byte, digest domain.Digest) (Proposal, error) {
	if domain.Hash(payload) != digest {
		return Proposal{}, fmt.Errorf("proposal integrity mismatch")
	}
	var p Proposal
	if err := json.Unmarshal(payload, &p); err != nil {
		return Proposal{}, err
	}
	p.Digest = digest
	if err := p.Service.Validate(); err != nil {
		return Proposal{}, err
	}
	return p, nil
}

func (s *Store) ListProposals(ctx context.Context) ([]Proposal, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT payload,digest FROM proposals ORDER BY created_at,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Proposal{}
	for rows.Next() {
		var payload []byte
		var digest domain.Digest
		if err := rows.Scan(&payload, &digest); err != nil {
			return nil, err
		}
		p, err := decodeProposal(payload, digest)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

// ApproveProposal commits an already validated immutable registration. Callers
// must enforce administrator access and executor bootstrap root restrictions.
func (s *Store) ApproveProposal(ctx context.Context, id domain.ID, digest domain.Digest, actor domain.ID, at time.Time) (domain.Service, error) {
	if err := actor.Validate(); err != nil {
		return domain.Service{}, err
	}
	if err := digest.Validate(); err != nil {
		return domain.Service{}, err
	}
	if at.IsZero() {
		return domain.Service{}, fmt.Errorf("approval timestamp required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Service{}, err
	}
	defer tx.Rollback()
	var payload []byte
	var storedDigest domain.Digest
	if err := tx.QueryRowContext(ctx, "SELECT payload,digest FROM proposals WHERE id=?", id).Scan(&payload, &storedDigest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Service{}, ErrNotFound
		}
		return domain.Service{}, err
	}
	if storedDigest != digest {
		return domain.Service{}, ErrConflict
	}
	p, err := decodeProposal(payload, digest)
	if err != nil {
		return domain.Service{}, err
	}
	var previousApproval string
	err = tx.QueryRowContext(ctx, "SELECT actor FROM approvals WHERE proposal_id=?", id).Scan(&previousApproval)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return domain.Service{}, err
		}
		return p.Service, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Service{}, err
	}
	var lockOwner domain.ID
	lockErr := tx.QueryRowContext(ctx, "SELECT operation_id FROM locks WHERE resource=? LIMIT 1", "service:"+string(p.Service.ID)).Scan(&lockOwner)
	if lockErr == nil {
		return domain.Service{}, &BusyError{Resource: "service:" + string(p.Service.ID), Owner: lockOwner}
	}
	if !errors.Is(lockErr, sql.ErrNoRows) {
		return domain.Service{}, lockErr
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,revision,payload FROM services")
	if err != nil {
		return domain.Service{}, err
	}
	for rows.Next() {
		var existingID domain.ID
		var revision uint64
		var raw []byte
		if err := rows.Scan(&existingID, &revision, &raw); err != nil {
			rows.Close()
			return domain.Service{}, err
		}
		var existing domain.Service
		if err := json.Unmarshal(raw, &existing); err != nil {
			rows.Close()
			return domain.Service{}, err
		}
		if existingID == p.Service.ID {
			if p.Service.PolicyRevision != revision+1 {
				rows.Close()
				return domain.Service{}, fmt.Errorf("%w: policy revision must advance by one", ErrConflict)
			}
		} else if existing.Conflicts(p.Service) {
			rows.Close()
			return domain.Service{}, fmt.Errorf("%w: service conflicts with %s", ErrConflict, existingID)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return domain.Service{}, err
	}
	rows.Close()
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM services WHERE id=?)", p.Service.ID).Scan(&exists); err != nil {
		return domain.Service{}, err
	}
	if !exists && p.Service.PolicyRevision != 1 {
		return domain.Service{}, fmt.Errorf("first policy revision must be 1")
	}
	servicePayload, err := json.Marshal(p.Service)
	if err != nil {
		return domain.Service{}, err
	}
	serviceDigest := domain.Hash(servicePayload)
	if _, err := tx.ExecContext(ctx, "INSERT INTO service_revisions(service_id,revision,payload,digest) VALUES(?,?,?,?)", p.Service.ID, p.Service.PolicyRevision, servicePayload, serviceDigest); err != nil {
		return domain.Service{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO services(id,revision,payload,digest) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload,digest=excluded.digest", p.Service.ID, p.Service.PolicyRevision, servicePayload, serviceDigest); err != nil {
		return domain.Service{}, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO approvals(proposal_id,actor,approved_at) VALUES(?,?,?)", id, actor, at.UnixNano()); err != nil {
		return domain.Service{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Service{}, err
	}
	return p.Service, nil
}

func (s *Store) GetService(ctx context.Context, id domain.ID) (domain.Service, error) {
	var payload []byte
	var digest domain.Digest
	if err := s.db.QueryRowContext(ctx, "SELECT payload,digest FROM services WHERE id=?", id).Scan(&payload, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Service{}, ErrNotFound
		}
		return domain.Service{}, err
	}
	if domain.Hash(payload) != digest {
		return domain.Service{}, fmt.Errorf("service policy integrity mismatch")
	}
	var result domain.Service
	if err := json.Unmarshal(payload, &result); err != nil {
		return result, err
	}
	return result, result.Validate()
}

func (s *Store) ListServices(ctx context.Context) ([]domain.Service, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT payload,digest FROM services ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []domain.Service{}
	for rows.Next() {
		var raw []byte
		var digest domain.Digest
		if err := rows.Scan(&raw, &digest); err != nil {
			return nil, err
		}
		if domain.Hash(raw) != digest {
			return nil, fmt.Errorf("service policy integrity mismatch")
		}
		var service domain.Service
		if err := json.Unmarshal(raw, &service); err != nil {
			return nil, err
		}
		if err := service.Validate(); err != nil {
			return nil, err
		}
		result = append(result, service)
	}
	return result, rows.Err()
}
