package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctf-service-manager/ctf-service-manager/internal/domain"
)

// GetServiceConfiguration resolves the immutable configuration approved for one
// exact policy revision. A newer pending proposal cannot replace that binding.
func (s *Store) GetServiceConfiguration(ctx context.Context, id domain.ID, revision uint64) (domain.Digest, error) {
	if err := id.Validate(); err != nil {
		return "", err
	}
	if revision == 0 {
		return "", fmt.Errorf("policy revision required")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT p.payload,p.digest FROM proposals p JOIN approvals a ON a.proposal_id=p.id WHERE p.service_id=? ORDER BY p.created_at,p.id", id)
	if err != nil {
		return "", err
	}
	var found *Proposal
	for rows.Next() {
		var payload []byte
		var digest domain.Digest
		if err := rows.Scan(&payload, &digest); err != nil {
			rows.Close()
			return "", err
		}
		p, err := decodeProposal(payload, digest)
		if err != nil {
			rows.Close()
			return "", err
		}
		if p.Service.ID != id {
			rows.Close()
			return "", fmt.Errorf("approved proposal identity mismatch")
		}
		if p.Service.PolicyRevision != revision {
			continue
		}
		if found != nil {
			rows.Close()
			return "", fmt.Errorf("multiple configurations approved for one policy revision")
		}
		found = &p
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if found == nil {
		return "", ErrNotFound
	}
	var servicePayload []byte
	var serviceDigest domain.Digest
	if err := s.db.QueryRowContext(ctx, "SELECT payload,digest FROM service_revisions WHERE service_id=? AND revision=?", id, revision).Scan(&servicePayload, &serviceDigest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	expected, err := json.Marshal(found.Service)
	if err != nil {
		return "", err
	}
	if domain.Hash(servicePayload) != serviceDigest || domain.Hash(expected) != serviceDigest {
		return "", fmt.Errorf("approved configuration policy binding integrity mismatch")
	}
	if err := found.ConfigurationDigest.Validate(); err != nil {
		return "", err
	}
	return found.ConfigurationDigest, nil
}

// FindOperation returns an actor-scoped idempotency match and its original
// request digest. The caller compares the digest before returning a prior job.
func (s *Store) FindOperation(ctx context.Context, actor domain.ID, key string) (domain.Operation, domain.Digest, error) {
	if err := actor.Validate(); err != nil {
		return domain.Operation{}, "", err
	}
	if key == "" || len(key) > 128 || !utf8.ValidString(key) || strings.TrimSpace(key) != key {
		return domain.Operation{}, "", fmt.Errorf("invalid idempotency key")
	}
	for _, r := range key {
		if unicode.IsControl(r) {
			return domain.Operation{}, "", fmt.Errorf("invalid idempotency key")
		}
	}
	var id domain.ID
	var payload []byte
	var inputHash domain.Digest
	err := s.db.QueryRowContext(ctx, "SELECT id,payload,input_hash FROM operations WHERE initiator=? AND idempotency_key=?", actor, key).Scan(&id, &payload, &inputHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Operation{}, "", ErrNotFound
		}
		return domain.Operation{}, "", err
	}
	var op domain.Operation
	if err := json.Unmarshal(payload, &op); err != nil {
		return domain.Operation{}, "", err
	}
	if err := op.Validate(); err != nil {
		return domain.Operation{}, "", err
	}
	if err := inputHash.Validate(); err != nil {
		return domain.Operation{}, "", err
	}
	if op.Spec.ID != id || op.Spec.Initiator != actor || op.Spec.IdempotencyKey != key {
		return domain.Operation{}, "", fmt.Errorf("stored operation identity mismatch")
	}
	return op, inputHash, nil
}
