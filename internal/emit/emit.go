// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package emit writes the reason that the agent did not fix a Finding.
//
// The reason is one property of the Finding that the agent read. It goes as a
// sighting, the same way as the priority of cve-triage: the agent reports what
// it saw, and the brain resolves the identity and the projector writes the
// node. The Finding is named by its brain_id, so the write enriches the
// Finding that the scan raised and does not create a second one.
//
// This package writes nothing else. The agent never writes the status of a
// Finding and never writes that a fix worked. The daemon sets the status
// from the merge request that it reads itself.
package emit

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/fix-agent/internal/fix"
	"github.com/zeroroot-ai/sdk/agent"
)

// LabelFinding is the taxonomy label of a Finding. A label outside the
// taxonomy lands as an untyped Observation, which reads back as no reason.
const LabelFinding = "Finding"

// IDPropFinding is the identity property of a Finding. Any other identity
// property creates a second node.
const IDPropFinding = "brain_id"

// PropReason is the property that holds the reason that the agent did not fix
// the Finding.
const PropReason = "fix_blocked_reason"

// Observer is the one platform capability that this package needs.
type Observer interface {
	Observe(ctx context.Context, obs agent.Observation) error
}

// Emitter writes reasons as observations. It satisfies fix.Emitter.
type Emitter struct {
	obs Observer
}

// New builds an Emitter over obs.
func New(obs Observer) (*Emitter, error) {
	if obs == nil {
		return nil, errors.New("emit: no observer")
	}
	return &Emitter{obs: obs}, nil
}

// Unfixed writes the reason on the Finding.
func (e *Emitter) Unfixed(ctx context.Context, f fix.Finding, reason string) error {
	obs, ok := Observation(f, reason)
	if !ok {
		return nil
	}
	if err := e.obs.Observe(ctx, obs); err != nil {
		return fmt.Errorf("emit: observe finding %s: %w", f.ID, err)
	}
	return nil
}

// Observation builds the sighting for one Finding, or reports that there is
// nothing to write. An empty reason is not written: a sighting that sets a
// property to "" erases what an earlier sighting set.
func Observation(f fix.Finding, reason string) (agent.LifecycleEntityObservation, bool) {
	id := strings.TrimSpace(f.ID)
	text := strings.TrimSpace(reason)
	if id == "" || text == "" {
		return agent.LifecycleEntityObservation{}, false
	}
	return agent.LifecycleEntityObservation{
		Label:        LabelFinding,
		IDProperties: map[string]string{IDPropFinding: id},
		Properties:   map[string]string{PropReason: text},
	}, true
}
