// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package emit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/fix-agent/internal/emit"
	"github.com/zeroroot-ai/fix-agent/internal/fix"
	"github.com/zeroroot-ai/sdk/agent"
)

type recorder struct {
	seen []agent.Observation
	err  error
}

func (r *recorder) Observe(_ context.Context, obs agent.Observation) error {
	r.seen = append(r.seen, obs)
	return r.err
}

func TestUnfixed_WritesTheReasonAndNothingElse(t *testing.T) {
	rec := &recorder{}
	e, err := emit.New(rec)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Unfixed(context.Background(), fix.Finding{ID: " f1 "}, " no repository "); err != nil {
		t.Fatalf("Unfixed: %v", err)
	}
	if len(rec.seen) != 1 {
		t.Fatalf("wrote %d observations, want 1", len(rec.seen))
	}
	l, ok := rec.seen[0].(agent.LifecycleEntityObservation)
	if !ok {
		t.Fatalf("observation is %T, want a lifecycle entity observation", rec.seen[0])
	}
	if l.Label != "Finding" || len(l.IDProperties) != 1 || l.IDProperties["brain_id"] != "f1" {
		t.Errorf("identity = %q %v, want Finding named by brain_id alone", l.Label, l.IDProperties)
	}
	if len(l.Properties) != 1 || l.Properties[emit.PropReason] != "no repository" {
		t.Errorf("properties = %v, want only the reason", l.Properties)
	}
	if _, bad := l.Properties["status"]; bad {
		t.Error("the agent must never write the status of a Finding")
	}
	if len(l.Edges) != 0 {
		t.Errorf("edges = %v, want none", l.Edges)
	}
}

func TestUnfixed_AnEmptyReasonOrIDWritesNothing(t *testing.T) {
	for _, tc := range []struct{ id, reason string }{{"f", " "}, {" ", "why"}, {"", ""}} {
		rec := &recorder{}
		e, _ := emit.New(rec)
		if err := e.Unfixed(context.Background(), fix.Finding{ID: tc.id}, tc.reason); err != nil {
			t.Fatalf("Unfixed: %v", err)
		}
		if len(rec.seen) != 0 {
			t.Errorf("id %q reason %q wrote %d observations, want 0: an empty value erases an earlier one", tc.id, tc.reason, len(rec.seen))
		}
	}
}

func TestUnfixed_AFailedWriteIsAnError(t *testing.T) {
	boom := errors.New("no")
	e, _ := emit.New(&recorder{err: boom})
	if err := e.Unfixed(context.Background(), fix.Finding{ID: "f"}, "why"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the observe error", err)
	}
}

func TestNew_NoObserverIsAnError(t *testing.T) {
	if _, err := emit.New(nil); err == nil {
		t.Fatal("want an error for no observer")
	}
}
