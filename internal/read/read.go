// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package read turns the open Findings of one Application into the shape that
// the fix pass works on.
//
// It reads the same traversal as cve-triage, ApplicationFindings, and it reads
// the priority that cve-triage wrote back onto each Finding.
//
// An unavailable read is never an empty read. A pass that took a failed read
// for "nothing is open" would report a clean pass over a live backlog. So this
// package returns the error and never an empty slice in its place.
package read

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/fix-agent/internal/fix"
	"github.com/zeroroot-ai/sdk/agent"
)

// ServerDefaultLimit asks the server for its own default bound.
const ServerDefaultLimit = 0

// Findings is the one platform capability that this package needs. The
// harness satisfies it, and so does a fake.
type Findings interface {
	ApplicationFindings(ctx context.Context, application string, statuses []string, limit int) ([]agent.ApplicationFinding, error)
}

// Reader reads the open Findings of one Application. It satisfies
// fix.Reader.
type Reader struct {
	src Findings
}

// New builds a Reader over src.
func New(src Findings) (*Reader, error) {
	if src == nil {
		return nil, errors.New("read: no findings source")
	}
	return &Reader{src: src}, nil
}

// OpenFindings returns the open Findings of the Application.
//
// The read asks the server for the status open, and it also keeps only the
// rows at that status. A Finding at fixing has a merge request already, so a
// second coding job for it opens a second merge request. The check here does
// not depend on the server filter.
//
// The row carries fix_blocked_reason when an earlier pass wrote one. The
// reader keeps it in BlockedReason so that the pass does not start a coding job
// for the same Finding again (gibson#1579).
//
// The server caps the read. An Application with a larger backlog gives the
// first page. Each Finding in it is correct, and the pass fixes the highest
// priority of the page.
func (r *Reader) OpenFindings(ctx context.Context, application string) ([]fix.Finding, error) {
	app := strings.TrimSpace(application)
	if app == "" {
		return nil, errors.New("read: no application")
	}
	raw, err := r.src.ApplicationFindings(ctx, app, []string{fix.StatusOpen}, ServerDefaultLimit)
	if err != nil {
		return nil, fmt.Errorf("read: application findings for %s: %w", app, err)
	}
	out := make([]fix.Finding, 0, len(raw))
	for _, f := range raw {
		id := strings.TrimSpace(f.FindingID)
		if id == "" {
			// A Finding with no brain_id cannot get a reason written back,
			// and the coding job cannot name it as its input.
			continue
		}
		if f.Status != fix.StatusOpen {
			continue
		}
		out = append(out, fix.Finding{
			ID:             id,
			Vulnerability:  strings.TrimSpace(f.VulnerabilityID),
			Severity:       strings.ToLower(strings.TrimSpace(f.Severity)),
			PlaceLabel:     strings.TrimSpace(f.PlaceLabel),
			PlaceKey:       strings.TrimSpace(f.PlaceKey),
			Priority:       strings.ToUpper(strings.TrimSpace(f.Priority)),
			PriorityReason: strings.TrimSpace(f.PriorityReason),
			Reachable:      f.Reachable,
			Exposed:        f.Reachable && f.Exposed,
			BlockedReason:  strings.TrimSpace(f.FixBlockedReason),
		})
	}
	return out, nil
}
