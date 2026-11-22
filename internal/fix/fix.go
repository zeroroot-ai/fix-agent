// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fix wires one pass over one Application: read the open Findings,
// order them by priority, decide for each if the agent can fix it, send the
// first one that it can fix to the coding path, and write a reason on each
// Finding that it cannot fix.
//
// The pass never states that a fix worked. It ends when a merge request
// exists. The daemon reads the merge, the deploy and the health signal
// through the connector of the tenant, and the daemon decides what happens to
// the Finding after that.
//
// The seams below are the interfaces that the harness-backed packages
// implement. A fake of each one is enough to test the pass.
package fix

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// MaxAttempts bounds the coding jobs that one pass starts. A coding job is
// the costly step, so a backlog of findings that the coding path cannot fix
// does not turn one dispatch into one job for each of them.
const MaxAttempts = 3

// The statuses of a Finding that the agent reads (gibson#1656). The daemon sets
// them. It also sets fixed and verified, and the agent never reads those.
const (
	// StatusOpen is the one status that a pass sends to the coding path.
	StatusOpen = "open"
	// StatusFixing means that a merge request for the Finding exists. The
	// daemon sets it when a fix job closes with a merge request.
	StatusFixing = "fixing"
)

// ErrRetry means that the coding path gave no merge request and the cause can
// be temporary. Examples are a mission that did not complete and a daemon that
// did not show the status fixing before the settle bound ended. The pass
// writes no reason on the Finding, so the next pass tries it again, and goes
// on to the next Finding.
//
// Any error from a Coder that does not wrap ErrRetry is a failure of the call
// itself and stops the pass.
var ErrRetry = errors.New("the coding job gave no merge request yet")

// Finding is one open Finding of the Application with the facts that the
// agent reads. The graph is the source of every value, so the code that
// builds a prompt from it quotes it.
type Finding struct {
	ID             string
	Vulnerability  string
	Severity       string
	PlaceLabel     string
	PlaceKey       string
	Priority       string
	PriorityReason string
	Reachable      bool
	Exposed        bool
	// BlockedReason is why an earlier pass did not fix the Finding. It is empty
	// when no pass gave up on it. A pass does not try a blocked Finding again.
	BlockedReason string
}

// Repository is the one repository that the Application is built from.
type Repository struct {
	// Name is the directory name of the worktree that the coding agent sees.
	Name string
	// ConnectorRef names the connector that holds the credential of the Git
	// host, in the slash form "connector/<name>".
	ConnectorRef string
	// Project is the project path on the Git host, for example "group/repo".
	Project string
	// BaseBranch is the branch that the merge request targets. Empty means
	// the default branch of the project.
	BaseBranch string
}

// Delivery is the proof that the coding job opened a merge request: the
// status that the daemon set on the Finding after the job closed.
//
// The agent does not read the merge request from the output of the mission.
// No harness call returns that output, and text in it can come from the
// coding agent. The status comes from the daemon, which set it from the
// deliverable that the driver opened (gibson job_graph_link.go).
type Delivery struct {
	// Status is the status of the Finding after the job: StatusFixing, or a
	// later status if the daemon moved it on.
	Status string
	// MissionID is the coding mission.
	MissionID string
}

// Reader returns the open Findings of one Application.
type Reader interface {
	OpenFindings(ctx context.Context, application string) ([]Finding, error)
}

// Coder sends one Finding to the coding path and returns the merge request.
// It returns an error that wraps ErrRetry when the job gave no merge request.
type Coder interface {
	Fix(ctx context.Context, f Finding, repo Repository) (Delivery, error)
}

// Emitter writes a reason on a Finding that the agent did not fix.
type Emitter interface {
	Unfixed(ctx context.Context, f Finding, reason string) error
}

// Skip is a Finding that the agent did not fix and the reason that it wrote.
type Skip struct {
	Finding Finding
	Reason  string
}

// Summary is the result of one pass.
type Summary struct {
	// Total is the number of open Findings that the pass read.
	Total int
	// Delivered is the Finding that the coding job fixed with a merge
	// request. It is nil when no Finding got one.
	Delivered *Finding
	// Delivery is the merge request of Delivered.
	Delivery Delivery
	// Skipped lists the Findings that got a reason.
	Skipped []Skip
	// Blocked lists the Findings that already carried a reason from an earlier
	// pass. The pass sent none of them to the coding path and wrote no new
	// reason.
	Blocked []Skip
	// Deferred lists the Findings whose coding job failed, was canceled, or
	// gave no merge request within the settle time. They got no reason, so the
	// next pass tries them again.
	Deferred []Skip
	// Attempts is the number of coding jobs that the pass started.
	Attempts int
}

// Pass runs one pass over one Application.
//
// only is empty to take the highest priority first, or the id of the one
// Finding to fix.
func Pass(ctx context.Context, app string, repo Repository, only string,
	reader Reader, coder Coder, emitter Emitter,
) (Summary, error) {
	findings, err := reader.OpenFindings(ctx, app)
	if err != nil {
		return Summary{}, fmt.Errorf("fix: read open findings for %s: %w", app, err)
	}
	sum := Summary{Total: len(findings)}
	ranked := Rank(findings)
	if only != "" {
		ranked = only1(ranked, only)
		if len(ranked) == 0 {
			return sum, fmt.Errorf("fix: finding %s is not an open finding of %s", only, app)
		}
	}

	for _, f := range ranked {
		if err := ctx.Err(); err != nil {
			return sum, fmt.Errorf("fix: %w", err)
		}
		if sum.Attempts >= MaxAttempts {
			break
		}
		// A named Finding is an explicit request, so it ignores an old reason.
		if f.BlockedReason != "" && only == "" {
			sum.Blocked = append(sum.Blocked, Skip{Finding: f, Reason: f.BlockedReason})
			continue
		}
		if v := Decide(f); !v.Fixable {
			if err := skip(ctx, emitter, &sum, f, v.Reason); err != nil {
				return sum, err
			}
			continue
		}
		sum.Attempts++
		del, err := coder.Fix(ctx, f, repo)
		switch {
		case errors.Is(err, ErrRetry):
			// A job that ended with no merge request gets no block reason. The
			// cause can be temporary, and a reason keeps the Finding out of the
			// next pass. A Finding that carries a reason from the rule in
			// Decide is skipped at the top of this loop (gibson#1579).
			slog.Warn("coding job gave no merge request yet, no reason written", "finding", f.ID, "error", err)
			sum.Deferred = append(sum.Deferred, Skip{Finding: f, Reason: err.Error()})
			continue
		case err != nil:
			return sum, fmt.Errorf("fix: finding %s: %w", f.ID, err)
		}
		slog.Info("merge request opened", "finding", f.ID, "status", del.Status, "mission", del.MissionID)
		sum.Delivered, sum.Delivery = &f, del
		break
	}
	return sum, nil
}

func skip(ctx context.Context, e Emitter, sum *Summary, f Finding, reason string) error {
	if err := e.Unfixed(ctx, f, reason); err != nil {
		return fmt.Errorf("fix: write the reason on finding %s: %w", f.ID, err)
	}
	sum.Skipped = append(sum.Skipped, Skip{Finding: f, Reason: reason})
	return nil
}

func only1(in []Finding, id string) []Finding {
	for _, f := range in {
		if f.ID == id {
			return []Finding{f}
		}
	}
	return nil
}

// Rank orders Findings with the highest priority first: P1 to P4, then
// Findings that no triage pass ranked. Findings with the same priority keep
// the order of their ids, so two runs over the same graph choose the same
// Finding.
//
// An empty priority means that no pass has decided yet. It never means that
// the Finding is unimportant, but it has no rank to sort on, so it comes last.
func Rank(in []Finding) []Finding {
	out := append([]Finding(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := rankOf(out[i].Priority), rankOf(out[j].Priority)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func rankOf(p string) int {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "P1":
		return 1
	case "P2":
		return 2
	case "P3":
		return 3
	case "P4":
		return 4
	default:
		return 5
	}
}
