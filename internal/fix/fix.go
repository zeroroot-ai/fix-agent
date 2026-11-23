// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package fix wires one pass over one Application: read the open Findings,
// order them by priority, decide for each if the agent can fix it, send the
// first one that it can fix to the coding path, and write a reason on each
// Finding that it cannot fix.
//
// The pass never states that a fix worked. After the coding job it asks the
// connector to merge the merge request, and the daemon allows that call only
// when it granted the merge slot. The daemon reads the merge, the deploy and
// the health signal through the connector of the tenant, and the daemon
// decides what happens to the Finding after that.
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
	"time"
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
	// MergeRequest is the key of the merge request that the daemon linked to
	// the Finding (the FIXED_BY edge). It is empty when the daemon did not
	// return it. The key is the argument of the merge tool.
	MergeRequest string
	// HeadSHA is the head commit of the fix merge request, and Files are the
	// files that it changes. The daemon fills both from its own read of the
	// merge request when it links the Finding (the fields FixHeadSHA and
	// FixFiles of the finding row). They are empty when the daemon has not
	// filled them. The merge step does not merge without them.
	HeadSHA string
	Files   []File
}

// File is one file that the fix merge request changes. It holds no content.
type File struct {
	Path         string
	Change       string
	PreviousPath string
	BlobSHA      string
	// Mode is the file mode that the daemon recorded, for example 100644. It is
	// empty when the daemon records none.
	Mode string
}

// Pending is a Finding at fixing whose merge request is still open, with the
// delivery that the daemon recorded for it. An earlier pass opened the merge
// request, and no merge call has merged it.
type Pending struct {
	Finding  Finding
	Delivery Delivery
}

// Reader returns the open Findings of one Application, and the Findings whose
// merge request waits for a merge.
type Reader interface {
	OpenFindings(ctx context.Context, application string) ([]Finding, error)
	PendingMerges(ctx context.Context, application string) ([]Pending, error)
}

// Coder sends one Finding to the coding path and returns the merge request.
// It returns an error that wraps ErrRetry when the job gave no merge request.
type Coder interface {
	Fix(ctx context.Context, f Finding, repo Repository) (Delivery, error)
}

// MergeState is how the attempt to merge a merge request ended.
type MergeState string

// The states of Merge. None of them says that the fix worked. The daemon reads
// the merge, the deploy and the health signal, and it decides the Finding.
const (
	// MergeDone means that the connector merged the merge request.
	MergeDone MergeState = "merged"
	// MergeWaiting means that the daemon granted no merge slot while the agent
	// waited. The merge request stays open. The daemon frees the slot when the run ends
	// with the merge request open, and it queues the slot again (gibson#1626).
	// The next pass merges it.
	MergeWaiting MergeState = "waiting"
	// MergeNotAllowed means that the agent holds no merge grant. The merge
	// request stays open for a person.
	MergeNotAllowed MergeState = "not_allowed"
	// MergeRefused means that the Git host refused the merge, for example the
	// branch protection. The daemon reads the reason and records it.
	MergeRefused MergeState = "refused"
	// MergeHeadMoved means that the head of the merge request is not the head
	// that the daemon recorded, for example a person pushed a commit. The agent
	// saw it in the state or the host refused the merge. The refusal is final.
	MergeHeadMoved MergeState = "head_moved"
	// MergeForeignChange means that the files of the merge request are not the
	// files that the daemon recorded for the fix, for example a person committed
	// to the branch before the job opened the merge request. It also covers a change of mode, a
	// list that the host cut and a list that the host did not give. The refusal
	// is final.
	MergeForeignChange MergeState = "foreign_change"
	// MergeSkipped means that the agent made no merge call, because the daemon
	// recorded no key, no head or no files for the merge request, or the
	// connector returned no head.
	MergeSkipped MergeState = "skipped"
)

// Merge is the outcome of the merge step.
type Merge struct {
	State MergeState
	// Called is true when the step sent the merge call to the daemon. A step
	// that ended on the state of the merge request, or on a missing fact, sent
	// no call.
	Called bool
	// Reason is one plain sentence. It is empty for MergeDone.
	Reason string
}

// Merger merges the merge request of a delivery after the daemon granted the
// merge slot. It returns an error only when the call itself failed.
type Merger interface {
	Merge(ctx context.Context, repo Repository, d Delivery) (Merge, error)
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
	// Merge is the outcome of the merge step for Delivered. It is the zero
	// value when no merge request exists.
	Merge Merge
	// Resumed is the Finding at fixing whose open merge request this pass
	// tried to merge before the coding loop. It is nil when no merge request
	// was pending.
	Resumed *Finding
	// ResumedDelivery is the merge request of Resumed.
	ResumedDelivery Delivery
	// ResumedMerge is the outcome of the merge step for Resumed.
	ResumedMerge Merge
	// Passed lists the pending merges that ended with a final outcome before
	// Resumed, or all of them when none counted. The pass went on to the next pending merge.
	Passed []Resumption
	// Skipped lists the Findings that got a reason.
	Skipped []Skip
	// Deferred lists the Findings whose coding job failed, was canceled, or
	// gave no merge request within the settle time. They got no reason, so the
	// next pass tries them again.
	Deferred []Skip
	// Attempts is the number of coding jobs that the pass started.
	Attempts int
}

// Resumption is one pending merge that the pass tried.
type Resumption struct {
	Finding  Finding
	Delivery Delivery
	Merge    Merge
}

// counts says if a merge step is the one merge step of the pass. A step that
// waited for the slot is, and a step that merged with a merge call is. A final
// outcome is not, and the pass goes on to the next merge request. This holds
// for a final refusal after a merge call too, so a merge request that the
// branch protection refuses does not starve the next one.
func (m Merge) counts() bool {
	return m.State == MergeWaiting || (m.State == MergeDone && m.Called)
}

// MergeBudget is the one wait budget that all pending merge steps of a pass
// share. The first step that reads the deadline starts it.
type MergeBudget struct {
	deadline time.Time
	started  bool
}

// Deadline returns the end of the budget. The first call sets it to wait from
// now, and each later call returns the same time.
func (b *MergeBudget) Deadline(wait time.Duration) time.Time {
	if !b.started {
		b.deadline, b.started = time.Now().Add(wait), true
	}
	return b.deadline
}

// Spent says if the budget started and its time is used.
func (b *MergeBudget) Spent() bool { return b.started && !time.Now().Before(b.deadline) }

type budgetKey struct{}

// WithMergeBudget returns a context that carries the budget. A Merger that
// finds a budget in its context waits until the end of the budget and not for
// its own bound.
func WithMergeBudget(ctx context.Context, b *MergeBudget) context.Context {
	return context.WithValue(ctx, budgetKey{}, b)
}

// MergeBudgetFrom returns the budget of the context, or nil.
func MergeBudgetFrom(ctx context.Context) *MergeBudget {
	b, _ := ctx.Value(budgetKey{}).(*MergeBudget)
	return b
}

// Pass runs one pass over one Application.
//
// only is empty to take the highest priority first, or the id of the one
// Finding to fix.
func Pass(ctx context.Context, app string, repo Repository, only string,
	reader Reader, coder Coder, merger Merger, emitter Emitter,
) (Summary, error) {
	findings, err := reader.OpenFindings(ctx, app)
	if err != nil {
		return Summary{}, fmt.Errorf("fix: read open findings for %s: %w", app, err)
	}
	pending, err := reader.PendingMerges(ctx, app)
	if err != nil {
		return Summary{}, fmt.Errorf("fix: read pending merges for %s: %w", app, err)
	}
	sum := Summary{Total: len(findings)}
	ranked := Rank(findings)
	if only != "" {
		ranked = only1(ranked, only)
		pending = onlyPending(pending, only)
		if len(ranked) == 0 && len(pending) == 0 {
			return sum, fmt.Errorf("fix: finding %s is not an open finding of %s", only, app)
		}
	}

	// A merge request that an earlier pass opened can still be open. The slot
	// can come after that run ended, so this pass merges the one of the
	// highest priority. The pass makes at most one merge step that waits or merges.
	merged := false
	budget := &MergeBudget{}
	pctx := WithMergeBudget(ctx, budget)
	for _, p := range rankPending(pending) {
		if budget.Spent() {
			// All pending merge steps share one wait budget.
			break
		}
		slog.Info("resume the merge of an open merge request", "finding", p.Finding.ID, "merge_request", p.Delivery.MergeRequest)
		m, err := merger.Merge(pctx, repo, p.Delivery)
		if err != nil {
			return sum, fmt.Errorf("fix: merge the open merge request of finding %s: %w", p.Finding.ID, err)
		}
		slog.Info("merge step ended", "finding", p.Finding.ID, "state", m.State, "reason", m.Reason, "called", m.Called)
		f := p.Finding
		if m.counts() {
			sum.Resumed, sum.ResumedDelivery, sum.ResumedMerge = &f, p.Delivery, m
			merged = true
			break
		}
		sum.Passed = append(sum.Passed, Resumption{Finding: f, Delivery: p.Delivery, Merge: m})
	}

	for _, f := range ranked {
		if err := ctx.Err(); err != nil {
			return sum, fmt.Errorf("fix: %w", err)
		}
		if sum.Attempts >= MaxAttempts {
			break
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
			// A job that ended with no merge request can be a temporary fault.
			// A temporary fault is not a fact about the finding, so the agent
			// writes no block reason for it. The next pass tries the finding
			// again.
			slog.Warn("coding job gave no merge request yet, no reason written", "finding", f.ID, "error", err)
			sum.Deferred = append(sum.Deferred, Skip{Finding: f, Reason: err.Error()})
			continue
		case err != nil:
			return sum, fmt.Errorf("fix: finding %s: %w", f.ID, err)
		}
		slog.Info("merge request opened", "finding", f.ID, "status", del.Status, "mission", del.MissionID)
		sum.Delivered, sum.Delivery = &f, del
		if merged {
			// The pass made its one merge step for the resumed merge request.
			// The next pass merges this one.
			sum.Merge = Merge{State: MergeSkipped, Reason: "this pass already made a merge step for finding " + sum.Resumed.ID}
			break
		}
		m, err := merger.Merge(ctx, repo, del)
		if err != nil {
			return sum, fmt.Errorf("fix: merge the merge request of finding %s: %w", f.ID, err)
		}
		slog.Info("merge step ended", "finding", f.ID, "state", m.State, "reason", m.Reason)
		sum.Merge = m
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

func onlyPending(in []Pending, id string) []Pending {
	for _, p := range in {
		if p.Finding.ID == id {
			return []Pending{p}
		}
	}
	return nil
}

// rankPending returns the pending merges in the order of Rank, the highest
// priority first.
func rankPending(in []Pending) []Pending {
	byID := make(map[string]Pending, len(in))
	fs := make([]Finding, 0, len(in))
	for _, p := range in {
		byID[p.Finding.ID] = p
		fs = append(fs, p.Finding)
	}
	out := make([]Pending, 0, len(in))
	for _, f := range Rank(fs) {
		out = append(out, byID[f.ID])
	}
	return out
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
