// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package pass assembles one fix pass from the modules and runs it against
// the harness that the daemon provisions.
//
// # One dispatch is one finding
//
// The mission node dispatches this agent for one Application. The agent reads
// the open Findings, takes the highest priority that it can fix, sends it to
// the coding path, and ends when a merge request exists. A Finding that it
// cannot fix gets a reason, and the agent goes on to the next one.
//
// # Where the pass stops
//
// The pass ends at the merge request. It does not merge, it does not wait for
// the pipeline, and it does not revert. See AGENTS.md for the seams that the
// daemon has to offer before the agent can merge.
package pass

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/fix-agent/internal/code"
	"github.com/zeroroot-ai/fix-agent/internal/emit"
	"github.com/zeroroot-ai/fix-agent/internal/fix"
	"github.com/zeroroot-ai/fix-agent/internal/read"
	"github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/mission"
)

// The task-context keys that the mission node sets. The application, the
// bank, the connector and the project are required. A dispatch that lacks
// one of them fails, and no Finding gets a reason.
const (
	// ContextKeyApplication names the Application to fix.
	ContextKeyApplication = "application"
	// ContextKeyFinding names one Finding to fix. Empty takes the highest
	// priority first.
	ContextKeyFinding = "finding"
	// ContextKeyBank names the bank of coding agents.
	ContextKeyBank = "bank"
	// ContextKeyTarget names the target of the coding mission.
	ContextKeyTarget = "target"
	// ContextKeyConnector names the connector of the Git host, in the slash
	// form "connector/<name>".
	ContextKeyConnector = "connector"
	// ContextKeyProject is the project path on the Git host.
	ContextKeyProject = "project"
	// ContextKeyBaseBranch is the branch that the merge request targets.
	ContextKeyBaseBranch = "base_branch"
	// ContextKeyRepository is the directory name of the worktree.
	ContextKeyRepository = "repository"
	// ContextKeyTimeout bounds the wait for the coding job, as a Go duration.
	ContextKeyTimeout = "timeout"
)

// Platform is everything that this agent needs from the harness: the
// lifecycle read, the mission calls of the coding path and the observation
// write.
//
// agent.Harness satisfies it. Naming the methods and not taking the whole
// harness is what lets a test run the pass without a daemon.
type Platform interface {
	ApplicationFindings(ctx context.Context, application string, statuses []string, limit int) ([]agent.ApplicationFinding, error)
	CreateMission(ctx context.Context, missionDef any, targetID string, opts *mission.CreateMissionOpts) (*mission.MissionInfo, error)
	RunMission(ctx context.Context, missionID string, opts *mission.RunMissionOpts) error
	WaitForMission(ctx context.Context, missionID string, timeout time.Duration) (*mission.MissionResult, error)
	Observe(ctx context.Context, obs agent.Observation) error
}

// ctxString reads one string of the task context.
func ctxString(task agent.Task, key string) string {
	if s, ok := task.Context[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// ApplicationID resolves which Application a task is about. The task context
// is the source. The goal is the fallback, so a hand-dispatched pass can name
// the Application.
func ApplicationID(task agent.Task) (string, error) {
	if s := ctxString(task, ContextKeyApplication); s != "" {
		return s, nil
	}
	if t := strings.TrimSpace(task.Goal); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("pass: no application: set task context %q or the goal", ContextKeyApplication)
}

// RepositoryOf reads the repository from the task context.
//
// A dispatch with no connector or no project is a fault of the dispatch, as
// a dispatch with no bank is. It fails the run. A reason on each Finding
// would state a fact about the dispatch as a fact about the Finding, and the
// next pass would skip Findings that it can fix.
func RepositoryOf(task agent.Task) (fix.Repository, error) {
	connector, project := ctxString(task, ContextKeyConnector), ctxString(task, ContextKeyProject)
	if connector == "" || project == "" {
		return fix.Repository{}, fmt.Errorf("pass: no repository: set the task context keys %q and %q",
			ContextKeyConnector, ContextKeyProject)
	}
	return fix.Repository{
		Name:         ctxString(task, ContextKeyRepository),
		ConnectorRef: connector,
		Project:      project,
		BaseBranch:   ctxString(task, ContextKeyBaseBranch),
	}, nil
}

// Run performs one pass over one Application and reports what it did.
func Run(ctx context.Context, p Platform, task agent.Task) (agent.Result, error) {
	if p == nil {
		return failed(), errors.New("pass: no platform")
	}
	app, err := ApplicationID(task)
	if err != nil {
		return failed(), err
	}
	repo, err := RepositoryOf(task)
	if err != nil {
		return failed(), err
	}
	reader, err := read.New(p)
	if err != nil {
		return failed(), err
	}
	emitter, err := emit.New(p)
	if err != nil {
		return failed(), err
	}
	cfg := code.Config{
		Application: app,
		Bank:        ctxString(task, ContextKeyBank),
		Target:      ctxString(task, ContextKeyTarget),
	}
	if raw := ctxString(task, ContextKeyTimeout); raw != "" {
		d, perr := time.ParseDuration(raw)
		if perr != nil || d <= 0 {
			return failed(), fmt.Errorf("pass: task context %q is %q: want a positive duration such as 30m", ContextKeyTimeout, raw)
		}
		cfg.Timeout = d
	}
	coder, err := code.New(p, cfg)
	if err != nil {
		return failed(), err
	}

	sum, err := fix.Pass(ctx, app, repo, ctxString(task, ContextKeyFinding), reader, coder, emitter)
	if err != nil {
		return failed(), err
	}
	// Result.Findings is for the Findings that a run discovered. This agent
	// discovers none, so it stays empty. The Finding that got a merge request
	// goes in the metadata.
	res := agent.Result{Status: a2a.TaskStateCompleted, Output: Report(app, sum)}
	if sum.Delivered != nil {
		res.Metadata = map[string]any{
			"finding":        sum.Delivered.ID,
			"finding_status": sum.Delivery.Status,
			"mission":        sum.Delivery.MissionID,
		}
	}
	return res, nil
}

func failed() agent.Result { return agent.Result{Status: a2a.TaskStateFailed} }

// Report renders a pass summary as one readable block.
//
// It says that a merge request is open. It never says that a fix worked,
// because the agent does not know that. The daemon reads the merge, the deploy
// and the health signal, and it decides.
func Report(app string, s fix.Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "fix-agent: %s: %d open findings, %d coding jobs, %d without a fix\n", app, s.Total, s.Attempts, len(s.Skipped))
	if s.Delivered != nil {
		fmt.Fprintf(&b, "  merge request open for %s: the daemon set the status %s (mission %s)",
			s.Delivered.ID, s.Delivery.Status, s.Delivery.MissionID)
		b.WriteString("\n  waiting for the daemon to read the merge")
	} else {
		b.WriteString("  no merge request opened")
	}
	for _, sk := range s.Skipped {
		fmt.Fprintf(&b, "\n  not fixed %s: %s", sk.Finding.ID, sk.Reason)
	}
	for _, sk := range s.Deferred {
		fmt.Fprintf(&b, "\n  try again %s: %s", sk.Finding.ID, sk.Reason)
	}
	return b.String()
}
