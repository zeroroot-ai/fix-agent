// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command fix-agent is a Gibson agent that fixes one finding of an
// Application.
//
// One dispatch is one pass over one Application. The agent reads the open
// findings, takes the highest priority that cve-triage wrote, and sends it to
// the coding path of Gibson: a job on a bank of coding agents with a merge
// request as its deliverable. A finding that the agent cannot fix gets a
// reason, and the agent goes on.
//
// The agent never states that a fix worked. It ends when a merge request
// exists. The daemon reads the merge, the deploy and the health signal
// through the connector of the tenant, and the daemon decides the status of
// the finding and the revert.
//
// # How it runs
//
// It is dispatched, not enrolled (ADR-0116). Gibson launches this image once
// per mission run inside an ephemeral setec sandbox, hands it a capability
// grant scoped to that tenant and run, and reaps the sandbox when the process
// exits. The binary reads its task from the environment, runs one pass, and
// returns. It never polls, never registers, and holds no identity between
// runs.
//
// See AGENTS.md for the Gibson agent contract this binary implements.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/zeroroot-ai/fix-agent/internal/dispatch"
	"github.com/zeroroot-ai/fix-agent/internal/pass"
	"github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/serve"
	"github.com/zeroroot-ai/sdk/types"
)

// Version is the agent version this binary reports. It is set at build time
// from the release tag; "dev" is what a local build reports.
//
// It is a var set by -ldflags rather than a const, because a hardcoded version
// here would drift from the release-please tag the moment either moved, and a
// component that misreports its own version is worse than one that says "dev".
var Version = "dev"

func main() {
	res, err := run(context.Background())
	if err != nil {
		slog.Error("fix-agent", "version", Version, "err", err)
	}
	// The result line is written on success and on failure. The launcher
	// reads it for the output of the mission node, and the exit status
	// still says whether the run failed.
	if werr := writeResult(os.Stdout, res, err); werr != nil {
		slog.Error("fix-agent", "version", Version, "err", werr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}

// run performs one dispatched pass and returns its result.
//
// Every failure returns an error rather than logging and continuing. Gibson
// learns about this run from the exit status and the result line, so a pass
// that could not read, could not code, or could not write must exit
// non-zero: exiting 0 after failing would report a clean fix pass over an
// application nobody looked at.
func run(ctx context.Context) (agent.Result, error) {
	d, err := dispatch.FromEnv()
	if err != nil {
		return agent.Result{}, fmt.Errorf("read the launch contract: %w", err)
	}

	slog.Info("fix dispatched",
		"version", Version,
		"task", d.Task.ID,
		"mission", d.MissionID,
		"mission_run", d.MissionRunID,
		"agent_run", d.AgentRunID,
		"model", d.Model,
	)

	harness, closeHarness, err := connect(ctx, d)
	if err != nil {
		return agent.Result{}, err
	}
	defer closeHarness()

	res, err := pass.Run(ctx, harness, d.Task)
	if err != nil {
		return res, fmt.Errorf("task %s: %w", d.Task.ID, err)
	}

	slog.Info("fix complete", "task", d.Task.ID, "output", res.Output)
	return res, nil
}

// connect dials the harness callback service with this run's grant.
//
// The grant is the whole credential: there is no bootstrap token and no
// enrolled identity to fall back on, which is what keeps a sandboxed run
// unable to act outside the tenant and run it was launched for.
func connect(ctx context.Context, d dispatch.Dispatch) (*serve.CallbackHarness, func(), error) {
	client, err := serve.NewCallbackClient(d.CallbackEndpoint, serve.WithCallbackToken(d.Grant))
	if err != nil {
		return nil, nil, fmt.Errorf("callback client: %w", err)
	}
	if err := client.Connect(ctx); err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", d.CallbackEndpoint, err)
	}

	harness := serve.NewCallbackHarness(client,
		serve.WithCallbackMission(types.MissionContext{
			ID:           d.MissionID,
			CurrentAgent: "fix-agent",
		}),
	)

	return harness, func() {
		if err := client.Close(); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("close callback client", "err", err)
		}
	}, nil
}
