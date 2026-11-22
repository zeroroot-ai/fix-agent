// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package merge merges the merge request of a fix after the daemon granted
// the merge slot (gibson#1458).
//
// # Who decides
//
// The agent never decides that a merge may happen. It calls the connector tool
// merge_merge_request through invoke_tool, and the daemon gates that call in
// three steps. The call must pass the can_execute check of the grant. The tool
// has the role merge in its manifest, so the call must name a merge request
// that holds a granted slot in the World of the tenant. The slot binds the
// mission of the fix, and only the mission that originated it may merge with
// it. The agent runs in that parent mission. The word of the agent is never
// the source of any of these facts.
//
// # How the agent learns of the grant
//
// The daemon emits MergeGranted when the pipeline is green and the queue of
// the Application has a free slot. No harness call returns the slot. The agent
// asks by calling the tool. A refusal that says "merge not granted yet" means
// that the slot is not granted. The agent waits and calls again until the Wait
// bound ends. The daemon keeps the queue, so an agent that stops waiting loses
// nothing: the merge request stays open.
//
// # What it leaves to the daemon
//
// A refusal of the Git host, for example the branch protection, ends the step
// and leaves the Finding at fixing. The daemon reads the refusal through
// merge_request_state and records it on the Timeline. This package does not
// read the health signal and does not revert. Only the daemon reverts.
package merge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/fix-agent/internal/fix"
	"github.com/zeroroot-ai/sdk/agent"
	"google.golang.org/protobuf/encoding/protojson"
	protolib "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// Tool is the connector tool that merges one merge request. Both Git host
// connectors of Zero Root serve it (zeroroot-ai/connectors, github-fixloop and
// gitlab-fixloop).
const Tool = "merge_merge_request"

// ConnectorPrefix starts a connector reference in the task context.
const ConnectorPrefix = "connector/"

// DefaultWait bounds the wait for the merge slot. The pipeline and the queue
// run at their own speed, so the bound is long. It exists so that a queue that
// never grants does not hold the sandbox open.
const DefaultWait = 30 * time.Minute

// DefaultPoll is the time between two calls. The daemon reads the facts of the
// fix loop on its own interval, so a faster call gives the same answer.
const DefaultPoll = 15 * time.Second

// The texts that the daemon puts in a refusal of invoke_tool. The SDK returns
// a refusal as an error with the message of the daemon, so this is the one
// place that reads them. Source: gibson internal/engine/metatool
// (approval.go and metatool.go) and internal/engine/harness/callback_metatool.go.
const (
	// textNotGranted is in ErrMergeNotGranted.
	textNotGranted = "merge not granted yet"
	// textUnauthorized is in ErrUnauthorized, the failed can_execute check.
	textUnauthorized = "not authorized to invoke tool"
	// textBlocked is in ErrBlocked, a tool that the mission policy blocks.
	textBlocked = "blocked by mission policy"
	// textTransport starts the error of the SDK when the call did not reach
	// the daemon.
	textTransport = "CallToolProto callback failed"
)

// Caller is the one harness call that this package needs. agent.Harness
// satisfies it, and so does a fake.
type Caller interface {
	CallToolProto(ctx context.Context, name string, request, response protolib.Message, opts ...agent.ToolCallOption) error
}

// Config is what the dispatch states about the merge.
type Config struct {
	// Wait bounds the wait for the merge slot. Zero takes DefaultWait.
	Wait time.Duration
	// Poll is the time between two calls. Zero takes DefaultPoll.
	Poll time.Duration
}

// Merger merges the merge request of a delivery. It satisfies fix.Merger.
type Merger struct {
	c   Caller
	cfg Config
}

// New builds a Merger over c.
func New(c Caller, cfg Config) (*Merger, error) {
	if c == nil {
		return nil, errors.New("merge: no caller")
	}
	if cfg.Wait <= 0 {
		cfg.Wait = DefaultWait
	}
	if cfg.Poll <= 0 {
		cfg.Poll = DefaultPoll
	}
	return &Merger{c: c, cfg: cfg}, nil
}

// ToolID returns the id of the merge tool of the connector in the form that
// invoke_tool takes: mcp:<connector>:merge_merge_request.
func ToolID(connectorRef string) (string, error) {
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(connectorRef), ConnectorPrefix))
	if name == "" || strings.ContainsAny(name, ": \t\n") {
		return "", fmt.Errorf("merge: the connector reference %q is not of the form %s<name>", connectorRef, ConnectorPrefix)
	}
	return "mcp:" + name + ":" + Tool, nil
}

// Merge asks the connector to merge the merge request of the delivery. It
// waits for the merge slot. It returns an error only when a call did not reach
// the daemon. A refusal is an outcome and not an error.
func (m *Merger) Merge(ctx context.Context, repo fix.Repository, d fix.Delivery) (fix.Merge, error) {
	if d.MergeRequest == "" {
		return fix.Merge{
			State:  fix.MergeSkipped,
			Reason: "the daemon returned no key for the merge request, so the agent cannot name it to the merge tool",
		}, nil
	}
	id, err := ToolID(repo.ConnectorRef)
	if err != nil {
		return fix.Merge{}, err
	}
	in, err := request(id, d.MergeRequest)
	if err != nil {
		return fix.Merge{}, err
	}
	deadline := time.Now().Add(m.cfg.Wait)
	for {
		out := &structpb.Struct{}
		cerr := m.c.CallToolProto(ctx, "invoke_tool", in, out)
		res, again, jerr := judge(out, cerr)
		if jerr != nil {
			return fix.Merge{}, jerr
		}
		if !again {
			return res, nil
		}
		if !time.Now().Add(m.cfg.Poll).Before(deadline) {
			return res, nil
		}
		t := time.NewTimer(m.cfg.Poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return fix.Merge{}, fmt.Errorf("merge: wait for the merge slot: %w", ctx.Err())
		case <-t.C:
		}
	}
}

func request(id, mergeRequest string) (*structpb.Struct, error) {
	in, err := structpb.NewStruct(map[string]any{
		"id":   id,
		"args": map[string]any{"merge_request": mergeRequest},
	})
	if err != nil {
		return nil, fmt.Errorf("merge: build the request: %w", err)
	}
	return in, nil
}

// judge reads one answer of invoke_tool. again is true when the same call can
// succeed later: the slot is not granted yet, or the host has not settled the
// merge status. A non-nil error means that the call did not reach the daemon,
// or that the answer is not an object.
func judge(out *structpb.Struct, err error) (m fix.Merge, again bool, _ error) {
	if err != nil {
		return refusal(err)
	}
	raw, jerr := protojson.Marshal(out.GetFields()["result"].GetStructValue())
	if jerr != nil {
		return fix.Merge{}, false, fmt.Errorf("merge: read the result of the merge tool: %w", jerr)
	}
	var r struct {
		Merged bool   `json:"merged"`
		State  string `json:"state"`
		Reason string `json:"reason"`
	}
	if uerr := json.Unmarshal(raw, &r); uerr != nil {
		return fix.Merge{}, false, fmt.Errorf("merge: read the result of the merge tool: %w", uerr)
	}
	switch {
	case r.Merged:
		return fix.Merge{State: fix.MergeDone}, false, nil
	case r.State == "refused" || r.State == "closed":
		return fix.Merge{State: fix.MergeRefused, Reason: hostReason(r.State, r.Reason)}, false, nil
	}
	// The merge request is open and the host did not merge it yet.
	return fix.Merge{State: fix.MergeWaiting, Reason: hostReason(r.State, r.Reason)}, true, nil
}

// refusal reads the error of a call.
func refusal(err error) (m fix.Merge, again bool, _ error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, textTransport):
		return fix.Merge{}, false, fmt.Errorf("merge: %w", err)
	case strings.Contains(msg, textNotGranted):
		return fix.Merge{State: fix.MergeWaiting, Reason: "the daemon has not granted the merge slot"}, true, nil
	case strings.Contains(msg, textUnauthorized), strings.Contains(msg, textBlocked):
		return fix.Merge{
			State:  fix.MergeNotAllowed,
			Reason: "the agent holds no grant to merge, so the merge request stays open for a person",
		}, false, nil
	}
	// Any other refusal comes from the tool or the host. Do not call again.
	return fix.Merge{State: fix.MergeRefused, Reason: "the merge tool refused the call: " + msg}, false, nil
}

func hostReason(state, reason string) string {
	if r := strings.TrimSpace(reason); r != "" {
		return "the merge request is " + state + ": " + r
	}
	return "the merge request is " + state
}
