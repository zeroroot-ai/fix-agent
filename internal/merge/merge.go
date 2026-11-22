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
// bound ends. An agent that stops waiting leaves the merge request open, and
// a slot that the daemon grants after that is not used. It blocks the other
// fixes of the Application until MergeSlotHold ends (24 hours). The daemon
// must re-dispatch the agent on MergeGranted, or free the slot when the run
// ends. That change is in gibson, see gibson#1609.
//
// # The head of the merge request
//
// While the agent waits, a person with push access can add a commit to the fix
// branch. So the agent reads head_sha of the merge request before it asks for
// the merge, and it passes the value as expected_head_sha. The host refuses a
// merge when the head moved, and the agent treats that refusal as final. The
// tool argument expected_head_sha is in zeroroot-ai/connectors
// feat/fixloop-open-merge-request. The tool in main has the argument sha.
//
// # Paths that the job did not change
//
// The pin of the head does not stop a commit that was on the branch before the
// coding job pushed. So the agent also compares changed_files of
// merge_request_state with the set of paths that the coding job changed
// (Delivery.ChangedFiles), and it does not merge unless the two sets are equal.
// A mismatch is final. The agent does not guess the set. If the delivery has no
// record of it, or the connector returns no changed_files, the agent does not
// merge. No harness call returns the paths of the job yet, see AGENTS.md.
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
	"slices"
	"strings"
	"time"

	"github.com/zeroroot-ai/fix-agent/internal/fix"
	"github.com/zeroroot-ai/sdk/agent"
	"google.golang.org/protobuf/encoding/protojson"
	protolib "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// ToolState is the connector tool that reads one merge request. The merge step
// reads head_sha from it.
const ToolState = "merge_request_state"

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

// MaxBackoff bounds the wait between two calls to this factor of Poll. The wait
// starts at Poll and doubles after every retry, up to this cap. It applies to
// the read of the merge request and to the merge call alike.
const MaxBackoff = 8

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
	// textPending is in ErrApprovalPending.
	textPending = "pending authorization"
	// textAudit is in ErrAuditUnavailable.
	textAudit = "audit record of the call could not be written"
	// textMergeCheck is in the error of a failed MayMerge read.
	textMergeCheck = "the merge check of"
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
func ToolID(connectorRef string) (string, error) { return toolID(connectorRef, Tool) }

func toolID(connectorRef, tool string) (string, error) {
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(connectorRef), ConnectorPrefix))
	if name == "" || strings.ContainsAny(name, ": \t\n") {
		return "", fmt.Errorf("merge: the connector reference %q is not of the form %s<name>", connectorRef, ConnectorPrefix)
	}
	return "mcp:" + name + ":" + tool, nil
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
	if len(d.ChangedFiles) == 0 {
		return fix.Merge{
			State: fix.MergeSkipped,
			Reason: "the agent has no record of the paths that the coding job changed, " +
				"so it cannot tell a foreign commit on the branch from the change of the job",
		}, nil
	}
	id, err := ToolID(repo.ConnectorRef)
	if err != nil {
		return fix.Merge{}, err
	}
	w := &backoff{deadline: time.Now().Add(m.cfg.Wait), delay: m.cfg.Poll, max: m.cfg.Poll * MaxBackoff}
	var head string
	for {
		h, early, again, herr := m.head(ctx, repo, d)
		if herr != nil {
			return fix.Merge{}, herr
		}
		if !again {
			if early != nil {
				return *early, nil
			}
			head = h
			break
		}
		if ok, werr := w.next(ctx); werr != nil || !ok {
			return derefMerge(early), werr
		}
	}
	in, err := request(id, d.MergeRequest, head)
	if err != nil {
		return fix.Merge{}, err
	}
	for {
		out := &structpb.Struct{}
		cerr := m.c.CallToolProto(ctx, "invoke_tool", in, out)
		res, again, jerr := judge(out, cerr, head)
		if jerr != nil {
			return fix.Merge{}, jerr
		}
		if !again {
			return res, nil
		}
		if ok, werr := w.next(ctx); werr != nil || !ok {
			return res, werr
		}
	}
}

// backoff is the wait between two tries. It grows after every retry, up to max,
// and it ends at the deadline.
type backoff struct {
	deadline   time.Time
	delay, max time.Duration
}

// next waits for the next try. It returns false when no time is left before the
// deadline, and an error when the context ends.
func (b *backoff) next(ctx context.Context) (bool, error) {
	if !time.Now().Add(b.delay).Before(b.deadline) {
		return false, nil
	}
	t := time.NewTimer(b.delay)
	select {
	case <-ctx.Done():
		t.Stop()
		return false, fmt.Errorf("merge: wait for the merge slot: %w", ctx.Err())
	case <-t.C:
	}
	b.delay = min(b.delay*2, b.max)
	return true, nil
}

func derefMerge(m *fix.Merge) fix.Merge {
	if m == nil {
		return fix.Merge{}
	}
	return *m
}

// head reads head_sha of the merge request. It returns an outcome and no head
// when the agent must not ask for the merge: the connector gave no head_sha, or
// the read was refused.
func (m *Merger) head(ctx context.Context, repo fix.Repository, d fix.Delivery) (head string, early *fix.Merge, again bool, _ error) {
	key := d.MergeRequest
	id, err := toolID(repo.ConnectorRef, ToolState)
	if err != nil {
		return "", nil, false, err
	}
	in, err := structpb.NewStruct(map[string]any{"id": id, "args": map[string]any{"merge_request": key}})
	if err != nil {
		return "", nil, false, fmt.Errorf("merge: build the request: %w", err)
	}
	out := &structpb.Struct{}
	if cerr := m.c.CallToolProto(ctx, "invoke_tool", in, out); cerr != nil {
		res, retry, rerr := refusal(cerr)
		if rerr != nil {
			return "", nil, false, rerr
		}
		if res.State == fix.MergeRefused {
			res.Reason = "the read of the merge request failed: " + cerr.Error()
		}
		return "", &res, retry, nil
	}
	r, jerr := result(out)
	if jerr != nil {
		return "", nil, false, jerr
	}
	if r.HeadSHA == "" {
		return "", &fix.Merge{
			State:  fix.MergeSkipped,
			Reason: "the connector returned no head_sha, so the agent cannot bind the merge to the head that it saw",
		}, false, nil
	}
	if len(r.ChangedFiles) == 0 {
		return "", &fix.Merge{
			State:  fix.MergeSkipped,
			Reason: "the connector returned no changed_files, so the agent cannot check the paths of the branch",
		}, false, nil
	}
	if r.Truncated || r.TruncatedFiles {
		return "", &fix.Merge{
			State:  fix.MergeForeignChange,
			Reason: "the host gave only a part of the changed files, so the agent cannot compare them with the paths of the coding job",
		}, false, nil
	}
	if extra, missing := diff(paths(r.ChangedFiles), d.ChangedFiles); len(extra)+len(missing) > 0 {
		return "", &fix.Merge{
			State: fix.MergeForeignChange,
			Reason: "the paths of the merge request are not the paths that the coding job changed" +
				listed(" (not from the job: ", extra) + listed(" (missing: ", missing),
		}, false, nil
	}
	return r.HeadSHA, nil, false, nil
}

// diff returns the paths of got that are not in want, and the paths of want
// that are not in got. Both are sorted.
func diff(got, want []string) (extra, missing []string) {
	g, w := map[string]bool{}, map[string]bool{}
	for _, p := range got {
		g[p] = true
	}
	for _, p := range want {
		w[p] = true
	}
	for p := range g {
		if !w[p] {
			extra = append(extra, p)
		}
	}
	for p := range w {
		if !g[p] {
			missing = append(missing, p)
		}
	}
	slices.Sort(extra)
	slices.Sort(missing)
	return extra, missing
}

func listed(label string, paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	if len(paths) > 5 {
		paths = append(paths[:5:5], "...")
	}
	return label + strings.Join(paths, ", ") + ")"
}

func request(id, mergeRequest, head string) (*structpb.Struct, error) {
	in, err := structpb.NewStruct(map[string]any{
		"id":   id,
		"args": map[string]any{"merge_request": mergeRequest, "expected_head_sha": head},
	})
	if err != nil {
		return nil, fmt.Errorf("merge: build the request: %w", err)
	}
	return in, nil
}

// changedFile is one entry of changed_files. The entry also holds change and
// blob_sha. The agent reads them when the job record gives the blob ids of its
// files.
type changedFile struct {
	Path         string `json:"path"`
	PreviousPath string `json:"previous_path"`
}

// paths returns the paths of the list. A renamed file counts under its new and
// its old path, so a rename that the job did not make shows as a difference.
func paths(files []changedFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
		if f.PreviousPath != "" {
			out = append(out, f.PreviousPath)
		}
	}
	return out
}

// toolResult is the result object of a connector tool.
type toolResult struct {
	Merged  bool   `json:"merged"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
	HeadSHA string `json:"head_sha"`
	// ChangedFiles lists the files that the merge request changes. The tool
	// merge_request_state returns it in the connectors change that adds
	// changed_files. The list holds no file content.
	ChangedFiles []changedFile `json:"changed_files"`
	// Truncated is true when the host gave only a part of the list. The two
	// names are the two places that the contract can put the flag.
	Truncated      bool `json:"truncated"`
	TruncatedFiles bool `json:"changed_files_truncated"`
}

// result reads the result object of an invoke_tool answer. An answer with no
// result object is an error: the agent cannot tell what the daemon did, so it
// does not ask again.
func result(out *structpb.Struct) (toolResult, error) {
	v, ok := out.GetFields()["result"]
	if !ok || v.GetStructValue() == nil {
		return toolResult{}, errors.New("merge: the answer of invoke_tool has no result object")
	}
	raw, err := protojson.Marshal(v.GetStructValue())
	if err != nil {
		return toolResult{}, fmt.Errorf("merge: read the result of the tool: %w", err)
	}
	var r toolResult
	if err := json.Unmarshal(raw, &r); err != nil {
		return toolResult{}, fmt.Errorf("merge: read the result of the tool: %w", err)
	}
	return r, nil
}

// judge reads one answer of invoke_tool. again is true when the same call can
// succeed later: the slot is not granted yet, a check of the daemon failed for
// now, or the host has not settled the merge status. A non-nil error means that
// the call did not reach the daemon, or that the answer is not usable.
func judge(out *structpb.Struct, err error, head string) (m fix.Merge, again bool, _ error) {
	if err != nil {
		return refusal(err)
	}
	r, rerr := result(out)
	if rerr != nil {
		return fix.Merge{}, false, rerr
	}
	switch {
	case r.Merged:
		return fix.Merge{State: fix.MergeDone}, false, nil
	case r.HeadSHA != "" && !strings.EqualFold(r.HeadSHA, head):
		return fix.Merge{
			State:  fix.MergeHeadMoved,
			Reason: "the head of the merge request moved from " + head + " to " + r.HeadSHA + ", so the agent did not merge it",
		}, false, nil
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
	case strings.Contains(msg, textPending), strings.Contains(msg, textAudit), strings.Contains(msg, textMergeCheck):
		// These refusals pass with time. Call again inside the Wait bound.
		return fix.Merge{State: fix.MergeWaiting, Reason: "the daemon could not allow the call now: " + msg}, true, nil
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
