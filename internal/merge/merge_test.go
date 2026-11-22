// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package merge_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/fix-agent/internal/fix"
	"github.com/zeroroot-ai/fix-agent/internal/merge"
	"github.com/zeroroot-ai/sdk/agent"
	protolib "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// gate is the invoke_tool of the daemon, reduced to the two checks that decide
// a merge (gibson internal/engine/metatool): the can_execute check of the
// grant, then the merge slot of the World. The texts are the texts of the
// daemon.
type gate struct {
	granted    bool // the agent holds can_execute on the connector
	slotAfter  int  // the slot is granted from this call on (1 is the first call)
	hostAnswer map[string]any
	// calls counts the merge calls. reads counts the reads of the state.
	calls, reads int
	got          []map[string]any
	transport    error

	// head is the head_sha that merge_request_state returns. Empty with
	// noHead false means "h1".
	head   string
	noHead bool
	// files is changed_files of the state. Nil means the two paths of the job.
	// noFiles leaves the key out.
	files     []any
	noFiles   bool
	truncated bool
	// readTransient is the refusal text for the first readTransientN reads.
	readTransient  string
	readTransientN int
	// transient is the refusal text for the first transientN merge calls.
	transient  string
	transientN int
	// emptyReply makes the merge call answer with no result object.
	emptyReply bool
}

func (g *gate) CallToolProto(_ context.Context, name string, req, resp protolib.Message, _ ...agent.ToolCallOption) error {
	if g.transport != nil {
		return g.transport
	}
	in, _ := req.(*structpb.Struct)
	if name != "invoke_tool" || in == nil {
		return errors.New("unexpected call " + name)
	}
	if id, _ := in.AsMap()["id"].(string); strings.HasSuffix(id, ":merge_request_state") {
		g.reads++
		if g.reads <= g.readTransientN {
			return errors.New(g.readTransient)
		}
		head := g.head
		if head == "" {
			head = "h1"
		}
		res := map[string]any{"state": "open"}
		if !g.noHead {
			res["head_sha"] = head
		}
		if !g.noFiles {
			files := g.files
			if files == nil {
				files = []any{file("a.go", "modified"), file("b_test.go", "added")}
			}
			res["changed_files"] = files
			if g.truncated {
				res["truncated"] = true
			}
		}
		out, err := structpb.NewStruct(map[string]any{"result": res})
		if err != nil {
			return fmt.Errorf("build the answer: %w", err)
		}
		protolib.Merge(resp, out)
		return nil
	}
	g.calls++
	g.got = append(g.got, in.AsMap())
	if g.emptyReply {
		return nil
	}
	if g.calls <= g.transientN {
		return errors.New(g.transient)
	}
	if !g.granted {
		return errors.New("CallToolProto error: metatool: not authorized to invoke tool: " + in.AsMap()["id"].(string))
	}
	if g.calls < g.slotAfter {
		return errors.New("CallToolProto error: metatool: merge not granted yet: the merge request waits for its merge slot: " +
			"acme/portal!7. Do not retry now. Call again after the merge slot is granted.")
	}
	answer := g.hostAnswer
	if answer == nil {
		answer = map[string]any{"state": "merged", "merged": true}
	}
	out, err := structpb.NewStruct(map[string]any{"result": answer})
	if err != nil {
		return fmt.Errorf("build the answer: %w", err)
	}
	protolib.Merge(resp, out)
	return nil
}

// file is one entry of changed_files, in the shape of the connector.
func file(path, change string) map[string]any {
	return map[string]any{"path": path, "change": change, "blob_sha": "blob-" + path}
}

var (
	repo     = fix.Repository{ConnectorRef: "connector/github-acme", Project: "acme/portal"}
	delivery = fix.Delivery{
		Status: fix.StatusFixing, MissionID: "mis-1", MergeRequest: "acme/portal#7",
		ChangedFiles: []string{"b_test.go", "a.go"},
	}
	fast = merge.Config{Wait: time.Minute, Poll: time.Millisecond}
)

func run(t *testing.T, g *gate, cfg merge.Config, d fix.Delivery) (fix.Merge, error) {
	t.Helper()
	m, err := merge.New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := m.Merge(context.Background(), repo, d)
	if err != nil {
		return got, fmt.Errorf("merge: %w", err)
	}
	return got, nil
}

func TestMerge_MergesWhenTheSlotIsGrantedAndNeedsNoPerson(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeDone {
		t.Fatalf("got %+v err %v, want merged", got, err)
	}
	args, _ := g.got[0]["args"].(map[string]any)
	if g.got[0]["id"] != "mcp:github-acme:merge_merge_request" || args["merge_request"] != "acme/portal#7" {
		t.Errorf("request = %v", g.got[0])
	}
}

func TestMerge_WaitsForTheSlotAndCallsAgain(t *testing.T) {
	g := &gate{granted: true, slotAfter: 4}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeDone || g.calls != 4 {
		t.Fatalf("got %+v err %v after %d calls, want merged on the fourth call", got, err, g.calls)
	}
}

func TestMerge_ASlotThatIsNeverGrantedLeavesTheMergeRequestOpen(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1 << 30}
	got, err := run(t, g, merge.Config{Wait: 30 * time.Millisecond, Poll: 5 * time.Millisecond}, delivery)
	if err != nil || got.State != fix.MergeWaiting || g.calls < 2 {
		t.Fatalf("got %+v err %v after %d calls, want waiting after more than one call", got, err, g.calls)
	}
}

func TestMerge_NoMergeGrantIsARefusalAndNotARetry(t *testing.T) {
	g := &gate{granted: false}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeNotAllowed || g.calls != 1 {
		t.Fatalf("got %+v err %v after %d calls, want not_allowed after one call", got, err, g.calls)
	}
}

func TestMerge_ABlockedToolIsARefusalAndNotARetry(t *testing.T) {
	g := &gate{}
	m, _ := merge.New(blocked{g}, fast)
	got, err := m.Merge(context.Background(), repo, delivery)
	if err != nil || got.State != fix.MergeNotAllowed {
		t.Fatalf("got %+v err %v, want not_allowed", got, err)
	}
}

type blocked struct{ *gate }

func (b blocked) CallToolProto(context.Context, string, protolib.Message, protolib.Message, ...agent.ToolCallOption) error {
	return errors.New("CallToolProto error: metatool: the tool is blocked by mission policy: mcp:x:merge_merge_request")
}

func TestMerge_TheHostResultDecides(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer map[string]any
		want   fix.MergeState
		reason string
	}{
		{"refused by the branch protection", map[string]any{"state": "refused", "merged": false, "reason": "a review is required"},
			fix.MergeRefused, "a review is required"},
		{"closed", map[string]any{"state": "closed", "merged": false}, fix.MergeRefused, "closed"},
		{"already merged", map[string]any{"state": "merged", "merged": true}, fix.MergeDone, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &gate{granted: true, slotAfter: 1, hostAnswer: tc.answer}
			got, err := run(t, g, fast, delivery)
			if err != nil || got.State != tc.want || !strings.Contains(got.Reason, tc.reason) || g.calls != 1 {
				t.Fatalf("got %+v err %v after %d calls, want %s with %q after one call", got, err, g.calls, tc.want, tc.reason)
			}
		})
	}
}

func TestMerge_AnOpenMergeRequestThatTheHostHasNotSettledIsCalledAgain(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, hostAnswer: map[string]any{
		"state": "open", "merged": false, "reason": "GitHub has not settled the merge status: unknown",
	}}
	got, err := run(t, g, merge.Config{Wait: 30 * time.Millisecond, Poll: 5 * time.Millisecond}, delivery)
	if err != nil || got.State != fix.MergeWaiting || g.calls < 2 || !strings.Contains(got.Reason, "not settled") {
		t.Fatalf("got %+v err %v after %d calls, want waiting after more than one call", got, err, g.calls)
	}
}

func TestMerge_AnyOtherToolErrorIsARefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1}
	m, _ := merge.New(failing{errors.New("CallToolProto error: merge_request must be a pull request URL")}, fast)
	got, err := m.Merge(context.Background(), repo, delivery)
	if err != nil || got.State != fix.MergeRefused || !strings.Contains(got.Reason, "pull request URL") {
		t.Fatalf("got %+v err %v (%d calls), want refused with the text of the tool", got, err, g.calls)
	}
}

type failing struct{ err error }

func (f failing) CallToolProto(context.Context, string, protolib.Message, protolib.Message, ...agent.ToolCallOption) error {
	return f.err
}

func TestMerge_ACallThatDoesNotReachTheDaemonIsAnError(t *testing.T) {
	boom := errors.New("CallToolProto callback failed: connection refused")
	_, err := run(t, &gate{granted: true, transport: boom}, fast, delivery)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the transport error", err)
	}
}

func TestMerge_NoKeyMeansNoCall(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1}
	d := delivery
	d.MergeRequest = ""
	got, err := run(t, g, fast, d)
	if err != nil || got.State != fix.MergeSkipped || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d calls, want skipped with no call", got, err, g.calls)
	}
}

func TestMerge_ACanceledContextStopsTheWait(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1 << 30}
	m, _ := merge.New(g, merge.Config{Wait: 2 * time.Hour, Poll: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := m.Merge(ctx, repo, delivery); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context error", err)
	}
}

func TestToolID(t *testing.T) {
	for _, tc := range []struct{ ref, want string }{
		{"connector/gitlab-acme", "mcp:gitlab-acme:merge_merge_request"},
		{" connector/github-x ", "mcp:github-x:merge_merge_request"},
		{"github-bare", "mcp:github-bare:merge_merge_request"},
	} {
		if got, err := merge.ToolID(tc.ref); err != nil || got != tc.want {
			t.Errorf("ToolID(%q) = %q, %v, want %q", tc.ref, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "connector/", "connector/a:b", "connector/a b"} {
		if _, err := merge.ToolID(bad); err == nil {
			t.Errorf("ToolID(%q) accepted", bad)
		}
	}
}

func TestNew_NoCaller(t *testing.T) {
	if _, err := merge.New(nil, merge.Config{}); err == nil {
		t.Fatal("want an error for no caller")
	}
}

func TestMerge_SendsTheHeadThatItReadAsExpectedHeadSha(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, head: "abc123"}
	if got, err := run(t, g, fast, delivery); err != nil || got.State != fix.MergeDone {
		t.Fatalf("got %+v err %v", got, err)
	}
	args, _ := g.got[0]["args"].(map[string]any)
	if g.reads != 1 || args["expected_head_sha"] != "abc123" {
		t.Fatalf("reads %d args %v, want one read and expected_head_sha abc123", g.reads, args)
	}
}

// A person pushes a commit while the agent waits. The host refuses and names
// the new head. The refusal is final: one merge call.
func TestMerge_APushedCommitIsAFinalRefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, head: "h1", hostAnswer: map[string]any{
		"state": "open", "merged": false, "head_sha": "h2-pushed",
		"reason": "the head of the pull request moved: expected h1, now h2-pushed. A push changed it.",
	}}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeHeadMoved || g.calls != 1 || !strings.Contains(got.Reason, "h2-pushed") {
		t.Fatalf("got %+v err %v after %d calls, want head_moved after one call", got, err, g.calls)
	}
}

func TestMerge_NoHeadShaMeansNoMergeCall(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, noHead: true}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeSkipped || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d calls, want skipped with no merge call", got, err, g.calls)
	}
}

func TestMerge_ARefusedStateReadIsAnOutcome(t *testing.T) {
	m, _ := merge.New(failing{errors.New("CallToolProto error: metatool: not authorized to invoke tool: x")}, fast)
	got, err := m.Merge(context.Background(), repo, delivery)
	if err != nil || got.State != fix.MergeNotAllowed {
		t.Fatalf("got %+v err %v, want not_allowed", got, err)
	}
}

// These refusals pass with time. The agent retries them inside the wait.
func TestMerge_RefusalsThatPassWithTimeAreRetried(t *testing.T) {
	for name, text := range map[string]string{
		"audit":   "CallToolProto error: the audit record of the call could not be written",
		"pending": "CallToolProto error: metatool: pending authorization: a person must approve this call before it runs",
		"check":   "CallToolProto error: metatool: the merge check of x:merge_merge_request failed: world unavailable",
	} {
		t.Run(name, func(t *testing.T) {
			g := &gate{granted: true, slotAfter: 1, transient: text, transientN: 3}
			got, err := run(t, g, fast, delivery)
			if err != nil || got.State != fix.MergeDone || g.calls != 4 {
				t.Fatalf("got %+v err %v after %d calls, want merged on the fourth call", got, err, g.calls)
			}
		})
	}
}

func TestMerge_ATransientRefusalThatNeverPassesEndsAsWaiting(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, transient: "CallToolProto error: the audit record of the call could not be written", transientN: 1 << 30}
	got, err := run(t, g, merge.Config{Wait: 40 * time.Millisecond, Poll: 2 * time.Millisecond}, delivery)
	if err != nil || got.State != fix.MergeWaiting {
		t.Fatalf("got %+v err %v, want waiting", got, err)
	}
}

// The wait between two calls grows. With a poll of 4 ms and a wait of 100 ms a
// fixed poll makes about 25 calls, and a growing one makes far fewer.
func TestMerge_TheWaitBetweenCallsGrows(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1 << 30}
	if _, err := run(t, g, merge.Config{Wait: 100 * time.Millisecond, Poll: 4 * time.Millisecond}, delivery); err != nil {
		t.Fatal(err)
	}
	if g.calls > 10 {
		t.Fatalf("calls = %d, want fewer than 10 with a growing wait", g.calls)
	}
}

// An answer with no result object is an error, and the agent does not send the
// call again.
func TestMerge_AnAnswerWithNoResultObjectIsAnErrorAndIsNotResent(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, emptyReply: true}
	_, err := run(t, g, fast, delivery)
	if err == nil || !strings.Contains(err.Error(), "no result object") || g.calls != 1 {
		t.Fatalf("err %v after %d calls, want an error after one call", err, g.calls)
	}
}

// A person committed to the fix branch before the coding job pushed. The head
// pin passes, because the agent reads the head after that commit. The set of
// paths does not equal the set of the job, so the agent does not merge.
func TestMerge_ABranchWithAForeignCommitIsAFinalRefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), file("b_test.go", "added"), file("deploy/secrets.yaml", "modified")}}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change and no merge call", got, err, g.calls)
	}
	if !strings.Contains(got.Reason, "deploy/secrets.yaml") {
		t.Errorf("reason %q does not name the foreign path", got.Reason)
	}
}

func TestMerge_AMissingPathOfTheJobIsAFinalRefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified")}}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "b_test.go") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change naming b_test.go", got, err, g.calls)
	}
}

func TestMerge_NoRecordOfTheJobPathsMeansNoCall(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1}
	d := delivery
	d.ChangedFiles = nil
	got, err := run(t, g, fast, d)
	if err != nil || got.State != fix.MergeSkipped || g.calls != 0 || g.reads != 0 {
		t.Fatalf("got %+v err %v calls %d reads %d, want skipped with no call", got, err, g.calls, g.reads)
	}
}

func TestMerge_NoChangedFilesFromTheConnectorMeansNoMergeCall(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, noFiles: true}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeSkipped || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d merge calls, want skipped", got, err, g.calls)
	}
}

func TestMerge_ARenameThatTheJobDidNotMakeIsAFinalRefusal(t *testing.T) {
	renamed := file("b_test.go", "renamed")
	renamed["previous_path"] = "internal/old_b_test.go"
	g := &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), renamed}}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "internal/old_b_test.go") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change naming the old path", got, err, g.calls)
	}
	d := delivery
	d.ChangedFiles = []string{"a.go", "b_test.go", "internal/old_b_test.go"}
	g = &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), renamed}}
	if got, err = run(t, g, fast, d); err != nil || got.State != fix.MergeDone {
		t.Fatalf("got %+v err %v, want merged when the job made the rename", got, err)
	}
}

func TestMerge_ATruncatedListIsAFinalRefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, truncated: true}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "only a part") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
	}
}

// A refusal of the read of the merge request that passes with time is retried
// inside the wait, as the merge call is.
func TestMerge_ATransientRefusalOfTheReadIsRetried(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, readTransient: "CallToolProto error: the audit record of the call could not be written", readTransientN: 2}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeDone || g.reads != 3 {
		t.Fatalf("got %+v err %v after %d reads, want merged after three reads", got, err, g.reads)
	}
}

func TestMerge_ARealRefusalOfTheReadIsFinal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, readTransient: "CallToolProto error: metatool: not authorized to invoke tool: x", readTransientN: 5}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeNotAllowed || g.reads != 1 || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d reads, want not_allowed after one read", got, err, g.reads)
	}
}
