// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package merge_test

import (
	"context"
	"errors"
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
	calls      int
	got        []map[string]any
	transport  error
}

func (g *gate) CallToolProto(_ context.Context, name string, req, resp protolib.Message, _ ...agent.ToolCallOption) error {
	g.calls++
	if g.transport != nil {
		return g.transport
	}
	in, _ := req.(*structpb.Struct)
	if name != "invoke_tool" || in == nil {
		return errors.New("unexpected call " + name)
	}
	g.got = append(g.got, in.AsMap())
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
		return err
	}
	protolib.Merge(resp, out)
	return nil
}

var (
	repo     = fix.Repository{ConnectorRef: "connector/github-acme", Project: "acme/portal"}
	delivery = fix.Delivery{Status: fix.StatusFixing, MissionID: "mis-1", MergeRequest: "acme/portal#7"}
	fast     = merge.Config{Wait: time.Minute, Poll: time.Millisecond}
)

func run(t *testing.T, g *gate, cfg merge.Config, d fix.Delivery) (fix.Merge, error) {
	t.Helper()
	m, err := merge.New(g, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m.Merge(context.Background(), repo, d)
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
	for ref, want := range map[string]string{
		"connector/gitlab-acme": "mcp:gitlab-acme:merge_merge_request",
		" connector/github-x ":  "mcp:github-x:merge_merge_request",
		"github-bare":           "mcp:github-bare:merge_merge_request",
	} {
		if got, err := merge.ToolID(ref); err != nil || got != want {
			t.Errorf("ToolID(%q) = %q, %v, want %q", ref, got, err, want)
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
