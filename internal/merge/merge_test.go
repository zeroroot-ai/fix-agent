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
	// filesErr is changed_files_error of the state.
	filesErr string
	// readTransient is the refusal text for the first readTransientN reads.
	readTransient  string
	readTransientN int
	// readCode is the code of that refusal. Empty means unavailable.
	readCode string
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
			return &agent.ToolCallError{Code: orUnavailable(g.readCode), Message: g.readTransient}
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
			if g.filesErr != "" {
				res["changed_files_error"] = g.filesErr
			}
			if g.truncated {
				res["changed_files_truncated"] = true
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
		return &agent.ToolCallError{Code: agent.ToolErrUnavailable, Message: g.transient}
	}
	if !g.granted {
		return denied("metatool: not authorized to invoke tool: " + in.AsMap()["id"].(string))
	}
	if g.calls < g.slotAfter {
		return &agent.ToolCallError{Code: agent.ToolErrUnavailable, Message: "metatool: merge not granted yet: " +
			"the merge request waits for its merge slot: acme/portal!7. Do not retry now. Call again after the merge slot is granted."}
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
	return map[string]any{"path": path, "change": change, "blob_sha": "blob-" + path, "mode": "100644"}
}

func denied(msg string) error {
	return &agent.ToolCallError{Code: agent.ToolErrPermissionDenied, Message: msg}
}

func orUnavailable(code string) string {
	if code == "" {
		return agent.ToolErrUnavailable
	}
	return code
}

var (
	repo     = fix.Repository{ConnectorRef: "connector/github-acme", Project: "acme/portal"}
	delivery = fix.Delivery{
		Status: fix.StatusFixing, MissionID: "mis-1", MergeRequest: "acme/portal#7",
		HeadSHA: "h1",
		Files: []fix.File{
			{Path: "a.go", Change: "modified", BlobSHA: "blob-a.go"},
			{Path: "b_test.go", Change: "added", BlobSHA: "blob-b_test.go"},
		},
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
	return denied("metatool: the tool is blocked by mission policy: mcp:x:merge_merge_request")
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
	calls := 0
	m, _ := merge.New(failing{
		err:   &agent.ToolCallError{Code: "ERROR_CODE_INVALID_ARGUMENT", Message: "merge_request must be a pull request URL"},
		calls: &calls,
	}, fast)
	got, err := m.Merge(context.Background(), repo, delivery)
	if err != nil || got.State != fix.MergeRefused || !strings.Contains(got.Reason, "pull request URL") || calls != 1 {
		t.Fatalf("got %+v err %v after %d calls, want refused with the text of the tool after one call", got, err, calls)
	}
}

type failing struct {
	err   error
	calls *int
}

func (f failing) CallToolProto(context.Context, string, protolib.Message, protolib.Message, ...agent.ToolCallOption) error {
	if f.calls != nil {
		*f.calls++
	}
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

func TestMerge_SendsTheRecordedHeadAsExpectedHeadSha(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, head: "abc123"}
	d := delivery
	d.HeadSHA = "abc123"
	if got, err := run(t, g, fast, d); err != nil || got.State != fix.MergeDone {
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

// A person pushed after the daemon linked the merge request. The state shows
// another head than the one that the daemon recorded, so the agent does not ask
// for the merge.
func TestMerge_AHeadThatDiffersFromTheRecordedOneMeansNoMergeCall(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, head: "h2-pushed"}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeHeadMoved || g.calls != 0 || !strings.Contains(got.Reason, "h2-pushed") {
		t.Fatalf("got %+v err %v after %d merge calls, want head_moved and no merge call", got, err, g.calls)
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
	m, _ := merge.New(failing{err: denied("metatool: not authorized to invoke tool: x")}, fast)
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
	if !strings.Contains(got.Reason, "deploy/secrets.yaml is not a file of the fix") {
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

// Until the daemon fills the head and the files, the agent makes no call at all.
func TestMerge_NoRecordFromTheDaemonMeansNoCall(t *testing.T) {
	for name, mod := range map[string]func(*fix.Delivery){
		"no head":  func(d *fix.Delivery) { d.HeadSHA = "" },
		"no files": func(d *fix.Delivery) { d.Files = nil },
		"neither":  func(d *fix.Delivery) { d.HeadSHA, d.Files = "", nil },
	} {
		t.Run(name, func(t *testing.T) {
			g := &gate{granted: true, slotAfter: 1}
			d := delivery
			mod(&d)
			got, err := run(t, g, fast, d)
			if err != nil || got.State != fix.MergeSkipped || g.calls != 0 || g.reads != 0 {
				t.Fatalf("got %+v err %v calls %d reads %d, want skipped with no call", got, err, g.calls, g.reads)
			}
		})
	}
}

func TestMerge_NoChangedFilesFromTheConnectorIsAFinalRefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, noFiles: true}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
	}
}

func TestMerge_ARenameThatTheFixDidNotMakeIsAFinalRefusal(t *testing.T) {
	renamed := file("b_test.go", "renamed")
	renamed["previous_path"] = "internal/old_b_test.go"
	g := &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), renamed}}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
	}
	d := delivery
	d.Files = []fix.File{
		{Path: "a.go", Change: "modified", BlobSHA: "blob-a.go"},
		{Path: "b_test.go", Change: "renamed", PreviousPath: "internal/old_b_test.go", BlobSHA: "blob-b_test.go"},
	}
	g = &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), renamed}}
	if got, err = run(t, g, fast, d); err != nil || got.State != fix.MergeDone {
		t.Fatalf("got %+v err %v, want merged when the fix made the rename", got, err)
	}
}

func TestMerge_ATruncatedListIsAFinalRefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, truncated: true}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "only a part") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
	}
}

func TestMerge_AListThatTheHostDidNotGiveIsAFinalRefusal(t *testing.T) {
	g := &gate{granted: true, slotAfter: 1, filesErr: "the host refused the list"}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "refused the list") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
	}
}

// The path set is the same and the content or the kind of change is not.
func TestMerge_ADifferentBlobOrChangeIsAFinalRefusal(t *testing.T) {
	blob := file("a.go", "modified")
	blob["blob_sha"] = "blob-of-another-content"
	for name, files := range map[string][]any{
		"another blob":   {blob, file("b_test.go", "added")},
		"another change": {file("a.go", "added"), file("b_test.go", "added")},
	} {
		t.Run(name, func(t *testing.T) {
			g := &gate{granted: true, slotAfter: 1, files: files}
			got, err := run(t, g, fast, delivery)
			if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "a.go") {
				t.Fatalf("got %+v err %v after %d merge calls, want foreign_change naming a.go", got, err, g.calls)
			}
		})
	}
}

func TestMerge_AChangeOfModeIsAFinalRefusal(t *testing.T) {
	exec := file("a.go", "modified")
	exec["mode"] = "100755"
	link := file("a.go", "modified")
	link["mode"] = "120000"
	onlyMode := file("c.sh", "mode_changed")
	for name, files := range map[string][]any{
		"an executable file":   {exec, file("b_test.go", "added")},
		"a symbolic link":      {link, file("b_test.go", "added")},
		"a change of the mode": {file("a.go", "modified"), file("b_test.go", "added"), onlyMode},
	} {
		t.Run(name, func(t *testing.T) {
			g := &gate{granted: true, slotAfter: 1, files: files}
			got, err := run(t, g, fast, delivery)
			if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 {
				t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
			}
		})
	}
}

// GitHub gives no mode in the list of files. An empty mode is not a refusal.
func TestMerge_AnEmptyModeIsAccepted(t *testing.T) {
	a, b := file("a.go", "modified"), file("b_test.go", "added")
	delete(a, "mode")
	delete(b, "mode")
	g := &gate{granted: true, slotAfter: 1, files: []any{a, b}}
	if got, err := run(t, g, fast, delivery); err != nil || got.State != fix.MergeDone {
		t.Fatalf("got %+v err %v, want merged", got, err)
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
	g := &gate{granted: true, slotAfter: 1, readTransient: "metatool: not authorized to invoke tool: x", readCode: agent.ToolErrPermissionDenied, readTransientN: 5}
	got, err := run(t, g, fast, delivery)
	if err != nil || got.State != fix.MergeNotAllowed || g.reads != 1 || g.calls != 0 {
		t.Fatalf("got %+v err %v after %d reads, want not_allowed after one read", got, err, g.reads)
	}
}

// An error that is not a ToolCallError did not come from the daemon. It is
// returned, whatever its text says.
func TestMerge_AnErrorThatIsNotAToolCallErrorIsReturned(t *testing.T) {
	for _, text := range []string{"connection refused", "merge not granted yet", "not authorized to invoke tool"} {
		boom := errors.New(text)
		_, err := run(t, &gate{granted: true, transport: boom}, fast, delivery)
		if !errors.Is(err, boom) {
			t.Errorf("%q: err = %v, want the error", text, err)
		}
	}
}

// The code decides and the words do not. The same words with another code do
// not change the outcome.
func TestMerge_TheCodeDecidesAndNotTheText(t *testing.T) {
	m, _ := merge.New(failing{err: &agent.ToolCallError{Code: agent.ToolErrPermissionDenied, Message: "merge not granted yet"}}, fast)
	got, err := m.Merge(context.Background(), repo, delivery)
	if err != nil || got.State != fix.MergeNotAllowed {
		t.Fatalf("got %+v err %v, want not_allowed", got, err)
	}
}

// The rename has the same change and the same blob, and another previous path.
func TestMerge_ARenameFromAnotherPathIsAFinalRefusal(t *testing.T) {
	d := delivery
	d.Files = []fix.File{
		{Path: "a.go", Change: "modified", BlobSHA: "blob-a.go"},
		{Path: "b_test.go", Change: "renamed", PreviousPath: "internal/old_b_test.go", BlobSHA: "blob-b_test.go"},
	}
	other := file("b_test.go", "renamed")
	other["previous_path"] = "internal/another_b_test.go"
	g := &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), other}}
	got, err := run(t, g, fast, d)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "b_test.go differs") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
	}
}

// The path is a file of the fix and the entry is a change of the mode. Every
// other field equals the record, so only the mode rule can refuse it.
func TestMerge_AModeChangeOnAPathOfTheFixIsAFinalRefusal(t *testing.T) {
	d := delivery
	d.Files = []fix.File{
		{Path: "a.go", Change: "mode_changed", BlobSHA: "blob-a.go"},
		{Path: "b_test.go", Change: "added", BlobSHA: "blob-b_test.go"},
	}
	g := &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "mode_changed"), file("b_test.go", "added")}}
	got, err := run(t, g, fast, d)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "a.go changes the mode") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change for the mode change", got, err, g.calls)
	}
}

// A deleted file has no mode at the head. A mode that the host shows for it does
// not refuse the merge.
func TestMerge_ADeletedFileIsMergedWhateverModeTheHostShows(t *testing.T) {
	d := delivery
	d.Files = []fix.File{
		{Path: "a.go", Change: "modified", BlobSHA: "blob-a.go"},
		{Path: "old.go", Change: "deleted"},
	}
	gone := map[string]any{"path": "old.go", "change": "deleted", "blob_sha": "", "mode": "000000"}
	g := &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), gone}}
	if got, err := run(t, g, fast, d); err != nil || got.State != fix.MergeDone {
		t.Fatalf("got %+v err %v, want merged", got, err)
	}
	// The same entry for a file that is not deleted is a refusal.
	d.Files[1] = fix.File{Path: "old.go", Change: "modified"}
	gone["change"] = "modified"
	g = &gate{granted: true, slotAfter: 1, files: []any{file("a.go", "modified"), gone}}
	if got, err := run(t, g, fast, d); err != nil || got.State != fix.MergeForeignChange {
		t.Fatalf("got %+v err %v, want foreign_change for the mode 000000", got, err)
	}
}

// When the daemon records a mode and the host gives one, they must be equal.
func TestMerge_AModeThatDiffersFromTheRecordedModeIsAFinalRefusal(t *testing.T) {
	d := delivery
	d.Files = []fix.File{
		{Path: "a.go", Change: "modified", BlobSHA: "blob-a.go", Mode: "100755"},
		{Path: "b_test.go", Change: "added", BlobSHA: "blob-b_test.go", Mode: "100644"},
	}
	// The host shows 100644 for a.go, and the daemon recorded 100755.
	g := &gate{granted: true, slotAfter: 1}
	got, err := run(t, g, fast, d)
	if err != nil || got.State != fix.MergeForeignChange || g.calls != 0 || !strings.Contains(got.Reason, "recorded 100755") {
		t.Fatalf("got %+v err %v after %d merge calls, want foreign_change", got, err, g.calls)
	}
	// The recorded mode that equals the mode of the host is not a refusal.
	d.Files[0].Mode = "100644"
	g = &gate{granted: true, slotAfter: 1}
	if got, err = run(t, g, fast, d); err != nil || got.State != fix.MergeDone {
		t.Fatalf("got %+v err %v, want merged", got, err)
	}
}

// hang blocks until its context ends, as a call that never answers.
type hang struct{ calls *int }

func (h hang) CallToolProto(ctx context.Context, _ string, _, _ protolib.Message, _ ...agent.ToolCallOption) error {
	*h.calls++
	<-ctx.Done()
	return fmt.Errorf("hung call: %w", ctx.Err())
}

// A call that never answers ends at its own bound, and the step ends inside
// merge_wait with the merge request open.
func TestMerge_AHungCallEndsAtItsOwnBoundInsideTheWait(t *testing.T) {
	calls := 0
	m, _ := merge.New(hang{calls: &calls}, merge.Config{Wait: 200 * time.Millisecond, Poll: time.Millisecond, CallTimeout: 20 * time.Millisecond})
	start := time.Now()
	got, err := m.Merge(context.Background(), repo, delivery)
	if err != nil || got.State != fix.MergeWaiting || calls < 2 {
		t.Fatalf("got %+v err %v after %d calls, want waiting after more than one call", got, err, calls)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the step took %v, want it to end inside the wait", d)
	}
}

// The call bound is never longer than what is left of the wait.
func TestMerge_ACallBoundDoesNotOutliveTheWait(t *testing.T) {
	calls := 0
	m, _ := merge.New(hang{calls: &calls}, merge.Config{Wait: 50 * time.Millisecond, Poll: time.Millisecond, CallTimeout: time.Hour})
	start := time.Now()
	if got, err := m.Merge(context.Background(), repo, delivery); err != nil || got.State != fix.MergeWaiting {
		t.Fatalf("got %+v err %v, want waiting", got, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the step took %v, want it to end with the wait of 50 ms", d)
	}
}
