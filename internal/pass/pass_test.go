// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pass_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/fix-agent/internal/pass"
	"github.com/zeroroot-ai/sdk/agent"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/mission"
	"google.golang.org/protobuf/encoding/protojson"
	protolib "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// fakePlatform is the harness callback client of a test. Nothing here touches
// a daemon or the network.
//
// It answers in the shapes that the daemon uses. ApplicationFindings filters
// on the statuses of the request, as the Cypher read does. WaitForMission
// returns no output, as the callback of the daemon does. When deliver is
// set, the wait moves the Finding of the job to fixing, as the daemon does
// when a job closes with a merge request (gibson job_graph_link.go).
type fakePlatform struct {
	findings []agent.ApplicationFinding
	readErr  error
	reads    int

	created []any
	result  *mission.MissionResult
	deliver bool
	runs    int

	observed []agent.Observation

	// merge is the answer of the daemon to invoke_tool. Nil means that the
	// slot is granted and the host merges. calls are the requests.
	merge func(call int, in *structpb.Struct) (*structpb.Struct, error)
	calls []*structpb.Struct
}

// CallToolProto answers invoke_tool for the merge tool.
func (f *fakePlatform) CallToolProto(_ context.Context, name string, req, resp protolib.Message, _ ...agent.ToolCallOption) error {
	in, _ := req.(*structpb.Struct)
	if name != "invoke_tool" || in == nil {
		return errors.New("unexpected tool " + name)
	}
	f.calls = append(f.calls, in)
	merge := f.merge
	if merge == nil {
		merge = mergedAnswer
	}
	out, err := merge(len(f.calls), in)
	if err != nil {
		return err
	}
	if out != nil {
		protolib.Reset(resp)
		protolib.Merge(resp, out)
	}
	return nil
}

func (f *fakePlatform) ApplicationFindings(_ context.Context, _ string, statuses []string, _ int) ([]agent.ApplicationFinding, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	out := make([]agent.ApplicationFinding, 0, len(f.findings))
	for _, af := range f.findings {
		if len(statuses) == 0 || slices.Contains(statuses, af.Status) {
			out = append(out, af)
		}
	}
	return out, nil
}

func (f *fakePlatform) CreateMission(_ context.Context, def any, _ string, _ *mission.CreateMissionOpts) (*mission.MissionInfo, error) {
	f.created = append(f.created, def)
	return &mission.MissionInfo{ID: "mis-1"}, nil
}

func (f *fakePlatform) RunMission(context.Context, string, *mission.RunMissionOpts) error {
	f.runs++
	return nil
}

func (f *fakePlatform) WaitForMission(context.Context, string, time.Duration) (*mission.MissionResult, error) {
	if f.deliver {
		f.close(f.created[len(f.created)-1])
	}
	return f.result, nil
}

// close sets the input of the job to fixing.
func (f *fakePlatform) close(def any) {
	raw, _ := def.(json.RawMessage)
	var d missionpb.MissionDefinition
	if err := protojson.Unmarshal(raw, &d); err != nil {
		return
	}
	for _, n := range d.GetNodes() {
		for _, id := range n.GetJobConfig().GetSpec().GetInputs() {
			for i := range f.findings {
				if f.findings[i].FindingID == id {
					f.findings[i].Status = "fixing"
				}
			}
		}
	}
}

func (f *fakePlatform) Observe(_ context.Context, obs agent.Observation) error {
	f.observed = append(f.observed, obs)
	return nil
}

func task(ctx map[string]any) agent.Task { return agent.Task{ID: "t-1", Context: ctx} }

func fullContext() map[string]any {
	return map[string]any{
		"application": "portal", "bank": "bank-1",
		"connector": "connector/gitlab-acme", "project": "acme/portal",
	}
}

func openFindings() []agent.ApplicationFinding {
	return []agent.ApplicationFinding{
		{FindingID: "low", Status: "open", VulnerabilityID: "CVE-2026-2", Priority: "P4", PlaceLabel: "Package",
			MergeRequest: "acme/portal!8"},
		{FindingID: "top", Status: "open", VulnerabilityID: "CVE-2026-1", Priority: "P1", PlaceLabel: "Package",
			MergeRequest: "acme/portal!7"},
	}
}

// answer is the reply of invoke_tool with the given result of the tool.
func answer(result map[string]any) (*structpb.Struct, error) {
	out, err := structpb.NewStruct(map[string]any{"result": result})
	if err != nil {
		return nil, fmt.Errorf("build the answer: %w", err)
	}
	return out, nil
}

// mergedAnswer is the result of the merge tool of a connector.
func mergedAnswer(_ int, _ *structpb.Struct) (*structpb.Struct, error) {
	return answer(map[string]any{"merge_request": "acme/portal!7", "state": "merged", "merged": true})
}

func completed() *mission.MissionResult {
	return &mission.MissionResult{MissionID: "mis-1", Status: mission.MissionStatusCompleted, CompletedAt: time.Now()}
}

func TestRun_FixesTheHighestPriorityAndReportsTheMergeRequest(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: completed(), deliver: true, merge: mergedAnswer}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != a2a.TaskStateCompleted {
		t.Errorf("status = %v, want completed", res.Status)
	}
	if len(p.created) != 1 || p.runs != 1 {
		t.Fatalf("missions created %d run %d, want one coding job", len(p.created), p.runs)
	}
	def, merr := json.Marshal(p.created[0])
	if merr != nil || !strings.Contains(string(def), `"top"`) {
		t.Errorf("the coding job is not for the P1 finding: %s (%v)", def, merr)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %v, want none: Result.Findings is for discovered findings", res.Findings)
	}
	if res.Metadata["finding"] != "top" || res.Metadata["finding_status"] != "fixing" || res.Metadata["mission"] != "mis-1" ||
		res.Metadata["merge"] != "merged" {
		t.Errorf("metadata = %v", res.Metadata)
	}
	out, _ := res.Output.(string)
	if strings.Contains(strings.ToLower(out), "fixed") && !strings.Contains(out, "not fixed") {
		t.Errorf("the report says a fix worked, and the agent does not know that:\n%s", out)
	}
	if !strings.Contains(out, "merge request opened for top") || !strings.Contains(out, "merge step: merged") {
		t.Errorf("report lacks the merge request:\n%s", out)
	}
	if len(p.observed) != 0 {
		t.Errorf("wrote %d observations, want none: the daemon sets the status", len(p.observed))
	}
}

// The tests below prove the merge step against the gate of the daemon. The
// fake answers as gibson internal/engine/metatool does: the call reaches the
// connector only when the caller holds the grant and the merge request holds
// its slot. Each refusal text is the text that the daemon returns.

func TestRun_MergesWithNoPersonWhenTheDaemonGrantedTheSlot(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: completed(), deliver: true, merge: mergedAnswer}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Metadata["merge"] != "merged" || len(p.calls) != 1 {
		t.Fatalf("merge %v after %d calls, want merged on the first call", res.Metadata["merge"], len(p.calls))
	}
	last := p.calls[0].AsMap()
	args, _ := last["args"].(map[string]any)
	if last["id"] != "mcp:gitlab-acme:merge_merge_request" || args["merge_request"] != "acme/portal!7" {
		t.Errorf("request = %v, want the merge tool of the connector with the key of the merge request", last)
	}
	if len(p.observed) != 0 {
		t.Errorf("wrote %d observations, want none: the daemon sets the status", len(p.observed))
	}
}

func TestRun_AnAgentWithNoMergeGrantDoesNotMerge(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: completed(), deliver: true}
	p.merge = func(int, *structpb.Struct) (*structpb.Struct, error) {
		return nil, errors.New("CallToolProto error: metatool: not authorized to invoke tool: mcp:gitlab-acme:merge_merge_request")
	}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err != nil {
		t.Fatalf("Run: %v, want a clean pass: a missing grant is not a fault of the run", err)
	}
	if res.Status != a2a.TaskStateCompleted || res.Metadata["merge"] != "not_allowed" || len(p.calls) != 1 {
		t.Fatalf("status %v merge %v calls %d, want completed, not_allowed and one call with no retry",
			res.Status, res.Metadata["merge"], len(p.calls))
	}
	if out, _ := res.Output.(string); !strings.Contains(out, "holds no grant to merge") {
		t.Errorf("report does not say why:\n%s", out)
	}
}

func TestRun_ARefusalOfTheGitHostLeavesTheMergeRequestOpen(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: completed(), deliver: true}
	p.merge = func(int, *structpb.Struct) (*structpb.Struct, error) {
		return answer(map[string]any{
			"state": "refused", "merged": false,
			"reason": "GitHub does not allow the merge: a review is required",
		})
	}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err != nil || res.Metadata["merge"] != "refused" || len(p.calls) != 1 {
		t.Fatalf("res %v err %v calls %d, want refused after one call", res.Metadata, err, len(p.calls))
	}
	if out, _ := res.Output.(string); !strings.Contains(out, "a review is required") {
		t.Errorf("report lacks the reason of the host:\n%s", out)
	}
}

func TestRun_ASlotThatIsNeverGrantedEndsTheWaitWithTheMergeRequestOpen(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: completed(), deliver: true}
	p.merge = func(int, *structpb.Struct) (*structpb.Struct, error) {
		return nil, errors.New("CallToolProto error: metatool: merge not granted yet: the merge request waits for its merge slot")
	}
	c := fullContext()
	c["merge_wait"] = "50ms"
	res, err := pass.Run(context.Background(), p, task(c))
	if err != nil || res.Metadata["merge"] != "waiting" {
		t.Fatalf("res %v err %v, want waiting", res.Metadata, err)
	}
}

func TestRun_NoMergeRequestKeyMeansNoMergeCall(t *testing.T) {
	f := openFindings()
	for i := range f {
		f[i].MergeRequest = "" // a daemon that does not fill the key yet (gibson#1579)
	}
	p := &fakePlatform{findings: f, result: completed(), deliver: true, merge: mergedAnswer}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err != nil || res.Metadata["merge"] != "skipped" || len(p.calls) != 0 {
		t.Fatalf("res %v err %v calls %d, want skipped with no call", res.Metadata, err, len(p.calls))
	}
}

func TestRun_AMergeCallThatDoesNotReachTheDaemonFailsTheRun(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: completed(), deliver: true}
	p.merge = func(int, *structpb.Struct) (*structpb.Struct, error) {
		return nil, errors.New("CallToolProto callback failed: connection refused")
	}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err == nil || res.Status != a2a.TaskStateFailed {
		t.Fatalf("res %v err %v, want a failed run", res.Status, err)
	}
}

func TestRun_ABadMergeWaitFailsTheRun(t *testing.T) {
	c := fullContext()
	c["merge_wait"] = "soon"
	if _, err := pass.Run(context.Background(), &fakePlatform{}, task(c)); err == nil || !strings.Contains(err.Error(), "merge_wait") {
		t.Fatalf("err = %v, want an error that names merge_wait", err)
	}
}

func TestRun_NoRepositoryFailsTheRunAndWritesNoReason(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"none":           {},
		"connector only": {"connector": "connector/gitlab-acme"},
		"project only":   {"project": "acme/portal"},
	} {
		t.Run(name, func(t *testing.T) {
			c := map[string]any{"application": "portal", "bank": "bank-1"}
			for k, v := range extra {
				c[k] = v
			}
			p := &fakePlatform{findings: openFindings(), result: completed()}
			res, err := pass.Run(context.Background(), p, task(c))
			if err == nil || !strings.Contains(err.Error(), "repository") || res.Status != a2a.TaskStateFailed {
				t.Fatalf("res %v err %v, want a failed run that names the repository", res.Status, err)
			}
			if len(p.observed) != 0 || len(p.created) != 0 || p.reads != 0 {
				t.Errorf("observed %d created %d reads %d, want nothing: a fault of the dispatch is not a fact about a Finding",
					len(p.observed), len(p.created), p.reads)
			}
		})
	}
}

func TestRun_AMissionThatDidNotCompleteWritesNoReasonAndGoesOn(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: &mission.MissionResult{
		MissionID: "mis-1", Status: mission.MissionStatusFailed, Error: "sandbox stopped",
	}}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(p.created) != 2 {
		t.Errorf("coding jobs = %d, want 2: the pass goes on to the next finding", len(p.created))
	}
	if len(p.observed) != 0 {
		t.Errorf("reasons = %d, want 0: a temporary fault must not block a Finding", len(p.observed))
	}
	if res.Status != a2a.TaskStateCompleted || !strings.Contains(res.Output.(string), "try again top") {
		t.Errorf("status %v report %q", res.Status, res.Output)
	}
}

func TestRun_AFailedReadFailsTheRun(t *testing.T) {
	boom := errors.New("graph down")
	res, err := pass.Run(context.Background(), &fakePlatform{readErr: boom}, task(fullContext()))
	if !errors.Is(err, boom) || res.Status != a2a.TaskStateFailed {
		t.Fatalf("res %v err %v, want a failed run with the read error", res.Status, err)
	}
}

func TestRun_NoBankFailsTheRun(t *testing.T) {
	c := fullContext()
	delete(c, "bank")
	_, err := pass.Run(context.Background(), &fakePlatform{findings: openFindings()}, task(c))
	if err == nil || !strings.Contains(err.Error(), "bank") {
		t.Fatalf("err = %v, want an error that names the bank", err)
	}
}

func TestRun_ABadTimeoutFailsTheRun(t *testing.T) {
	c := fullContext()
	c["timeout"] = "soon"
	_, err := pass.Run(context.Background(), &fakePlatform{}, task(c))
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("err = %v, want an error that names the timeout", err)
	}
}

func TestRun_NoPlatformFailsTheRun(t *testing.T) {
	if _, err := pass.Run(context.Background(), nil, task(fullContext())); err == nil {
		t.Fatal("want an error for no platform")
	}
}

func TestRun_ANamedFindingIsTheOneFixed(t *testing.T) {
	c := fullContext()
	c["finding"] = "low"
	p := &fakePlatform{findings: openFindings(), result: completed(), deliver: true}
	res, err := pass.Run(context.Background(), p, task(c))
	if err != nil || res.Metadata["finding"] != "low" {
		t.Fatalf("res %+v err %v, want low", res, err)
	}
}

func TestApplicationID(t *testing.T) {
	for _, tc := range []struct {
		name string
		task agent.Task
		want string
		fail bool
	}{
		{"context", agent.Task{Context: map[string]any{"application": " portal "}}, "portal", false},
		{"goal fallback", agent.Task{Goal: " portal "}, "portal", false},
		{"context wins", agent.Task{Goal: "other", Context: map[string]any{"application": "portal"}}, "portal", false},
		{"context of another type", agent.Task{Goal: "g", Context: map[string]any{"application": 5}}, "g", false},
		{"none", agent.Task{}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pass.ApplicationID(tc.task)
			if (err != nil) != tc.fail || got != tc.want {
				t.Fatalf("got %q err %v, want %q fail %v", got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestRepositoryOf(t *testing.T) {
	if r, err := pass.RepositoryOf(task(map[string]any{"application": "a"})); err == nil {
		t.Errorf("got %+v, want an error when the dispatch names no repository", r)
	}
	r, err := pass.RepositoryOf(task(map[string]any{"connector": "connector/x", "project": "g/r", "base_branch": "dev", "repository": "r"}))
	if err != nil || r.ConnectorRef != "connector/x" || r.Project != "g/r" || r.BaseBranch != "dev" || r.Name != "r" {
		t.Errorf("got %+v err %v", r, err)
	}
}
