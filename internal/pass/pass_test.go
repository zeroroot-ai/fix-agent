// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pass_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/zeroroot-ai/fix-agent/internal/emit"
	"github.com/zeroroot-ai/fix-agent/internal/pass"
	"github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/mission"
)

// fakePlatform is the harness callback client of a test. Nothing here touches
// a daemon or the network.
type fakePlatform struct {
	findings []agent.ApplicationFinding
	readErr  error

	created []any
	result  *mission.MissionResult
	runs    int

	observed []agent.Observation
}

func (f *fakePlatform) ApplicationFindings(_ context.Context, _ string, _ []string, _ int) ([]agent.ApplicationFinding, error) {
	return f.findings, f.readErr
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
	return f.result, nil
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
		{FindingID: "low", VulnerabilityID: "CVE-2026-2", Priority: "P4", PlaceLabel: "Package"},
		{FindingID: "top", VulnerabilityID: "CVE-2026-1", Priority: "P1", PlaceLabel: "Package"},
	}
}

func mrResult() *mission.MissionResult {
	return &mission.MissionResult{Status: mission.MissionStatusCompleted, Output: map[string]any{
		"deliverables": []any{map[string]any{"kind": "DELIVERABLE_KIND_MERGE_REQUEST", "ref": "acme/portal!7", "url": "https://git.example/mr/7"}},
	}}
}

func TestRun_FixesTheHighestPriorityAndReportsTheMergeRequest(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: mrResult()}
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
	if len(res.Findings) != 1 || res.Findings[0] != "top" {
		t.Errorf("findings = %v, want [top]", res.Findings)
	}
	if res.Metadata["merge_request"] != "acme/portal!7" {
		t.Errorf("metadata = %v", res.Metadata)
	}
	out, _ := res.Output.(string)
	if strings.Contains(strings.ToLower(out), "fixed") && !strings.Contains(out, "not fixed") {
		t.Errorf("the report says a fix worked, and the agent does not know that:\n%s", out)
	}
	if !strings.Contains(out, "merge request open for top") {
		t.Errorf("report lacks the merge request:\n%s", out)
	}
	if len(p.observed) != 0 {
		t.Errorf("wrote %d observations, want none: the daemon sets the status", len(p.observed))
	}
}

func TestRun_NoRepositoryWritesAReasonOnEachFindingAndOpensNoJob(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: mrResult()}
	res, err := pass.Run(context.Background(), p, task(map[string]any{"application": "portal", "bank": "bank-1"}))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(p.created) != 0 {
		t.Fatalf("opened %d coding jobs with no repository", len(p.created))
	}
	if len(p.observed) != 2 {
		t.Fatalf("wrote %d reasons, want 2", len(p.observed))
	}
	l := p.observed[0].(agent.LifecycleEntityObservation)
	if l.Properties[emit.PropReason] == "" {
		t.Errorf("no reason in %v", l.Properties)
	}
	if res.Status != a2a.TaskStateCompleted || len(res.Findings) != 0 {
		t.Errorf("result = %+v, want completed with no finding", res)
	}
	if !strings.Contains(res.Output.(string), "no merge request opened") {
		t.Errorf("report = %q", res.Output)
	}
}

func TestRun_AJobWithNoMergeRequestWritesAReasonAndGoesOn(t *testing.T) {
	p := &fakePlatform{findings: openFindings(), result: &mission.MissionResult{Status: mission.MissionStatusFailed, Error: "tests red"}}
	res, err := pass.Run(context.Background(), p, task(fullContext()))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(p.created) != 2 {
		t.Errorf("coding jobs = %d, want 2: the pass goes on to the next finding", len(p.created))
	}
	if len(p.observed) != 2 {
		t.Errorf("reasons = %d, want 2", len(p.observed))
	}
	if res.Status != a2a.TaskStateCompleted {
		t.Errorf("status = %v", res.Status)
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
	p := &fakePlatform{findings: openFindings(), result: mrResult()}
	res, err := pass.Run(context.Background(), p, task(c))
	if err != nil || len(res.Findings) != 1 || res.Findings[0] != "low" {
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
	if r := pass.RepositoryOf(task(map[string]any{"application": "a"})); r != nil {
		t.Errorf("got %+v, want nil when the dispatch names no repository", r)
	}
	r := pass.RepositoryOf(task(map[string]any{"connector": "connector/x", "project": "g/r", "base_branch": "dev", "repository": "r"}))
	if r == nil || r.ConnectorRef != "connector/x" || r.Project != "g/r" || r.BaseBranch != "dev" || r.Name != "r" {
		t.Errorf("got %+v", r)
	}
}
