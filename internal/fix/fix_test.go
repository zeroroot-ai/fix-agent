// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fix_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroroot-ai/fix-agent/internal/fix"
)

type fakeReader struct {
	findings []fix.Finding
	err      error
}

func (r fakeReader) OpenFindings(context.Context, string) ([]fix.Finding, error) {
	return r.findings, r.err
}

// fakeCoder answers by finding id. A finding with no entry gets a merge
// request named after it.
type fakeCoder struct {
	errs  map[string]error
	asked []string
}

func (c *fakeCoder) Fix(_ context.Context, f fix.Finding, _ fix.Repository) (fix.Delivery, error) {
	c.asked = append(c.asked, f.ID)
	if err := c.errs[f.ID]; err != nil {
		return fix.Delivery{}, err
	}
	return fix.Delivery{Status: fix.StatusFixing, MissionID: "mis-" + f.ID}, nil
}

type fakeEmitter struct {
	reasons map[string]string
	err     error
}

func (e *fakeEmitter) Unfixed(_ context.Context, f fix.Finding, reason string) error {
	if e.err != nil {
		return e.err
	}
	if e.reasons == nil {
		e.reasons = map[string]string{}
	}
	e.reasons[f.ID] = reason
	return nil
}

var repo = fix.Repository{ConnectorRef: "connector/gitlab-acme", Project: "acme/portal"}

func finding(id, prio string) fix.Finding {
	return fix.Finding{ID: id, Priority: prio, Vulnerability: "CVE-2026-0001", PlaceLabel: "Package", PlaceKey: "libx"}
}

func TestRank_HighestPriorityFirstAndUnrankedLast(t *testing.T) {
	got := fix.Rank([]fix.Finding{
		finding("f5", ""), finding("f3", "P3"), finding("f2b", "p2"), finding("f1", "P1"), finding("f2a", "P2"), finding("f4", "P4"),
	})
	ids := make([]string, 0, len(got))
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if want := "f1 f2a f2b f3 f4 f5"; strings.Join(ids, " ") != want {
		t.Fatalf("order = %v, want %s", ids, want)
	}
}

func TestRank_DoesNotChangeTheInput(t *testing.T) {
	in := []fix.Finding{finding("b", "P2"), finding("a", "P1")}
	fix.Rank(in)
	if in[0].ID != "b" {
		t.Fatalf("Rank reordered its input: %v", in)
	}
}

func TestPass_FixesTheHighestPriorityFirst(t *testing.T) {
	coder, em := &fakeCoder{}, &fakeEmitter{}
	sum, err := fix.Pass(context.Background(), "app", repo, "",
		fakeReader{findings: []fix.Finding{finding("low", "P4"), finding("top", "P1"), finding("mid", "P2")}}, coder, em)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if sum.Delivered == nil || sum.Delivered.ID != "top" || sum.Delivery.MissionID != "mis-top" {
		t.Fatalf("delivered = %+v %+v, want top from mis-top", sum.Delivered, sum.Delivery)
	}
	if len(coder.asked) != 1 {
		t.Fatalf("coding jobs = %v, want exactly one: one dispatch fixes one finding", coder.asked)
	}
	if sum.Total != 3 {
		t.Errorf("Total = %d, want 3", sum.Total)
	}
}

func TestPass_ANamedFindingIsTheOnlyOneFixed(t *testing.T) {
	coder := &fakeCoder{}
	sum, err := fix.Pass(context.Background(), "app", repo, "mid",
		fakeReader{findings: []fix.Finding{finding("top", "P1"), finding("mid", "P2")}}, coder, &fakeEmitter{})
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if sum.Delivered == nil || sum.Delivered.ID != "mid" {
		t.Fatalf("delivered = %+v, want mid", sum.Delivered)
	}
}

func TestPass_ANamedFindingThatIsNotOpenFails(t *testing.T) {
	_, err := fix.Pass(context.Background(), "app", repo, "gone",
		fakeReader{findings: []fix.Finding{finding("top", "P1")}}, &fakeCoder{}, &fakeEmitter{})
	if err == nil || !strings.Contains(err.Error(), "gone") {
		t.Fatalf("err = %v, want an error that names the finding", err)
	}
}

func TestPass_AFindingThatCannotBeFixedGetsAReasonAndThePassGoesOn(t *testing.T) {
	host := finding("host", "P1")
	host.PlaceLabel = "Host"
	coder, em := &fakeCoder{}, &fakeEmitter{}
	sum, err := fix.Pass(context.Background(), "app", repo, "",
		fakeReader{findings: []fix.Finding{host, finding("pkg", "P2")}}, coder, em)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if !strings.Contains(em.reasons["host"], "patch") {
		t.Errorf("reason for host = %q, want a reason that names the patch connector", em.reasons["host"])
	}
	if sum.Delivered == nil || sum.Delivered.ID != "pkg" {
		t.Fatalf("delivered = %+v, want pkg: the pass must go on after a Finding it cannot fix", sum.Delivered)
	}
	if len(sum.Skipped) != 1 || sum.Skipped[0].Finding.ID != "host" {
		t.Errorf("skipped = %+v, want only host", sum.Skipped)
	}
}

func TestPass_TheNumberOfCodingJobsIsBounded(t *testing.T) {
	fail := fmt.Errorf("no: %w", fix.ErrRetry)
	errs := map[string]error{}
	in := make([]fix.Finding, 0, 10)
	for i := range 10 {
		id := fmt.Sprintf("f%02d", i)
		in = append(in, finding(id, "P2"))
		errs[id] = fail
	}
	coder := &fakeCoder{errs: errs}
	sum, err := fix.Pass(context.Background(), "app", repo, "", fakeReader{findings: in}, coder, &fakeEmitter{})
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if len(coder.asked) != fix.MaxAttempts || sum.Delivered != nil {
		t.Fatalf("jobs = %d delivered = %v, want %d jobs and no delivery", len(coder.asked), sum.Delivered, fix.MaxAttempts)
	}
}

func TestPass_AFailedCallStopsThePass(t *testing.T) {
	boom := errors.New("daemon down")
	coder := &fakeCoder{errs: map[string]error{"a": boom}}
	_, err := fix.Pass(context.Background(), "app", repo, "",
		fakeReader{findings: []fix.Finding{finding("a", "P1"), finding("b", "P2")}}, coder, &fakeEmitter{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the daemon error: a failed call is not a Finding that cannot be fixed", err)
	}
	if len(coder.asked) != 1 {
		t.Errorf("coding jobs = %v, want the pass to stop after the failure", coder.asked)
	}
}

func TestPass_AFailedReadIsAnErrorAndNotAnEmptyPass(t *testing.T) {
	boom := errors.New("graph unavailable")
	_, err := fix.Pass(context.Background(), "app", repo, "", fakeReader{err: boom}, &fakeCoder{}, &fakeEmitter{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the read error", err)
	}
}

func TestPass_AFailedReasonWriteIsAnError(t *testing.T) {
	boom := errors.New("observe failed")
	host := finding("a", "P1")
	host.PlaceLabel = "Host"
	_, err := fix.Pass(context.Background(), "app", repo, "",
		fakeReader{findings: []fix.Finding{host}}, &fakeCoder{}, &fakeEmitter{err: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the write error: a reason that went nowhere must not pass as success", err)
	}
}

func TestPass_AMissionThatDidNotCompleteWritesNoReason(t *testing.T) {
	coder := &fakeCoder{errs: map[string]error{"a": fmt.Errorf("mission ended as failed: %w", fix.ErrRetry)}}
	em := &fakeEmitter{}
	sum, err := fix.Pass(context.Background(), "app", repo, "",
		fakeReader{findings: []fix.Finding{finding("a", "P1"), finding("b", "P2")}}, coder, em)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if r, ok := em.reasons["a"]; ok {
		t.Errorf("a temporary fault wrote the permanent reason %q, so the next pass never tries a again", r)
	}
	if len(sum.Deferred) != 1 || sum.Deferred[0].Finding.ID != "a" || len(sum.Skipped) != 0 {
		t.Errorf("deferred %+v skipped %+v, want a deferred and nothing skipped", sum.Deferred, sum.Skipped)
	}
	if sum.Delivered == nil || sum.Delivered.ID != "b" || sum.Attempts != 2 {
		t.Fatalf("delivered %+v attempts %d, want b after 2 jobs", sum.Delivered, sum.Attempts)
	}
}

func TestPass_NothingOpenIsACleanEmptyPass(t *testing.T) {
	sum, err := fix.Pass(context.Background(), "app", repo, "", fakeReader{}, &fakeCoder{}, &fakeEmitter{})
	if err != nil || sum.Total != 0 || sum.Delivered != nil {
		t.Fatalf("sum = %+v err = %v, want an empty pass", sum, err)
	}
}

func TestPass_ACanceledContextStopsThePass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fix.Pass(ctx, "app", repo, "", fakeReader{findings: []fix.Finding{finding("a", "P1")}}, &fakeCoder{}, &fakeEmitter{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestDecide(t *testing.T) {
	for _, tc := range []struct {
		name    string
		f       fix.Finding
		fixable bool
		reason  string
	}{
		{"package", finding("a", "P1"), true, ""},
		{"host place", fix.Finding{ID: "a", Vulnerability: "CVE-1", PlaceLabel: "Host"}, false, "patch"},
		{"service place in other case", fix.Finding{ID: "a", Vulnerability: "CVE-1", PlaceLabel: " service "}, false, "patch"},
		{"no weakness and no place", fix.Finding{ID: "a"}, false, "nothing to start from"},
		{"place only", fix.Finding{ID: "a", PlaceKey: "repo/x"}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := fix.Decide(tc.f)
			if v.Fixable != tc.fixable {
				t.Fatalf("Fixable = %v, want %v (%s)", v.Fixable, tc.fixable, v.Reason)
			}
			if !strings.Contains(v.Reason, tc.reason) {
				t.Errorf("Reason = %q, want it to contain %q", v.Reason, tc.reason)
			}
			if tc.fixable && v.Reason != "" {
				t.Errorf("a fixable finding has the reason %q", v.Reason)
			}
		})
	}
}

func TestPass_AFindingWithAnOldReasonStartsNoCodingJob(t *testing.T) {
	blocked := finding("top", "P1")
	blocked.BlockedReason = "the flaw is on a host"
	coder, em := &fakeCoder{}, &fakeEmitter{}
	sum, err := fix.Pass(context.Background(), "app", repo, "",
		fakeReader{findings: []fix.Finding{blocked, finding("next", "P2")}}, coder, em)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if len(coder.asked) != 1 || coder.asked[0] != "next" {
		t.Fatalf("coding jobs = %v, want one for next and none for the blocked top", coder.asked)
	}
	if len(sum.Blocked) != 1 || sum.Blocked[0].Finding.ID != "top" || sum.Blocked[0].Reason != "the flaw is on a host" {
		t.Errorf("blocked = %+v, want top with its old reason", sum.Blocked)
	}
	if len(em.reasons) != 0 {
		t.Errorf("wrote reasons %v, want none: the reason is on the finding already", em.reasons)
	}
}

func TestPass_BlockedFindingsDoNotUseTheAttemptBudget(t *testing.T) {
	var in []fix.Finding
	for i := range fix.MaxAttempts + 2 {
		f := finding(string(rune('a'+i)), "P1")
		f.BlockedReason = "old"
		in = append(in, f)
	}
	in = append(in, finding("z", "P4"))
	coder := &fakeCoder{}
	sum, err := fix.Pass(context.Background(), "app", repo, "", fakeReader{findings: in}, coder, &fakeEmitter{})
	if err != nil || sum.Delivered == nil || sum.Delivered.ID != "z" || len(sum.Blocked) != fix.MaxAttempts+2 {
		t.Fatalf("err %v delivered %+v blocked %d, want z delivered after every blocked finding", err, sum.Delivered, len(sum.Blocked))
	}
}

func TestPass_ANamedFindingIgnoresAnOldReason(t *testing.T) {
	blocked := finding("top", "P1")
	blocked.BlockedReason = "old"
	coder := &fakeCoder{}
	sum, err := fix.Pass(context.Background(), "app", repo, "top", fakeReader{findings: []fix.Finding{blocked}}, coder, &fakeEmitter{})
	if err != nil || sum.Delivered == nil || len(sum.Blocked) != 0 {
		t.Fatalf("err %v delivered %+v blocked %v, want the named finding fixed", err, sum.Delivered, sum.Blocked)
	}
}
