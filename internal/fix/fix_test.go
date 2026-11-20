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
	return fix.Delivery{MergeRequest: "mr-" + f.ID}, nil
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

var repo = &fix.Repository{ConnectorRef: "connector/gitlab-acme", Project: "acme/portal"}

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
	if sum.Delivered == nil || sum.Delivered.ID != "top" || sum.Delivery.MergeRequest != "mr-top" {
		t.Fatalf("delivered = %+v %+v, want top with mr-top", sum.Delivered, sum.Delivery)
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

func TestPass_ACodingJobWithNoMergeRequestGetsAReasonAndThePassGoesOn(t *testing.T) {
	coder := &fakeCoder{errs: map[string]error{"a": fmt.Errorf("job ended: %w", fix.ErrNoDelivery)}}
	em := &fakeEmitter{}
	sum, err := fix.Pass(context.Background(), "app", repo, "",
		fakeReader{findings: []fix.Finding{finding("a", "P1"), finding("b", "P2")}}, coder, em)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if em.reasons["a"] == "" {
		t.Error("no reason was written on the Finding whose job gave no merge request")
	}
	if sum.Delivered == nil || sum.Delivered.ID != "b" {
		t.Fatalf("delivered = %+v, want b", sum.Delivered)
	}
	if sum.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", sum.Attempts)
	}
}

func TestPass_TheNumberOfCodingJobsIsBounded(t *testing.T) {
	fail := fmt.Errorf("no: %w", fix.ErrNoDelivery)
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
	_, err := fix.Pass(context.Background(), "app", nil, "",
		fakeReader{findings: []fix.Finding{finding("a", "P1")}}, &fakeCoder{}, &fakeEmitter{err: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the write error: a reason that went nowhere must not pass as success", err)
	}
}

func TestPass_NoRepositoryWritesAReasonOnEachFinding(t *testing.T) {
	coder, em := &fakeCoder{}, &fakeEmitter{}
	sum, err := fix.Pass(context.Background(), "app", nil, "",
		fakeReader{findings: []fix.Finding{finding("a", "P1"), finding("b", "P2")}}, coder, em)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if len(coder.asked) != 0 || sum.Delivered != nil {
		t.Fatalf("coding jobs = %v, want none", coder.asked)
	}
	if len(em.reasons) != 2 {
		t.Errorf("reasons = %v, want one for each Finding", em.reasons)
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
		repo    *fix.Repository
		fixable bool
		reason  string
	}{
		{"package with repository", finding("a", "P1"), repo, true, ""},
		{"no repository", finding("a", "P1"), nil, false, "no repository"},
		{"repository without project", finding("a", "P1"), &fix.Repository{ConnectorRef: "connector/x"}, false, "no repository"},
		{"host place", fix.Finding{ID: "a", Vulnerability: "CVE-1", PlaceLabel: "Host"}, repo, false, "patch"},
		{"service place in other case", fix.Finding{ID: "a", Vulnerability: "CVE-1", PlaceLabel: " service "}, repo, false, "patch"},
		{"no weakness and no place", fix.Finding{ID: "a"}, repo, false, "nothing to start from"},
		{"place only", fix.Finding{ID: "a", PlaceKey: "repo/x"}, repo, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := fix.Decide(tc.f, tc.repo)
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
