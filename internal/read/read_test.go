// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package read_test

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/fix-agent/internal/read"
	"github.com/zeroroot-ai/sdk/agent"
)

type fakeFindings struct {
	out      []agent.ApplicationFinding
	err      error
	statuses []string
	app      string
}

func (f *fakeFindings) ApplicationFindings(_ context.Context, app string, statuses []string, _ int) ([]agent.ApplicationFinding, error) {
	f.app, f.statuses = app, statuses
	return f.out, f.err
}

func TestOpenFindings_ReadsOnlyOpenAndMapsThePriority(t *testing.T) {
	src := &fakeFindings{out: []agent.ApplicationFinding{{
		FindingID: " f1 ", Status: "open", VulnerabilityID: "CVE-2026-1", Severity: "HIGH", PlaceLabel: "Package", PlaceKey: "libx",
		Reachable: true, Exposed: true, Priority: "p1", PriorityReason: " live and exposed ",
	}}}
	r, err := read.New(src)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := r.OpenFindings(context.Background(), " portal ")
	if err != nil {
		t.Fatalf("OpenFindings: %v", err)
	}
	if src.app != "portal" || len(src.statuses) != 1 || src.statuses[0] != "open" {
		t.Errorf("read app %q statuses %v, want portal and [open]", src.app, src.statuses)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.ID != "f1" || f.Status != "open" || f.Priority != "P1" || f.Severity != "high" || f.PriorityReason != "live and exposed" || !f.Exposed {
		t.Errorf("finding = %+v", f)
	}
}

func TestOpenFindings_ExposedNeedsReachable(t *testing.T) {
	src := &fakeFindings{out: []agent.ApplicationFinding{{FindingID: "f", Status: "open", Exposed: true}}}
	r, _ := read.New(src)
	got, _ := r.OpenFindings(context.Background(), "a")
	if got[0].Exposed {
		t.Error("a Finding that is not reachable cannot be exposed")
	}
}

func TestOpenFindings_DropsAFindingWithNoID(t *testing.T) {
	src := &fakeFindings{out: []agent.ApplicationFinding{{FindingID: "  ", Status: "open"}, {FindingID: "ok", Status: "open"}}}
	r, _ := read.New(src)
	got, err := r.OpenFindings(context.Background(), "a")
	if err != nil || len(got) != 1 || got[0].ID != "ok" {
		t.Fatalf("got %+v err %v, want only ok", got, err)
	}
}

func TestOpenFindings_KeepsOnlyOpenWhateverTheServerReturns(t *testing.T) {
	// The statuses are the four that the daemon sets (gibson#1656). A server
	// that ignored the filter must not make the agent open a second merge
	// request for a Finding at fixing.
	src := &fakeFindings{out: []agent.ApplicationFinding{
		{FindingID: "a", Status: "fixing"},
		{FindingID: "b", Status: "open"},
		{FindingID: "c", Status: "fixed"},
		{FindingID: "d", Status: "verified"},
		{FindingID: "e", Status: ""},
	}}
	r, _ := read.New(src)
	got, err := r.OpenFindings(context.Background(), "a")
	if err != nil || len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("got %+v err %v, want only b", got, err)
	}
}

func TestOpenFindings_AFailedReadIsNeverAnEmptyRead(t *testing.T) {
	boom := errors.New("unavailable")
	r, _ := read.New(&fakeFindings{err: boom})
	got, err := r.OpenFindings(context.Background(), "a")
	if !errors.Is(err, boom) || got != nil {
		t.Fatalf("got %v err %v, want nil and the read error", got, err)
	}
}

func TestOpenFindings_NoApplicationIsAnError(t *testing.T) {
	r, _ := read.New(&fakeFindings{})
	if _, err := r.OpenFindings(context.Background(), " "); err == nil {
		t.Fatal("want an error for a blank application")
	}
}

func TestNew_NoSourceIsAnError(t *testing.T) {
	if _, err := read.New(nil); err == nil {
		t.Fatal("want an error for no source")
	}
}
