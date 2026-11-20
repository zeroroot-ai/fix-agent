// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fix

import "strings"

// Verdict is the decision about one Finding: the agent either sends it to the
// coding path or writes the reason that it cannot.
type Verdict struct {
	Fixable bool
	// Reason is one plain sentence. It is empty when the Finding is fixable.
	Reason string
}

// The places that no repository change reaches. A fix of a host goes through
// a connector of the class patch, and this agent has none.
var hostPlaces = map[string]bool{"host": true, "service": true}

// Decide says if the agent can send a Finding to the coding path.
//
// The rules are few on purpose. The agent does not judge how hard a change
// is. The coding path and the pipeline of the repository judge that. A rule
// here covers only a Finding that the coding path cannot start from.
func Decide(f Finding, repo *Repository) Verdict {
	switch {
	case repo == nil || strings.TrimSpace(repo.ConnectorRef) == "" || strings.TrimSpace(repo.Project) == "":
		return Verdict{Reason: "the Application has no repository, so there is nothing to change: " +
			"set the task context keys connector and project"}
	case hostPlaces[strings.ToLower(strings.TrimSpace(f.PlaceLabel))]:
		return Verdict{Reason: "the flaw is on a host, and a repository change does not reach it: " +
			"a host fix needs a connector of the class patch"}
	case strings.TrimSpace(f.Vulnerability) == "" && strings.TrimSpace(f.PlaceKey) == "":
		return Verdict{Reason: "the finding names no weakness and no place, so the coding job has nothing to start from"}
	}
	return Verdict{Fixable: true}
}
