# AGENTS.md: fix-agent

This directory is a **Gibson agent**. Gibson dispatches it. It launches the
image once for each mission run, and the process runs one pass and exits.
This file is the contract. If this file and the code disagree, the code wins.

## What the agent does

One dispatch is one pass over one Application. The agent does these steps in order.

1. Read the open findings of the Application from the graph (`internal/read`).
2. Order them by the priority that `cve-triage` wrote: P1 first, then P2, P3 and P4. A finding with no priority comes last (`internal/fix`, `Rank`).
3. Decide for each finding if the agent can fix it (`internal/fix`, `Decide`).
4. Send the first fixable finding to the coding path and get one merge request (`internal/code`).
5. Write a reason on each finding that it cannot fix, and go on to the next finding (`internal/emit`).

The pass starts at most three coding jobs (`fix.MaxAttempts`). One dispatch gives at most one merge request.

## How a fix is written: the decision

**This agent does not write code. It dispatches the code change to the coding path that Gibson already has.**

Checked on `origin/epic/fix-loop` of `gibson` on 2026-11-20:

| Path | Writes a change? | Why it is not this agent |
|---|---|---|
| A bank of always-on coding agents (`internal/platform/bank/`, ADR-0119) | Yes. A member runs Claude Code in a sandbox with its own worktrees. | This is the path that the agent uses. |
| The job node (`internal/engine/jobnode/`) | Opens a job on a bank and runs the verify loop. The deliverable kind `MERGE_REQUEST` makes the driver push the job branch and open the merge request under the connector token of the job. | This is the path that the agent uses. |
| The catalog agents `zerocool` and `claude` | They run the same coding agent. | A second route to the same code. |
| `cve-triage` | No. It sets a priority and changes no code. | It is the producer of the order that this agent reads. |

A second coding agent in this repo would copy that path and would hold a credential that the first one does not need. The coding agent never holds the token of the Git host. The driver holds it.

So `internal/code` builds a mission of one job node:

- `bank_ref` is the bank from the task context.
- The spec has one repository with the deliverable kind `MERGE_REQUEST`.
- The spec input is the id of the finding. The daemon links the merge request to the finding when the job closes (`job_graph_link.go`), and it sets the status `fixing`.
- The spec has no acceptance step. A job with no verifier accepts its first turn. The pipeline of the repository is the check.

The agent creates the mission, runs it, waits, and reads the merge request from the `deliverables` of the mission output.

## What the agent never does

- It never states that a fix worked. The agent ends when a merge request exists. The daemon reads the merge state, the deploy and the health signal through the connector of the tenant. The daemon sets `fixed`, `verified` or the revert.
- It never writes the status of a finding.
- It never calls a connector tool of the Git host (see the next section).

## Seams that are not built: merge and revert

These two steps are part of the design of the fix loop (gibson#1454). The agent is built up to them and no further, because the daemon does not offer the read that each one needs.

**Merge (gibson#1458).** The agent must call `mcp:<connector>:merge_merge_request` only after the daemon granted the merge. The daemon emits `MergeGranted` (`internal/engine/brain/mergegate.go` on `epic/fix-loop`). Today no agent can read it:

- No SDK method and no callback RPC returns the slot of a merge request.
- Nothing in the code of the daemon emits `MergeRequestQueued`.
- The check of `World.MayMerge` in `internal/engine/metatool` does not exist. Without it, `invoke_tool` would merge for any caller.

So the agent does not call `merge_merge_request`. When these exist, add one package that calls `invoke_tool` with the id `mcp:<connector>:merge_merge_request` and the argument `merge_request`, and call it at the end of `fix.Pass`.

**Revert (gibson#1465).** The daemon calls `revert_merge_request` itself, with its own client, after a failed health signal that it read. No message from the daemon asks the agent to revert. So the agent has no revert code. If the owner of the grants moves the revert to the agent, the daemon must send a revert request to the agent first, and the agent calls the tool only on that request.

## Task context

The mission node that dispatches the agent sets these keys of the task context.

| Key | Needed | Meaning |
|---|---|---|
| `application` | yes | The Application to fix. The goal of the task is the fallback. |
| `bank` | yes | The bank of coding agents, by id or name. |
| `connector` | no | The connector of the Git host, in the form `connector/<name>`. |
| `project` | no | The project path on the Git host. |
| `base_branch` | no | The branch that the merge request targets. |
| `repository` | no | The name of the worktree. The default is `repo`. |
| `finding` | no | One finding to fix. The default is the highest priority. |
| `target` | no | The target of the coding mission. |
| `timeout` | no | The wait for the coding job, as a Go duration. The default is 45 minutes. |

With no `connector` and no `project`, the agent writes a reason on each finding and starts no job.

## Which findings the agent can fix

`fix.Decide` is the one place of this rule. A finding that the coding path cannot start from gets a reason.

- The Application has no repository.
- The flaw is on a host or a service. A host fix goes through a connector of the class `patch`, and this agent has none.
- The finding names no weakness and no place.

The agent works for a scan finding, a finding from an attack proof and a finding from a tool of the buyer, because it reads only the fields that all three have. It does not judge how hard a change is. The coding agent and the pipeline judge that.

The reason is the property `fix_blocked_reason` of the finding (`internal/emit`). It is written as a sighting with the identity property `brain_id`. The projector of the daemon must store this property. See the open items in the README.

## Dispatch, not enrollment

This agent is **dispatched**, not enrolled (ADR-0116). It has no bootstrap token, no host key, no `~/.gibson/agent/` state and no run loop. Gibson launches the image once for each mission run inside an ephemeral setec sandbox. It hands the agent a capability grant scoped to that tenant and run, and it reaps the sandbox when the process exits.

**The launch contract** is these seven variables. Gibson sets them, and it is the only writer of these names.

| Variable | Carries |
|---|---|
| `GIBSON_CG_JWT` | The per-dispatch capability grant. It is the whole credential. |
| `GIBSON_CALLBACK_ENDPOINT` | The address of the HarnessCallbackService to dial back. |
| `GIBSON_AGENT_TASK_B64` | The base64 protojson of the `gibson.types.v1.Task`. |
| `GIBSON_MODEL` | The model resolved for the tenant at dispatch. The agent makes no model call. |
| `GIBSON_MISSION_ID` / `GIBSON_MISSION_RUN_ID` / `GIBSON_AGENT_RUN_ID` | The run scope for provenance. |

`internal/dispatch` reads it. A missing grant fails the launch. Decode the task through proto: `Task.context` is a `map<string, TypedValue>`, and a plain string read drops every key.

## Do not

- Call the daemon directly outside the harness. The harness is the contract.
- Read or write secrets through environment variables.
- Reintroduce a polling or enrolled path beside the dispatched one (ADR-0027).
- Add a second coding path in this repo.
- Use `replace` directives in `go.mod`, or add a `go.work`. Pin the SDK by tag.
- Hand-edit the catalog manifest in `gibson`. It carries the image digest that the release produces.

## Naming

Agents follow `{domain}-{function}`. The name `fix-agent` is the name of the repo, the image and the catalog id.
