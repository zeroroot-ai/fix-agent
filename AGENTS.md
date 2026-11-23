# AGENTS.md: fix-agent

This directory is a **Gibson agent**. Gibson dispatches it. It launches the
image once for each mission run, and the process runs one pass and exits.
This file is the contract. If this file and the code disagree, the code wins.

## What the agent does

One dispatch is one pass over one Application. The agent does these steps in order.

1. Read the open findings of the Application from the graph (`internal/read`). The agent keeps only a finding at the status `open`, even if the server returns more.
2. Read the findings at `fixing` that have a merge request key, a fix head and fix files (`PendingMerges`). Try them in the order of priority. Go to the next one after a final outcome, for example merged, closed, refused, not allowed, head moved or foreign change. Stop at the first merge step that merged with a call or waited for the slot. All these steps share one `merge_wait` budget. A named run merges only the named finding. After gibson#1626 merges, the daemon frees the merge slot when a run ends with the merge request open, and it queues the slot again. The next pass merges that merge request.
3. Order the open findings by the priority that `cve-triage` wrote: P1 first, then P2, P3 and P4. A finding with no priority comes last (`internal/fix`, `Rank`).
4. Decide for each finding if the agent can fix it (`internal/fix`, `Decide`).
5. Send the first fixable finding to the coding path and get one merge request (`internal/code`).
6. Call the merge tool of the connector for the new merge request, and wait for the merge slot (`internal/merge`).
7. Write a reason on each finding that it cannot fix, and go on to the next finding (`internal/emit`). A coding mission that did not complete gets no reason. The next pass tries that finding again.

The pass starts at most three coding jobs (`fix.MaxAttempts`). One dispatch gives at most one merge request. One pass makes at most one merge step that waits for the slot. The step retries the call inside `merge_wait`. If step 2 made such a step, the new merge request of this pass waits for the next pass.

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

The agent creates the mission, runs it and waits. Then it reads the status of the finding through `ApplicationFindings`. The status `fixing` is the proof that a merge request exists. The agent reads only that status, because the daemon caps a read at 500 rows. The agent reads the status again for up to 30 seconds, because the graph projector writes the status a short time after the job closes.

The agent does not read the mission output. The callback `WaitForMission` of the daemon returns the id, the status, the error and the time only. The output is never sent. Text in a node output can also come from the coding agent, so a merge request in it is a claim and not a fact.

| Mission end | Meaning | What the agent does |
|---|---|---|
| Completed, finding at `fixing` | A merge request exists. | Reports it and ends the pass. |
| Completed, finding not at `fixing` after 30 seconds | No merge request, or the projector is slow. The agent cannot tell which. | Writes no reason and goes on. The next pass tries again. |
| Failed or canceled | The cause can be temporary. | Writes no reason and goes on. The next pass tries again. |

## What the agent never does

- It never states that a fix worked. The agent ends after the merge step. The daemon reads the merge state, the deploy and the health signal through the connector of the tenant. The daemon sets `fixed`, `verified` or the revert.
- It never writes the status of a finding.
- It never calls a connector tool of the Git host except `merge_request_state` (a read) and `merge_merge_request`, and only through `invoke_tool` (see the next section).
- It never calls `revert_merge_request`. Only the daemon reverts.

## Merge, and the revert that is not here

**Merge (gibson#1458).** The agent calls `invoke_tool` with the id `mcp:<connector>:merge_merge_request` and the argument `merge_request`. The key comes from the field `MergeRequest` of the finding row that the harness returns. The daemon gates the call (`internal/engine/metatool/approval.go` on `origin/main` of `gibson`):

- The `can_execute` check of the grant. A caller with no merge grant gets a refusal, and the agent leaves the merge request open.
- The role `merge` of the tool. The daemon runs the call only when `World.MayMerge` finds a slot that `MergeGranted` granted. The slot binds the fix mission, and the parent mission may merge with it. The agent runs in the parent mission.
- The refusal "merge not granted yet" is the only signal of the slot that an agent gets. The agent calls again until `merge_wait` ends.

Before the call, the agent reads `merge_request_state`. It sends `fix_head_sha` of the finding as `expected_head_sha`. It merges only when `changed_files` equals `fix_files` of the finding in path, change, previous path and blob sha, and it refuses a mode change, a mode other than 100644, a cut list and a list that the host did not give. The daemon fills `fix_head_sha` and `fix_files` from its own read of the merge request. The agent never takes them from the coding job. When either is empty, the agent makes no merge call.

`internal/merge` holds this step. It reads the refusals of the daemon by the code of `agent.ToolCallError` (`errors.As`), never by their text.

**Revert (gibson#1465).** The daemon calls `revert_merge_request` itself, with its own client, after a failed health signal that it read. The tool has the role `daemon`, so a call by an agent is refused. The agent has no revert code, and it must get none.

## Task context

The mission node that dispatches the agent sets these keys of the task context.

| Key | Needed | Meaning |
|---|---|---|
| `application` | yes | The Application to fix. The goal of the task is the fallback. |
| `bank` | yes | The bank of coding agents, by id or name. |
| `connector` | yes | The connector of the Git host, in the form `connector/<name>`. |
| `project` | yes | The project path on the Git host. |
| `base_branch` | no | The branch that the merge request targets. |
| `repository` | no | The name of the worktree. The default is `repo`. |
| `finding` | no | One finding to fix. The default is the highest priority. |
| `target` | no | The target of the coding mission. |
| `timeout` | no | The wait for the coding job, as a Go duration. The default is 45 minutes. |
| `merge_wait` | no | The wait for the merge slot, as a Go duration. The default is 30 minutes. |

A dispatch with no `bank`, no `connector` or no `project` fails the run. The agent writes no reason, because a fault of the dispatch is not a fact about a finding.

## Which findings the agent can fix

`fix.Decide` is the one place of this rule. A finding that the coding path cannot start from gets a reason.

- The flaw is on a host or a service. A host fix goes through a connector of the class `patch`, and this agent has none.
- The finding names no weakness and no place.

The agent works for a scan finding, a finding from an attack proof and a finding from a tool of the buyer, because it reads only the fields that all three have. It does not judge how hard a change is. The coding agent and the pipeline judge that.

The reason is the property `fix_blocked_reason` of the finding (`internal/emit`). It is written as a sighting with the identity property `brain_id`. The projector of the daemon stores this property, and the daemon returns it in the component read. The harness read returns it too (gibson#1603). The agent does not skip a finding by an old reason. It checks each finding again in each pass, because the facts of a finding can change and no actor clears a reason.

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
