# fix-agent

A Gibson agent that fixes one finding of an Application.

It reads the open findings from the knowledge graph, takes the highest priority that `cve-triage` wrote, and sends it to a bank of coding agents. The coding job opens a merge request. The agent then calls the merge tool of the connector. The daemon allows that call only after it granted the merge slot. A later pass also merges a finding at `fixing` whose merge request is still open. A finding that the agent cannot fix by a rule gets a reason on the finding. A job that gives no merge request is deferred with no reason. In both cases the agent goes on to the next finding.

The agent never states that a fix worked. The daemon reads the merge, the deploy and the health signal through the connector of the tenant, and the daemon decides the status of the finding. Only the daemon reverts. The agent contract is in [AGENTS.md](./AGENTS.md).

It is built with the ADK the way `cve-triage` is built. One dispatch is one pass, and the process exits when the pass ends.

## Layout

| Path | What it is | State |
|---|---|---|
| `internal/fix` | The pass: rank, decide, code, write a reason. The seams of the parts below. | done, tested with fakes |
| `internal/read` | The open findings of one Application, with the priority of `cve-triage`. | done, tested with fakes |
| `internal/code` | Builds a mission of one job node with a merge request deliverable, runs it and reads the status that the daemon sets on the finding. | done, tested with a fake in the shapes of the daemon |
| `internal/emit` | Writes the reason on a finding that the agent did not fix. | done, tested with fakes |
| `internal/pass` | Assembles the modules and runs one pass against the harness. | done, tested with fakes |
| `internal/dispatch` | The launch contract: grant, callback endpoint, task. | done, tested with a fake environment |
| `internal/merge` | Calls `merge_merge_request` through `invoke_tool` and waits for the merge slot. | done, tested with a fake of the gate of the daemon |
| Revert | Calls `revert_merge_request`. | not built, the daemon reverts with its own client |
| Image build | Build, cosign signature and SBOM. | `.github/workflows/image.yml`, runs on `main` |
| Catalog manifest | The entry in `gibson` that makes the agent dispatchable. | not in this repo, see below |
| End to end on kind | One dispatch against a seeded tenant. | not built |

## How the merge works

The agent merges its own fix on a green pipeline. No person acts. Three checks of the daemon decide, and the agent decides none of them.

1. The call passes the `can_execute` check of the grant of the agent on the connector. An agent with no merge grant gets a refusal. It opens the merge request and does not merge.
2. The manifest of the connector gives the tool `merge_merge_request` the role `merge`. The daemon runs the call only when the World of the tenant holds a granted slot for the merge request. The slot comes from `MergeGranted`, after the pipeline is green and no other fix of the Application holds a slot.
3. The slot binds the merge request and the tenant, not a mission (gibson#1609). A later run of the agent with a new mission may merge with it.

The agent calls `invoke_tool` with the id `mcp:<connector>:merge_merge_request` and the argument `merge_request`. A refusal with the code `UNAVAILABLE` (for example "merge not granted yet") means that the call can succeed later. The agent calls again until `merge_wait` ends (default 30 minutes). One call has its own bound of 2 minutes, or the time left of the wait if that is shorter, and a call that hangs ends there. The wait between two calls starts at 15 seconds and doubles after every retry, up to 2 minutes. The same rule applies to the read of the merge request that comes before the merge call. When the wait ends, the merge request stays open. The finding stays `fixing`. The daemon frees a granted slot that no merge used within the grant window (45 minutes by default) when the host shows the merge request still open (gibson#1626). It queues the merge request again after the requeue backoff (10 minutes by default). The next pass merges that merge request with a new mission.

**A later pass merges an open merge request.** Before the coding loop, a pass reads the findings at `fixing` that have a merge request key, a fix head and fix files. It tries them in the order of priority. It goes to the next one after a final outcome: merged without a merge call, closed, not allowed, refused (also a refused read), head moved, foreign change, or no head. It stops at the first merge step that merged with a call or waited for the slot. All pending merge steps share one `merge_wait` budget, and the loop stops when the budget is used. Then it goes on to the coding loop, and the loop makes no second merge step that waits. A named run (`finding` set) merges only that finding, if it is pending. The outcomes of this merge are the ones in the table below. A `fixing` row with no key, no head or no files is not a pending merge.

The daemon fills `fix_head_sha` and `fix_files` on the finding row from its own read of the fix merge request, when it links the finding to it. The agent never takes them from the coding job, because a report of the job is a claim. The agent sends `fix_head_sha` as `expected_head_sha`, so the host refuses the merge when a person pushed a commit after the link. That refusal is final.

Before the merge call, the agent also reads `merge_request_state`. It merges only when `changed_files` equals `fix_files` in path, change, previous path and blob sha. These cases are final refusals: a change of mode (`mode_changed`), a mode other than 100644, a list that the host cut (`changed_files_truncated`), a list that the host did not give (`changed_files_error`), and a head that differs from `fix_head_sha`. GitHub gives no mode, and an empty mode is not a refusal. A commit that a person pushes between the end of the job and the link is in both values, and the agent cannot see it.

**Fail closed.** The daemon fills `fix_head_sha` and `fix_files` from its own read of the merge request (gibson#1619). When either is empty, the agent makes no merge call and no read, and the outcome is `skipped`. The merge request stays open for a person.

The agent tells the refusals of the daemon apart by the code of `agent.ToolCallError`, never by its text. `UNAVAILABLE` means that the same call can succeed later (the slot is not granted, an approval is pending, a check of the daemon failed). `PERMISSION_DENIED` is final. Any other code is a refusal of the tool or the host. An error that is not a `ToolCallError` did not come from the daemon, and the run fails.

| Answer | Outcome | What the agent does |
|---|---|---|
| The result has `merged: true` | `merged` | Ends the pass. |
| Code `UNAVAILABLE`, on the merge call or on the read | `waiting` | Calls again, with the wait that doubles, until `merge_wait` ends. |
| The host has not settled the merge status | `waiting` | Calls again until `merge_wait` ends. |
| Code `PERMISSION_DENIED` | `not_allowed` | Does not call again. The merge request stays open for a person. |
| The head of the merge request differs from `fix_head_sha`, or the host refuses the head | `head_moved` | Does not call again. |
| The files of the merge request are not `fix_files`, a mode change, a cut list or no list | `foreign_change` | Does not call again. |
| The daemon filled no `fix_head_sha` or no `fix_files` | `skipped` | Makes no call. |
| The key of the merge request is empty | `skipped` | Makes no call. |
| The connector gives no `head_sha` | `skipped` | Makes no merge call. |
| The host refuses, for example the branch protection | `refused` | Does not call again. The finding stays `fixing`, and the daemon records the reason. |
| Another code, for example `INVALID_ARGUMENT` | `refused` | Does not call again. |
| The answer has no result object | none | The run fails. The agent does not send the call again. |
| The call does not reach the daemon | none | The run fails. |

The tool of both Git host connectors is `merge_merge_request`. See the docs of the host APIs that the tool calls:

- GitHub: <https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request>
- GitLab: <https://docs.gitlab.com/ee/api/merge_requests.html#merge-a-merge-request>

## Launch contract

Gibson sets seven variables when it launches the image. See [AGENTS.md](./AGENTS.md) for the list. To run the binary by hand, set the variables and run `make run`.

## Open items

These items need a change in another repo.

1. **Merge grant.** No harness call returns the merge slot. The agent asks by calling the merge tool, and the daemon refuses the call until it granted the slot. See [How the merge works](#how-the-merge-works). The agent names the merge request with the key that the harness read returns in `merge_request`. The daemon fills that key (gibson#1603). The daemon frees a granted slot that no merge used within the grant window (45 minutes by default) when the host shows the merge request still open (gibson#1626). It queues the merge request again after the requeue backoff (10 minutes by default). The next pass merges the merge request.
2. **Head and files of the fix.** The daemon fills `fix_head_sha` and `fix_files` on the finding row from its own read of the fix merge request (gibson#1619). The file mode comes with [gibson#1628](https://github.com/zeroroot-ai/gibson/pull/1628).
3. **Revert.** The daemon reverts a failed fix with its own client. See gibson#1465.
4. **The merge request ref.** The agent knows that a merge request exists from the status `fixing`. It reads that status, because the daemon caps a read at 500 rows. The SDK type `agent.ApplicationFinding` has the fields `MergeRequest` and `MergeRequestURL`. The agent reads the key from the row of the finding. The agent does not read the mission output.
5. **The reason property.** The agent writes `fix_blocked_reason` when a rule says that it cannot fix a finding (`Unfixed`). The harness read returns the reason (gibson#1603). The agent does not skip a finding by an old reason. It checks each finding again in each pass, because the facts of a finding can change and no actor clears a reason. A job that ends with no merge request gets no reason, and the next pass tries the finding again.
6. **A job in flight.** The daemon already holds one fix job for each finding (`FixClaimed`). A second dispatch for the same finding fails its mission. The agent reads that as a temporary fault and defers the finding. No change is needed in another repo.
7. **A catalog mission.** The mission graph is built here. A checked-in catalog mission would be the one definition (ADR-0027).

## Develop

```
make build   # compile
make test    # unit tests
make check   # gofmt, go vet, unwired guard
```
