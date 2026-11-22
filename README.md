# fix-agent

A Gibson agent that fixes one finding of an Application.

It reads the open findings from the knowledge graph, takes the highest priority that `cve-triage` wrote, and sends it to a bank of coding agents. The coding job opens a merge request. The agent then calls the merge tool of the connector. The daemon allows that call only after it granted the merge slot. A finding that the agent cannot fix by a rule gets a reason on the finding. A job that gives no merge request is deferred with no reason. In both cases the agent goes on to the next finding.

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
3. The slot binds the fix mission. Only a call from the mission that started the fix mission may merge with it. The agent runs in that mission.

The agent calls `invoke_tool` with the id `mcp:<connector>:merge_merge_request` and the argument `merge_request`. A refusal "merge not granted yet" means that the slot is not granted. The agent calls again until `merge_wait` ends (default 30 minutes). The wait between two calls starts at 15 seconds and doubles after every retry, up to 2 minutes. The same rule applies to the read of the merge request that comes before the merge call. When the wait ends, the merge request stays open. A slot that the daemon grants after that is not used, and it blocks the other fixes of the Application until `MergeSlotHold` ends (24 hours). The daemon must re-dispatch the agent on `MergeGranted`, or free the slot when the run ends. That change is in gibson (gibson#1609).

Before the first merge call, the agent reads `head_sha` of the merge request with `merge_request_state`. It sends the value as `expected_head_sha`. The host refuses the merge when a person pushed a commit to the fix branch while the agent waited. The agent treats that refusal as final. The argument `expected_head_sha` is in `zeroroot-ai/connectors` on the branch `feat/fixloop-open-merge-request` and is not on `main` yet. If the connector returns no `head_sha`, the agent does not merge.

The pin does not stop a commit that was on the branch before the coding job pushed. So the agent also reads `changed_files` of `merge_request_state`. It reads the list as `{path, change, previous_path, blob_sha}` entries. A renamed file counts under both paths. A truncated list is a refusal. It merges only when that set of paths equals the set that the coding job changed (`Delivery.ChangedFiles`). A mismatch is final (`foreign_change`). **The merge step does not merge today.** No harness call returns the paths that the coding job changed, so `Delivery.ChangedFiles` is empty and the outcome is `skipped`. The field `changed_files` is also not in `merge_request_state` yet. Both changes are listed in the open items.

| Answer | Outcome | What the agent does |
|---|---|---|
| The result has `merged: true` | `merged` | Ends the pass. |
| Refusal "merge not granted yet" | `waiting` | Calls again until `merge_wait` ends. |
| A refusal that passes with time (pending authorization, audit record, failed merge check), on the merge call or on the read | `waiting` | Calls again, with the wait that doubles, until `merge_wait` ends. |
| The head of the merge request moved | `head_moved` | Does not call again. |
| The connector gives no `head_sha` or no `changed_files` | `skipped` | Makes no merge call. |
| The paths of the merge request are not the paths of the coding job | `foreign_change` | Does not call again. |
| The agent has no record of the paths of the coding job | `skipped` | Makes no call. This is the case today. |
| The answer has no result object | none | The run fails. The agent does not send the call again. |
| The host has not settled the merge status | `waiting` | Calls again until `merge_wait` ends. |
| Refusal "not authorized to invoke tool" | `not_allowed` | Does not call again. The merge request stays open for a person. |
| The host refuses, for example the branch protection | `refused` | Does not call again. The finding stays `fixing`, and the daemon records the reason. |
| The key of the merge request is empty | `skipped` | Makes no call. |
| The call does not reach the daemon | none | The run fails. |

The agent reads the refusal text of the daemon, because the SDK returns a refusal as an error with the message of the daemon. The text is in one place, `internal/merge`.

The tool of both Git host connectors is `merge_merge_request`. See the docs of the host APIs that the tool calls:

- GitHub: <https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request>
- GitLab: <https://docs.gitlab.com/ee/api/merge_requests.html#merge-a-merge-request>

## Launch contract

Gibson sets seven variables when it launches the image. See [AGENTS.md](./AGENTS.md) for the list. To run the binary by hand, set the variables and run `make run`.

## Open items

These items need a change in another repo.

1. **Merge grant.** No harness call returns the merge slot. The agent asks by calling the merge tool, and the daemon refuses the call until it granted the slot. See [How the merge works](#how-the-merge-works). The agent names the merge request with the key that the harness read returns in `merge_request`. The daemon fills that key under [gibson#1579](https://github.com/zeroroot-ai/gibson/issues/1579). Until then the merge step is skipped and the merge request stays open.
2. **Paths of the coding job.** The agent must know which paths the coding job changed, and no harness call returns them. The driver of the job knows them from the deliverable. Until a harness field carries them, the merge step reports `skipped`. The connectors change that adds `changed_files` to `merge_request_state` is also open.
3. **Revert.** The daemon reverts a failed fix with its own client. See gibson#1465.
4. **The merge request ref.** The agent knows that a merge request exists from the status `fixing`. It reads that status, because the daemon caps a read at 500 rows. The SDK type `agent.ApplicationFinding` has the fields `MergeRequest` and `MergeRequestURL`. The agent reads the key from the row of the finding, and the daemon must fill it (see item 1). The agent does not read the mission output.
5. **The reason property.** The projector stores `fix_blocked_reason`, and the component read of `ApplicationFinding` returns it (gibson#1556). The harness callback proto `ApplicationFinding` and the SDK type `agent.ApplicationFinding` have no field for it. Until both have it, the agent cannot skip a finding with a block reason. A job that ends with no merge request is deferred with no reason, and the next pass tries the same finding again. A finding that the agent cannot fix by a rule still gets a reason (`Unfixed`). Gibson fills `fix_blocked_reason` under [gibson#1579](https://github.com/zeroroot-ai/gibson/issues/1579). The SDK release that ships it comes after that.
6. **A job in flight.** The daemon already holds one fix job for each finding (`FixClaimed`). A second dispatch for the same finding fails its mission. The agent reads that as a temporary fault and defers the finding. No change is needed in another repo.
7. **A catalog mission.** The mission graph is built here. A checked-in catalog mission would be the one definition (ADR-0027).

## Develop

```
make build   # compile
make test    # unit tests
make check   # gofmt, go vet, unwired guard
```
