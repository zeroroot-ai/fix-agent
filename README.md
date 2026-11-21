# fix-agent

A Gibson agent that fixes one finding of an Application.

It reads the open findings from the knowledge graph, takes the highest priority that `cve-triage` wrote, and sends it to a bank of coding agents. The coding job opens a merge request. A finding that the agent cannot fix by a rule gets a reason on the finding. A job that gives no merge request is deferred with no reason. In both cases the agent goes on to the next finding.

The agent never states that a fix worked. The daemon reads the merge, the deploy and the health signal through the connector of the tenant, and the daemon decides the status of the finding. The agent contract is in [AGENTS.md](./AGENTS.md).

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
| Merge on a granted slot | Calls `merge_merge_request` after `MergeGranted`. | not built, the daemon has no read of the grant |
| Revert | Calls `revert_merge_request`. | not built, the daemon reverts with its own client |
| Image build | Build, cosign signature and SBOM. | `.github/workflows/image.yml`, runs on `main` |
| Catalog manifest | The entry in `gibson` that makes the agent dispatchable. | not in this repo, see below |
| End to end on kind | One dispatch against a seeded tenant. | not built |

## Launch contract

Gibson sets seven variables when it launches the image. See [AGENTS.md](./AGENTS.md) for the list. To run the binary by hand, set the variables and run `make run`.

## Open items

These items need a change in another repo.

1. **Merge grant.** No agent can read `MergeGranted`. See gibson#1458.
2. **Revert.** The daemon reverts a failed fix with its own client. See gibson#1465.
3. **The merge request ref.** The agent knows that a merge request exists from the status `fixing`. It reads only that status, because the daemon caps a read at 500 rows. It does not know the ref or the URL, because no harness call returns the mission output or the `FIXED_BY` edge. The daemon has both (the `merge_request` field of the World finding).
4. **The reason property.** The projector stores `fix_blocked_reason`, and the component read of `ApplicationFinding` returns it (gibson#1556). The harness callback proto `ApplicationFinding` and the SDK type `agent.ApplicationFinding` have no field for it. Until both have it, the agent cannot skip a finding with a block reason. A job that ends with no merge request, and a finding that the agent cannot fix, are deferred with no reason, and the next pass tries the same finding again. Gibson fills `fix_blocked_reason` under [gibson#1579](https://github.com/zeroroot-ai/gibson/issues/1579). The SDK release that ships it comes after that.
5. **A job in flight.** The daemon already holds one fix job for each finding (`FixClaimed`). A second dispatch for the same finding fails its mission. The agent reads that as a temporary fault and defers the finding. No change is needed in another repo.
6. **A catalog mission.** The mission graph is built here. A checked-in catalog mission would be the one definition (ADR-0027).

## Develop

```
make build   # compile
make test    # unit tests
make check   # gofmt, go vet, unwired guard
```
