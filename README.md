# fix-agent

A Gibson agent that fixes one finding of an Application.

It reads the open findings from the knowledge graph, takes the highest priority that `cve-triage` wrote, and sends it to a bank of coding agents. The coding job opens a merge request. A finding that the agent cannot fix gets a reason on the finding, and the agent goes on to the next one.

The agent never states that a fix worked. The daemon reads the merge, the deploy and the health signal through the connector of the tenant, and the daemon decides the status of the finding. The agent contract is in [AGENTS.md](./AGENTS.md).

It is built with the ADK the way `cve-triage` is built. One dispatch is one pass, and the process exits when the pass ends.

## Layout

| Path | What it is | State |
|---|---|---|
| `internal/fix` | The pass: rank, decide, code, write a reason. The seams of the parts below. | done, tested with fakes |
| `internal/read` | The open findings of one Application, with the priority of `cve-triage`. | done, tested with fakes |
| `internal/code` | Builds a mission of one job node with a merge request deliverable, runs it and reads the merge request. | done, tested with a fake mission client |
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
3. **Mission output.** `internal/code` finds the merge request in the `deliverables` of the mission output. No test against a daemon has shown that shape yet.
4. **The reason property.** The projector must store `fix_blocked_reason` on the `Finding` node, and `ApplicationFinding` must return it. Without the read, the next pass tries the same finding again.
5. **A catalog mission.** The mission graph is built here. A checked-in catalog mission would be the one definition (ADR-0027).

## Develop

```
make build   # compile
make test    # unit tests
make check   # gofmt, go vet, unwired guard
```
