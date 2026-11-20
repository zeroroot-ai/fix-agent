# fix-agent

An ADK-built Gibson agent that fixes one finding, merges the fix on a green pipeline, and reverts it when the health signal fails.

It is built with the ADK (`gibson component init --kind agent`), the same way as `cve-triage`.
