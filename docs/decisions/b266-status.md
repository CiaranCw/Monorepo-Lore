# B2.6.6 status

Accepted in this baseline:

- Manager API, AuthBridge, and the Lore adapter.
- Snapshot publish and crash recovery against the in-memory driver, plus a real Lore publish from the Manager process when `[publish]` is configured.
- Batch clone, status, sync, commit, and push, filtered on the server.
- TLS gateway and a client CA file for Lore child processes.

Not accepted as done:

- An independent second Linux client. Status: NOT_RUN.
- A chosen license.
