# Snapshot publisher

A snapshot is the module revisions captured at one moment. Later commits do not change that set.

SQLite allows one running publish per project. The database transaction does not cover the Lore push. After a crash, recovery looks for a commit message that carries the operation id and checks that the links match the captured set. A match is recorded as success and is not pushed again. If the remote result cannot be proven, the operation is marked for a person to review.

The Manager mounts `LoreDriver` only when publish workspace, parent URL, and service-account auth path are set. That credential stays on the server.
