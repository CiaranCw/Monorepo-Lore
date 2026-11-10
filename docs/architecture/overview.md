# Architecture

Monorepo-Lore is a Manager in front of Lore 0.10.1.

Lore stores repositories, revisions, and links. The Manager stores users, projects, modules, grants, operations, and snapshot rows in SQLite. AuthBridge answers the Lore authentication RPCs. It issues access tokens only for repositories the permission service allows.

A parent repository holds links pinned to module revisions. Ordinary users and project administrators do not receive that parent repository in their Lore resource list. A separate service account is used when the Manager publishes.

The remote entry is a TLS HTTP/2 gateway. It forwards streams and does not authorize repositories.
