# Monorepo-Lore

This project is an internal-oriented logical monorepo management system built on top of Lore.

It does not replace Lore. Lore remains the system of record for repositories, revisions, links, clone, commit, push, and sync. Monorepo-Lore adds a Manager that records projects and modules, decides who may see each module, and publishes an immutable snapshot of module revisions into a parent repository.

A license has not been chosen yet. This repository does not grant one.

## Why Monorepo-Lore

A game or product tree is often several Lore repositories that must move together: engine, client, and documents. People should see only the modules they are allowed to use. A snapshot should record the exact revisions that were current at one moment, and later pushes must not rewrite that record.

## Architecture

```
lore-mono  -->  Manager HTTP API
                    |
                    +--> SQLite (users, projects, modules, grants, snapshots)
                    +--> AuthBridge (identity and access tokens for Lore)
                    |
Lore CLI   -->  TLS gateway  -->  Lore Server
                    |
                    +--> AuthBridge
```

The gateway forwards HTTP/2. It does not decide repository access. AuthBridge does.

## Core features

- Username and password login, then a Lore identity token stored by the Lore CLI.
- Projects, modules, membership, and per-module read or write grants.
- `lore-mono` commands for login, project selection, module list, clone, status, sync, commit, push, history, refs, show, import, and publish.
- Complete per-module commit DAG indexing (all branches, tags, and merge parents without truncation) and permission-filtered monorepo aggregated commit timelines with keyset cursor pagination.
- Single and batch external Git repository import (GitHub, Gitee, GitLab, Gongfeng, and generic Git) preserving commit DAG topology, branches, tags, original authorship/timestamps, and Git LFS / submodule metadata, with dry-run, checkpoint resume, failure isolation, and post-import digest verification.
- Batch commands run one Lore process per authorized module and print a per-module result plus a summary.
- A client `ca_file` is passed to Lore child processes as `SSL_CERT_FILE`. It is not written into the parent process environment.

Lore 0.10.1 cannot enforce read and write separately. A read grant still becomes Lore access, and that token can push. Read is not a safe read-only Lore permission.

Access tokens last five minutes. Revoking a grant changes the next token. It does not make an already issued token expire early.

## Repository isolation

A user sees only modules with an explicit grant. The same module name in two projects is two repository ids. Knowing another repository id returns the same not-found response as an unknown id. Project administrators do not receive the parent repository. The publisher service account is a separate identity and its credential is not returned by the user API.

## Snapshot publishing

A snapshot is the set of module revisions captured at one moment. Later module commits do not change that set. One project publishes at a time. If Lore already contains that publish, recovery records success instead of pushing again. A publish that cannot be matched to a remote commit is left for a person to review.

The Manager process mounts this publisher only when `[publish]` is configured with a workspace and a service-account credential path.

## TLS gateway

Clients use TLS to the gateway. The gateway uses TLS to the Lore server. Plaintext gRPC is not the remote entry. Certificate generation is `scripts/gen-certs.py`. The gateway program is `gateway/gateway.js`.

An independent second Linux machine has not been tested. That item is **NOT_RUN**.

## Technology stack

- Go 1.20
- SQLite
- Lore 0.10.1 CLI and server
- A small Node.js HTTP/2 TLS proxy

## Development environment

Use Go 1.20.4. Module mode is on. Do not run `go mod tidy` or upgrade dependencies as part of routine work.

```sh
go test -mod=readonly -count=1 ./...
go vet -mod=readonly ./...
go build -mod=readonly ./...
```

Tests that talk to a live Lore server are skipped unless their environment variables are set. A skipped live test is not a pass of that live scenario.

### Migration operations

Operational migration documents and fillable templates are under
[`docs/migration/`](docs/migration/):

- final migration-readiness report;
- import and backup/rollback runbooks;
- repository inventory, Monorepo mapping, and user-permission CSV templates;
- per-import acceptance checklist and known limitations.

`manager-ops` provides executable backup, verification, isolated restore,
consistency audit, and per-module quarantine operations:

```sh
go build -mod=readonly ./cmd/manager-ops
manager-ops backup --db /path/manager.db --store /path/store --imports /path/imports --keys /path/keys --configs /path/config --certs /path/certs --out /new/backup
manager-ops verify --bundle /new/backup
manager-ops restore --bundle /new/backup --target /new/restore-drill
manager-ops audit --db /new/restore-drill/db/manager.db
```

### Protobuf generation

The generated Go files are committed under `gen/`. To regenerate them, install the Buf CLI and the exact plugin versions used by this repository, and make sure the Go binary directory is on `PATH`:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0
buf generate
```

Run `buf generate` from the repository root. `buf.gen.yaml` resolves both plugins by executable name through `PATH`; it does not depend on a machine-specific absolute path.

### Development-only test seeder

`cmd/b26seed` is a development/test fixture utility. It creates the fixed test identities `carol`, `alice`, `bob`, `dave`, and `publisher`, using the password supplied through `B26_PASSWORD`. Use it only with a fresh, disposable, isolated test database. **Never run it against a production or shared database.** Do not put the password in source control, TOML configuration, or logs.

## Current status

The B2.6.6 baseline includes Manager, AuthBridge, the Lore adapter, snapshot publishing, batch module commands, and the TLS gateway. Windows has been exercised against an isolated lab. An independent Linux client machine remains **NOT_RUN**.

## Roadmap

- Repeat the client workflow on a separate Linux machine.
- Choose a license.
- Keep snapshot recovery and permission checks aligned with later Lore versions.
