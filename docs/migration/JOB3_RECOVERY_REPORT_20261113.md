# Job 3 Recovery Report — 2026-11-13

## Result

Job 3 is `succeeded`: 18/18 items succeeded, 0 failed. The ten modules that
entered this recovery all pass source/Lore/SQLite verification, remote clone,
default-branch history, and current-tree SHA-256 comparison.

The original Kubee baseline remains unchanged:

- 42 original modules;
- 814 original revisions;
- Snapshot 1 and its 42 pins;
- existing users and grants.

Current totals are 60 modules, 1,944 distinct revisions, and 60 explicit
`ciaranxu` module grants.

## Backup

Pre-recovery cold backup:

```text
/data/lore-lab/monorepo-p3b/kubee-formal-20261111T184000Z/backup/pre-job3-recovery-20261112T144016Z
```

- 211,132 files;
- 115,727,704,173 bytes;
- SQLite `integrity_check=ok`;
- zero foreign-key errors;
- `SHA256SUMS` SHA-256:
  `9ec9f9b430ffe4acfafd201b6d9453e532cb9af4241633e9732ef290d7b5abab`.

The backup was opened on isolated ports 54137/54139. Repository lookup and
SQLite checks passed. Older backups were retained.

Post-recovery cold backup:

```text
/data/lore-lab/monorepo-p3b/kubee-formal-20261111T184000Z/backup/post-job3-recovery-20261112T211720Z
```

- 211,936 files;
- 125,905,890,417 bytes;
- Job 3 `succeeded`, 60 modules, 1,944 revisions;
- isolated restore check PASS;
- `SHA256SUMS` SHA-256:
  `137cd0574b79956d0d4db9133479f4b358178e9b5b1dd9abfa3ca8d283f450b3`.

## Recovery implementation

The migration-only `lore-fragment-repair` tool uses Lore's official
`lore.storage.v1.StorageService`:

1. inventory every current and historical file address through Lore CLI;
2. query the destination for the exact `(BLAKE3 hash, context)` address;
3. read fragment metadata and encoded payload from a loopback source Lore
   server backed by the existing local `.lore` store;
4. clear only store-local `PayloadStored*` flags;
5. stream `PutRequest` to the destination;
6. read the destination fragment back and compare address, encoding flags,
   payload/content sizes, and payload SHA-256;
7. query the exact context again;
8. persist restartable progress.

Existing destination addresses are never overwritten. A fragment found only
under another context is still copied into the required repository context.
Access tokens are refreshed silently every three minutes during large repairs.

The importer resumes one selected module from the existing Job 3 checkpoint.
No repository was recreated, no Repository ID changed, no force push was used,
and production SQLite was not edited manually.

Additional fixes discovered during recovery:

- Gateway reconnect callback no longer dereferences a session cleared by an
  earlier connection error.
- HEAD digest verification now includes every effective path mapping. This was
  required for `Code_SSR`, which intentionally combines `Code_SSR` and
  `Code_SSR_debut`.
- Resume positions an existing lane at the expected first parent before
  committing.
- Mixed-branch publication uses a full named-branch push where the first-parent
  chain crosses physical Lore branches; linear same-branch history remains
  incrementally checkpointed.

## Ten recovered modules

| Module | Repository ID | Default head | Source/SQLite | Branches | Tags | Merges | Repaired fragments | Clone tree SHA-256 |
|---|---|---|---:|---:|---:|---:|---:|---|
| BattleMech | `01a1ce99366e7b209288c9c223f4aa2b` | `main` `6b86fb5daeef…` | 408/408 | 9/9 | 2/2 | 24 | 1,699 | `1173867f14ea94605aa70d9ee0c6dc9287e0148a5fa76361a9c2636144250e96` |
| DWorld2 | `01a1ceb1734b74e2a3eaa21bde378edc` | `master` `d256bb8086de…` | 29/29 | 1/1 | 0/0 | 0 | 5,425 | `e9a616d7a63aac8879efe6d962695049fbf67764ba2227975b9c66a72c5a1d2f` |
| Ball | `01a1ce98d34f7eb397d91fe0d9674382` | `master` `8373a6326f89…` | 12/12 | 1/1 | 0/0 | 0 | 366 | `d3542415e3d4b4ddfead6d9638f994eafd2e7c1bf6fa1f248a60db99d4db875b` |
| COC | `01a1ceb1db4c7b12b15a3013c6b51f92` | `master` `968952923f7f…` | 32/32 | 1/1 | 0/0 | 0 | 4,661 | `10c0e73d1f15eaafabace37015709e307f55eba900b834511e50f84adb337373` |
| TheTruth | `01a1ceb805927b23ad2aa1435f018857` | `master` `0b822fbc8b20…` | 40/40 | 3/3 | 0/0 | 5 | 32,617 | `c490e72c423cb42a148ab27bc372648fa1a49762e64df3c8ddbbbef3e52c2b12` |
| Code_SSR | `01a1cea2bffa77f386a8b4b716983a31` | `master` `8e6b31f84610…` | 51/51 | 3/3 | 0/0 | 3 | 13,129 | `93d6320bf0b1858677ddd41edd95f8aa9166f03112a7c6fb5ad075e71770fb04` |
| OL | `01a1ceb41adf77118af846e5d9ba14a9` | `master` `fc1b4bb783b2…` | 8/8 | 1/1 | 0/0 | 0 | 1,236 | `949c2b4ff638ea38d34694af9da390dcb85a6f80ce3b5a214b06d791d9c8f47b` |
| NightWardenProject | `01a1ceb511bd7780a0c99083be5a2def` | `master` `34387a007306…` | 298/298 | 1/1 | 0/0 | 58 | 39,220 | `4bfea98f8ba1798a8ebb6a47f1e1f452a1400ca735f5fe1e56b5a2ce01942a68` |
| DT | `01a1ce9e02387ec3ade81b7e501342a1` | `master` `8eb92306d2aa…` | 142/142 | 1/1 | 0/0 | 0 | 84,057 | `67ed3fb12b2c4f92365953bb953bec4bd8cb27ecac95d2ae48a240440308af1c` |
| tide-holiday | `01a1ce97bcdc78319ff106e292788815` | `main` `47d9b253714a…` | 17/17 | 1/1 | 0/0 | 0 | 5,241 | `80519413cd6805807f99290930ac50568cd78b4b54ebf92ee5c12913f78de469` |

Total exact-context fragments repaired and read-back verified: **187,651**.
Final dry-run inventory reports zero missing fragments for every module.

`BattleMech`, `DWorld2`, `Ball`, `COC`, `TheTruth`, `Code_SSR`, and
`NightWardenProject` also report `lfs_hydration_status=hydrated_verified`.
The other three do not use LFS.

## Verification

- Job 3 automated verification: 18/18 PASS.
- Ten recovered modules: zero mismatches.
- Git and Lore HEAD digests: equal for every module.
- Fresh remote clone: PASS for every module.
- Default-branch local/remote history count: equal for every module.
- Clone working tree SHA-256: equal to the preserved import worktree.
- Job rerun: 1,944 rows / 1,944 distinct revisions before and after.
- SQLite integrity: PASS; foreign-key errors: zero.
- Windows Go 1.20.4 affected tests/vet/build: PASS.
- Linux Go 1.20.4 affected tests/vet/build: PASS.
- Gateway JavaScript syntax check: PASS.

## Deployed artifacts

```text
Manager SHA-256:
8d8a4527dc2e6c334983a4a565fa1e88a0ed6a4eeaf7a845b4828918f11110f6

Gateway source SHA-256:
013acc6f3651e27e8c9606e4c27cbfd9de97842cedba08f7f01396d98a8d9027

Fragment repair tool SHA-256:
74815356fbbd8c5a5cd2b6e2a14fa51e384b0e613149a9354a6dabcfd04de60b
```

Only the Kubee Manager and Kubee Gateway were restarted. Lore Store and the
original production authentication platform were not restarted or modified.

## Evidence

Protected raw reports, inventories, progress ledgers, clone histories, and tree
digests remain under:

```text
/data/lore-lab/monorepo-p3b/kubee-formal-20261111T184000Z/import/recovery-job3
```

`FINAL_RECOVERY_AUDIT.json` SHA-256:
`0b48214e8fa3a9847450a73e6ed5088acf47fa1ff65a6f540d845d12e0347d30`.
