package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Version is the lore-mono CLI version. Release builds may override it via -ldflags.
var Version = "0.1.0"

type guidePayload struct {
	Name          string          `json:"name"`
	Version       string          `json:"version"`
	Description   string          `json:"description"`
	Architecture  guideArch       `json:"architecture"`
	Auth          guideAuth       `json:"auth"`
	DiscoveryFlow guideDiscovery  `json:"discovery_flow"`
	Commands      []guideCommand  `json:"commands"`
	Workflows     []guideWorkflow `json:"workflows"`
	Constraints   []string        `json:"constraints"`
}

type guideArch struct {
	Manager            string `json:"manager"`
	Gateway            string `json:"gateway"`
	ProjectAndModules  string `json:"project_and_modules"`
	ModuleRepositories string `json:"module_repositories"`
	ParentRepository   string `json:"parent_repository"`
	AccessControl      string `json:"access_control"`
}

type guideAuth struct {
	CheckStatus       string `json:"check_status"`
	FirstLogin        string `json:"first_login"`
	PersistentSession string `json:"persistent_session"`
	LoreRefresh       string `json:"lore_credential_refresh"`
	Revocation        string `json:"revocation"`
	SecretHygiene     string `json:"secret_hygiene"`
}

type guideDiscovery struct {
	Steps []string `json:"steps"`
	Rules []string `json:"rules"`
}

type guideCommand struct {
	Name          string `json:"name"`
	Category      string `json:"category"`
	Purpose       string `json:"purpose"`
	RequiresLogin bool   `json:"requires_login"`
	OperationType string `json:"operation_type"` // read_only | local_write | remote_write | admin
	Arguments     string `json:"arguments"`
	Example       string `json:"example"`
}

type guideWorkflow struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Commands    []string `json:"commands"`
}

func guideCmd(args []string) error {
	asJSON := false
	for _, arg := range args {
		switch arg {
		case "--json":
			asJSON = true
		case "-h", "--help":
			fmt.Fprint(stdout, guideText)
			return nil
		default:
			return fmt.Errorf("unknown argument %s", arg)
		}
	}
	if !asJSON {
		fmt.Fprint(stdout, guideText)
		return nil
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(buildGuidePayload())
}

func buildGuidePayload() guidePayload {
	return guidePayload{
		Name:        "lore-mono",
		Version:     Version,
		Description: "Lightweight CLI for managing multi-module Lore monorepos via Manager and Lore 0.10.1.",
		Architecture: guideArch{
			Manager:            "HTTP API backed by SQLite for users, projects, modules, permissions, snapshots, and commit history indexing, plus AuthBridge for Lore token exchange.",
			Gateway:            "TLS HTTP/2 reverse proxy forwarding Lore CLI gRPC traffic to Lore Server; it does not make authorization decisions.",
			ProjectAndModules:  "A Project groups independent game/component Modules mounted at relative paths. Each Module has its own independent Lore Repository ID and remote URL.",
			ModuleRepositories: "Every Module has independent commit history, revisions, branches, tags, and default branch metadata (such as master or main).",
			ParentRepository:   "Holds snapshot links pinning module revisions. It is NOT a normal developer target and is hidden from ordinary members.",
			AccessControl:      "Ordinary project members only see and operate on Modules explicitly granted to them. Unauthorized or missing repositories both return not found.",
		},
		Auth: guideAuth{
			CheckStatus:       "Run `lore-mono project list --config <client.toml>` (or `lore-mono module list --config <client.toml>`). A zero exit confirms an active Manager session; `not logged in` or `request failed` means login or re-authentication is required.",
			FirstLogin:        "Run `lore-mono login --config <client.toml> --username <name>` (interactive hidden prompt) or pipe password via `--password-stdin`. Never pass passwords on command-line flags.",
			PersistentSession: "Manager issues an exp-free session token stored privately in `lore-mono-session.tok` (outside `client.toml`). Closing terminals or restarting Manager does not require re-login.",
			LoreRefresh:       "Lore 0.10.1 CLI requires short-lived exp-bearing tokens in its local store. Running any `lore-mono` workspace command silently refreshes the Lore credential when missing or expiring.",
			Revocation:        "Changing password (`lore-mono password`), disabling an account, or revoking module grants takes effect immediately via `auth_version` and server-side permission checks.",
			SecretHygiene:     "Never write passwords, identity tokens, access tokens, or private keys into `client.toml`, command arguments, git commits, or logs. `ca_file` is injected as `SSL_CERT_FILE` only into Lore child processes.",
		},
		DiscoveryFlow: guideDiscovery{
			Steps: []string{
				"Login (`lore-mono login --config <file> --username <name>`)",
				"Project List (`lore-mono project list --config <file>`)",
				"Select Project (`lore-mono project use <project> --config <file>`)",
				"Module List (`lore-mono module list --config <file>`)",
				"Select Authorized Module from server-returned list",
				"Clone (`lore-mono clone <module> --config <file> --dest <dir>` or `lore-mono clone --all-authorized --config <file> --root <dir>`)",
			},
			Rules: []string{
				"Never guess Repository IDs.",
				"Never guess module names.",
				"Always rely on `lore-mono module list` as the authoritative inventory of accessible modules.",
				"Clone only the module(s) required by the task (use `clone <module>` for single-module tasks).",
				"`lore-mono clone` automatically checks out each module's server-recorded default branch.",
			},
		},
		Commands: []guideCommand{
			{
				Name: "guide", Category: "Discovery",
				Purpose:       "Print this AI agent onboarding guide (add --json for machine-readable output).",
				RequiresLogin: false, OperationType: "read_only",
				Arguments: "[--json]",
				Example:   "lore-mono guide --json",
			},
			{
				Name: "help", Category: "Discovery",
				Purpose:       "Show categorized CLI usage summary.",
				RequiresLogin: false, OperationType: "read_only",
				Arguments: "[-h|--help|help]",
				Example:   "lore-mono --help",
			},
			{
				Name: "login", Category: "Authentication",
				Purpose:       "Authenticate with Manager and store persistent session plus Lore credential.",
				RequiresLogin: false, OperationType: "local_write",
				Arguments: "[--config file] [--manager url] [--username name] [--lore-binary path] [--auth-url url] [--auth-path dir] [--auth-store fallback] [--password-stdin]",
				Example:   "lore-mono login --config client.toml --username dev1",
			},
			{
				Name: "password", Category: "Authentication",
				Purpose:       "Change current user's password (hidden prompt or stdin) and invalidate older tokens.",
				RequiresLogin: true, OperationType: "remote_write",
				Arguments: "[--config file] [--password-stdin]",
				Example:   "lore-mono password --config client.toml",
			},
			{
				Name: "logout", Category: "Authentication",
				Purpose:       "Delete local persistent session and Lore stored credentials.",
				RequiresLogin: false, OperationType: "local_write",
				Arguments: "[--config file]",
				Example:   "lore-mono logout --config client.toml",
			},
			{
				Name: "project list", Category: "Discovery",
				Purpose:       "List projects accessible to the logged-in user (also verifies active session).",
				RequiresLogin: true, OperationType: "read_only",
				Arguments: "[--config file]",
				Example:   "lore-mono project list --config client.toml",
			},
			{
				Name: "project use", Category: "Discovery",
				Purpose:       "Persist selected default project name into client.toml.",
				RequiresLogin: false, OperationType: "local_write",
				Arguments: "<project> [--config file]",
				Example:   "lore-mono project use Kubee --config client.toml",
			},
			{
				Name: "module list", Category: "Discovery",
				Purpose:       "List authorized modules, mount paths, permissions, and repository URLs.",
				RequiresLogin: true, OperationType: "read_only",
				Arguments: "[--config file]",
				Example:   "lore-mono module list --config client.toml",
			},
			{
				Name: "clone", Category: "Workspace & Sync",
				Purpose:       "Clone one authorized module or all authorized modules and check out each default branch.",
				RequiresLogin: true, OperationType: "local_write",
				Arguments: "<module> [--dest dir] [--config file] | --all-authorized [--root dir] [--config file]",
				Example:   "lore-mono clone BLITZ_VECTOR --config client.toml --dest ./work/BLITZ_VECTOR",
			},
			{
				Name: "status", Category: "Workspace & Sync",
				Purpose:       "Check working tree status for current repo, one module, or all authorized modules.",
				RequiresLogin: true, OperationType: "read_only",
				Arguments: "[--all|<module>] [--root dir] [--config file]",
				Example:   "lore-mono status --all --config client.toml --root ./work",
			},
			{
				Name: "sync", Category: "Workspace & Sync",
				Purpose:       "Sync local cloned module(s) with remote Lore Server.",
				RequiresLogin: true, OperationType: "local_write",
				Arguments: "<--all|module> [--root dir] [--config file]",
				Example:   "lore-mono sync --all --config client.toml --root ./work",
			},
			{
				Name: "stage", Category: "Change & Commit",
				Purpose:       "Scan and stage changes independently in cloned authorized modules (skips uncloned).",
				RequiresLogin: true, OperationType: "local_write",
				Arguments: "<--all|module> [--root dir] [--config file]",
				Example:   "lore-mono stage --all --config client.toml --root ./work",
			},
			{
				Name: "commit", Category: "Change & Commit",
				Purpose:       "Commit staged changes independently per module (never creates cross-module commits).",
				RequiresLogin: true, OperationType: "local_write",
				Arguments: "<--all|module> --message text [--root dir] [--config file]",
				Example:   "lore-mono commit --all --message \"feat: update config\" --config client.toml --root ./work",
			},
			{
				Name: "push", Category: "Change & Commit",
				Purpose:       "Push committed local branch(es) of authorized module(s) to remote Lore Server.",
				RequiresLogin: true, OperationType: "remote_write",
				Arguments: "<--all|module> [--root dir] [--config file]",
				Example:   "lore-mono push --all --config client.toml --root ./work",
			},
			{
				Name: "history", Category: "History & Inspection",
				Purpose:       "Query single-module DAG history or permission-filtered project-aggregated commit timeline.",
				RequiresLogin: true, OperationType: "read_only",
				Arguments: "[module|--all] [--project name] [--module m] [--branch b] [--tag t] [--from rev] [--first-parent] [--author a] [--search q] [--since ts] [--until ts] [--merges] [--no-merges] [--order asc|desc] [--limit n] [--cursor c] [--all-pages] [--sync] [--json] [--config file]",
				Example:   "lore-mono history --all --all-pages --config client.toml",
			},
			{
				Name: "refs", Category: "History & Inspection",
				Purpose:       "List indexed branches and tags for one authorized module.",
				RequiresLogin: true, OperationType: "read_only",
				Arguments: "<module> [--project name] [--type branch|tag] [--json] [--config file]",
				Example:   "lore-mono refs BLITZ_VECTOR --config client.toml",
			},
			{
				Name: "show", Category: "History & Inspection",
				Purpose:       "Inspect commit metadata and module-local parents by Git SHA or Lore revision.",
				RequiresLogin: true, OperationType: "read_only",
				Arguments: "<module> <commit-or-revision> [--project name] [--json] [--config file]",
				Example:   "lore-mono show BLITZ_VECTOR d57dc8a0cb13de1fca16fbb9df47a55736ed6bdd6050644acd209190934b0df6 --config client.toml",
			},
			{
				Name: "import", Category: "Admin & Migration",
				Purpose:       "Project-admin only: dry-run or run external Git import into project modules.",
				RequiresLogin: true, OperationType: "admin",
				Arguments: "--manifest file [--dry-run] [--on-conflict policy] [--project name] [--job-key k] [--concurrency n] [--json] [--config file] | --source url --module name ... | jobs [--project name] [--job id] [--json]",
				Example:   "lore-mono import --manifest import.toml --dry-run --config client.toml",
			},
			{
				Name: "publish", Category: "Admin & Migration",
				Purpose:       "Project-admin/publisher: trigger server-side parent snapshot publish for selected project.",
				RequiresLogin: true, OperationType: "admin",
				Arguments: "[--config file]",
				Example:   "lore-mono publish --config client.toml",
			},
		},
		Workflows: []guideWorkflow{
			{
				Name:        "read_single_module",
				Description: "Discover authorization, clone one module read-only, and inspect its history and refs.",
				Commands: []string{
					"lore-mono project list --config client.toml",
					"lore-mono project use Kubee --config client.toml",
					"lore-mono module list --config client.toml",
					"lore-mono clone BLITZ_VECTOR --config client.toml --dest ./work/BLITZ_VECTOR",
					"lore-mono history BLITZ_VECTOR --all-pages --config client.toml",
					"lore-mono refs BLITZ_VECTOR --config client.toml",
				},
			},
			{
				Name:        "modify_single_module",
				Description: "Create a temporary branch with native lore CLI, edit files, then stage, commit, and push one module.",
				Commands: []string{
					"lore branch create --repository ./work/BLITZ_VECTOR feat/task-branch",
					"lore branch switch --repository ./work/BLITZ_VECTOR feat/task-branch",
					"# edit files under ./work/BLITZ_VECTOR",
					"lore-mono stage BLITZ_VECTOR --config client.toml --root ./work",
					"lore-mono commit BLITZ_VECTOR --message \"fix: update game config\" --config client.toml --root ./work",
					"lore-mono push BLITZ_VECTOR --config client.toml --root ./work",
				},
			},
			{
				Name:        "modify_multiple_modules",
				Description: "Modify multiple cloned modules and batch stage/commit/push so each repository gets its own independent revision.",
				Commands: []string{
					"# switch each target repository to its task branch and edit files",
					"lore-mono stage --all --config client.toml --root ./work",
					"lore-mono commit --all --message \"chore: apply cross-module update\" --config client.toml --root ./work",
					"lore-mono push --all --config client.toml --root ./work",
				},
			},
			{
				Name:        "project_aggregated_history",
				Description: "Inspect permission-filtered project timeline across all accessible modules.",
				Commands: []string{
					"lore-mono history --all --limit 50 --config client.toml",
					"lore-mono history --all --all-pages --json --config client.toml",
				},
			},
		},
		Constraints: []string{
			"Each Module is an independent Lore repository and must receive its own independent commits and revisions.",
			"Batch operations (`stage --all`, `commit --all`, `push --all`) execute once per authorized module; never create a single commit spanning multiple modules.",
			"Parent pointers must stay strictly inside the same module; cross-module parent pointers are forbidden.",
			"Do not access, clone, or mutate the parent snapshot repository as an ordinary developer.",
			"Do not bypass Manager authorization or guess unauthorized Repository IDs or module names.",
			"`push`, `password`, `import`, and `publish` mutate remote state and require explicit task authorization; use temporary branches for test writes and never push to default branches without approval.",
			"Never modify server SQLite databases or Lore Store files directly.",
		},
	}
}

func validateGuideReferences() error {
	b := buildGuidePayload()
	for _, c := range b.Commands {
		if strings.TrimSpace(c.Name) == "" || strings.TrimSpace(c.Example) == "" {
			return fmt.Errorf("incomplete guide command %+v", c)
		}
	}
	return nil
}

const guideText = `Monorepo-Lore Agent Guide (` + "`lore-mono`" + `)

========================================================================
A. Architecture
========================================================================
- Manager (HTTP API + SQLite): manages users, projects, modules, module
  permissions, snapshot metadata, and indexed commit history. It also runs
  AuthBridge to exchange Identity Tokens for short-lived Lore Access Tokens.
- Lore Gateway: TLS HTTP/2 proxy forwarding Lore CLI gRPC traffic to Lore
  Server. The gateway does not decide permissions; AuthBridge enforces them.
- Project & Module: A Project (for example Kubee) groups independent Modules.
  Each Module maps to its own independent Lore Repository ID and remote URL,
  with separate commit history, revisions, branches, and tags.
- Parent Repository: Stores published immutable snapshot links pinning module
  revisions. It is NOT an operational entry point for ordinary developers and
  is hidden from normal member listings.
- Access Control: Ordinary members only see and access explicitly granted
  modules. Unauthorized and non-existent repositories both return not found.

========================================================================
B. Authentication & Session
========================================================================
- Check login status:
  ` + "`lore-mono project list --config client.toml`" + ` (or ` + "`module list`" + `)
  Succeeds if your persistent session is valid; fails with ` + "`not logged in`" + `
  or ` + "`request failed`" + ` otherwise. You may also inspect Lore's store via
  ` + "`lore auth list`" + ` (using ` + "`LORE_AUTH_STORE`" + `/` + "`LORE_AUTH_PATH`" + ` from ` + "`client.toml`" + `).
- First login:
  ` + "`lore-mono login --config client.toml --username <user>`" + ` (hidden prompt)
  or ` + "`--password-stdin`" + `. Never pass passwords on CLI arguments.
- Persistent Login & Silent Lore Refresh:
  ` + "`login`" + ` stores an exp-free Manager session (` + "`lore-mono-session.tok`" + `) and an
  exp-bearing Lore token. Re-opening terminals or restarting Manager keeps
  the session valid. When running ` + "`lore-mono`" + ` workspace commands (` + "`clone`" + `,
  ` + "`status`" + `, ` + "`sync`" + `, ` + "`stage`" + `, ` + "`commit`" + `, ` + "`push`" + `), ` + "`lore-mono`" + ` silently refreshes
  expired Lore credentials via Manager without prompting for a password.
- Revocation:
  Changing password (` + "`lore-mono password`" + `), disabling an account, or revoking
  a module grant invalidates older tokens or access immediately.
- Secret Hygiene:
  Never write passwords, tokens, or keys into ` + "`client.toml`" + `, argv, git
  commits, or logs. ` + "`ca_file`" + ` sets ` + "`SSL_CERT_FILE`" + ` only on Lore child processes.

========================================================================
C. Repository Discovery Flow
========================================================================
Follow this exact sequence:

  Login -> Project List -> Select Project -> Module List -> Select Module -> Clone

Rules for AI Agents:
1. Never guess Repository IDs.
2. Never guess module names.
3. Treat ` + "`lore-mono module list --config <file>`" + ` as the authoritative list.
4. Clone only the modules needed for the current task (or use
   ` + "`--all-authorized`" + ` when the task explicitly requires the full workspace).
5. ` + "`lore-mono clone`" + ` automatically switches each cloned directory to the
   server-recorded default branch (for example ` + "`master`" + ` or ` + "`main`" + `).

========================================================================
D. Command Reference (verified against current CLI)
========================================================================
Global/config flags accepted by commands:
  --config <file>  --manager <url>  --lore-binary <path>
  --auth-url <url> --auth-path <dir> --auth-store <fallback>

Discovery & Help:
  lore-mono --help
  lore-mono guide [--json]

Authentication:
  lore-mono login [--config file] [--manager url] [--username name] [--password-stdin]
    Authenticate and persist Manager session + Lore credential.
  lore-mono password [--config file] [--password-stdin]
    Update your password and invalidate older sessions.
  lore-mono logout [--config file]
    Clear local Manager session and Lore credential.

Project & Module Discovery:
  lore-mono project list [--config file]
    List accessible projects.
  lore-mono project use <project> [--config file]
    Save default project in client.toml.
  lore-mono module list [--config file]
    List authorized modules, mount paths, permissions, and Lore URLs.

Workspace & Sync:
  lore-mono clone <module> [--config file] [--dest dir]
    Clone one authorized module and check out its default branch.
  lore-mono clone --all-authorized [--config file] [--root dir]
    Clone all authorized modules under --root.
  lore-mono status [--config file]
  lore-mono status <module> [--config file] [--root dir]
  lore-mono status --all [--config file] [--root dir]
    Inspect working tree status (single dir, named module, or all modules).
  lore-mono sync <module> [--config file] [--root dir]
  lore-mono sync --all [--config file] [--root dir]
    Synchronize local cloned module(s) with remote Lore Server.

Change, Stage, Commit & Push:
  lore-mono stage <module> [--config file] [--root dir]
  lore-mono stage --all [--config file] [--root dir]
    Scan & stage local changes in cloned authorized modules (skips uncloned).
  lore-mono commit <module> --message text [--config file] [--root dir]
  lore-mono commit --all --message text [--config file] [--root dir]
    Create one independent Lore commit per staged module.
  lore-mono push <module> [--config file] [--root dir]
  lore-mono push --all [--config file] [--root dir]
    Push committed local branch(es) to remote Lore Server.

History & Inspection:
  lore-mono history [module|--all] [--project name] [--module m] [--branch b]
    [--tag t] [--from rev] [--first-parent] [--author a] [--search q]
    [--since ts] [--until ts] [--merges] [--no-merges] [--order asc|desc]
    [--limit n] [--cursor c] [--all-pages] [--sync] [--json] [--config file]
    Query single-module DAG history or project-aggregated timeline.
  lore-mono refs <module> [--project name] [--type branch|tag] [--json] [--config file]
    List branches and tags recorded for one module.
  lore-mono show <module> <commit-or-revision> [--project name] [--json] [--config file]
    Show commit metadata and module-local parents by Git SHA or Lore revision.

Admin / Migration (requires project_admin / publisher):
  lore-mono import --manifest file [--project name] [--dry-run]
    [--on-conflict fail|skip_if_imported|resume] [--job-key k] [--concurrency n] [--json]
  lore-mono import --source url --module name [--subdir path] [--mount path]
    [--token-env VAR] [--ssh-key file] [--dry-run] ...
  lore-mono import jobs [--project name] [--job id] [--json]
  lore-mono publish [--config file]

Native Lore CLI inside a cloned module directory (when needed for branches):
  lore branch list | lore branch create <branch> | lore branch switch <branch>
  lore status | lore branch archive <branch>
  (Pass LORE_AUTH_STORE/LORE_AUTH_PATH and SSL_CERT_FILE matching client.toml
   if running native lore directly outside lore-mono.)

========================================================================
E. Common Workflows
========================================================================
1. Read-only inspection of one game:
   lore-mono project list --config client.toml
   lore-mono project use Kubee --config client.toml
   lore-mono module list --config client.toml
   lore-mono clone BLITZ_VECTOR --config client.toml --dest ./work/BLITZ_VECTOR
   lore-mono history BLITZ_VECTOR --all-pages --config client.toml
   lore-mono refs BLITZ_VECTOR --config client.toml

2. Modify one game on a temporary branch and submit:
   lore branch create --repository ./work/BLITZ_VECTOR feat/my-change
   lore branch switch --repository ./work/BLITZ_VECTOR feat/my-change
   # modify files inside ./work/BLITZ_VECTOR
   lore-mono stage BLITZ_VECTOR --config client.toml --root ./work
   lore-mono commit BLITZ_VECTOR --message "fix: update config" --config client.toml --root ./work
   lore-mono push BLITZ_VECTOR --config client.toml --root ./work

3. Modify multiple games and submit independently:
   # switch each cloned module to a task branch and edit files
   lore-mono stage --all --config client.toml --root ./work
   lore-mono commit --all --message "chore: batch update" --config client.toml --root ./work
   lore-mono push --all --config client.toml --root ./work

4. View project-wide aggregated history:
   lore-mono history --all --limit 50 --config client.toml
   lore-mono history --all --all-pages --json --config client.toml

========================================================================
F. Operational Constraints
========================================================================
- One Module = one independent Lore repository and independent commit chain.
- Batch commands run once per authorized module; ` + "`commit --all`" + ` creates separate
  revisions per module and NEVER merges changes from multiple modules into one
  revision. Cross-module parent pointers are strictly prohibited.
- Do not access, clone, or mutate the parent repository as a normal user.
- Do not bypass Manager permissions or guess unauthorized Repository IDs.
- ` + "`push`" + `, ` + "`password`" + `, ` + "`import`" + `, and ` + "`publish`" + ` mutate remote state: execute them only when
  explicitly authorized by the task; use temporary branches for test writes
  and do not push to default branches (` + "`master`" + `/` + "`main`" + `) unless asked.
- Never modify server Lore Store files or SQLite directly.
`
