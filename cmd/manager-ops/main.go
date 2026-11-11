// manager-ops provides executable backup, verification, isolated restore drill,
// consistency audit, and per-module quarantine operations for migration operators.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/opsbackup"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	switch args[0] {
	case "backup":
		fs := flag.NewFlagSet("backup", flag.ContinueOnError)
		db := fs.String("db", "", "Manager SQLite database path")
		store := fs.String("store", "", "Lore Store directory")
		imports := fs.String("imports", "", "Import workspace directory")
		keys := fs.String("keys", "", "Signing key directory")
		configs := fs.String("configs", "", "Configuration directory")
		certs := fs.String("certs", "", "TLS certificate directory")
		out := fs.String("out", "", "New/empty backup bundle directory")
		if fs.Parse(args[1:]) != nil {
			return 2
		}
		man, err := opsbackup.CreateBackup(ctx, opsbackup.BackupSpec{
			DatabasePath: *db, StoreDir: *store, ImportsDir: *imports,
			KeysDir: *keys, ConfigsDir: *configs, CertsDir: *certs, OutputDir: *out,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		writeJSON(man)
		return 0

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		bundle := fs.String("bundle", "", "Backup bundle directory")
		if fs.Parse(args[1:]) != nil || *bundle == "" {
			return 2
		}
		if err := opsbackup.VerifyBackup(ctx, *bundle); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		writeJSON(map[string]string{"status": "verified"})
		return 0

	case "restore":
		fs := flag.NewFlagSet("restore", flag.ContinueOnError)
		bundle := fs.String("bundle", "", "Backup bundle directory")
		target := fs.String("target", "", "New/empty isolated restore directory")
		if fs.Parse(args[1:]) != nil || *bundle == "" || *target == "" {
			return 2
		}
		if err := opsbackup.RestoreBackup(ctx, *bundle, *target); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		writeJSON(map[string]string{"status": "restored", "target": *target})
		return 0

	case "audit":
		fs := flag.NewFlagSet("audit", flag.ContinueOnError)
		dbPath := fs.String("db", "", "Manager SQLite database path")
		loreBin := fs.String("lore", "", "Optional Lore CLI binary for physical branch checks")
		authPath := fs.String("auth-path", "", "Optional publisher service credential path")
		if fs.Parse(args[1:]) != nil || *dbPath == "" {
			return 2
		}
		db, err := opsbackup.OpenExistingDatabase(*dbPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer db.Close()
		var lore *loreadapter.Client
		if *loreBin != "" {
			env := map[string]string{}
			if *authPath != "" {
				env["LORE_AUTH_PATH"] = *authPath
			}
			exec := loreexec.Executor{Config: loreexec.Config{Binary: *loreBin, Timeout: 2 * time.Minute, Env: env}}
			lore = &loreadapter.Client{Exec: exec, Env: env}
		}
		report, err := opsbackup.AuditConsistency(ctx, db, lore)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		writeJSON(report)
		if !report.Healthy {
			return 1
		}
		return 0

	case "quarantine-module":
		fs := flag.NewFlagSet("quarantine-module", flag.ContinueOnError)
		dbPath := fs.String("db", "", "Manager SQLite database path")
		projectID := fs.Int64("project-id", 0, "Project id")
		module := fs.String("module", "", "Module name")
		actor := fs.String("actor", "", "Administrative actor username")
		if fs.Parse(args[1:]) != nil || *dbPath == "" || *projectID == 0 || *module == "" || *actor == "" {
			return 2
		}
		db, err := opsbackup.OpenExistingDatabase(*dbPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer db.Close()
		result, err := opsbackup.QuarantineModuleImport(ctx, db, *actor, *projectID, *module)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		writeJSON(result)
		if result.RequiresHumanReview {
			return 3
		}
		return 0

	default:
		usage()
		return 2
	}
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  manager-ops backup --db PATH [--store DIR] [--imports DIR] [--keys DIR] [--configs DIR] [--certs DIR] --out NEW_DIR
  manager-ops verify --bundle DIR
  manager-ops restore --bundle DIR --target NEW_DIR
  manager-ops audit --db PATH [--lore BIN --auth-path DIR]
  manager-ops quarantine-module --db PATH --project-id ID --module NAME --actor USER`)
}
