package main

import (
	"context"
	"fmt"
	"os"

	"lore-monorepo/internal/config"
	"lore-monorepo/internal/logging"
	"lore-monorepo/internal/loreadapter"
	"lore-monorepo/internal/loreexec"
	"lore-monorepo/internal/manager"
	"lore-monorepo/internal/publish"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	if flags.help {
		fmt.Fprint(os.Stdout, usage)
		return 0
	}
	if flags.version {
		fmt.Printf("manager %s commit %s\n", manager.Version, manager.Commit)
		return 0
	}
	if flags.configPath == "" {
		fmt.Fprintln(os.Stderr, "manager: -config is required")
		return 2
	}
	cfg, err := config.Load(flags.configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	if flags.check {
		fmt.Println("config ok")
		return 0
	}
	log := logging.New(os.Stdout, logging.ParseLevel(cfg.LogLevel), "manager")
	app, err := manager.New(cfg, log)
	if err != nil {
		log.Error("startup failed", map[string]any{"err": err.Error()})
		return 1
	}
	if cfg.Publish.Workspace != "" && cfg.Publish.ParentURL != "" && cfg.Publish.AuthPath != "" {
		env := map[string]string{}
		if cfg.Publish.AuthStore != "" {
			env["LORE_AUTH_STORE"] = cfg.Publish.AuthStore
		}
		env["LORE_AUTH_PATH"] = cfg.Publish.AuthPath
		if cfg.Publish.CAFile != "" {
			env["SSL_CERT_FILE"] = cfg.Publish.CAFile
		}
		exec := loreexec.Executor{Config: loreexec.Config{Binary: cfg.LoreBinary, Timeout: cfg.CommandTimeout, Env: env}}
		lore := &loreadapter.Client{Exec: exec, Env: env}
		drv := &publish.LoreDriver{Client: lore, ParentURL: cfg.Publish.ParentURL}
		app.PublishDriver = drv
		app.PublishLore = lore
		app.PublishRoot = cfg.Publish.Workspace
	}
	ctx, cancel := manager.NotifyContext(context.Background())
	defer cancel()
	if err := app.Run(ctx); err != nil {
		log.Error("manager exited", map[string]any{"err": err.Error()})
		return 1
	}
	return 0
}

type cliFlags struct {
	configPath string
	version    bool
	check      bool
	help       bool
}

func parseArgs(args []string) (cliFlags, error) {
	var f cliFlags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			f.help = true
		case "-version", "--version":
			f.version = true
		case "-check", "--check":
			f.check = true
		case "-config", "--config":
			if i+1 >= len(args) {
				return f, fmt.Errorf("manager: -config requires a path")
			}
			i++
			f.configPath = args[i]
		default:
			return f, fmt.Errorf("manager: unknown argument %s", args[i])
		}
	}
	return f, nil
}

const usage = `manager runs the Lore monorepo Manager process.

Usage:
  manager -config <file>
  manager -config <file> -check
  manager -version

-config  TOML configuration file. Relative paths inside it are resolved
         against the file's directory.
-check   Validate the configuration and exit. Does not open the database,
         create signing keys, or contact Lore.
-version Print the Manager version.
`
