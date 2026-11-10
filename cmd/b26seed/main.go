package main

import (
	"context"
	"fmt"
	"os"

	"lore-monorepo/internal/database"
	"lore-monorepo/internal/user"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "b26seed needs a database path")
		os.Exit(2)
	}
	password := os.Getenv("B26_PASSWORD")
	if password == "" {
		fmt.Fprintln(os.Stderr, "B26_PASSWORD is required")
		os.Exit(2)
	}
	db, err := database.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "database")
		os.Exit(1)
	}
	defer db.Close()
	ctx := context.Background()
	for _, name := range []string{"carol", "alice", "bob", "dave"} {
		if _, err := user.Create(ctx, db, "b26seed", name, password, "user"); err != nil {
			fmt.Fprintf(os.Stderr, "user %s: exists or rejected\n", name)
			continue
		}
		fmt.Println(name)
	}
	if _, err := user.Create(ctx, db, "b26seed", "publisher", password, "service"); err != nil {
		fmt.Fprintln(os.Stderr, "user publisher: exists or rejected")
	} else {
		fmt.Println("publisher")
	}
}
