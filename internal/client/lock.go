package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	inProcLocksMu sync.Mutex
	inProcLocks   = map[string]chan struct{}{}
)

func getInProcSem(key string) chan struct{} {
	inProcLocksMu.Lock()
	defer inProcLocksMu.Unlock()
	ch, ok := inProcLocks[key]
	if !ok {
		ch = make(chan struct{}, 1)
		inProcLocks[key] = ch
	}
	return ch
}

func connectLockPath(baseDir, managerURL, explicitConfigPath string) string {
	if strings.TrimSpace(explicitConfigPath) != "" {
		abs, err := filepath.Abs(explicitConfigPath)
		if err != nil {
			abs = explicitConfigPath
		}
		return abs + ".lock"
	}
	sum := sha256.Sum256([]byte(managerURL))
	return filepath.Join(baseDir, "locks", "manager-"+hex.EncodeToString(sum[:8])+".lock")
}

// acquireConnectLock acquires both an in-process mutex and an OS kernel-backed
// advisory exclusive file lock on lockPath, polling until acquired or ctx ends.
// Kernel-backed locks are automatically released by the OS on process crash/exit.
func acquireConnectLock(ctx context.Context, lockPath string) (func() error, error) {
	if strings.TrimSpace(lockPath) == "" {
		return func() error { return nil }, nil
	}
	cleanKey := filepath.Clean(lockPath)
	sem := getInProcSem(cleanKey)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for connect lock: %w", ctx.Err())
	}

	releaseSem := func() { <-sem }

	if err := os.MkdirAll(filepath.Dir(cleanKey), 0o700); err != nil {
		releaseSem()
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	f, err := os.OpenFile(cleanKey, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		releaseSem()
		return nil, fmt.Errorf("open lock file %s: %w", cleanKey, err)
	}

	for {
		locked, err := tryLockFile(f)
		if err != nil {
			_ = f.Close()
			releaseSem()
			return nil, fmt.Errorf("lock %s: %w", cleanKey, err)
		}
		if locked {
			break
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			releaseSem()
			return nil, fmt.Errorf("wait for connect lock %s: %w", cleanKey, ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}

	var once sync.Once
	var unlockErr error
	return func() error {
		once.Do(func() {
			var errs []string
			if err := unlockFile(f); err != nil {
				errs = append(errs, err.Error())
			}
			if err := f.Close(); err != nil {
				errs = append(errs, err.Error())
			}
			releaseSem()
			if len(errs) > 0 {
				unlockErr = errors.New("unlock connect lock: " + strings.Join(errs, "; "))
			}
		})
		return unlockErr
	}, nil
}
