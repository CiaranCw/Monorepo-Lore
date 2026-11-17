package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

type lockTarget struct {
	key  string
	path string
}

// canonicalPathForLock resolves absolute path, cleans separators, and resolves
// symlinks along the longest existing path prefix so equivalent paths across
// relative/slash/case differences map deterministically on Windows and Linux.
func canonicalPathForLock(raw string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)

	cur := abs
	var tail []string
	for {
		resolved, evalErr := filepath.EvalSymlinks(cur)
		if evalErr == nil {
			parts := append([]string{resolved}, tail...)
			return filepath.Clean(filepath.Join(parts...)), nil
		}
		if !errors.Is(evalErr, os.ErrNotExist) {
			// Fall back to cleaned abs path if EvalSymlinks hits permission/dangling link.
			return abs, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
}

func makeLockTarget(lockFilePath string) (lockTarget, error) {
	canon, err := canonicalPathForLock(lockFilePath)
	if err != nil {
		return lockTarget{}, err
	}
	key := canon
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return lockTarget{key: key, path: canon}, nil
}

// connectLockTargets returns the deduplicated, lexicographically sorted lock
// targets for Connect:
//   - Default mode (explicitConfigPath == ""): Manager-level lock (plus auth lock
//     only if ExplicitAuthPath was overridden outside the profile).
//   - Explicit --config mode: locks BOTH the config file path and the auth dir
//     path in a fixed global order so concurrent runs sharing either config or
//     auth serialize without deadlocks.
func connectLockTargets(baseDir, managerURL, explicitConfigPath, authPath, explicitAuthPath string) ([]lockTarget, error) {
	var candidates []string
	if strings.TrimSpace(explicitConfigPath) != "" {
		canonCfg, err := canonicalPathForLock(explicitConfigPath)
		if err != nil {
			return nil, fmt.Errorf("normalize config lock path: %w", err)
		}
		candidates = append(candidates, canonCfg+".lock")
		if strings.TrimSpace(authPath) != "" {
			canonAuth, err := canonicalPathForLock(authPath)
			if err != nil {
				return nil, fmt.Errorf("normalize auth lock path: %w", err)
			}
			candidates = append(candidates, canonAuth+".lock")
		}
	} else {
		sum := sha256.Sum256([]byte(managerURL))
		candidates = append(candidates, filepath.Join(baseDir, "locks", "manager-"+hex.EncodeToString(sum[:8])+".lock"))
		if strings.TrimSpace(explicitAuthPath) != "" && strings.TrimSpace(authPath) != "" {
			canonAuth, err := canonicalPathForLock(authPath)
			if err != nil {
				return nil, fmt.Errorf("normalize auth lock path: %w", err)
			}
			candidates = append(candidates, canonAuth+".lock")
		}
	}

	seen := make(map[string]struct{}, len(candidates))
	targets := make([]lockTarget, 0, len(candidates))
	for _, c := range candidates {
		t, err := makeLockTarget(c)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[t.key]; ok {
			continue
		}
		seen[t.key] = struct{}{}
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].key < targets[j].key
	})
	return targets, nil
}

func acquireConnectLockTarget(ctx context.Context, target lockTarget) (func() error, error) {
	sem := getInProcSem(target.key)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("wait for connect lock: %w", ctx.Err())
	}

	releaseSem := func() { <-sem }

	if err := os.MkdirAll(filepath.Dir(target.path), 0o700); err != nil {
		releaseSem()
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	f, err := os.OpenFile(target.path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		releaseSem()
		return nil, fmt.Errorf("open lock file %s: %w", target.path, err)
	}

	for {
		locked, err := tryLockFile(f)
		if err != nil {
			_ = f.Close()
			releaseSem()
			return nil, fmt.Errorf("lock %s: %w", target.path, err)
		}
		if locked {
			break
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			releaseSem()
			return nil, fmt.Errorf("wait for connect lock %s: %w", target.path, ctx.Err())
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

// acquireConnectLock acquires a single lock path (convenience wrapper used by tests).
func acquireConnectLock(ctx context.Context, lockPath string) (func() error, error) {
	if strings.TrimSpace(lockPath) == "" {
		return func() error { return nil }, nil
	}
	t, err := makeLockTarget(lockPath)
	if err != nil {
		return nil, err
	}
	return acquireConnectLockTarget(ctx, t)
}

// acquireConnectLocks acquires all lock targets in fixed sorted order.
// On partial failure, already-acquired locks are released in reverse order.
func acquireConnectLocks(ctx context.Context, targets []lockTarget) (func() error, error) {
	unlocks := make([]func() error, 0, len(targets))
	releaseAll := func() error {
		var errs []string
		for i := len(unlocks) - 1; i >= 0; i-- {
			if err := unlocks[i](); err != nil {
				errs = append(errs, err.Error())
			}
		}
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	}
	for _, t := range targets {
		u, err := acquireConnectLockTarget(ctx, t)
		if err != nil {
			if rErr := releaseAll(); rErr != nil {
				return nil, fmt.Errorf("%w; %v", err, rErr)
			}
			return nil, err
		}
		unlocks = append(unlocks, u)
	}
	var once sync.Once
	var outErr error
	return func() error {
		once.Do(func() {
			outErr = releaseAll()
		})
		return outErr
	}, nil
}
