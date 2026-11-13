//go:build !windows

package client

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

func verifyRealDirNoFollow(dir string) error {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}

func openAuthRootNoFollow(dir string, createIfMissing bool) (int, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_DIRECTORY | syscall.O_CLOEXEC
	fd, err := syscall.Open(dir, flags, 0)
	if err == nil {
		return fd, nil
	}
	if !createIfMissing || !errors.Is(err, os.ErrNotExist) {
		return -1, err
	}
	if mkErr := os.Mkdir(dir, 0o700); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
		return -1, mkErr
	}
	return syscall.Open(dir, flags, 0)
}

func openSubdirNoFollow(rootFD int, rel string, createMissing bool) (int, error) {
	curFD, err := syscall.Dup(rootFD)
	if err != nil {
		return -1, err
	}
	if rel == "" || rel == "." {
		return curFD, nil
	}
	parts := strings.Split(filepath.ToSlash(filepath.Clean(rel)), "/")
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			_ = syscall.Close(curFD)
			return -1, fmt.Errorf("invalid relative auth subdir %q", rel)
		}
		flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_DIRECTORY | syscall.O_CLOEXEC
		nextFD, err := syscall.Openat(curFD, part, flags, 0)
		if err != nil && createMissing && errors.Is(err, syscall.ENOENT) {
			if mkErr := syscall.Mkdirat(curFD, part, 0o700); mkErr != nil && !errors.Is(mkErr, syscall.EEXIST) {
				_ = syscall.Close(curFD)
				return -1, mkErr
			}
			nextFD, err = syscall.Openat(curFD, part, flags, 0)
		}
		_ = syscall.Close(curFD)
		if err != nil {
			return -1, err
		}
		curFD = nextFD
	}
	return curFD, nil
}

func writeAllFD(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := syscall.Write(fd, data)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		data = data[n:]
	}
	return nil
}

func writeFileAtNoFollow(parentFD int, name string, data []byte) error {
	tmpName := name + ".tmp"
	_ = syscall.Unlinkat(parentFD, tmpName)
	fd, err := syscall.Openat(parentFD, tmpName, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	wErr := writeAllFD(fd, data)
	cErr := syscall.Close(fd)
	if wErr != nil {
		_ = syscall.Unlinkat(parentFD, tmpName)
		return wErr
	}
	if cErr != nil {
		_ = syscall.Unlinkat(parentFD, tmpName)
		return cErr
	}
	if err := syscall.Renameat(parentFD, tmpName, parentFD, name); err != nil {
		_ = syscall.Unlinkat(parentFD, tmpName)
		return err
	}
	return nil
}

func removeNewAuthDirSafe(dir string) error {
	rootFD, err := openAuthRootNoFollow(dir, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("validate new auth dir %s: %w", dir, err)
	}
	_ = syscall.Close(rootFD)

	var subdirs []string
	walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, wErr error) error {
		if wErr != nil {
			if errors.Is(wErr, os.ErrNotExist) {
				return nil
			}
			return wErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in auth dir: %s", p)
		}
		if d.IsDir() {
			if p != dir {
				if err := verifyRealDirNoFollow(p); err != nil {
					return fmt.Errorf("validate auth subdir %s: %w", p, err)
				}
				subdirs = append(subdirs, p)
			}
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular file in auth dir: %s", p)
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("remove new auth dir %s: %w", dir, walkErr)
	}

	rootFD, err = openAuthRootNoFollow(dir, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("re-verify new auth dir %s: %w", dir, err)
	}
	defer syscall.Close(rootFD)

	// Remove files via dirfd-pinned Unlinkat, then subdirs deepest-first, then root.
	var relFiles []string
	var relDirs []string
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, wErr error) error {
		if wErr != nil {
			if errors.Is(wErr, os.ErrNotExist) {
				return nil
			}
			return wErr
		}
		if p == dir {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in auth dir: %s", p)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			relDirs = append(relDirs, rel)
		} else {
			relFiles = append(relFiles, rel)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk new auth dir %s: %w", dir, err)
	}
	for _, rel := range relFiles {
		parentRel := filepath.Dir(rel)
		pFD, err := openSubdirNoFollow(rootFD, parentRel, false)
		if err != nil {
			return fmt.Errorf("open auth parent %s: %w", parentRel, err)
		}
		uErr := syscall.Unlinkat(pFD, filepath.Base(rel))
		_ = syscall.Close(pFD)
		if uErr != nil && !errors.Is(uErr, syscall.ENOENT) {
			return fmt.Errorf("remove new auth file %s: %w", rel, uErr)
		}
	}
	sort.Slice(relDirs, func(i, j int) bool { return len(relDirs[i]) > len(relDirs[j]) })
	for _, rel := range relDirs {
		if err := rollbackRemove(filepath.Join(dir, rel)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove new auth subdir %s: %w", rel, err)
		}
	}
	if err := rollbackRemove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove new auth dir %s: %w", dir, err)
	}
	_ = subdirs
	return nil
}

func restoreExistingAuthDirSafe(snap authDirSnapshot) error {
	rootFD, err := openAuthRootNoFollow(snap.dir, true)
	if err != nil {
		return fmt.Errorf("auth root %s failed no-follow directory verification: %w", snap.dir, err)
	}
	defer syscall.Close(rootFD)

	origDirs := make(map[string]struct{}, len(snap.dirs))
	for _, d := range snap.dirs {
		origDirs[d] = struct{}{}
	}
	var errs []string
	var curDirs []string
	var newFiles []string
	walkErr := filepath.WalkDir(snap.dir, func(p string, d fs.DirEntry, wErr error) error {
		if wErr != nil {
			if errors.Is(wErr, os.ErrNotExist) {
				return nil
			}
			return wErr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in auth dir: %s", p)
		}
		if p == snap.dir {
			if !d.IsDir() {
				return fmt.Errorf("auth path %s is not a directory", p)
			}
			if err := verifyRealDirNoFollow(p); err != nil {
				return fmt.Errorf("auth root %s verification failed: %w", p, err)
			}
			return nil
		}
		rel, err := filepath.Rel(snap.dir, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := verifyRealDirNoFollow(p); err != nil {
				return fmt.Errorf("auth subdir %s verification failed: %w", p, err)
			}
			curDirs = append(curDirs, rel)
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular file in auth dir: %s", p)
		}
		if _, existed := snap.files[rel]; !existed {
			newFiles = append(newFiles, rel)
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("walk auth dir %s: %w", snap.dir, walkErr)
	}

	for _, rel := range newFiles {
		parentRel := filepath.Dir(rel)
		pFD, err := openSubdirNoFollow(rootFD, parentRel, false)
		if err != nil {
			errs = append(errs, fmt.Sprintf("open auth parent %s: %v", parentRel, err))
			continue
		}
		if uErr := syscall.Unlinkat(pFD, filepath.Base(rel)); uErr != nil && !errors.Is(uErr, syscall.ENOENT) {
			errs = append(errs, fmt.Sprintf("remove new auth file %s: %v", rel, uErr))
		}
		_ = syscall.Close(pFD)
	}

	sort.Slice(curDirs, func(i, j int) bool {
		return len(curDirs[i]) > len(curDirs[j])
	})
	for _, rel := range curDirs {
		if _, existed := origDirs[rel]; !existed {
			p := filepath.Join(snap.dir, rel)
			if err := verifyRealDirNoFollow(p); err != nil {
				errs = append(errs, fmt.Sprintf("verify new auth subdir %s: %v", rel, err))
				continue
			}
			if err := rollbackRemove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("remove new auth subdir %s: %v", rel, err))
			}
		}
	}

	for _, rel := range snap.dirs {
		subFD, err := openSubdirNoFollow(rootFD, rel, true)
		if err != nil {
			errs = append(errs, fmt.Sprintf("restore auth subdir %s: %v", rel, err))
			continue
		}
		_ = syscall.Close(subFD)
	}

	for rel, data := range snap.files {
		parentRel := filepath.Dir(rel)
		pFD, err := openSubdirNoFollow(rootFD, parentRel, true)
		if err != nil {
			errs = append(errs, fmt.Sprintf("open auth parent %s: %v", parentRel, err))
			continue
		}
		wErr := writeFileAtNoFollow(pFD, filepath.Base(rel), data)
		_ = syscall.Close(pFD)
		if wErr != nil {
			errs = append(errs, fmt.Sprintf("restore auth file %s: %v", rel, wErr))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
