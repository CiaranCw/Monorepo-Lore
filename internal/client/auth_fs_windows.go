//go:build windows

package client

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	winFlagBackupSemantics   = 0x02000000
	winFlagOpenReparsePoint  = 0x00200000
	winAttrDirectory         = 0x00000010
	winAttrReparsePoint      = 0x00000400
	winShareAll              = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
)

// verifyRealDirNoFollow opens dir with FILE_FLAG_OPEN_REPARSE_POINT and checks
// via GetFileInformationByHandle that it is a real directory and NOT a symlink
// or NTFS junction/reparse point.
func verifyRealDirNoFollow(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %s is a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("path %s is not a directory", dir)
	}
	utf16Path, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(
		utf16Path,
		0,
		winShareAll,
		nil,
		syscall.OPEN_EXISTING,
		winFlagBackupSemantics|winFlagOpenReparsePoint,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)

	var data syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &data); err != nil {
		return err
	}
	if data.FileAttributes&winAttrReparsePoint != 0 {
		return fmt.Errorf("path %s is a reparse point/symlink", dir)
	}
	if data.FileAttributes&winAttrDirectory == 0 {
		return fmt.Errorf("path %s is not a directory", dir)
	}
	return nil
}

func verifyRegularFileNoFollow(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("path %s is not a regular file", path)
	}
	utf16Path, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(
		utf16Path,
		0,
		winShareAll,
		nil,
		syscall.OPEN_EXISTING,
		winFlagOpenReparsePoint,
		0,
	)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)

	var data syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &data); err != nil {
		return err
	}
	if data.FileAttributes&winAttrReparsePoint != 0 {
		return fmt.Errorf("path %s is a reparse point/symlink", path)
	}
	if data.FileAttributes&winAttrDirectory != 0 {
		return fmt.Errorf("path %s is a directory", path)
	}
	return nil
}

func ensureAuthRootNoFollow(dir string, createIfMissing bool) error {
	err := verifyRealDirNoFollow(dir)
	if err == nil {
		return nil
	}
	if !createIfMissing || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if mkErr := os.Mkdir(dir, 0o700); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
		return mkErr
	}
	return verifyRealDirNoFollow(dir)
}

func ensureSubdirNoFollow(rootDir, rel string, createMissing bool) error {
	if err := verifyRealDirNoFollow(rootDir); err != nil {
		return err
	}
	if rel == "" || rel == "." {
		return nil
	}
	cur := rootDir
	for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(rel)), "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return fmt.Errorf("invalid relative auth subdir %q", rel)
		}
		cur = filepath.Join(cur, part)
		err := verifyRealDirNoFollow(cur)
		if err != nil && createMissing && errors.Is(err, os.ErrNotExist) {
			if mkErr := os.Mkdir(cur, 0o700); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
				return mkErr
			}
			err = verifyRealDirNoFollow(cur)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func writeAuthFileNoFollow(rootDir, rel string, data []byte) error {
	parentRel := filepath.Dir(rel)
	if err := ensureSubdirNoFollow(rootDir, parentRel, true); err != nil {
		return err
	}
	target := filepath.Join(rootDir, rel)
	if err := verifyRegularFileNoFollow(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parentDir := filepath.Dir(target)
	var (
		tmp string
		f   *os.File
		err error
	)
	for attempt := 0; attempt < 8; attempt++ {
		var rnd [8]byte
		if _, rErr := rand.Read(rnd[:]); rErr != nil {
			return rErr
		}
		tmp = filepath.Join(parentDir, ".lore-tmp-"+hex.EncodeToString(rnd[:]))
		f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if err != nil {
		return err
	}
	_, wErr := f.Write(data)
	cErr := f.Close()
	if wErr != nil {
		_ = os.Remove(tmp)
		return wErr
	}
	if cErr != nil {
		_ = os.Remove(tmp)
		return cErr
	}
	// Re-verify root & parent chain immediately before rename.
	if err := ensureSubdirNoFollow(rootDir, parentRel, false); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removeNewAuthDirSafe(dir string) error {
	err := verifyRealDirNoFollow(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("validate new auth dir %s: %w", dir, err)
	}

	var files []string
	var dirs []string
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
		if p == dir {
			return verifyRealDirNoFollow(p)
		}
		if d.IsDir() {
			if err := verifyRealDirNoFollow(p); err != nil {
				return err
			}
			dirs = append(dirs, p)
			return nil
		}
		if err := verifyRegularFileNoFollow(p); err != nil {
			return err
		}
		files = append(files, p)
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("remove new auth dir %s: %w", dir, walkErr)
	}

	for _, f := range files {
		if err := verifyRealDirNoFollow(filepath.Dir(f)); err != nil {
			return fmt.Errorf("validate parent of %s: %w", f, err)
		}
		if err := rollbackRemove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove new auth file %s: %w", f, err)
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, d := range dirs {
		if err := verifyRealDirNoFollow(d); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("validate subdir %s: %w", d, err)
		}
		if err := rollbackRemove(d); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove new auth subdir %s: %w", d, err)
		}
	}
	if err := verifyRealDirNoFollow(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("validate auth dir %s: %w", dir, err)
	}
	if err := rollbackRemove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove new auth dir %s: %w", dir, err)
	}
	return nil
}

func restoreExistingAuthDirSafe(snap authDirSnapshot) error {
	if err := ensureAuthRootNoFollow(snap.dir, true); err != nil {
		return fmt.Errorf("auth root %s failed directory verification: %w", snap.dir, err)
	}
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
			return verifyRealDirNoFollow(p)
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
		if err := verifyRegularFileNoFollow(p); err != nil {
			return err
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
		if err := ensureSubdirNoFollow(snap.dir, parentRel, false); err != nil {
			errs = append(errs, fmt.Sprintf("verify auth parent %s: %v", parentRel, err))
			continue
		}
		p := filepath.Join(snap.dir, rel)
		if err := verifyRegularFileNoFollow(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("verify new auth file %s: %v", rel, err))
			continue
		}
		if err := rollbackRemove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("remove new auth file %s: %v", rel, err))
		}
	}

	sort.Slice(curDirs, func(i, j int) bool {
		return len(curDirs[i]) > len(curDirs[j])
	})
	for _, rel := range curDirs {
		if _, existed := origDirs[rel]; !existed {
			p := filepath.Join(snap.dir, rel)
			if err := verifyRealDirNoFollow(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("verify new auth subdir %s: %v", rel, err))
				continue
			}
			if err := rollbackRemove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Sprintf("remove new auth subdir %s: %v", rel, err))
			}
		}
	}

	for _, rel := range snap.dirs {
		if err := ensureSubdirNoFollow(snap.dir, rel, true); err != nil {
			errs = append(errs, fmt.Sprintf("restore auth subdir %s: %v", rel, err))
		}
	}

	for rel, data := range snap.files {
		if err := writeAuthFileNoFollow(snap.dir, rel, data); err != nil {
			errs = append(errs, fmt.Sprintf("restore auth file %s: %v", rel, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
