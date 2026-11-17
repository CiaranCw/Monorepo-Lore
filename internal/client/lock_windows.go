//go:build windows

package client

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32DLL      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32DLL.NewProc("LockFileEx")
	procUnlockFileEx = kernel32DLL.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	errLockViolation        = syscall.Errno(33)
)

func tryLockFile(f *os.File) (bool, error) {
	var ov syscall.Overlapped
	r1, _, err := procLockFileEx.Call(
		f.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ov)),
	)
	if r1 != 0 {
		return true, nil
	}
	if err == errLockViolation {
		return false, nil
	}
	return false, err
}

func unlockFile(f *os.File) error {
	var ov syscall.Overlapped
	r1, _, err := procUnlockFileEx.Call(
		f.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&ov)),
	)
	if r1 != 0 {
		return nil
	}
	return err
}
