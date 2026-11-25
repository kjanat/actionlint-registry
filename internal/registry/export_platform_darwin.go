package registry

import "golang.org/x/sys/unix"

func exchangeExport(old, next string) error {
	return unix.RenameatxNp(unix.AT_FDCWD, old, unix.AT_FDCWD, next, unix.RENAME_SWAP)
}
