package registry

import (
	"errors"

	"golang.org/x/sys/unix"
)

func exchangeExport(old, next string) error {
	err := unix.Renameat2(unix.AT_FDCWD, old, unix.AT_FDCWD, next, unix.RENAME_EXCHANGE)
	// Some filesystems report EINVAL for a rename flag they do not implement.
	if err == unix.EINVAL {
		return errors.ErrUnsupported
	}
	return err
}
