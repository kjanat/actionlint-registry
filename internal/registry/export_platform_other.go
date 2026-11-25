//go:build !darwin && !linux

package registry

import "errors"

func exchangeExport(old, next string) error {
	return errors.ErrUnsupported
}
