package store

import (
	"syscall"

	"github.com/infinityabundance/WeftFS-Go/werr"
)

// Errno maps a store error to a POSIX errno for the FUSE frontend.
func Errno(err error) syscall.Errno {
	switch werr.ClassOf(err) {
	case werr.NotFound:
		return syscall.ENOENT
	case werr.Exists:
		return syscall.EEXIST
	case werr.NotDir:
		return syscall.ENOTDIR
	case werr.IsDir:
		return syscall.EISDIR
	case werr.NotEmpty:
		return syscall.ENOTEMPTY
	case werr.ReadOnly:
		return syscall.EROFS
	case werr.Unauthorized:
		return syscall.EACCES
	case werr.InvalidName, werr.InvalidArgument, werr.Parse:
		return syscall.EINVAL
	case werr.LimitExceeded:
		return syscall.EFBIG
	case werr.BudgetExceeded:
		return syscall.EDQUOT
	case werr.Conflict:
		return syscall.EEXIST
	case werr.Busy:
		return syscall.EBUSY
	case werr.Malformed, werr.Corrupt:
		return syscall.EIO
	default:
		return syscall.EIO
	}
}
