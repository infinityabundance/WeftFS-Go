// Package werr defines the WeftFS store error taxonomy. The interoperable
// contract is the class string; messages are human text. Classes already
// defined by WEFTCODEC-FORMAT §11 and WEFT-SELECTORS §5 keep their exact
// spelling. Store-specific POSIX-ish classes (Busy, Exists, IsDir, NotDir,
// NotEmpty, InvalidName) are documented in README.md.
package werr

import (
	"errors"
	"fmt"

	"github.com/infinityabundance/WeftCodec-Go/werrors"
)

// Kind is a normative error class.
type Kind string

const (
	Busy              Kind = "Busy"
	NotFound          Kind = "NotFound"
	Ambiguous         Kind = "Ambiguous"
	Unauthorized      Kind = "Unauthorized"
	NamespaceMismatch Kind = "NamespaceMismatch"
	ReadOnly          Kind = "ReadOnly"
	Exists            Kind = "Exists"
	NotDir            Kind = "NotDir"
	IsDir             Kind = "IsDir"
	NotEmpty          Kind = "NotEmpty"
	InvalidName       Kind = "InvalidName"
	InvalidArgument   Kind = "InvalidArgument"
	Corrupt           Kind = Kind(werrors.Corrupt)
	Malformed         Kind = Kind(werrors.Malformed)
	LimitExceeded     Kind = Kind(werrors.LimitExceeded)
	NonCanonical      Kind = Kind(werrors.NonCanonical)
	Unsupported       Kind = Kind(werrors.UnsupportedVersion)
	Parse             Kind = Kind(werrors.Parse)
	UnknownSchema     Kind = Kind(werrors.UnknownSchema)
	Io                Kind = Kind(werrors.Io)
)

// Error is a typed store error.
type Error struct {
	Kind  Kind
	Msg   string
	Cause error
}

// Error implements error.
func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Kind, e.Msg) }

// Unwrap exposes the underlying cause.
func (e *Error) Unwrap() error { return e.Cause }

// New builds an error with an explicit class.
func New(kind Kind, msg string) *Error { return &Error{Kind: kind, Msg: msg} }

// Newf builds a formatted error.
func Newf(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...)}
}

// Wrap builds an error with a cause.
func Wrap(kind Kind, cause error, format string, args ...any) *Error {
	return &Error{Kind: kind, Msg: fmt.Sprintf(format, args...), Cause: cause}
}

// FromCodec maps a WeftCodec-Go error into the store taxonomy.
func FromCodec(err error) error {
	if err == nil {
		return nil
	}
	var typed *werrors.Error
	if errors.As(err, &typed) {
		switch typed.Kind {
		case werrors.Malformed:
			return &Error{Kind: Malformed, Msg: typed.Msg, Cause: err}
		case werrors.Corrupt:
			return &Error{Kind: Corrupt, Msg: typed.Msg, Cause: err}
		case werrors.UnsupportedVersion:
			return &Error{Kind: Unsupported, Msg: typed.Msg, Cause: err}
		case werrors.UnsupportedFeature, werrors.UnsupportedMode:
			return &Error{Kind: Malformed, Msg: typed.Msg, Cause: err}
		case werrors.LimitExceeded:
			return &Error{Kind: LimitExceeded, Msg: typed.Msg, Cause: err}
		case werrors.NonCanonical:
			return &Error{Kind: NonCanonical, Msg: typed.Msg, Cause: err}
		case werrors.Parse:
			return &Error{Kind: Parse, Msg: typed.Msg, Cause: err}
		case werrors.UnknownSchema:
			return &Error{Kind: UnknownSchema, Msg: typed.Msg, Cause: err}
		case werrors.DependencyMissing, werrors.DependencyDenied,
			werrors.DependencyMismatch, werrors.DependencyCycle:
			return &Error{Kind: Corrupt, Msg: typed.Msg, Cause: err}
		}
	}
	return &Error{Kind: Io, Msg: err.Error(), Cause: err}
}

// ClassOf extracts the class from any error in the chain.
func ClassOf(err error) Kind {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	return ""
}

// Is reports whether err has the given class.
func Is(err error, kind Kind) bool { return ClassOf(err) == kind }

// Convenience constructors.

func BusyError(msg string) *Error               { return New(Busy, msg) }
func NotFoundError(msg string) *Error           { return New(NotFound, msg) }
func AmbiguousError(msg string) *Error          { return New(Ambiguous, msg) }
func UnauthorizedError(msg string) *Error       { return New(Unauthorized, msg) }
func NamespaceMismatchError(msg string) *Error  { return New(NamespaceMismatch, msg) }
func ReadOnlyError(msg string) *Error           { return New(ReadOnly, msg) }
func ExistsError(msg string) *Error             { return New(Exists, msg) }
func NotDirError(msg string) *Error             { return New(NotDir, msg) }
func IsDirError(msg string) *Error              { return New(IsDir, msg) }
func NotEmptyError(msg string) *Error           { return New(NotEmpty, msg) }
func InvalidNameError(msg string) *Error        { return New(InvalidName, msg) }
func InvalidArgumentError(msg string) *Error    { return New(InvalidArgument, msg) }
func Corruptf(format string, args ...any) error { return Newf(Corrupt, format, args...) }
func Malformedf(format string, args ...any) error {
	return Newf(Malformed, format, args...)
}
func LimitExceededf(format string, args ...any) error {
	return Newf(LimitExceeded, format, args...)
}
func IoErrorf(format string, args ...any) error { return Newf(Io, format, args...) }
