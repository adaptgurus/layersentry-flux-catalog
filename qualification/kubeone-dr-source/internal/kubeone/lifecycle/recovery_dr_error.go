package lifecycle

import (
	"errors"
	"net/http"
)

// Internal operation failures become HTTP status codes only at the authenticated
// gateway boundary. Automation has no synthetic gateway actor or MFA bypass.
type drActionFailure struct {
	Code int
	Err  error
}

func (e *drActionFailure) Error() string { return e.Err.Error() }
func (e *drActionFailure) Unwrap() error { return e.Err }
func drActionFault(status int, err error) error {
	return &drActionFailure{Code: status, Err: err}
}
func drActionStatus(err error) int {
	var failure *drActionFailure
	if errors.As(err, &failure) && failure.Code >= 400 && failure.Code < 600 {
		return failure.Code
	}
	return http.StatusConflict
}
