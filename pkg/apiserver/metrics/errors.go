package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// retryAfterSeconds is the Retry-After a concurrency rejection carries. It is
// one source granularity on the coarsest live source, which is how long the
// caller must wait before a retry can see new data anyway.
const retryAfterSeconds = 1

// ErrorKind classifies a metrics read failure. It is the whole client-visible
// error vocabulary: raw ClickHouse text and compiled SQL never reach a client,
// they go to the server log with the request id.
type ErrorKind int

const (
	// KindBadRequest is a guardrail violation, an unknown groupBy, an unknown
	// include token, or an unknown scopeKind. The message lists valid values.
	KindBadRequest ErrorKind = iota
	// KindNotFound is a missing owner object or a missing recipe.
	KindNotFound
	// KindUnprocessable is a recipe or fragment that does not compile.
	KindUnprocessable
	// KindTooManyRequests is the per-apiserver concurrency cap.
	KindTooManyRequests
	// KindUnavailable is a metrics backend that cannot be reached.
	KindUnavailable
	// KindNotImplemented is a build with no metrics backend configured.
	KindNotImplemented
	// KindInternal is a server bug. Its detail never reaches the client.
	KindInternal
)

// Error is a classified metrics read failure. Msg is safe to show a client;
// the wrapped error is not, and is only for the server log.
type Error struct {
	// Kind selects the status code.
	Kind ErrorKind
	// Msg is the client-visible message.
	Msg string
	// Resource and Name name the missing object on a KindNotFound.
	Resource schema.GroupResource
	Name     string
	// err is the unsanitized cause, for the server log only.
	err error
}

func (e *Error) Error() string {
	if e.err != nil {
		return e.Msg + ": " + e.err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.err }

// BadRequest returns a 400 whose message must list the valid values.
func BadRequest(format string, a ...any) *Error {
	return &Error{Kind: KindBadRequest, Msg: fmt.Sprintf(format, a...)}
}

// NotFound returns a 404 for a missing owner object or recipe. A series read
// over an owner that does not exist is a 404, not a 200 full of zeros.
func NotFound(gr schema.GroupResource, name string) *Error {
	return &Error{
		Kind:     KindNotFound,
		Msg:      fmt.Sprintf("%s %q not found", gr.String(), name),
		Resource: gr,
		Name:     name,
	}
}

// Unprocessable returns a 422 with the mapped compiler message.
func Unprocessable(format string, a ...any) *Error {
	return &Error{Kind: KindUnprocessable, Msg: fmt.Sprintf(format, a...)}
}

// TooManyRequests returns a 429 for the concurrency cap.
func TooManyRequests() *Error {
	return &Error{Kind: KindTooManyRequests, Msg: "too many concurrent metrics reads"}
}

// Unavailable returns a 503. The cause is logged, never returned: a backend
// error message states the table layout and the tenancy predicate.
func Unavailable(cause error) *Error {
	return &Error{Kind: KindUnavailable, Msg: "metrics backend unavailable", err: cause}
}

// NotImplemented returns a 501 naming the flags the build is missing, so the
// failure reads as a configuration message and not as a missing path.
func NotImplemented(flags ...string) *Error {
	msg := "no metrics backend is configured"
	if len(flags) > 0 {
		msg += "; set " + strings.Join(flags, ", ")
	}
	return &Error{Kind: KindNotImplemented, Msg: msg}
}

// Internal returns a 500 that hides its cause from the client.
func Internal(cause error) *Error {
	return &Error{Kind: KindInternal, Msg: "internal metrics read error", err: cause}
}

// ToStatusError maps err to the status the client sees. An unclassified error
// becomes a generic internal error, so no backend text can leak by accident. A
// cancelled or timed-out read is a 503, not a 500: the backend did not answer.
func ToStatusError(verb string, err error) error {
	if err == nil {
		return nil
	}

	var statusErr *apierrors.StatusError
	if errors.As(err, &statusErr) {
		return statusErr
	}

	var mErr *Error
	if !errors.As(err, &mErr) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			mErr = Unavailable(err)
		} else {
			mErr = Internal(err)
		}
	}

	switch mErr.Kind {
	case KindBadRequest:
		return apierrors.NewBadRequest(mErr.Msg)
	case KindNotFound:
		return apierrors.NewNotFound(mErr.Resource, mErr.Name)
	case KindUnprocessable:
		return genericStatus(http.StatusUnprocessableEntity, verb, mErr, 0)
	case KindTooManyRequests:
		return apierrors.NewTooManyRequests(mErr.Msg, retryAfterSeconds)
	case KindUnavailable:
		return apierrors.NewServiceUnavailable(mErr.Msg)
	case KindNotImplemented:
		return genericStatus(http.StatusNotImplemented, verb, mErr, 0)
	default:
		// The cause is dropped on purpose: it can carry the compiled SQL.
		return genericStatus(http.StatusInternalServerError, verb, mErr, 0)
	}
}

// genericStatus builds a Status for a code apierrors has no constructor for.
func genericStatus(code int, verb string, e *Error, retryAfter int) error {
	return &apierrors.StatusError{ErrStatus: metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    int32(code),
		Reason:  metav1.StatusReason(http.StatusText(code)),
		Message: e.Msg,
		Details: &metav1.StatusDetails{
			Group:             e.Resource.Group,
			Kind:              e.Resource.Resource,
			Name:              e.Name,
			RetryAfterSeconds: int32(retryAfter),
			Causes: []metav1.StatusCause{{
				Type:    metav1.CauseType(verb),
				Message: e.Msg,
			}},
		},
	}}
}

// StatusCode reports the status code err maps to. It is what a handler logs
// next to the request id, and what a test asserts on.
func StatusCode(err error) int {
	status := ToStatusError("get", err)
	var statusErr *apierrors.StatusError
	if errors.As(status, &statusErr) {
		return int(statusErr.ErrStatus.Code)
	}
	return http.StatusInternalServerError
}
