package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// attempts is the number of tries of each HTTP request.
const attempts = 4

var retryBase = time.Second

// statusError is an HTTP response with a status other than 200.
type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.code, e.body)
}

// do sends the request that newReq makes. It tries again after a network
// error, a 429 or a 5xx, and returns the body of a 200 response.
func do(ctx context.Context, client *http.Client, newReq func() (*http.Request, error)) ([]byte, error) {
	var err error
	for i := range attempts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, errors.Join(err, ctx.Err())
			case <-time.After(retryBase << (i - 1)):
			}
		}
		var body []byte
		body, err = doOnce(client, newReq)
		var se *statusError
		if err == nil || (errors.As(err, &se) && se.code != http.StatusTooManyRequests && se.code < 500) {
			return body, err
		}
		if ctx.Err() != nil {
			return nil, errors.Join(err, ctx.Err())
		}
		slog.Warn("HTTP request failed; trying again", "attempt", i+1, "error", err)
	}
	return nil, err
}

func doOnce(client *http.Client, newReq func() (*http.Request, error)) ([]byte, error) {
	req, err := newReq()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, redact(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, redact(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &statusError{code: resp.StatusCode, body: string(bytes.TrimSpace(body[:min(len(body), 512)]))}
	}
	return body, nil
}

// redact removes the query of a URL in an error, because it has the presigned signature.
func redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if u, perr := url.Parse(ue.URL); perr == nil {
			u.RawQuery = ""
			return &url.Error{Op: ue.Op, URL: u.String(), Err: ue.Err}
		}
	}
	return err
}

func get(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	return do(ctx, client, func() (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	})
}

// put sends data with a presigned PUT URL.
func put(ctx context.Context, client *http.Client, u string, data []byte) error {
	_, err := do(ctx, client, func() (*http.Request, error) {
		// A bytes.Reader body sets Content-Length, which S3 needs.
		return http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	})
	return err
}

// fetch puts f in dir with the file mode, and checks its SHA-256.
func fetch(ctx context.Context, client *http.Client, f File, dir string, mode os.FileMode) error {
	path := filepath.Join(dir, f.Name)
	if f.URL != "" {
		data, err := get(ctx, client, f.URL)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", f.Name, err)
		}
		if got := sha256Hex(data); got != f.SHA256 {
			return fmt.Errorf("fetch %s: sha256 is %s, want %s", f.Name, got, f.SHA256)
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, mode); err != nil {
			return err
		}
		return os.Rename(tmp, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s has no URL and is not in %s: %w", f.Name, dir, err)
	}
	if got := sha256Hex(data); got != f.SHA256 {
		return fmt.Errorf("%s: sha256 is %s, want %s", f.Name, got, f.SHA256)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() == mode {
		return err
	}
	return os.Chmod(path, mode)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
