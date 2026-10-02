// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
)

// fakeAttacher answers with err, or with an attachment of the spec.
type fakeAttacher struct {
	err error
}

func (f fakeAttacher) Attach(_ context.Context, s AttachmentSpec) (Attachment, error) {
	return Attachment{Name: s.Name, Routes: s.Routes, ID: "id-1", Address: netip.MustParseAddr("fd00::1")}, f.err
}

func (f fakeAttacher) Detach(context.Context, string) error { return f.err }

func (f fakeAttacher) Attachments() []Attachment {
	return []Attachment{{Name: "base", Base: true}, {Name: "x"}}
}

func TestAdminHandler(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		path     string
		body     string
		err      error
		want     int
		wantBody string
	}{
		{name: "list", method: "GET", path: "/v1/attachments", want: 200, wantBody: `"name":"base"`},
		{name: "attach", method: "POST", path: "/v1/attachments", body: `{"name":"x","routes":["10.1.0.0/16"]}`, want: 200, wantBody: `"routes":["10.1.0.0/16"]`},
		{name: "body is not JSON", method: "POST", path: "/v1/attachments", body: `{`, want: 400},
		{name: "unknown field", method: "POST", path: "/v1/attachments", body: `{"name":"x","color":"red"}`, want: 400},
		{name: "route is not a prefix", method: "POST", path: "/v1/attachments", body: `{"name":"x","routes":["10.1.0.0"]}`, want: 400},
		{name: "spec is not valid", method: "POST", path: "/v1/attachments", body: `{"name":"X"}`, err: ErrInvalidAttachment, want: 400},
		{name: "relay refuses the spec", method: "POST", path: "/v1/attachments", body: `{"name":"x"}`, err: rpc.Errorf(rpc.InvalidArgument, "bad"), want: 400},
		{name: "name in use", method: "POST", path: "/v1/attachments", body: `{"name":"x"}`, err: ErrAttachmentExists, want: 409},
		{name: "no relay session", method: "POST", path: "/v1/attachments", body: `{"name":"x"}`, err: errNoRelay, want: 503, wantBody: `"error":"no relay session"`},
		{name: "detach", method: "DELETE", path: "/v1/attachments/x", want: 204},
		{name: "detach an unknown name", method: "DELETE", path: "/v1/attachments/x", err: ErrNoAttachment, want: 404},
		{name: "detach the base", method: "DELETE", path: "/v1/attachments/base", err: ErrBaseAttachment, want: 409},
		{name: "relay fails", method: "DELETE", path: "/v1/attachments/x", err: errors.New("relay is down"), want: 503},
		{name: "unknown method", method: "PUT", path: "/v1/attachments", want: 405},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			AdminHandler(fakeAttacher{err: tc.err}).ServeHTTP(rec, req)
			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.wantBody)
		})
	}
}

func TestAdminUID(t *testing.T) {
	cases := []struct {
		name string
		uid  int
		want bool
	}{
		{name: "this user", uid: os.Getuid(), want: true},
		{name: "root", uid: 0, want: true},
		{name: "other user", uid: os.Getuid() + 1, want: os.Getuid()+1 == 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, adminUID(tc.uid))
		})
	}
}

// adminPath returns a socket path that is short enough for all systems.
func adminPath(t *testing.T) string {
	dir, err := os.MkdirTemp("", "vpc-admin")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "admin.sock")
}

// serveAdmin runs ServeAdmin on path until the end of the test, and returns
// a client for it.
func serveAdmin(t *testing.T, path string, a Attacher) *http.Client {
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- ServeAdmin(ctx, path, a) }()
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, <-served)
		_, err := os.Lstat(path)
		assert.True(t, errors.Is(err, os.ErrNotExist), "the socket is removed")
	})
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	require.Eventually(t, func() bool {
		res, err := c.Get("http://agent/v1/attachments")
		if err == nil {
			_ = res.Body.Close()
		}
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	return c
}

func TestServeAdmin(t *testing.T) {
	cases := []struct {
		name    string
		before  func(t *testing.T, path string) // Makes the file at path.
		wantErr string
	}{
		{name: "no file"},
		{name: "socket of an earlier run", before: func(t *testing.T, path string) {
			ln, err := net.Listen("unix", path)
			require.NoError(t, err)
			ln.(*net.UnixListener).SetUnlinkOnClose(false)
			require.NoError(t, ln.Close())
		}},
		{name: "socket that another process serves", before: func(t *testing.T, path string) {
			ln, err := net.Listen("unix", path)
			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })
		}, wantErr: "another process serves it"},
		{name: "file that is not a socket", before: func(t *testing.T, path string) {
			require.NoError(t, os.WriteFile(path, nil, 0o600))
		}, wantErr: "not a socket"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := adminPath(t)
			if tc.before != nil {
				tc.before(t, path)
			}
			if tc.wantErr != "" {
				assert.ErrorContains(t, ServeAdmin(context.Background(), path, fakeAttacher{}), tc.wantErr)
				return
			}
			c := serveAdmin(t, path, fakeAttacher{})
			fi, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
			res, err := c.Get("http://agent/v1/attachments")
			require.NoError(t, err)
			defer res.Body.Close()
			assert.Equal(t, http.StatusOK, res.StatusCode)
		})
	}
}

// adminCall sends a request to the admin API and decodes the answer into out.
func adminCall(t *testing.T, c *http.Client, method, path, body string, out any) int {
	t.Helper()
	req, err := http.NewRequest(method, "http://agent"+path, strings.NewReader(body))
	require.NoError(t, err)
	res, err := c.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	if out != nil && res.StatusCode == http.StatusOK {
		require.NoError(t, json.Unmarshal(b, out), string(b))
	}
	return res.StatusCode
}

// TestAdmin adds and removes extra attachments of an agent through the admin
// API, while another agent sends to one of them.
func TestAdmin(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a, b := w.agent(t, "a", r, agentOptions{}), w.agent(t, "b", r, agentOptions{})
	a.attached(t)
	eb := b.attached(t)
	echo(t, b.stack, eb.addr, 9001)
	c := serveAdmin(t, adminPath(t), a.a)

	var x1, x2 Attachment
	require.Equal(t, 200, adminCall(t, c, "POST", "/v1/attachments", `{"name":"x-1"}`, &x1))
	require.Equal(t, 200, adminCall(t, c, "POST", "/v1/attachments", `{"name":"x-2","labels":{"app":"web"}}`, &x2))
	var list []Attachment
	require.Equal(t, 200, adminCall(t, c, "GET", "/v1/attachments", "", &list))
	require.Len(t, list, 3)
	assert.Equal(t, []string{"a", "x-1", "x-2"}, []string{list[0].Name, list[1].Name, list[2].Name})
	assert.True(t, list[0].Base)
	assert.Equal(t, x1, list[1])
	assert.Equal(t, map[string]string{"app": "web"}, list[2].Labels)

	// b opens a peer session to x-1.
	echo(t, a.stack, x1.Address, 9002)
	ping(t, b.stack, eb.addr, x1.Address, 9002, "to x-1")
	ping(t, a.stack, x1.Address, eb.addr, 9001, "from x-1")
	pb := onlyPeer(t, b.a)

	assert.Equal(t, 204, adminCall(t, c, "DELETE", "/v1/attachments/x-1", "", nil))
	require.Equal(t, 200, adminCall(t, c, "GET", "/v1/attachments", "", &list))
	assert.Len(t, list, 2)
	require.Eventually(t, func() bool { return !slices.Contains(b.routeSet(), x1.Prefixes[0]) },
		5*time.Second, 10*time.Millisecond, "b gets the remove of the route of x-1")
	require.Eventually(t, func() bool {
		b.a.mu.Lock()
		defer b.a.mu.Unlock()
		return !pb.origin(x1.ID)
	}, 5*time.Second, 10*time.Millisecond, "b removes the grant of x-1")
	assert.Contains(t, b.routeSet(), x2.Prefixes[0])

	cases := []struct {
		method, path, body string
		want               int
	}{
		{"DELETE", "/v1/attachments/a", "", 409},
		{"DELETE", "/v1/attachments/x-1", "", 404},
		{"POST", "/v1/attachments", `{"name":"x-2"}`, 409},
		{"POST", "/v1/attachments", `{"name":"X_3"}`, 400},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.method, " ", tc.path, " ", tc.body), func(t *testing.T) {
			assert.Equal(t, tc.want, adminCall(t, c, tc.method, tc.path, tc.body, nil))
		})
	}
}
