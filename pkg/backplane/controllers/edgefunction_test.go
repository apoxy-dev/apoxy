package controllers

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	extensionsv1alpha2 "github.com/apoxy-dev/apoxy/api/extensions/v1alpha2"
)

const testEFName = "router"

// goStoreFixture is a reconciler wired to a fake client, a temp store and an
// httptest apiserver serving /go/<ref>.
type goStoreFixture struct {
	t      *testing.T
	r      *EdgeFunctionRevisionReconciler
	client client.Client
	dir    string

	mu     sync.Mutex
	blobs  map[string][]byte // ref -> bytes served
	mapped map[string]bool
}

func newGoStoreFixture(t *testing.T) *goStoreFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, extensionsv1alpha2.AddToScheme(scheme))

	f := &goStoreFixture{
		t:      t,
		dir:    t.TempDir(),
		blobs:  map[string][]byte{},
		mapped: map[string]bool{},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		data, ok := f.blobs[strings.TrimPrefix(req.URL.Path, "/go/")]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	ef := &extensionsv1alpha2.EdgeFunction{ObjectMeta: metav1.ObjectMeta{Name: testEFName, UID: "ef-uid"}}
	f.client = fake.NewClientBuilder().WithScheme(scheme).WithObjects(ef).Build()
	f.r = NewEdgeFunctionRevisionReconciler(
		f.client, "replica", strings.TrimPrefix(srv.URL, "http://"), nil, f.dir, t.TempDir(), nil,
	)
	f.r.mappedBlobs = func() (map[string]bool, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := make(map[string]bool, len(f.mapped))
		for k, v := range f.mapped {
			out[k] = v
		}
		return out, nil
	}
	return f
}

func (f *goStoreFixture) setMapped(blob string, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mapped[blob] = v
}

// addRevision creates a Ready Go-plugin revision whose ref is its name.
func (f *goStoreFixture) addRevision(name string, data []byte) {
	f.t.Helper()
	f.mu.Lock()
	f.blobs[name] = data
	f.mu.Unlock()
	rev := &extensionsv1alpha2.EdgeFunctionRevision{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: extensionsv1alpha2.GroupVersion.String(),
				Kind:       "EdgeFunction",
				Name:       testEFName,
				UID:        "ef-uid",
				Controller: ptr.To(true),
			}},
		},
		Spec: extensionsv1alpha2.EdgeFunctionRevisionSpec{
			Code: extensionsv1alpha2.EdgeFunctionCodeSource{
				GoPluginSource: &extensionsv1alpha2.GoPluginSource{},
			},
		},
		Status: extensionsv1alpha2.EdgeFunctionRevisionStatus{
			Ref:        name,
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}
	require.NoError(f.t, f.client.Create(context.Background(), rev))
}

func (f *goStoreFixture) deleteRevision(name string) {
	f.t.Helper()
	rev := &extensionsv1alpha2.EdgeFunctionRevision{}
	require.NoError(f.t, f.client.Get(context.Background(), types.NamespacedName{Name: name}, rev))
	require.NoError(f.t, f.client.Delete(context.Background(), rev))
}

func (f *goStoreFixture) reconcile(name string) {
	f.t.Helper()
	_, err := f.r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
	require.NoError(f.t, err)
}

func (f *goStoreFixture) funcSo(ref string) string {
	return filepath.Join(f.dir, ref, goFuncSoName)
}

func (f *goStoreFixture) blobNames() []string {
	f.t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.dir, goBlobsDirName))
	require.NoError(f.t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// blobOf returns the blob name func.so of ref resolves to.
func (f *goStoreFixture) blobOf(ref string) string {
	f.t.Helper()
	target, err := filepath.EvalSymlinks(f.funcSo(ref))
	require.NoError(f.t, err)
	return filepath.Base(target)
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	return fi.Sys().(*syscall.Stat_t).Ino
}

func TestReconcileIdenticalBytesShareBlob(t *testing.T) {
	f := newGoStoreFixture(t)
	data := []byte("identical plugin bytes")
	f.addRevision("router-aaaa", data)
	f.addRevision("router-bbbb", data)
	f.reconcile("router-aaaa")
	f.reconcile("router-bbbb")

	a, err := os.Stat(f.funcSo("router-aaaa"))
	require.NoError(t, err)
	b, err := os.Stat(f.funcSo("router-bbbb"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(a, b))
	assert.Len(t, f.blobNames(), 1)

	got, err := os.ReadFile(f.funcSo("router-bbbb"))
	require.NoError(t, err)
	assert.Equal(t, data, got)

	target, err := os.Readlink(f.funcSo("router-aaaa"))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("..", goBlobsDirName, f.blobOf("router-aaaa")), target)
	assert.Equal(t, os.FileMode(0644), a.Mode().Perm())
}

func TestReconcileDistinctBytes(t *testing.T) {
	f := newGoStoreFixture(t)
	f.addRevision("router-aaaa", []byte("build A"))
	f.addRevision("router-bbbb", []byte("build B"))
	f.reconcile("router-aaaa")
	f.reconcile("router-bbbb")

	assert.Len(t, f.blobNames(), 2)
	assert.NotEqual(t, f.blobOf("router-aaaa"), f.blobOf("router-bbbb"))
}

func TestStoreNeverReplacesBlob(t *testing.T) {
	f := newGoStoreFixture(t)
	data := []byte("build A")
	blob, reused, err := f.r.storeGoPlugin("router-aaaa", data)
	require.NoError(t, err)
	assert.False(t, reused)
	blobPath := filepath.Join(f.dir, goBlobsDirName, blob)
	ino := inode(t, blobPath)

	// A stray temp file and a re-store of the same bytes must not touch the blob.
	stray := filepath.Join(f.dir, goBlobsDirName, goBlobTmpPrefix+"stray")
	require.NoError(t, os.WriteFile(stray, []byte("partial"), 0600))
	blob2, reused, err := f.r.storeGoPlugin("router-bbbb", data)
	require.NoError(t, err)
	assert.True(t, reused)
	assert.Equal(t, blob, blob2)
	assert.Equal(t, ino, inode(t, blobPath))
	assert.Equal(t, ino, inode(t, f.funcSo("router-aaaa")))
	assert.Equal(t, ino, inode(t, f.funcSo("router-bbbb")))

	// A writer that lost the race to publish keeps the existing blob.
	racer := filepath.Join(f.dir, goBlobsDirName, goBlobTmpPrefix+"racer")
	require.NoError(t, os.WriteFile(racer, data, 0644))
	existed, err := linkNoClobber(racer, blobPath)
	require.NoError(t, err)
	assert.True(t, existed)
	assert.Equal(t, ino, inode(t, blobPath))
}

func TestStoreRecoversPartialState(t *testing.T) {
	f := newGoStoreFixture(t)
	data := []byte("build A")
	ref := "router-aaaa"
	f.addRevision(ref, data)

	// Dangling func.so (blob gone), stale temp link and stray blob temp file.
	refDir := filepath.Join(f.dir, ref)
	require.NoError(t, os.MkdirAll(refDir, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(f.dir, goBlobsDirName), 0755))
	require.NoError(t, os.Symlink(filepath.Join("..", goBlobsDirName, "sha256-gone.so"), f.funcSo(ref)))
	require.NoError(t, os.Symlink("nowhere", filepath.Join(refDir, goFuncSoTmpName)))
	stray := filepath.Join(f.dir, goBlobsDirName, goBlobTmpPrefix+"stray")
	require.NoError(t, os.WriteFile(stray, []byte("partial"), 0600))

	f.reconcile(ref)

	got, err := os.ReadFile(f.funcSo(ref))
	require.NoError(t, err)
	assert.Equal(t, data, got)
	_, err = os.Lstat(filepath.Join(refDir, goFuncSoTmpName))
	assert.True(t, errors.Is(err, os.ErrNotExist))

	removed, err := gcBlobs(f.dir, f.r.mappedBlobs)
	require.NoError(t, err)
	assert.Equal(t, []string{goBlobTmpPrefix + "stray"}, removed)
	assert.Equal(t, []string{f.blobOf(ref)}, f.blobNames())
}

func TestReconcileDeletedRevisionCleansRefDir(t *testing.T) {
	t.Run("mapped blob kept", func(t *testing.T) {
		f := newGoStoreFixture(t)
		f.addRevision("router-aaaa", []byte("build A"))
		f.reconcile("router-aaaa")
		blob := f.blobOf("router-aaaa")
		f.setMapped(blob, true)

		f.deleteRevision("router-aaaa")
		f.reconcile("router-aaaa")

		_, err := os.Lstat(filepath.Join(f.dir, "router-aaaa"))
		assert.True(t, errors.Is(err, os.ErrNotExist))
		assert.Equal(t, []string{blob}, f.blobNames())
	})
	t.Run("unmapped blob removed", func(t *testing.T) {
		f := newGoStoreFixture(t)
		f.addRevision("router-aaaa", []byte("build A"))
		f.reconcile("router-aaaa")

		f.deleteRevision("router-aaaa")
		f.reconcile("router-aaaa")

		_, err := os.Lstat(filepath.Join(f.dir, "router-aaaa"))
		assert.True(t, errors.Is(err, os.ErrNotExist))
		assert.Empty(t, f.blobNames())
	})
	t.Run("blob shared with live revision kept", func(t *testing.T) {
		f := newGoStoreFixture(t)
		data := []byte("build A")
		f.addRevision("router-aaaa", data)
		f.addRevision("router-bbbb", data)
		f.reconcile("router-aaaa")
		f.reconcile("router-bbbb")

		f.deleteRevision("router-aaaa")
		f.reconcile("router-aaaa")

		assert.Equal(t, []string{f.blobOf("router-bbbb")}, f.blobNames())
	})
}

func TestOrphanSweep(t *testing.T) {
	f := newGoStoreFixture(t)
	f.addRevision("router-live", []byte("build A"))
	f.reconcile("router-live")
	// Simulate a revision deleted while the backplane was down.
	orphanBlob, _, err := f.r.storeGoPlugin("router-orphan", []byte("build B"))
	require.NoError(t, err)

	require.NoError(t, f.r.sweepOrphans(context.Background()))

	_, err = os.Stat(f.funcSo("router-live"))
	assert.NoError(t, err)
	_, err = os.Lstat(filepath.Join(f.dir, "router-orphan"))
	assert.True(t, errors.Is(err, os.ErrNotExist))
	assert.NotContains(t, f.blobNames(), orphanBlob)
	assert.Equal(t, []string{f.blobOf("router-live")}, f.blobNames())
}

func TestGCBlobsRules(t *testing.T) {
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, goBlobsDirName)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "router-ref"), 0755))
	require.NoError(t, os.MkdirAll(blobsDir, 0755))
	for _, name := range []string{"sha256-ref.so", "sha256-mapped.so", "sha256-unused.so", goBlobTmpPrefix + "1"} {
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, name), []byte(name), 0644))
	}
	require.NoError(t, os.Symlink(filepath.Join("..", goBlobsDirName, "sha256-ref.so"), filepath.Join(dir, "router-ref", goFuncSoName)))
	mapped := func() (map[string]bool, error) { return map[string]bool{"sha256-mapped.so": true}, nil }

	t.Run("proc error removes nothing", func(t *testing.T) {
		removed, err := gcBlobs(dir, func() (map[string]bool, error) { return nil, errors.New("no /proc") })
		assert.Error(t, err)
		assert.Empty(t, removed)
		entries, err := os.ReadDir(blobsDir)
		require.NoError(t, err)
		assert.Len(t, entries, 4)
	})
	t.Run("referenced and mapped kept, rest removed", func(t *testing.T) {
		removed, err := gcBlobs(dir, mapped)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"sha256-unused.so", goBlobTmpPrefix + "1"}, removed)
		entries, err := os.ReadDir(blobsDir)
		require.NoError(t, err)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		assert.ElementsMatch(t, []string{"sha256-ref.so", "sha256-mapped.so"}, names)
	})
}

func TestGCBlobsAbortsOnUnreadableRef(t *testing.T) {
	f := newGoStoreFixture(t)
	f.addRevision("router-aaaa", []byte("build A"))
	f.reconcile("router-aaaa")
	blob := f.blobOf("router-aaaa")

	prior := readlink
	readlink = func(name string) (string, error) {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: syscall.EACCES}
	}
	t.Cleanup(func() { readlink = prior })

	removed, err := gcBlobs(f.dir, f.r.mappedBlobs)
	assert.ErrorIs(t, err, syscall.EACCES)
	assert.Empty(t, removed)
	assert.Equal(t, []string{blob}, f.blobNames())

	// Missing and non-symlink func.so are not errors: neither references a blob.
	readlink = prior
	require.NoError(t, os.MkdirAll(filepath.Join(f.dir, "router-empty"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(f.dir, "router-file"), 0755))
	require.NoError(t, os.WriteFile(f.funcSo("router-file"), nil, 0644))
	removed, err = gcBlobs(f.dir, f.r.mappedBlobs)
	require.NoError(t, err)
	assert.Empty(t, removed)
	assert.Equal(t, []string{blob}, f.blobNames())
}

func TestNotFoundRejectsBadNames(t *testing.T) {
	f := newGoStoreFixture(t)
	f.addRevision("router-aaaa", []byte("build A"))
	f.reconcile("router-aaaa")
	blob := f.blobOf("router-aaaa")
	sentinel := filepath.Join(filepath.Dir(f.dir), "sentinel")
	require.NoError(t, os.WriteFile(sentinel, nil, 0644))

	for _, name := range []string{"..", goBlobsDirName, "router-aaaa/.."} {
		f.reconcile(name)
	}
	require.NoError(t, f.r.cleanupDeletedGoRef(context.Background(), ""))

	assert.Equal(t, []string{blob}, f.blobNames())
	_, err := os.Stat(f.funcSo("router-aaaa"))
	assert.NoError(t, err)
	_, err = os.Stat(sentinel)
	assert.NoError(t, err)
}

func TestProcMappedBlobs(t *testing.T) {
	if _, err := os.Stat("/proc/self/maps"); err != nil {
		t.Skip("requires procfs")
	}
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, goBlobsDirName)
	require.NoError(t, os.MkdirAll(blobsDir, 0755))
	path := filepath.Join(blobsDir, "sha256-mapped.so")
	require.NoError(t, os.WriteFile(path, make([]byte, os.Getpagesize()), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "sha256-idle.so"), []byte("x"), 0644))

	file, err := os.Open(path)
	require.NoError(t, err)
	mem, err := syscall.Mmap(int(file.Fd()), 0, os.Getpagesize(), syscall.PROT_READ, syscall.MAP_SHARED)
	require.NoError(t, err)
	file.Close()
	defer syscall.Munmap(mem)

	got, err := procMappedBlobs(dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"sha256-mapped.so": true}, got)
}
