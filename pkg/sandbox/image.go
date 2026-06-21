package sandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	ocispecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/singleflight"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	orasretry "oras.land/oras-go/v2/registry/remote/retry"
)

// ImageStore manages OCI image pulling and rootfs extraction. Images are
// pulled via ORAS and their layers extracted to a shared rootfs directory.
type ImageStore struct {
	baseDir string // e.g. /run/apoxy/images
	log     *slog.Logger

	mu     sync.Mutex
	images map[string]*ImageInfo // imageRef → info
	flight singleflight.Group    // Deduplicates concurrent pulls for the same image.
}

// ImageInfo holds metadata for a pulled image.
type ImageInfo struct {
	RootFS     string   // Path to extracted rootfs directory.
	Entrypoint []string // Default entrypoint from image config.
	Cmd        []string // Default cmd from image config.
}

// ImageStoreOption configures an ImageStore.
type ImageStoreOption func(*ImageStore)

// WithImageStoreLogger sets the structured logger the store writes pull/extract
// progress to. Defaults to slog.Default().
func WithImageStoreLogger(l *slog.Logger) ImageStoreOption {
	return func(s *ImageStore) {
		if l != nil {
			s.log = l
		}
	}
}

// NewImageStore creates a new ImageStore rooted at baseDir.
func NewImageStore(baseDir string, opts ...ImageStoreOption) *ImageStore {
	s := &ImageStore{
		baseDir: baseDir,
		log:     slog.Default(),
		images:  make(map[string]*ImageInfo),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CachedRefs returns the image references currently resident in the store.
// A caller can use this to prefer a host that already has a revision's image
// when placing work (image affinity).
func (s *ImageStore) CachedRefs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := make([]string, 0, len(s.images))
	for ref := range s.images {
		refs = append(refs, ref)
	}
	return refs
}

// EnsureImage pulls and extracts the OCI image if not cached.
// Returns image info including the path to the extracted rootfs directory.
// Concurrent calls for the same imageRef are deduplicated via singleflight.
func (s *ImageStore) EnsureImage(ctx context.Context, imageRef string) (*ImageInfo, error) {
	s.mu.Lock()
	if info, ok := s.images[imageRef]; ok {
		s.mu.Unlock()
		return info, nil
	}
	s.mu.Unlock()

	// Deduplicate concurrent pulls for the same image.
	v, err, _ := s.flight.Do(imageRef, func() (interface{}, error) {
		// Re-check cache inside singleflight to handle the case where a
		// previous flight completed between our cache check and entering Do.
		s.mu.Lock()
		if info, ok := s.images[imageRef]; ok {
			s.mu.Unlock()
			return info, nil
		}
		s.mu.Unlock()

		return s.pullAndExtract(ctx, imageRef)
	})
	if err != nil {
		return nil, err
	}
	return v.(*ImageInfo), nil
}

// pullAndExtract does the actual OCI pull and layer extraction.
func (s *ImageStore) pullAndExtract(ctx context.Context, imageRef string) (*ImageInfo, error) {
	log := s.log.With("image", imageRef)
	log.Info("Pulling OCI image")

	// Create a temp dir for ORAS file store.
	stageDir, err := os.MkdirTemp(s.baseDir, "stage-*")
	if err != nil {
		return nil, fmt.Errorf("creating stage dir: %w", err)
	}
	defer os.RemoveAll(stageDir)

	// file.New caps unnamed-content pushes at 4 MiB by default; that's
	// where the manifest + image config end up, and many real-world
	// configs exceed it. 1 GiB is well above any practical config.
	fs, err := file.NewWithFallbackLimit(stageDir, 1<<30)
	if err != nil {
		return nil, fmt.Errorf("creating file store: %w", err)
	}
	defer fs.Close()

	repo, err := remote.NewRepository(imageRef)
	if err != nil {
		return nil, fmt.Errorf("creating repository: %w", err)
	}
	repo.Client = &auth.Client{
		Client:     orasretry.DefaultClient,
		Cache:      auth.NewCache(),
		Credential: auth.StaticCredential(repo.Reference.Registry, auth.EmptyCredential),
	}
	// dev: pull over plain HTTP when the registry is listed in
	// CLRK_INSECURE_REGISTRIES (host[:port], comma-separated). Lets a local
	// `clrk`/`apoxy dev` registry on the docker network serve images without TLS;
	// unset in production, so every pull stays HTTPS.
	if isInsecureRegistry(repo.Reference.Registry) {
		repo.PlainHTTP = true
	}

	// Pull manifest + all layers. The platform pin matches what the host can
	// actually exec; bump MaxMetadataBytes well above the 4 MiB default since
	// oras-go uses the same limit for blob caching during copy, and most real
	// images have layers larger than that.
	opts := oras.CopyOptions{
		CopyGraphOptions: oras.CopyGraphOptions{MaxMetadataBytes: 1 << 30},
	}
	opts.WithTargetPlatform(&ocispecv1.Platform{
		Architecture: runtime.GOARCH,
		OS:           "linux",
	})
	desc, err := oras.Copy(ctx, repo, repo.Reference.Reference, fs, "", opts)
	if err != nil {
		return nil, fmt.Errorf("pulling image: %w", err)
	}
	log.Info("Image pulled", "digest", desc.Digest.String())

	// Parse manifest.
	manifestBlob, err := content.FetchAll(ctx, fs, desc)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest: %w", err)
	}
	var manifest ocispecv1.Manifest
	if err := json.Unmarshal(manifestBlob, &manifest); err != nil {
		return nil, fmt.Errorf("unmarshaling manifest: %w", err)
	}

	// Parse image config to get entrypoint/cmd.
	configBlob, err := content.FetchAll(ctx, fs, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("fetching image config: %w", err)
	}
	var imgConfig ocispecv1.Image
	if err := json.Unmarshal(configBlob, &imgConfig); err != nil {
		return nil, fmt.Errorf("unmarshaling image config: %w", err)
	}

	// Extract layers to rootfs.
	rootFS := filepath.Join(s.baseDir, desc.Digest.Encoded(), "rootfs")
	if err := os.MkdirAll(rootFS, 0755); err != nil {
		return nil, fmt.Errorf("creating rootfs dir: %w", err)
	}
	for i, layer := range manifest.Layers {
		log.Info("Extracting layer", "index", i, "digest", layer.Digest.String(), "mediaType", layer.MediaType)
		layerBlob, err := content.FetchAll(ctx, fs, layer)
		if err != nil {
			return nil, fmt.Errorf("fetching layer %d: %w", i, err)
		}
		if err := extractLayer(rootFS, layerBlob, layer.MediaType); err != nil {
			return nil, fmt.Errorf("extracting layer %d: %w", i, err)
		}
	}

	if err := ensureBaseSystemFiles(rootFS); err != nil {
		return nil, fmt.Errorf("ensuring base system files: %w", err)
	}

	info := &ImageInfo{
		RootFS:     rootFS,
		Entrypoint: imgConfig.Config.Entrypoint,
		Cmd:        imgConfig.Config.Cmd,
	}

	s.mu.Lock()
	s.images[imageRef] = info
	s.mu.Unlock()

	log.Info("Image extracted", "rootfs", rootFS)
	return info, nil
}

// ensureBaseSystemFiles fills in /etc files that minimal images
// (curlimages/curl, alpine bare bones, distroless variants) leave out
// but networked code paths inside the sandbox depend on.
//
// /etc/resolv.conf only needs to exist as a placeholder: the per-sandbox
// resolver config is bind-mounted in at container-start time (see
// dns.go). nsswitch.conf is image-wide and not netns-dependent, so we
// write it here once and reuse across sandboxes.
func ensureBaseSystemFiles(rootfs string) error {
	etc := filepath.Join(rootfs, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return err
	}
	// Many images (alpine, curlimages/curl) ship a 0-byte mode-0700
	// placeholder for /etc/resolv.conf. The bind-mount source is what
	// the sandbox actually reads, so the mount-point's content/mode
	// don't matter — we only need the file to exist so the runtime
	// can attach a bind mount over it.
	resolv := filepath.Join(etc, "resolv.conf")
	if _, err := os.Stat(resolv); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(resolv, nil, 0o644); err != nil {
			return fmt.Errorf("creating placeholder /etc/resolv.conf: %w", err)
		}
	}
	// glibc NSS picks up nsswitch.conf to know which name sources to
	// use; without it, some images get stuck on a "files dns" default
	// that the loader doesn't initialize.
	nss := filepath.Join(etc, "nsswitch.conf")
	if _, err := os.Stat(nss); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(nss, []byte("hosts: files dns\n"), 0o644); err != nil {
			return fmt.Errorf("writing /etc/nsswitch.conf: %w", err)
		}
	}
	return nil
}

// extractLayer extracts a tar (optionally gzipped) layer into the rootfs directory,
// handling OCI whiteout files for layer squashing.
//
// All filesystem operations are scoped to an *os.Root pinned at rootFS so that
// neither path-traversal entries (../foo, /etc/passwd) nor symlinks created by
// earlier entries can escape rootFS. A prefix check on filepath.Clean alone is
// not sufficient: it accepts sibling paths sharing the prefix (e.g. a peer
// "rootfs-evil" directory next to "rootfs"), and it does not constrain
// resolution through attacker-controlled symlinks at intermediate components.
func extractLayer(rootFS string, data []byte, mediaType string) error {
	root, err := os.OpenRoot(rootFS)
	if err != nil {
		return fmt.Errorf("opening rootfs: %w", err)
	}
	defer root.Close()

	var r io.Reader = bytes.NewReader(data)

	// Handle gzip-compressed layers.
	if strings.Contains(mediaType, "gzip") {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("creating gzip reader: %w", err)
		}
		defer gr.Close()
		r = gr
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}

		// Skip entries we can't safely place under rootFS: absolute paths and
		// any path that escapes the archive root via "..". *os.Root would
		// reject these too, but rejecting up front keeps a single malicious
		// entry from aborting extraction of the whole layer.
		name := filepath.Clean(hdr.Name)
		if name == "" || name == "." {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			continue
		}

		base := filepath.Base(name)
		dir := filepath.Dir(name)
		if base == ".wh..wh..opq" {
			// Opaque whiteout: remove all children of this directory.
			entries, err := fs.ReadDir(root.FS(), dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				_ = root.RemoveAll(filepath.Join(dir, e.Name()))
			}
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			// File whiteout: remove the named file.
			_ = root.RemoveAll(filepath.Join(dir, strings.TrimPrefix(base, ".wh.")))
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, tarFileMode(hdr.Mode)); err != nil {
				return fmt.Errorf("creating directory %s: %w", name, err)
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return fmt.Errorf("creating parent dir for %s: %w", name, err)
			}
			// Drop any pre-existing entry first: an O_CREATE|O_TRUNC open
			// would otherwise follow a symlink left by a prior layer and
			// truncate its (in-root) target instead of replacing the entry.
			_ = root.Remove(name)
			f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, tarFileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("creating file %s: %w", name, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("writing file %s: %w", name, err)
			}
			f.Close()
		case tar.TypeSymlink:
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return fmt.Errorf("creating parent dir for symlink %s: %w", name, err)
			}
			_ = root.Remove(name)
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				return fmt.Errorf("creating symlink %s: %w", name, err)
			}
		case tar.TypeLink:
			if err := root.MkdirAll(filepath.Dir(name), 0755); err != nil {
				return fmt.Errorf("creating parent dir for hardlink %s: %w", name, err)
			}
			linkSrc := filepath.Clean(hdr.Linkname)
			if filepath.IsAbs(linkSrc) || linkSrc == ".." || strings.HasPrefix(linkSrc, ".."+string(filepath.Separator)) {
				continue
			}
			_ = root.Remove(name)
			if err := root.Link(linkSrc, name); err != nil {
				return fmt.Errorf("creating hardlink %s: %w", name, err)
			}
		}
	}
	return nil
}

// isInsecureRegistry reports whether registry (host[:port]) is listed in the
// CLRK_INSECURE_REGISTRIES env var, in which case the image store pulls from it
// over plain HTTP. This is a dev affordance for a local registry on the docker
// network; it is unset in production.
func isInsecureRegistry(registry string) bool {
	for _, r := range strings.Split(os.Getenv("CLRK_INSECURE_REGISTRIES"), ",") {
		if r = strings.TrimSpace(r); r != "" && r == registry {
			return true
		}
	}
	return false
}

// tarFileMode extracts the 9 permission bits from a tar header mode.
// *os.Root.{MkdirAll,OpenFile} reject any bit outside 0o777 with
// "unsupported file mode" — including ModeSetuid/ModeSetgid/ModeSticky
// (Go represents those as high bits, not the POSIX 0o4000/0o2000/0o1000).
// The runtime layer doesn't preserve those special bits.
func tarFileMode(m int64) os.FileMode {
	return os.FileMode(m & 0o777)
}
