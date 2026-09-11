package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-github/v61/github"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

type ReleaseDownloader interface {
	// String returns the release version.
	String() string

	// DownloadBinary downloads the release binary.
	DownloadBinary(ctx context.Context) (io.ReadCloser, error)
}

// ChecksumDownloader is implemented by releases that can publish a ".sha256"
// sidecar next to the binary.
type ChecksumDownloader interface {
	// DownloadChecksum returns the published SHA-256 digest of the binary in
	// lowercase hex. It returns an empty digest when no checksum is published.
	DownloadChecksum(ctx context.Context) (string, error)
}

var (
	_ ReleaseDownloader  = (*GitHubRelease)(nil)
	_ ChecksumDownloader = (*GitHubRelease)(nil)
	_ ReleaseDownloader  = (*URLRelease)(nil)
	_ ChecksumDownloader = (*URLRelease)(nil)
)

// sha256HexLen is the length of a SHA-256 digest in hexadecimal.
const sha256HexLen = 64

// fetchChecksum reads the ".sha256" sidecar of the binary URL. A missing or
// unreachable sidecar is not an error: the digest is empty and the caller
// skips the check.
func fetchChecksum(ctx context.Context, binURL string) (string, error) {
	sumURL := binURL + ".sha256"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build checksum request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Warnf("No checksum published for Envoy release, skipping verification: url=%s error=%v", sumURL, err)
		return "", nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Warnf("No checksum published for Envoy release, skipping verification: url=%s status=%s", sumURL, resp.Status)
		return "", nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		log.Warnf("No checksum published for Envoy release, skipping verification: url=%s error=%v", sumURL, err)
		return "", nil
	}

	sum, err := parseChecksum(string(body))
	if err != nil {
		return "", fmt.Errorf("bad checksum at %s: %w", sumURL, err)
	}
	return sum, nil
}

// parseChecksum reads the digest from the contents of a ".sha256" file. The
// file holds the digest first, and can hold the file name after it.
func parseChecksum(body string) (string, error) {
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return "", errors.New("checksum file is empty")
	}
	sum := strings.ToLower(fields[0])
	if len(sum) != sha256HexLen || strings.TrimLeft(sum, "0123456789abcdef") != "" {
		return "", fmt.Errorf("%q is not a sha256 digest", fields[0])
	}
	return sum, nil
}

type LatestCachedRelease struct {
	Path    string
	version string
	gh      *GitHubRelease
}

// findLatestVersion takes a list of version strings and returns the latest one.
// It handles both semver (with or without 'v' prefix) and non-semver versions.
func findLatestVersion(versions []string) string {
	if len(versions) == 0 {
		return ""
	}

	// Sort versions
	sort.Slice(versions, func(i, j int) bool {
		// Handle 'v' prefix for semver versions
		vi := versions[i]
		vj := versions[j]

		// Strip 'v' prefix if present for comparison
		if strings.HasPrefix(vi, "v") {
			vi = vi[1:]
		}
		if strings.HasPrefix(vj, "v") {
			vj = vj[1:]
		}

		// Try to parse as semver (major.minor.patch)
		viParts := strings.Split(vi, ".")
		vjParts := strings.Split(vj, ".")

		// Compare each part numerically if possible
		minLen := len(viParts)
		if len(vjParts) < minLen {
			minLen = len(vjParts)
		}

		for k := 0; k < minLen; k++ {
			// Extract the numeric part (handle cases like "1.2.3-alpha")
			viPartBase := viParts[k]
			vjPartBase := vjParts[k]

			// Split at first non-numeric character
			viNumStr := viPartBase
			vjNumStr := vjPartBase

			for idx, c := range viNumStr {
				if c < '0' || c > '9' {
					viNumStr = viNumStr[:idx]
					break
				}
			}

			for idx, c := range vjNumStr {
				if c < '0' || c > '9' {
					vjNumStr = vjNumStr[:idx]
					break
				}
			}

			// Parse as integers
			viNum, viErr := strconv.Atoi(viNumStr)
			vjNum, vjErr := strconv.Atoi(vjNumStr)

			// If both parts are numeric, compare them numerically
			if viErr == nil && vjErr == nil {
				if viNum != vjNum {
					return viNum < vjNum
				}
				// If numeric parts are equal, compare the full parts lexicographically
				if viPartBase != vjPartBase {
					return viPartBase < vjPartBase
				}
			} else {
				// If parts aren't numeric, compare lexicographically
				if viParts[k] != vjParts[k] {
					return viParts[k] < vjParts[k]
				}
			}
		}
		if len(viParts) != len(vjParts) {
			return len(viParts) < len(vjParts)
		}

		return versions[i] < versions[j]
	})

	return versions[len(versions)-1]
}

func (r *LatestCachedRelease) findRelease() {
	// List all directories in r.Path
	entries, err := os.ReadDir(r.Path)
	if err != nil || len(entries) == 0 {
		// If no directories exist or there's an error, use GitHubRelease
		r.gh = &GitHubRelease{}
		return
	}

	// Collect directory names as versions
	versions := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			versions = append(versions, entry.Name())
		}
	}

	// If no versions found, use GitHubRelease
	if len(versions) == 0 {
		r.gh = &GitHubRelease{}
		return
	}

	// Find the latest version
	r.version = findLatestVersion(versions)
}

func (r *LatestCachedRelease) String() string {
	if r.version == "" {
		r.findRelease()
	}
	return r.version
}

func (r *LatestCachedRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	// Make sure we've found a release
	if r.version == "" {
		r.findRelease()
	}

	// If r.version is set, throw an error
	if r.version != "" {
		return nil, fmt.Errorf("downloading from cached release not implemented: %s", r.version)
	}

	// If r.gh is in use, pass the call through
	if r.gh != nil {
		return r.gh.DownloadBinary(ctx)
	}

	return nil, fmt.Errorf("no release available")
}

// GitHubRelease represents a release from GitHub.
type GitHubRelease struct {
	Version string
	Sha     string
	Contrib bool
}

func (r *GitHubRelease) String() string {
	if r.Sha == "" {
		return r.Version
	}
	return fmt.Sprintf("%s@sha256:%s", r.Version, r.Sha)
}

// binaryURL returns the download URL of the release binary. It resolves the
// latest upstream release when no version is set.
func (r *GitHubRelease) binaryURL(ctx context.Context) (string, error) {
	if r.String() == "" {
		c := github.NewClient(nil)
		latest, _, err := c.Repositories.GetLatestRelease(ctx, "envoyproxy", "envoy")
		if err != nil {
			return "", fmt.Errorf("failed to get latest envoy release: %w", err)
		}
		r.Version = latest.GetTagName()
	}

	name := fmt.Sprintf("envoy-%s-%s-%s", strings.TrimPrefix(r.Version, "v"), runtime.GOOS, goArchToPlatform[runtime.GOARCH])
	if r.Contrib {
		name = fmt.Sprintf("envoy-contrib-%s-%s-%s", strings.TrimPrefix(r.Version, "v"), runtime.GOOS, goArchToPlatform[runtime.GOARCH])
	}

	return "https://" + filepath.Join(githubURL, r.Version, name), nil
}

func (r *GitHubRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	downloadURL, err := r.binaryURL(ctx)
	if err != nil {
		return nil, err
	}

	log.Infof("downloading envoy %s from %s", r, downloadURL)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download envoy: %w", err)
	}
	return resp.Body, nil
}

// DownloadChecksum returns the digest published next to the release binary.
func (r *GitHubRelease) DownloadChecksum(ctx context.Context) (string, error) {
	downloadURL, err := r.binaryURL(ctx)
	if err != nil {
		return "", err
	}
	return fetchChecksum(ctx, downloadURL)
}

type URLRelease struct {
	URL string
}

func (r *URLRelease) String() string {
	return filepath.Base(r.URL)
}

func (r *URLRelease) DownloadBinary(ctx context.Context) (io.ReadCloser, error) {
	log.Infof("downloading envoy from %s", r.URL)

	resp, err := http.Get(r.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to download envoy: %w", err)
	}
	return resp.Body, nil
}

// DownloadChecksum returns the digest published next to the release binary.
func (r *URLRelease) DownloadChecksum(ctx context.Context) (string, error) {
	return fetchChecksum(ctx, r.URL)
}
