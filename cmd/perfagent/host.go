package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Host has the facts of the host that ran the rows.
type Host struct {
	Kernel string `json:"kernel"`
	CPUs   int    `json:"cpus"`
	// EC2 is set with -ec2.
	EC2 *EC2 `json:"ec2,omitempty"`
}

// EC2 has the IMDSv2 facts of the instance.
type EC2 struct {
	InstanceID   string `json:"instance_id"`
	InstanceType string `json:"instance_type"`
	AZ           string `json:"az"`
	AMI          string `json:"ami"`
}

func hostFacts() Host {
	h := Host{CPUs: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(b))
	}
	return h
}

// readIMDS reads the instance facts with an IMDSv2 session token.
func readIMDS(ctx context.Context, base string) (*EC2, error) {
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	token, err := do(ctx, client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/latest/api/token", nil)
		if err == nil {
			req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "300")
		}
		return req, err
	})
	if err != nil {
		return nil, fmt.Errorf("get an IMDSv2 token: %w", err)
	}
	read := func(path string) (string, error) {
		b, err := do(ctx, client, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest/meta-data/"+path, nil)
			if err == nil {
				req.Header.Set("X-aws-ec2-metadata-token", string(token))
			}
			return req, err
		})
		if err != nil {
			return "", fmt.Errorf("read %s from IMDS: %w", path, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	var e EC2
	var errs []error
	for _, f := range []struct {
		path string
		dst  *string
	}{
		{"instance-id", &e.InstanceID},
		{"instance-type", &e.InstanceType},
		{"placement/availability-zone", &e.AZ},
		{"ami-id", &e.AMI},
	} {
		v, err := read(f.path)
		*f.dst = v
		errs = append(errs, err)
	}
	return &e, errors.Join(errs...)
}

// sysctlPath returns the /proc/sys file of a key, for example net.core.rmem_max.
func sysctlPath(key string) string {
	return filepath.Join("/proc/sys", strings.ReplaceAll(key, ".", "/"))
}

// setSysctls writes the host keys and logs each value that the kernel then has.
func setSysctls(m map[string]string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []error
	for _, k := range keys {
		path := sysctlPath(k)
		if err := os.WriteFile(path, []byte(m[k]+"\n"), 0); err != nil {
			errs = append(errs, fmt.Errorf("set sysctl %s: %w", k, err))
			continue
		}
		got, _ := os.ReadFile(path)
		slog.Info("Set sysctl", "key", k, "value", strings.Join(strings.Fields(string(got)), " "))
	}
	return errors.Join(errs...)
}

// loadModules loads the kernel modules. With install, it installs the
// linux-modules-extra package of the running kernel when a module is missing.
func loadModules(ctx context.Context, mods []string, kernel string, install bool) error {
	var missing []string
	for _, m := range mods {
		if out, err := exec.CommandContext(ctx, "modprobe", m).CombinedOutput(); err != nil {
			slog.Warn("Failed to load a kernel module", "module", m, "error", err, "output", strings.TrimSpace(string(out)))
			missing = append(missing, m)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if !install || kernel == "" {
		return fmt.Errorf("cannot load kernel modules %v", missing)
	}
	pkg := "linux-modules-extra-" + kernel
	slog.Info("Installing kernel modules", "package", pkg)
	for _, argv := range [][]string{
		{"apt-get", "-q", "update"},
		{"apt-get", "-yq", "install", pkg},
	} {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, tail(string(out), 10))
		}
	}
	var errs []error
	for _, m := range missing {
		if out, err := exec.CommandContext(ctx, "modprobe", m).CombinedOutput(); err != nil {
			errs = append(errs, fmt.Errorf("modprobe %s: %w: %s", m, err, strings.TrimSpace(string(out))))
		}
	}
	return errors.Join(errs...)
}

// ensureTun makes /dev/net/tun when it is missing. Some container runtimes do not add it.
func ensureTun() error {
	const path = "/dev/net/tun"
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := unix.Mknod(path, unix.S_IFCHR|0o666, int(unix.Mkdev(10, 200))); err != nil {
		return fmt.Errorf("make %s: %w", path, err)
	}
	return nil
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
