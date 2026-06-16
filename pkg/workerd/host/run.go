// SPDX-License-Identifier: AGPL-3.0-only

package host

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	computev1alpha1 "github.com/apoxy-dev/apoxy/api/compute/v1alpha1"
)

// Main is the workerd-host entry point, invoked after sandbox.DispatchRunsc().
// It installs the PID-1 reaper, constructs the runtime, optionally ensures a
// single resident from flags (the standalone 625-e acceptance harness), and
// blocks until signalled. A full lifecycle controller (APO-796 ServiceManager)
// drives Ensure/Stop on a Runtime instead of using this loop.
func Main() {
	var (
		stateDir     = flag.String("state_dir", "/run/workerd-host/state", "runsc --root state dir")
		rootDir      = flag.String("root_dir", "/run/workerd-host/root", "host staging dir for generated config")
		imageBaseDir = flag.String("image_base_dir", "/run/workerd-host/images", "OCI image extraction dir")
		tenant       = flag.String("tenant", "", "tenant/customer id for the resident")
		revision     = flag.String("revision", "", "ServiceRevision name")
		bundleRepo   = flag.String("bundle_repo", "", "OCI repo of the bundle, e.g. reg/acme/api")
		bundleDigest = flag.String("bundle_digest", "", "bundle digest, e.g. sha256:...")
		socketAddr   = flag.String("socket_addr", "*:8080", "workerd http socket bind address")
	)
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	// PID-1 reaper for the Sentry/gofer orphans (no-op off linux).
	StartChildReaper()

	rt, err := NewRuntime(Config{StateDir: *stateDir, RootDir: *rootDir, ImageBaseDir: *imageBaseDir})
	if err != nil {
		slog.Error("Failed to construct workerd runtime", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := rt.Cleanup(ctx); err != nil {
		slog.Warn("Sandbox cleanup reported an error", "error", err)
	}

	if *tenant != "" && *revision != "" && *bundleRepo != "" && *bundleDigest != "" {
		res, err := rt.Ensure(ctx, ResidentRef{
			Tenant:   *tenant,
			Revision: *revision,
			Bundle:   computev1alpha1.BundleRef{Repo: *bundleRepo, Digest: *bundleDigest},
			Config:   computev1alpha1.ServiceConfigSpec{},
			Socket:   SocketSpec{Kind: HTTPSocket, Addr: *socketAddr},
		})
		if err != nil {
			slog.Error("Failed to start resident workerd", "error", err)
			os.Exit(1)
		}
		slog.Info("Resident workerd serving",
			"tenant", res.Tenant, "revision", res.Revision,
			"sandbox", res.SandboxID, "socket", res.Socket.Addr)
	} else {
		slog.Info("No resident flags set; idling (lifecycle driven externally)")
	}

	<-ctx.Done()
	slog.Info("Shutting down workerd-host")
	if *tenant != "" {
		_ = rt.Stop(context.Background(), *tenant)
	}
}
