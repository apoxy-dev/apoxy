package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"

	"github.com/apoxy-dev/apoxy/pkg/workerd/bundle"
)

// registryPasswordEnv supplies the registry password/token non-interactively
// (CI). Used only together with --username.
const registryPasswordEnv = "APOXY_REGISTRY_PASSWORD"

var (
	bundlePushDir           string
	bundlePushUsername      string
	bundlePushPasswordStdin bool
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Manage compute service bundles",
	Long: `Bundles are the OCI artifacts compute Services run: JS/Wasm modules plus a
manifest describing them. Build one with "apoxy build", push it with
"apoxy bundle push", and reference it from Service.spec.source.oci.`,
}

var bundlePushCmd = &cobra.Command{
	Use:   "push <repo>[:tag]",
	Short: "Push a built bundle to an OCI registry",
	Long: `Packages the staged build output as an OCI artifact and pushes it, printing
the immutable digest to pin in Service.spec.source.oci.digest.

Authentication uses the local docker credential store (the same credentials
"docker push" would use) unless --username is given, in which case the
password is read from --password-stdin or $` + registryPasswordEnv + `.

Examples:
  # Push the default build output
  apoxy bundle push registry.example.com/acme/api

  # Push with an explicit tag and a CI token
  echo "$TOKEN" | apoxy bundle push ghcr.io/acme/api:v3 --username acme-ci --password-stdin`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		repo, dig, err := pushBundleDir(cmd.Context(), args[0], bundlePushDir, bundlePushUsername, bundlePushPasswordStdin)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s@%s\n", repo, dig)
		return nil
	},
}

// pushBundleDir loads the staging dir and pushes it to refArg, returning the
// repo (registry/repository, no tag) and the manifest digest. Shared by
// `apoxy bundle push` and `apoxy deploy`.
func pushBundleDir(ctx context.Context, refArg, dir, username string, passwordStdin bool) (repo, dig string, err error) {
	ref, err := registry.ParseReference(refArg)
	if err != nil {
		return "", "", fmt.Errorf("parsing repository %q: %w", refArg, err)
	}
	tag := ref.Reference
	if strings.Contains(tag, ":") {
		return "", "", fmt.Errorf("push by digest is not possible: the digest is minted by the push itself; pass a repo or repo:tag")
	}

	manifest, modules, err := bundle.LoadDir(dir)
	if err != nil {
		return "", "", fmt.Errorf("loading bundle from %q (run \"apoxy build\" first, or point --dir at a staged bundle): %w", dir, err)
	}

	credFn, err := registryCredentialFunc(ref.Registry, username, passwordStdin)
	if err != nil {
		return "", "", err
	}
	repo = ref.Registry + "/" + ref.Repository
	dst, err := bundle.NewRepository(repo, bundle.WithCredentialFunc(credFn))
	if err != nil {
		return "", "", fmt.Errorf("creating push repository %q: %w", repo, err)
	}
	dig, err = bundle.Push(ctx, dst, tag, manifest, modules)
	if err != nil {
		return "", "", err
	}
	return repo, dig, nil
}

// registryCredentialFunc resolves push credentials: explicit --username with a
// password from stdin or $APOXY_REGISTRY_PASSWORD, else whatever the local
// docker credential store holds for the registry (anonymous when neither
// exists).
func registryCredentialFunc(reg, username string, passwordStdin bool) (auth.CredentialFunc, error) {
	if username != "" {
		password := os.Getenv(registryPasswordEnv)
		if passwordStdin {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil && line == "" {
				return nil, fmt.Errorf("reading password from stdin: %w", err)
			}
			password = strings.TrimRight(line, "\r\n")
		}
		if password == "" {
			return nil, fmt.Errorf("--username requires a password via --password-stdin or $%s", registryPasswordEnv)
		}
		return auth.StaticCredential(reg, auth.Credential{Username: username, Password: password}), nil
	}
	if passwordStdin {
		return nil, fmt.Errorf("--password-stdin requires --username")
	}
	credStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err != nil {
		return nil, fmt.Errorf("loading docker credential store: %w", err)
	}
	return credentials.Credential(credStore), nil
}

func init() {
	bundlePushCmd.Flags().StringVar(&bundlePushDir, "dir", defaultBuildOutDir,
		"Staged bundle directory (the output of \"apoxy build\")")
	bundlePushCmd.Flags().StringVar(&bundlePushUsername, "username", "",
		"Registry username; password comes from --password-stdin or $"+registryPasswordEnv)
	bundlePushCmd.Flags().BoolVar(&bundlePushPasswordStdin, "password-stdin", false,
		"Read the registry password from stdin")
	bundleCmd.AddCommand(bundlePushCmd)
	RootCmd.AddCommand(bundleCmd)
}
