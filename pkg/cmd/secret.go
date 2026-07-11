package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"golang.org/x/term"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/config"
)

var secretCmd = &cobra.Command{
	Use:     "secret",
	Aliases: []string{"secrets", "secretstore", "secretstores"},
	Short:   "Manage secret stores and their values",
	Long: `SecretStores hold named secret values that compute Services consume through
secret bindings. Values are write-only: they can be set here but are never
returned by the API — confirm writes via the key digests in 'secret list'.`,
}

var secretCreateScopes []string

var secretCreateCmd = &cobra.Command{
	Use:   "create <store>",
	Short: "Create a secret store",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		for _, sc := range secretCreateScopes {
			if _, _, err := corev1alpha.ParseScope(sc); err != nil {
				return err
			}
		}
		store := &corev1alpha.SecretStore{
			ObjectMeta: metav1.ObjectMeta{Name: args[0]},
			Spec:       corev1alpha.SecretStoreSpec{Scopes: secretCreateScopes},
		}
		if _, err := c.CoreV1alpha().SecretStores().Create(cmd.Context(), store, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("creating secret store %q: %w", args[0], err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "secretstore %q created\n", args[0])
		return nil
	},
}

var secretSetFromFile string

var secretSetCmd = &cobra.Command{
	Use:   "set <store> <key>",
	Short: "Set one secret value (from stdin or --from-file)",
	Long: `Reads the value from --from-file when given, otherwise from stdin.
A trailing newline is stripped from terminal input.

Examples:
  echo -n "$TOKEN" | apoxy secret set my-store api-token
  apoxy secret set my-store tls-key --from-file key.pem`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		value, err := readSecretValue(cmd.InOrStdin())
		if err != nil {
			return err
		}
		return patchSecretValues(cmd.Context(), args[0], map[string]*string{args[1]: &value},
			func() { fmt.Fprintf(cmd.OutOrStdout(), "secretstore %q key %q set\n", args[0], args[1]) })
	},
}

var secretUnsetCmd = &cobra.Command{
	Use:   "unset <store> <key>",
	Short: "Delete one key from a secret store",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return patchSecretValues(cmd.Context(), args[0], map[string]*string{args[1]: nil},
			func() { fmt.Fprintf(cmd.OutOrStdout(), "secretstore %q key %q removed\n", args[0], args[1]) })
	},
}

var secretListCmd = &cobra.Command{
	Use:   "list [<store>]",
	Short: "List secret stores, or one store's keys and value digests",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if len(args) == 1 {
			store, err := c.CoreV1alpha().SecretStores().Get(cmd.Context(), args[0], metav1.GetOptions{})
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "%-24s %s\n", "KEY", "DIGEST")
			for _, k := range store.Status.Keys {
				fmt.Fprintf(out, "%-24s %s\n", k.Name, k.Digest)
			}
			return nil
		}
		stores, err := c.CoreV1alpha().SecretStores().List(cmd.Context(), metav1.ListOptions{})
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-24s %-6s %s\n", "NAME", "KEYS", "SCOPES")
		for i := range stores.Items {
			s := &stores.Items[i]
			fmt.Fprintf(out, "%-24s %-6d %s\n", s.Name, len(s.Status.Keys), strings.Join(s.Spec.Scopes, ","))
		}
		return nil
	},
}

var secretDeleteCmd = &cobra.Command{
	Use:   "delete <store>",
	Short: "Delete a secret store and all its values",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := config.DefaultAPIClient()
		if err != nil {
			return err
		}
		if err := c.CoreV1alpha().SecretStores().Delete(cmd.Context(), args[0], metav1.DeleteOptions{}); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "secretstore %q deleted\n", args[0])
		return nil
	},
}

// readSecretValue reads the whole input; on a terminal it prompts and strips
// one trailing newline so interactive `secret set` behaves as expected.
// File and pipe input is stored byte-exact — a trailing newline in a PEM
// file or a piped blob is part of the value.
func readSecretValue(in io.Reader) (string, error) {
	interactive := false
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		interactive = true
		fmt.Fprint(os.Stderr, "Value (end with Ctrl-D): ")
	}
	raw, err := io.ReadAll(in)
	if err != nil {
		return "", fmt.Errorf("reading secret value: %w", err)
	}
	if !interactive {
		return string(raw), nil
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r"), nil
}

// patchSecretValues merge-patches the store's values subresource: non-nil map
// entries set keys, nil entries delete them (JSON merge-patch null).
func patchSecretValues(ctx context.Context, store string, entries map[string]*string, onSuccess func()) error {
	c, err := config.DefaultAPIClient()
	if err != nil {
		return err
	}
	patch, err := json.Marshal(map[string]any{"data": entries})
	if err != nil {
		return err
	}
	err = c.CoreV1alpha().RESTClient().
		Patch(types.MergePatchType).
		Resource("secretstores").
		Name(store).
		SubResource("values").
		Body(patch).
		Do(ctx).
		Error()
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("secret store %q does not exist; create it with `apoxy secret create %s`", store, store)
	}
	if err != nil {
		return fmt.Errorf("updating values of secret store %q: %w", store, err)
	}
	onSuccess()
	return nil
}

func init() {
	secretCreateCmd.Flags().StringSliceVar(&secretCreateScopes, "scope", nil,
		"Consumer scope, \"<surface>\" or \"<surface>:<name-glob>\" (e.g. compute:frontend-*); repeatable. Empty = open to all consumers")
	secretSetCmd.Flags().StringVar(&secretSetFromFile, "from-file", "",
		"Read the value from a file instead of stdin")
	secretSetCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if secretSetFromFile != "" {
			f, err := os.Open(secretSetFromFile)
			if err != nil {
				return err
			}
			cmd.SetIn(f)
		}
		return nil
	}
	secretCmd.AddCommand(secretCreateCmd, secretSetCmd, secretUnsetCmd, secretListCmd, secretDeleteCmd)
	RootCmd.AddCommand(secretCmd)
}
