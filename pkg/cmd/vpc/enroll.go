package vpc

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	apoxyconfig "github.com/apoxy-dev/apoxy/config"
	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
)

// enrollOptions are the flags of vpc enroll.
type enrollOptions struct {
	name string
	out  string
}

// EnrollCmd returns the enroll command. It is in the alpha command tree.
func EnrollCmd() *cobra.Command {
	var o enrollOptions
	cmd := &cobra.Command{
		Use:   "enroll [VPC]",
		Short: "Write an identity file for the hosts of a VPC network",
		Long: `Get a certificate for a VPC network and write it to an identity file. The
default network is "default".

Give the file to each host and run "apoxy alpha vpc connect --identity <file>"
there. Many hosts can connect with one identity file, and they need no API
key. The certificate is valid for 24 hours. Run this command again before that
time and replace the file on each host.

The identity file has a private key. Keep it secret.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vpc := "default"
			if len(args) == 1 {
				vpc = args[0]
			}
			if err := o.validate(); err != nil {
				return err
			}
			cmd.SilenceUsage = true
			c, err := apoxyconfig.DefaultAPIClient()
			if err != nil {
				return err
			}
			cred, err := identity.EnrollFile(cmd.Context(), c.VpcV1alpha1().RESTClient(), vpc, o.name, o.out)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), enrollSummary(cred, o.out))
			return nil
		},
	}
	o.addFlags(cmd)
	return cmd
}

func (o *enrollOptions) addFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.name, "name", "", "Identity name, a DNS label. All hosts that use the file have this name in their certificate.")
	f.StringVar(&o.out, "out", "", "Path of the identity file. The command replaces a file that is there.")
}

// validate checks the flags. Both have no default: the name is for many
// hosts, so the host name is not a correct default.
func (o *enrollOptions) validate() error {
	if o.name == "" {
		return errors.New("set --name to the identity name")
	}
	if err := identity.ValidateAgentName(o.name); err != nil {
		return fmt.Errorf("invalid --name: %w", err)
	}
	if o.out == "" {
		return errors.New("set --out to the path of the identity file")
	}
	return nil
}

// enrollSummary is the output line of enroll. It never has the private key.
func enrollSummary(cred *identity.Credential, path string) string {
	relays := fmt.Sprintf("%d relays", len(cred.Relays))
	if len(cred.Relays) == 1 {
		relays = "1 relay"
	}
	return fmt.Sprintf("Wrote identity file %s: identity %s, %s, certificate expires at %s.",
		path, cred.ID, relays, cred.Cert.NotAfter.UTC().Format(time.RFC3339))
}
