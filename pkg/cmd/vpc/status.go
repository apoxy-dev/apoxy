package vpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy/pkg/vpc/agent"
)

// StatusCmd returns the status command. It is in the alpha command tree.
func StatusCmd() *cobra.Command {
	var adminAddr string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the direct paths of a connected host",
		Long: `Show the direct paths of a connected host to its peer hosts. The command
reads the admin API of "apoxy alpha vpc connect": give it the --admin-addr of
that command.

STATE is opening, probing, direct or relay. On direct, the data to the
PREFIXES goes to ADDRESS with no relay. REASON tells why a peer has no direct
path.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			st, err := readStatus(cmd.Context(), adminAddr)
			if err != nil {
				return err
			}
			return writeDirect(cmd.OutOrStdout(), st.Direct)
		},
	}
	cmd.Flags().StringVar(&adminAddr, "admin-addr", "", "Unix socket path of the admin API of the connect command.")
	_ = cmd.MarkFlagRequired("admin-addr")
	return cmd
}

// readStatus gets the status of the agent from its admin API on the unix socket at path.
func readStatus(ctx context.Context, path string) (agent.Status, error) {
	var st agent.Status
	c := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/v1/status", nil)
	if err != nil {
		return st, err
	}
	res, err := c.Do(req)
	if err != nil {
		return st, fmt.Errorf("failed to read the admin API at %s: %w", path, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return st, fmt.Errorf("admin API at %s: status %s", path, res.Status)
	}
	if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
		return st, fmt.Errorf("admin API at %s: %w", path, err)
	}
	return st, nil
}

// writeDirect writes a table with a row for each peer.
func writeDirect(w io.Writer, ds []agent.DirectStatus) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PEER\tSTATE\tADDRESS\tRTT\tPREFIXES\tREASON")
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, d := range ds {
		var addr, rtt string
		if d.Address.IsValid() {
			addr = d.Address.String()
		}
		if d.RTT > 0 {
			rtt = d.RTT.Round(100 * time.Microsecond).String()
		}
		pfx := make([]string, len(d.Prefixes))
		for i, p := range d.Prefixes {
			pfx[i] = p.String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", dash(d.Peer), d.State, dash(addr), dash(rtt), dash(strings.Join(pfx, ",")), dash(d.Reason))
	}
	return tw.Flush()
}
