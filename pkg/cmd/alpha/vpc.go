package alpha

import (
	"github.com/spf13/cobra"

	"github.com/apoxy-dev/apoxy/pkg/cmd/vpc"
)

var vpcCmd = &cobra.Command{
	Use:   "vpc",
	Short: "Connect hosts to VPC networks",
}

func init() {
	vpcCmd.AddCommand(vpc.ConnectCmd())
}
