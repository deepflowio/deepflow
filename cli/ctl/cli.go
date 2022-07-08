package ctl

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/metaflowys/metaflow/cli/ctl/common"
	"github.com/metaflowys/metaflow/server/ingester/ingesterctl/cmd"
)

type Ctl struct{}

func Execute() {
	root := &cobra.Command{
		Use:              "metaflow-ctl",
		Short:            "metaflow server tool",
		TraverseChildren: true,
	}

	root.PersistentFlags().StringP("ip", "i", common.GetDefaultRouteIP(), "metaflow-server service ip")
	root.PersistentFlags().Uint32P("port", "p", 30417, "metaflow-server service port")

	root.AddCommand(RegisterAgentCommand())
	root.AddCommand(RegisterAgentGroupCommand())
	root.AddCommand(RegisterAgentGroupConfigCommand())
	root.AddCommand(RegisterDomainCommand())
	root.AddCommand(RegisterTrisolarisCommand())

	cmd.RegisterIngesterCommand(root)

	root.SetArgs(os.Args[1:])
	root.Execute()
}
