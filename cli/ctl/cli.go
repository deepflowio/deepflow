package ctl

import (
	"os"

	"github.com/spf13/cobra"
)

type Ctl struct{}

func Execute() {
	root := &cobra.Command{
		Use:              "metaflow-ctl",
		Short:            "metaflow server tool",
		TraverseChildren: true,
	}

	root.PersistentFlags().StringP("ip", "i", "127.0.0.1", "metaflow-server service ip")
	root.PersistentFlags().Uint32P("port", "p", 30417, "metaflow-server service port")

	root.AddCommand(RegisterAgentCommand())
	root.AddCommand(RegisterAgentGroupCommand())
	root.AddCommand(RegisterAgentGroupConfigCommand())
	root.AddCommand(RegisterDomainCommand())

	root.SetArgs(os.Args[1:])
	root.Execute()
}
