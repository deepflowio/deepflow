package ctl

import (
	"os"

	"github.com/spf13/cobra"
)

type Ctl struct{}

func Execute() {
	root := &cobra.Command{
		Use:   "metaflow-ctl",
		Short: "metaflow server tool",
	}

	root.AddCommand(RegisterAgentCommand())
	root.AddCommand(RegisterAgentGroupCommand())
	root.AddCommand(RegisterAgentGroupConfigCommand())
	root.AddCommand(RegisterDomainCommand())

	root.SetArgs(os.Args[1:])
	root.Execute()
}
