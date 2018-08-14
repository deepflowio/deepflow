package main

import (
	"os"

	"github.com/spf13/cobra"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
)

func regiterCommand() {
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_ADAPTER, adapter.RegisterCommand)
}

func main() {
	regiterCommand()
	root := &cobra.Command{
		Use:   "droplet-ctl",
		Short: "Droplet Config Tool",
	}
	for _, handler := range dropletctl.RegisterHandlers {
		cmd := handler()
		root.AddCommand(cmd)
	}
	root.SetArgs(os.Args[1:])
	root.Execute()
}
