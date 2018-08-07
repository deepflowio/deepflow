package main

import (
	"os"

	"github.com/spf13/cobra"

	"gitlab.x.lan/yunshan/droplet/adapt"
	"gitlab.x.lan/yunshan/droplet/dpctl"
)

func regiterCommand() {
	dpctl.RegisterCommand(dpctl.DPCTL_ADAPT, adapt.RegisterCommand)
}

func main() {
	regiterCommand()
	root := &cobra.Command{
		Use:   "droplet-ctl",
		Short: "Droplet Config Tool",
	}
	for _, handler := range dpctl.RegisterHandlers {
		cmd := handler()
		root.AddCommand(cmd)
	}
	root.SetArgs(os.Args[1:])
	root.Execute()
}
