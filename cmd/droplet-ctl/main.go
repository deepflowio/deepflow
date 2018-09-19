package main

import (
	"os"

	"github.com/spf13/cobra"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/queue"
)

func regiterCommand() {
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_QUEUE, queue.RegisterCommand)
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_ADAPTER, adapter.RegisterCommand)
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_LABELER, labeler.RegisterCommand)
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
	root.GenBashCompletionFile("/usr/share/bash-completion/completions/droplet-ctl")
	root.SetArgs(os.Args[1:])
	root.Execute()
}
