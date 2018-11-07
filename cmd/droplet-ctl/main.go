package main

import (
	"flag"
	"os"

	"github.com/spf13/cobra"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/dropletctl/rpc"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/queue"
)

func regiterCommand() {
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_QUEUE, queue.RegisterCommand)
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_ADAPTER, adapter.RegisterCommand)
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_LABELER, labeler.RegisterCommand)
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_RPC, rpc.RegisterRpcCommand)
	dropletctl.RegisterCommand(dropletctl.DROPLETCTL_CONFIG, dropletctl.RegisterProfilerCommand)
}

func main() {
	flag.StringVar(&dropletctl.ConfigPath, "f", "/etc/droplet.yaml", "Specify config file location")
	regiterCommand()
	root := &cobra.Command{
		Use:   "droplet-ctl",
		Short: "Droplet Config Tool",
	}
	for _, handler := range dropletctl.RegisterHandlers {
		if handler != nil {
			cmd := handler()
			root.AddCommand(cmd)
		}
	}
	root.GenBashCompletionFile("/usr/share/bash-completion/completions/droplet-ctl")
	root.SetArgs(os.Args[1:])
	root.Execute()
}
