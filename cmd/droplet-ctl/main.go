package main

import (
	"flag"
	"os"

	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/debug"

	"gitlab.x.lan/yunshan/droplet/adapter"
	"gitlab.x.lan/yunshan/droplet/droplet"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/dropletctl/rpc"
	"gitlab.x.lan/yunshan/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/profiler"
	"gitlab.x.lan/yunshan/droplet/queue"
)

func regiterCommand() {
	debug.RegisterCommand(dropletctl.DROPLETCTL_QUEUE, queue.RegisterCommand)
	debug.RegisterCommand(dropletctl.DROPLETCTL_ADAPTER, adapter.RegisterCommand)
	debug.RegisterCommand(dropletctl.DROPLETCTL_LABELER, labeler.RegisterCommand)
	debug.RegisterCommand(dropletctl.DROPLETCTL_RPC, rpc.RegisterRpcCommand)
	debug.RegisterCommand(dropletctl.DROPLETCTL_CONFIG, profiler.RegisterProfilerCommand)
	debug.RegisterCommand(dropletctl.DROPLETCTL_LOGLEVEL, dropletctl.RegisterLoglevelCommand)
}

func main() {
	flag.StringVar(&dropletctl.ConfigPath, "f", "/etc/droplet.yaml", "Specify config file location")
	regiterCommand()
	root := &cobra.Command{
		Use:   "droplet-ctl",
		Short: "Droplet Config Tool",
	}
	for _, command := range debug.GenerateCommand() {
		if command != nil {
			root.AddCommand(command)
		}
	}
	debug.SetIpAndPort(droplet.DEBUG_LISTEN_IP, droplet.DEBUG_LISTEN_PORT)
	root.GenBashCompletionFile("/usr/share/bash-completion/completions/droplet-ctl")
	root.SetArgs(os.Args[1:])
	root.Execute()
}
