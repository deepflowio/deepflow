package receiver

import (
	"github.com/spf13/cobra"
	"gitlab.yunshan.net/yunshan/droplet-libs/debug"
)

const (
	TRIDENT_ADAPTER_STATUS_CMD = 40
)

// 客户端注册命令
func RegisterTridentStatusCommand() *cobra.Command {
	return debug.ClientRegisterSimple(TRIDENT_ADAPTER_STATUS_CMD,
		debug.CmdHelper{
			Cmd:    "adapter",
			Helper: "show trident status",
		},
		[]debug.CmdHelper{
			debug.CmdHelper{
				Cmd:    "pcap",
				Helper: "show trident pcap status",
			},
			debug.CmdHelper{
				Cmd:    "syslog",
				Helper: "show trident syslog status",
			},
			debug.CmdHelper{
				Cmd:    "statsd",
				Helper: "show trident statsd status",
			},
			debug.CmdHelper{
				Cmd:    "metric",
				Helper: "show trident metric status",
			},
			debug.CmdHelper{
				Cmd:    "l4-log",
				Helper: "show trident l4-flow-log status",
			},
			debug.CmdHelper{
				Cmd:    "l7-log",
				Helper: "show trident l7-http-dns flow log status",
			},
			debug.CmdHelper{
				Cmd:    "open_telemetry",
				Helper: "show trident open telemetry data status",
			},
			debug.CmdHelper{
				Cmd:    "dfstatsd",
				Helper: "show trident dfstatsd status",
			},
			debug.CmdHelper{
				Cmd:    "status",
				Helper: "show trident metric status",
			},
			debug.CmdHelper{
				Cmd:    "all",
				Helper: "show trident all status",
			},
		},
	)
}
