package receiver

import (
	"github.com/spf13/cobra"

	"github.com/metaflowys/metaflow/server/libs/debug"
)

const (
	TRIDENT_ADAPTER_STATUS_CMD = 40
)

// 客户端注册命令
func RegisterTridentStatusCommand() *cobra.Command {
	return debug.ClientRegisterSimple(TRIDENT_ADAPTER_STATUS_CMD,
		debug.CmdHelper{
			Cmd:    "adapter",
			Helper: "show agent status",
		},
		[]debug.CmdHelper{
			debug.CmdHelper{
				Cmd:    "pcap",
				Helper: "show agent pcap status",
			},
			debug.CmdHelper{
				Cmd:    "syslog",
				Helper: "show agent syslog status",
			},
			debug.CmdHelper{
				Cmd:    "statsd",
				Helper: "show agent statsd status",
			},
			debug.CmdHelper{
				Cmd:    "metric",
				Helper: "show agent metric status",
			},
			debug.CmdHelper{
				Cmd:    "l4-log",
				Helper: "show agent l4-flow-log status",
			},
			debug.CmdHelper{
				Cmd:    "l7-log",
				Helper: "show agent l7-http-dns flow log status",
			},
			debug.CmdHelper{
				Cmd:    "otel",
				Helper: "show agent open telemetry data status",
			},
			debug.CmdHelper{
				Cmd:    "prometheus",
				Helper: "show agent prometheus data status",
			},
			debug.CmdHelper{
				Cmd:    "telegraf",
				Helper: "show agent telegraf data status",
			},
			debug.CmdHelper{
				Cmd:    "pkg-seq",
				Helper: "show agent packet sequence data status",
			},
			debug.CmdHelper{
				Cmd:    "dfstatsd",
				Helper: "show agent dfstatsd status",
			},
			debug.CmdHelper{
				Cmd:    "status",
				Helper: "show agent metrics status",
			},
			debug.CmdHelper{
				Cmd:    "all",
				Helper: "show agent all status",
			},
		},
	)
}
