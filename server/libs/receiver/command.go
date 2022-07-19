/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package receiver

import (
	"github.com/spf13/cobra"

	"github.com/deepflowys/deepflow/server/libs/debug"
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
