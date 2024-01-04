/*
 * Copyright (c) 2024 Yunshan Networks
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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/server/libs/datatype"
	"github.com/deepflowio/deepflow/server/libs/debug"
)

const (
	TRIDENT_ADAPTER_STATUS_CMD = 40
)

// 客户端注册命令
func RegisterTridentStatusCommand() *cobra.Command {
	operates := []debug.CmdHelper{}
	for i := datatype.MessageType(0); i < datatype.MESSAGE_TYPE_MAX; i++ {
		operates = append(operates, debug.CmdHelper{Cmd: i.String(), Helper: fmt.Sprintf("show agent '%s' status", i)})
	}
	operates = append(operates, debug.CmdHelper{Cmd: "status", Helper: "show agent 'metrics' status"})
	operates = append(operates, debug.CmdHelper{Cmd: "all", Helper: "show all status"})

	return debug.ClientRegisterSimple(TRIDENT_ADAPTER_STATUS_CMD,
		debug.CmdHelper{
			Cmd:    "adapter",
			Helper: "show agent status",
		},
		operates,
	)
}
