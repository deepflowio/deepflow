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

package ctl

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/metaflowys/metaflow/cli/ctl/common"
	"github.com/metaflowys/metaflow/server/ingester/ingesterctl/cmd"
)

type Ctl struct{}

func Execute() {
	root := &cobra.Command{
		Use:              "metaflow-ctl",
		Short:            "metaflow server tool",
		TraverseChildren: true,
	}

	root.PersistentFlags().StringP("ip", "i", common.GetDefaultRouteIP(), "metaflow-server service ip")
	root.PersistentFlags().Uint32P("port", "p", 30417, "metaflow-server service port")

	root.AddCommand(RegisterAgentCommand())
	root.AddCommand(RegisterAgentUpgradeCommand())
	root.AddCommand(RegisterAgentGroupCommand())
	root.AddCommand(RegisterAgentGroupConfigCommand())
	root.AddCommand(RegisterDomainCommand())
	root.AddCommand(RegisterTrisolarisCommand())

	cmd.RegisterIngesterCommand(root)

	root.SetArgs(os.Args[1:])
	root.Execute()
}
