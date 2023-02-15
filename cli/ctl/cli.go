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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/server/ingester/ingesterctl/cmd"
)

type Ctl struct{}

func Execute(version string) {
	root := &cobra.Command{
		Use:              "deepflow-ctl",
		Short:            "deepflow server tool",
		TraverseChildren: true,
	}

	var outputVersion bool
	root.PersistentFlags().BoolVarP(&outputVersion, "version", "v", false, "deepflow-ctl version")
	root.PersistentFlags().StringP("ip", "i", common.GetDefaultRouteIP(), "deepflow-server service ip")
	root.PersistentFlags().Uint32P("api-port", "", 30417, "deepflow-server service http port")
	root.PersistentFlags().Uint32P("rpc-port", "", 30035, "deepflow-server service grpc port")
	root.ParseFlags(os.Args[1:])

	// support output version
	if outputVersion {
		fmt.Printf(version)
		return
	}

	root.AddCommand(RegisterAgentCommand())
	root.AddCommand(RegisterAgentUpgradeCommand())
	root.AddCommand(RegisterAgentGroupCommand())
	root.AddCommand(RegisterAgentGroupConfigCommand())
	root.AddCommand(RegisterDomainCommand())
	root.AddCommand(RegisterSubDomainCommand())
	root.AddCommand(RegisterGenesisCommand())
	root.AddCommand(RegisterCloudCommand())
	root.AddCommand(RegisterRecorderCommand())
	root.AddCommand(RegisterTrisolarisCommand())
	root.AddCommand(RegisterVPCCommend())
	root.AddCommand(RegisterServerCommand())
	root.AddCommand(RegisterRepoCommand())

	cmd.RegisterIngesterCommand(root)

	root.SetArgs(os.Args[1:])
	root.Execute()
}
