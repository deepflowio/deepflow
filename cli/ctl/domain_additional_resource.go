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
	"io/ioutil"
	"os"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/example"
)

func RegisterDomainAdditionalResourceCommand() *cobra.Command {
	DomainAdditionalResource := &cobra.Command{
		Use:   "additional-resource",
		Short: "additional-resource operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'apply | example'.\n")
		},
	}

	var applyFilename string
	apply := &cobra.Command{
		Use:     "apply",
		Short:   "apply domain additional resource file",
		Example: "deepflow-ctl domain additional-resource apply -f xxx.yaml, use example to see yaml templete",
		Run: func(cmd *cobra.Command, args []string) {
			applyDomainAdditionalResource(cmd, args, applyFilename)
		},
	}
	apply.Flags().StringVarP(&applyFilename, "filename", "f", "", "apply domain additional resource from yaml")
	apply.MarkFlagRequired("filename")

	exampleCmd := &cobra.Command{
		Use:     "example",
		Example: "domain additional-resource example",
		Run: func(cmd *cobra.Command, args []string) {
			exampleDomainAdditionalResourceConfig(cmd)
		},
	}

	DomainAdditionalResource.AddCommand(apply)
	DomainAdditionalResource.AddCommand(exampleCmd)
	return DomainAdditionalResource
}

func applyDomainAdditionalResource(cmd *cobra.Command, args []string, filename string) {
	body, err := loadBodyFromFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/domain-additional-resources/", server.IP, server.Port)
	_, err = common.CURLPerform("PUT", url, body, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func exampleDomainAdditionalResourceConfig(cmd *cobra.Command) {
	fmt.Printf(string(example.YamlDomainAdditionalResourceReader))
}

func loadBodyFromFile(filename string) (map[string]interface{}, error) {
	var body map[string]interface{}
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
