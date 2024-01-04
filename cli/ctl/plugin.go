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

package ctl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/jsonparser"
)

func RegisterPluginCommand() *cobra.Command {
	plugin := &cobra.Command{
		Use:   "plugin",
		Short: "plugin operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list | create | delete.'\n")
		},
	}

	var createType, image, name string
	create := &cobra.Command{
		Use:     "create",
		Short:   "create plugin",
		Example: "deepflow-ctl plugin create --type wasm --image /home/tom/hello.wasm --name hello",
		Run: func(cmd *cobra.Command, args []string) {
			if _, err := os.Stat(image); errors.Is(err, os.ErrNotExist) {
				fmt.Printf("file(%s) not found\n", image)
				return
			}
			if err := createPlugin(cmd, createType, image, name); err != nil {
				fmt.Println(err)
			}
		},
	}
	create.Flags().StringVarP(&createType, "type", "", "", "type of image file, currently supports: wasm | so")
	create.Flags().StringVarP(&image, "image", "", "", "plugin image to upload")
	create.Flags().StringVarP(&name, "name", "", "", "specify a unique alias for image")
	create.MarkFlagsRequiredTogether("type", "image", "name")

	list := &cobra.Command{
		Use:     "list",
		Short:   "list plugin",
		Example: "deepflow-ctl plugin list",
		Run: func(cmd *cobra.Command, args []string) {
			listPlugin(cmd)
		},
	}

	delete := &cobra.Command{
		Use:     "delete",
		Short:   "delete plugin",
		Example: "deepflow-ctl plugin delete <name>\n(get name from command `deepflow-ctl plugin list`)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := deletePlugin(cmd, args); err != nil {
				fmt.Println(err)
			}
		},
	}

	plugin.AddCommand(create)
	plugin.AddCommand(list)
	plugin.AddCommand(delete)
	return plugin
}

func createPlugin(cmd *cobra.Command, t, image, name string) error {
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)
	bodyWriter.WriteField("NAME", name)

	switch t {
	case "wasm":
		bodyWriter.WriteField("TYPE", "1")
	case "so":
		bodyWriter.WriteField("TYPE", "2")
	default:
		return errors.New(fmt.Sprintf("unknown type %s", t))
	}

	fileWriter, err := bodyWriter.CreateFormFile("IMAGE", path.Base(image))
	f, err := os.Open(image)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = io.Copy(fileWriter, f); err != nil {
		return err
	}
	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/plugin/", server.IP, server.Port)
	_, err = common.CURLPostFormData(url, contentType, bodyBuf, []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	return err
}

func listPlugin(cmd *cobra.Command) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/plugin/", server.IP, server.Port)
	response, err := common.CURLPerform("GET", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	if err != nil {
		fmt.Println(err)
		return
	}
	data := response.Get("DATA")
	var (
		typeMaxSize = jsonparser.GetTheMaxSizeOfAttr(data, "TYPE")
		nameMaxSize = jsonparser.GetTheMaxSizeOfAttr(data, "NAME")
	)
	cmdFormat := "%-*s %-*s %-19s\n"
	fmt.Printf(cmdFormat, typeMaxSize, "TYPE", nameMaxSize, "NAME", "UPDATED_AT")
	for i := range data.MustArray() {
		d := data.GetIndex(i)

		fmt.Printf(cmdFormat,
			typeMaxSize, common.PluginType(d.Get("TYPE").MustInt()),
			nameMaxSize, d.Get("NAME").MustString(),
			d.Get("UPDATED_AT").MustString(),
		)
	}
}

func deletePlugin(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("must specify name\nExample: %s", cmd.Example)
	} else if len(args) > 1 {
		return fmt.Errorf("must specify one name\nExample: %s", cmd.Example)
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/plugin/%s/", server.IP, server.Port, args[0])
	_, err := common.CURLPerform("DELETE", url, nil, "", []common.HTTPOption{common.WithTimeout(common.GetTimeout(cmd))}...)
	return err
}
