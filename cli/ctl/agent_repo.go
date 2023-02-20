/*
 * Copyright (c) 2023 Yunshan Networks
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
	"os/exec"
	"path"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/deepflowio/deepflow/cli/ctl/common"
	"github.com/deepflowio/deepflow/cli/ctl/common/jsonparser"
	"github.com/deepflowio/deepflow/cli/ctl/common/printutil"
)

var (
	BranchRegex   = regexp.MustCompile(`Branch:[\s](.*)`)
	RevCountRegex = regexp.MustCompile(`RevCount:[\s](.*)`)
	CommitIDRegex = regexp.MustCompile(`CommitId:[\s](.*)`)
)

func RegisterRepoCommand() *cobra.Command {
	repo := &cobra.Command{
		Use:   "repo",
		Short: "repo operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'agent'.\n")
		},
	}

	repo.AddCommand(registerAgentCommand())
	return repo
}

func registerAgentCommand() *cobra.Command {
	agent := &cobra.Command{
		Use:   "agent",
		Short: "repo agent operation commands",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with 'list | create | delete'.\n")
		},
	}

	var arch, image, versionImage string
	create := &cobra.Command{
		Use:     "create",
		Short:   "create repo agent",
		Example: "deepflow-ctl repo agent create --arch x86 --image deepflow-agent",
		Run: func(cmd *cobra.Command, args []string) {
			if _, err := os.Stat(image); errors.Is(err, os.ErrNotExist) {
				fmt.Printf("file %s not found\n", image)
				return
			}
			if strings.HasSuffix(image, ".exe") {
				if versionImage == "" {
					printutil.ErrorWithColor("version-image must be set when uploading a window image")
					return
				}
				if _, err := os.Stat(versionImage); errors.Is(err, os.ErrNotExist) {
					fmt.Printf("file %s not found\n", versionImage)
					return
				}
				printutil.WarnfWithColor("make sure %s and %s have the same version", image, versionImage)
			}
			if err := createRepoAgent(cmd, arch, image, versionImage); err != nil {
				fmt.Println(err)
			}
		},
	}
	create.Flags().StringVarP(&arch, "arch", "", "", "arch of deepflow-agent")
	create.Flags().StringVarP(&image, "image", "", "", "deepflow-agent image to upload")
	create.Flags().StringVarP(&versionImage, "version-image", "", "", "deepflow-agent Image to get branch, rev_count and commit_id")
	create.MarkFlagsRequiredTogether("arch", "image")

	list := &cobra.Command{
		Use:     "list",
		Short:   "list repo agent",
		Example: "deepflow-ctl repo agent list",
		Run: func(cmd *cobra.Command, args []string) {
			listRepoAgent(cmd)
		},
	}

	delete := &cobra.Command{
		Use:     "delete",
		Short:   "delete repo agent",
		Example: "deepflow-ctl repo agent delete <name>",
		Run: func(cmd *cobra.Command, args []string) {
			if err := deleteRepoAgent(cmd, args); err != nil {
				fmt.Println(err)
			}
		},
	}

	agent.AddCommand(create)
	agent.AddCommand(list)
	agent.AddCommand(delete)
	return agent
}

func createRepoAgent(cmd *cobra.Command, arch, image, versionImage string) error {
	execImage := image
	if versionImage != "" {
		execImage = versionImage
	}
	agentOutput, err := getAgentOutput(execImage)
	if err != nil {
		return err
	}
	branch, revCount, commitID := getAgentInfo(agentOutput)

	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)
	bodyWriter.WriteField("NAME", path.Base(image))
	bodyWriter.WriteField("ARCH", arch)
	bodyWriter.WriteField("BRANCH", branch)
	bodyWriter.WriteField("REV_COUNT", revCount)
	bodyWriter.WriteField("COMMIT_ID", commitID)
	osStr := "Linux"
	if strings.HasSuffix(image, ".exe") {
		osStr = "Windows"
	}
	bodyWriter.WriteField("OS", osStr)

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
	url := fmt.Sprintf("http://%s:%d/v1/vtap-repo/", server.IP, server.Port)
	resp, err := common.CURLPostFormData(url, contentType, bodyBuf)
	if err != nil {
		return err
	}
	data := resp.Get("DATA")
	data.Get("")
	fmt.Printf("created successfully, os: %s, branch: %s, rev_count: %s, commit_id: %s\n", data.Get("OS").MustString(),
		data.Get("BRANCH").MustString(), data.Get("REV_COUNT").MustString(), data.Get("COMMIT_ID").MustString())
	return nil
}

func getAgentOutput(image string) (string, error) {
	if !path.IsAbs(image) {
		image = "./" + image
	}
	command := image + " -v"
	output, err := exec.Command("/usr/bin/bash", "-c", command).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("command(%v) failed; result: %v, error:%v", command, string(output), err)
	}

	return string(output), nil
}

func getAgentInfo(s string) (branch, revCount, commitID string) {
	branchSubmatch := BranchRegex.FindStringSubmatch(s)
	if len(branchSubmatch) > 1 {
		branch = branchSubmatch[1]
	}
	revCountSubmatch := RevCountRegex.FindStringSubmatch(s)
	if len(revCountSubmatch) > 1 {
		revCount = revCountSubmatch[1]
	}
	commitIDSubmatch := CommitIDRegex.FindStringSubmatch(s)
	if len(commitIDSubmatch) > 1 {
		commitID = commitIDSubmatch[1]
	}
	return
}

func listRepoAgent(cmd *cobra.Command) {
	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-repo/", server.IP, server.Port)
	response, err := common.CURLPerform("GET", url, nil, "")
	if err != nil {
		fmt.Println(err)
		return
	}

	data := response.Get("DATA")
	var (
		nameMaxSize     = jsonparser.GetTheMaxSizeOfAttr(data, "NAME")
		archMaxSize     = jsonparser.GetTheMaxSizeOfAttr(data, "ARCH")
		osMaxSize       = jsonparser.GetTheMaxSizeOfAttr(data, "OS")
		branchMaxSize   = jsonparser.GetTheMaxSizeOfAttr(data, "BRANCH")
		revCountMaxSize = jsonparser.GetTheMaxSizeOfAttr(data, "REV_COUNT")
		commitIDMaxSize = jsonparser.GetTheMaxSizeOfAttr(data, "COMMIT_ID")
	)
	cmdFormat := "%-*s %-*s %-*s %-*s %-*s %-19s %-*s\n"
	fmt.Printf(cmdFormat, nameMaxSize, "NAME", archMaxSize, "ARCH", osMaxSize, "OS", branchMaxSize, "BRANCH",
		revCountMaxSize, "REV_COUNT", "UPDATED_AT", commitIDMaxSize, "COMMIT_ID")
	for i := range data.MustArray() {
		d := data.GetIndex(i)
		fmt.Printf(cmdFormat,
			nameMaxSize, d.Get("NAME").MustString(),
			archMaxSize, d.Get("ARCH").MustString(),
			osMaxSize, d.Get("OS").MustString(),
			branchMaxSize, d.Get("BRANCH").MustString(),
			revCountMaxSize, d.Get("REV_COUNT").MustString(),
			d.Get("UPDATED_AT").MustString(),
			commitIDMaxSize, d.Get("COMMIT_ID").MustString(),
		)
	}
}

func deleteRepoAgent(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("must specify name.\nExample: %s", cmd.Example)
	} else if len(args) > 1 {
		return fmt.Errorf("must specify one name.\nExample: %s", cmd.Example)
	}

	server := common.GetServerInfo(cmd)
	url := fmt.Sprintf("http://%s:%d/v1/vtap-repo/%s/", server.IP, server.Port, args[0])
	_, err := common.CURLPerform("DELETE", url, nil, "")
	if err != nil {
		return err
	}
	return nil
}
