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

package debug

import (
	"bytes"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

// 增加简单的命令接口, 支持一个字符串输入参数
type CommandSimpleProcess interface {
	HandleSimpleCommand(operate uint16, arg string) string
}

type CmdHelper struct {
	Cmd    string
	Helper string
}

var (
	simpleHandlers = [MODULE_MAX * 2]CommandSimpleProcess{}
)

// server端注册简单命令, module值要大于MODULE_MAX, 小于2*MODULE_MAX
func ServerRegisterSimple(module ModuleId, process CommandSimpleProcess) {
	simpleHandlers[module] = process
	if running == false {
		debugListener()
		running = true
	}
}

// client注册命令
func ClientRegisterSimple(moduleId ModuleId, module CmdHelper, operates []CmdHelper) *cobra.Command {
	command := &cobra.Command{
		Use:   module.Cmd,
		Short: module.Helper,
		Run: func(cmd *cobra.Command, args []string) {
			if len(operates) == 0 {
				arg := ""
				if len(args) > 0 {
					arg = args[0]
				}
				result, err := CommmandGetResult(moduleId, 0, arg)
				if err != nil {
					fmt.Println("Get result failed", err)
					return
				}
				fmt.Println(result)
				return
			}
			fmt.Printf("please run with arguments: ")
			for _, operate := range operates {
				fmt.Printf("'%s' ", operate.Cmd)
			}
			fmt.Println()
		},
	}

	for i, operate := range operates {
		op := i
		sub := &cobra.Command{
			Use:   operate.Cmd,
			Short: operate.Helper,
			Run: func(cmd *cobra.Command, args []string) {
				arg := ""
				if len(args) > 0 {
					arg = args[0]
				}
				result, err := CommmandGetResult(moduleId, op, arg)
				if err != nil {
					fmt.Println("Get result failed", err)
					return
				}
				fmt.Println(result)
			},
		}
		command.AddCommand(sub)
	}
	return command
}

func RecvFromServerMulti(conn *net.UDPConn) (*bytes.Buffer, error) {
	ret := bytes.NewBuffer(make([]byte, 0))
	for {
		data, err := RecvFromServer(conn)
		if err != nil {
			return ret, err
		}
		if data.Len() < MAX_PAYLOAD_LEN {
			if ret.Len() == 0 {
				return data, err
			} else {
				ret.Write(data.Bytes())
				return ret, err
			}
		}
		ret.Write(data.Bytes())
	}
	return ret, nil
}

func CommmandGetResult(mid ModuleId, operate int, arg string) (string, error) {
	_, result, err := SendToServer(mid, ModuleOperate(operate), bytes.NewBuffer([]byte(arg)))
	if err != nil {
		log.Warning(err)
		return "", err
	}
	return result.String(), nil
}
