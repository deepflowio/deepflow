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
	"encoding/gob"
	"fmt"
	"net"
	"strings"

	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"
)

const (
	LOG_LEVEL_CMD = 20
)

const (
	LOG_LEVEL_CMD_SHOW = iota
	LOG_LEVEL_CMD_SET
)

type LogLevelControl struct {
}

func NewLogLevelControl() *LogLevelControl {
	logLevelProcess := &LogLevelControl{}
	// 服务端注册处理函数
	Register(LOG_LEVEL_CMD, logLevelProcess)
	return logLevelProcess
}

func decodeBuffer(arg *bytes.Buffer) (string, error) {
	var buf string
	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&buf); err != nil {
		log.Error(err)
		return buf, err
	}
	return buf, nil
}

func encodeBuffer(buf string) (*bytes.Buffer, error) {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(buf); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		return nil, err
	}
	return &buffer, nil
}

func (l *LogLevelControl) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	switch operate {
	case LOG_LEVEL_CMD_SHOW:
		buf, err := decodeBuffer(arg)
		if err != nil {
			SendToClient(conn, remote, 1, nil)
			return
		}
		moduleLoglevel := strings.Split(buf, "|")
		if len(moduleLoglevel) < 2 {
			SendToClient(conn, remote, 1, nil)
			return
		}
		module := moduleLoglevel[0]
		logLevel := getLogLevel(module)

		enc, err := encodeBuffer(logLevel)
		if err != nil {
			SendToClient(conn, remote, 1, nil)
		} else {
			SendToClient(conn, remote, 0, enc)
		}
	case LOG_LEVEL_CMD_SET:
		buf, err := decodeBuffer(arg)
		if err != nil {
			SendToClient(conn, remote, 1, nil)
		} else {
			moduleLoglevel := strings.Split(buf, "|")
			if len(moduleLoglevel) < 2 {
				SendToClient(conn, remote, 1, nil)
				return
			}
			module, logLevel := moduleLoglevel[0], moduleLoglevel[1]

			log.Infof("set module(%s) logLevel to (%s)", module, logLevel)
			if err := setLogLevel(module, logLevel); err != nil {
				log.Warningf("set module(%s) logLevel(%s) failed: %s", module, logLevel, err)
				SendToClient(conn, remote, 1, nil)
			} else {
				enc, _ := encodeBuffer(logLevel)
				SendToClient(conn, remote, 0, enc)
			}
		}
	}
}

func getLogLevel(module string) string {
	return logging.GetLevel(module).String()
}

func setLogLevel(module, level string) error {
	levelId, err := logging.LogLevel(level)
	if err != nil {
		return err
	}
	logging.SetLevel(levelId, module)
	return nil
}

func sendCmd(operate int, module, logLevel string, out interface{}) bool {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(module + "|" + logLevel); err != nil {
		fmt.Printf("%v: %s\n", err, logLevel)
		return false
	}

	_, result, err := SendToServer(LOG_LEVEL_CMD, ModuleOperate(operate), &buffer)
	if err != nil {
		fmt.Println(err)
		return false
	}

	decoder := gob.NewDecoder(result)
	if err = decoder.Decode(out); err != nil {
		fmt.Printf("%v: %v\n", err, out)
		return false
	}
	return true
}

// 客户端注册命令
func RegisterLogLevelCommand() *cobra.Command {
	logLevel := &cobra.Command{
		Use:   "loglevel",
		Short: "control log level",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'show | set'.\n")
		},
	}

	show := &cobra.Command{
		Use:   "show [module]",
		Short: "show current module log Level",
		Run: func(cmd *cobra.Command, args []string) {
			module := ""
			if len(args) == 1 {
				module = args[0]
			}
			var level string
			if sendCmd(LOG_LEVEL_CMD_SHOW, module, "", &level) {
				fmt.Printf("Current module(%s) log level: %s\n", module, level)
			}
		},
	}

	set := &cobra.Command{
		Use:   "set [module] {loglevel}",
		Short: "set [module] log level 'debug|info|warning|error'",
		Run: func(cmd *cobra.Command, args []string) {
			module, logLevel := "", ""
			if len(args) == 1 {
				module = ""
				logLevel = args[0]
			} else if len(args) == 2 {
				module = args[0]
				logLevel = args[1]
			}

			if logLevel != "debug" && logLevel != "info" && logLevel != "warning" && logLevel != "error" {
				fmt.Println("please run with loglevel 'debug|info|warning|error'.")
				return
			}
			var level string
			if sendCmd(LOG_LEVEL_CMD_SET, module, logLevel, &level) {
				fmt.Printf("module(%s) set log level: %s\n", module, level)
			}
		},
	}

	logLevel.AddCommand(show)
	logLevel.AddCommand(set)
	return logLevel
}
