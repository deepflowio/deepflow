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

package debug

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"

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

func decodeLogLevel(arg *bytes.Buffer) (string, error) {
	var level string
	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&level); err != nil {
		log.Error(err)
		return level, err
	}
	return level, nil
}

func encodeLogLevel(level string) (*bytes.Buffer, error) {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(level); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		return nil, err
	}
	return &buffer, nil
}

func (l *LogLevelControl) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	switch operate {
	case LOG_LEVEL_CMD_SHOW:
		logLevel := getLogLevel()
		enc, err := encodeLogLevel(logLevel)
		if err != nil {
			SendToClient(conn, remote, 1, nil)
		} else {
			SendToClient(conn, remote, 0, enc)
		}
	case LOG_LEVEL_CMD_SET:
		logLevel, err := decodeLogLevel(arg)
		if err != nil {
			SendToClient(conn, remote, 1, nil)
		} else {
			log.Infof("set logLevel to (%s)", logLevel)
			if err := setLogLevel(logLevel); err != nil {
				log.Warningf("set logLevel(%s) failed: %s", logLevel, err)
				SendToClient(conn, remote, 1, nil)
			} else {
				enc, _ := encodeLogLevel(logLevel)
				SendToClient(conn, remote, 0, enc)
			}
		}
	}
}

func getLogLevel() string {
	return logging.GetLevel("").String()
}

func setLogLevel(level string) error {
	levelId, err := logging.LogLevel(level)
	if err != nil {
		return err
	}
	logging.SetLevel(levelId, "")
	return nil
}

func sendCmd(operate int, logLevel string, out interface{}) bool {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(logLevel); err != nil {
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
		Use:   "show",
		Short: "show current log Level",
		Run: func(cmd *cobra.Command, args []string) {
			var level string
			if sendCmd(LOG_LEVEL_CMD_SHOW, "", &level) {
				fmt.Printf("Current log level: %s\n", level)
			}
		},
	}

	set := &cobra.Command{
		Use:   "set {loglevel}",
		Short: "set log level 'debug|info|warning|error'",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println("please run with 'debug|info|warning|error'.")
				return
			}
			if args[0] != "debug" && args[0] != "info" && args[0] != "warning" && args[0] != "error" {
				fmt.Println("please run with 'debug|info|warning|error'.")
				return
			}
			var level string
			if sendCmd(LOG_LEVEL_CMD_SET, args[0], &level) {
				fmt.Printf("Set log level: %s\n", level)
			}
		},
	}

	logLevel.AddCommand(show)
	logLevel.AddCommand(set)
	return logLevel
}
