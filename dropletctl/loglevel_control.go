package dropletctl

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
)

const (
	LOGLEVEL_CMD_SHOW = iota
	LOGLEVEL_CMD_SET
)

type LevelInfo struct {
	Module string
	Level  string
}

type LoglevelControl struct {
}

var log = logging.MustGetLogger("dropletctl")

func NewLoglevelControl() *LoglevelControl {
	loglevelProcess := &LoglevelControl{}
	// 服务端注册处理函数
	debug.Register(DROPLETCTL_LOGLEVEL, loglevelProcess)
	return loglevelProcess
}

func decodeLoglevel(arg *bytes.Buffer) (*LevelInfo, error) {
	levelInfo := &LevelInfo{}
	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(levelInfo); err != nil {
		log.Error(err)
		return levelInfo, err
	}
	return levelInfo, nil
}

func encodeLoglevel(levelInfo *LevelInfo) (*bytes.Buffer, error) {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(levelInfo); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		return nil, err
	}
	return &buffer, nil
}

func (l *LoglevelControl) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	switch operate {
	case LOGLEVEL_CMD_SHOW:
		loglevel, _ := decodeLoglevel(arg)
		loglevel.Level = getLogInfo(loglevel.Module)
		enc, err := encodeLoglevel(loglevel)
		if err != nil {
			debug.SendToClient(conn, remote, 1, nil)
		} else {
			debug.SendToClient(conn, remote, 0, enc)
		}
	case LOGLEVEL_CMD_SET:
		loglevel, err := decodeLoglevel(arg)
		if err != nil {
			debug.SendToClient(conn, remote, 1, nil)
		} else {
			log.Infof("set loglevel to (%s)", loglevel)
			if err := setLogLevel(loglevel); err != nil {
				log.Warningf("set loglevel(%s) failed: %s", loglevel, err)
				debug.SendToClient(conn, remote, 1, nil)
			} else {
				if enc, err := encodeLoglevel(loglevel); err != nil {
					debug.SendToClient(conn, remote, 0, nil)
				} else {
					debug.SendToClient(conn, remote, 0, enc)
				}
			}
		}
	}
}

func getLogInfo(module string) string {
	if module == "modules" {
		return getModules()
	}
	levelId := logging.GetLevel(module)
	return levelId.String()
}

func setLogLevel(levelInfo *LevelInfo) error {
	levelId, err := logging.LogLevel(levelInfo.Level)
	if err != nil {
		return err
	}
	if levelInfo.Module == "all" {
		for i, _ := range logging.Modules {
			logging.SetLevel(levelId, logging.Modules[i])
		}
		return nil
	}
	logging.SetLevel(levelId, levelInfo.Module)
	return nil
}

func sendCmd(operate int, levelInfo *LevelInfo) bool {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(levelInfo); err != nil {
		fmt.Printf("%v: %s\n", err, levelInfo)
		return false
	}

	_, result, err := debug.SendToServer(DROPLETCTL_LOGLEVEL, debug.ModuleOperate(operate), &buffer)
	if err != nil {
		fmt.Println(err)
		return false
	}

	decoder := gob.NewDecoder(result)
	if err = decoder.Decode(levelInfo); err != nil {
		fmt.Printf("%v: %v\n", err, levelInfo)
		return false
	}
	return true
}

func checkInput(module string) bool {
	if module == "all" || module == "modules" {
		return true
	}
	for i, _ := range logging.Modules {
		if logging.Modules[i] == module {
			return true
		}
	}

	return false
}

func getModules() string {
	var modules string
	for i, _ := range logging.Modules {
		modules += logging.Modules[i]
		modules += "|"
	}

	return modules
}

// 客户端注册命令
func RegisterLoglevelCommand() *cobra.Command {
	loglevel := &cobra.Command{
		Use:   "loglevel",
		Short: "control loglevel",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'show | set'.\n")
		},
	}

	show := &cobra.Command{
		Use:     "show",
		Short:   "show current loglevel | Modules",
		Example: "droplet-ctl loglevel show flowgenerator|modules",
		Long:    "droplet-ctl loglevel show {module}",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 || !checkInput(args[0]) {
				fmt.Printf("Input Err. Example: %s\n", cmd.Example)
				return
			}
			levelInfo := LevelInfo{
				Module: args[0],
			}
			if sendCmd(LOGLEVEL_CMD_SHOW, &levelInfo) {
				fmt.Printf("Current Info: %s\n", levelInfo)
			}
		},
	}

	set := &cobra.Command{
		Use:     "set {module} {loglevel}",
		Short:   "set loglevel",
		Example: "droplet-ctl loglevel set flowgenerator info",
		Long: "droplet-ctl loglevel set {key+}\n" +
			"key list:\n" +
			"\tmodule       module| all(set all modules)\n" +
			"\tlevel        debug|info|warning|error",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				fmt.Printf("Input Err. Example: %s\n", cmd.Example)
				return
			}
			if !checkInput(args[0]) {
				fmt.Printf("Input Err. Example: %s\n", cmd.Example)
				return
			}
			if args[1] != "debug" && args[1] != "info" && args[1] != "warning" && args[1] != "error" {
				fmt.Println("please run with 'debug|info|warning|error'.")
				return
			}
			levelInfo := LevelInfo{
				Module: args[0],
				Level:  args[1],
			}
			if sendCmd(LOGLEVEL_CMD_SET, &levelInfo) {
				fmt.Printf("Set loglevel: %s\n", levelInfo)
			}
		},
	}

	loglevel.AddCommand(show)
	loglevel.AddCommand(set)
	return loglevel
}
