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

type LoglevelControl struct {
}

var log = logging.MustGetLogger("dropletctl")

func NewLoglevelControl() *LoglevelControl {
	loglevelProcess := &LoglevelControl{}
	// 服务端注册处理函数
	debug.Register(DROPLETCTL_LOGLEVEL, loglevelProcess)
	return loglevelProcess
}

func decodeLoglevel(arg *bytes.Buffer) (string, error) {
	var level string
	decoder := gob.NewDecoder(arg)
	if err := decoder.Decode(&level); err != nil {
		log.Error(err)
		return "", err
	}
	return level, nil
}

func encodeLoglevel(level string) (*bytes.Buffer, error) {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(level); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		return nil, err
	}
	return &buffer, nil
}

func (l *LoglevelControl) RecvCommand(conn *net.UDPConn, remote *net.UDPAddr, operate uint16, arg *bytes.Buffer) {
	switch operate {
	case LOGLEVEL_CMD_SHOW:
		loglevel := getLogLevel()
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

func getLogLevel() string {
	levelId := logging.GetLevel("")
	return levelId.String()
}

func setLogLevel(level string) error {
	levelId, err := logging.LogLevel(level)
	if err != nil {
		return err
	}
	logging.SetLevel(levelId, "")
	return nil
}

func sendCmd(operate int, loglevel string, out interface{}) bool {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(loglevel); err != nil {
		fmt.Printf("%v: %s\n", err, loglevel)
		return false
	}

	_, result, err := debug.SendToServer(DROPLETCTL_LOGLEVEL, debug.ModuleOperate(operate), &buffer)
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
func RegisterLoglevelCommand() *cobra.Command {
	loglevel := &cobra.Command{
		Use:   "loglevel",
		Short: "control loglevel",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("please run with arguments 'show | set'.\n")
		},
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "show current loglevel",
		Run: func(cmd *cobra.Command, args []string) {
			var level string
			if sendCmd(LOGLEVEL_CMD_SHOW, "", &level) {
				fmt.Printf("Current loglevel: %s\n", level)
			}
		},
	}

	set := &cobra.Command{
		Use:   "set {loglevel}",
		Short: "set loglevel",
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
			if sendCmd(LOGLEVEL_CMD_SET, args[0], &level) {
				fmt.Printf("Set loglevel: %s\n", level)
			}
		},
	}

	loglevel.AddCommand(show)
	loglevel.AddCommand(set)
	return loglevel
}
