package dpctl

import (
	"bytes"
	"net"

	"github.com/spf13/cobra"
)

type RegisterCommmandLine func() *cobra.Command

type DropletCtrlModuleId uint16
type DropletCtrlModuleOperate uint16

const (
	DPCTL_ADAPT DropletCtrlModuleId = iota
	DPCTL_MAX
)

const (
	DPCTL_PORT = 9527
	DPCTL_IP   = "127.0.0.1"
)

type CommandLineProcess interface {
	RecvCommand(conn *net.UDPConn, port int, operate uint16, arg *bytes.Buffer)
}

var RecvHandlers = [DPCTL_MAX]CommandLineProcess{}
var RegisterHandlers = [DPCTL_MAX]RegisterCommmandLine{}
