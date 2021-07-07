package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
	"unicode"

	logging "github.com/op/go-logging"
	"github.com/spf13/cobra"
	"gitlab.x.lan/yunshan/droplet-libs/debug"
	"gitlab.x.lan/yunshan/droplet-libs/grpc"
	"gitlab.x.lan/yunshan/droplet-libs/receiver"
	"gitlab.x.lan/yunshan/droplet-libs/store"
	"gitlab.x.lan/yunshan/droplet-libs/zmq"
	"gitlab.x.lan/yunshan/droplet/droplet/adapter"

	"gitlab.x.lan/yunshan/droplet/config"
	"gitlab.x.lan/yunshan/droplet/droplet/labeler"
	"gitlab.x.lan/yunshan/droplet/droplet/profiler"
	"gitlab.x.lan/yunshan/droplet/droplet/queue"
	"gitlab.x.lan/yunshan/droplet/dropletctl"
	"gitlab.x.lan/yunshan/droplet/dropletctl/rpc"
	rozecfg "gitlab.x.lan/yunshan/droplet/roze/config"
	"gitlab.x.lan/yunshan/droplet/roze/roze"
	streamcfg "gitlab.x.lan/yunshan/droplet/stream/config"
	"gitlab.x.lan/yunshan/droplet/stream/dbwriter"
	"gitlab.x.lan/yunshan/droplet/stream/jsonify/dfi"
	"gitlab.x.lan/yunshan/droplet/stream/stream"
)

func main() {
	flag.StringVar(&dropletctl.ConfigPath, "f", "/etc/droplet.yaml", "Specify config file location")
	debug.SetIpAndPort(dropletctl.DEBUG_LISTEN_IP, dropletctl.DEBUG_LISTEN_PORT)
	root := &cobra.Command{
		Use:   "droplet-ctl",
		Short: "Droplet Config Tool",
	}
	dropletCmd := &cobra.Command{
		Use:   "droplet",
		Short: "Droplet debug commands",
	}
	rozeCmd := &cobra.Command{
		Use:   "roze",
		Short: "Roze debug commands",
	}
	streamCmd := &cobra.Command{
		Use:   "stream",
		Short: "Stream debug commands",
	}

	cfg := config.Load(dropletctl.ConfigPath)
	controllers := make([]net.IP, len(cfg.ControllerIps))
	for i, ipString := range cfg.ControllerIps {
		controllers[i] = net.ParseIP(ipString)
		if controllers[i].To4() != nil {
			controllers[i] = controllers[i].To4()
		}
	}

	root.AddCommand(dropletCmd, rozeCmd, streamCmd)
	root.AddCommand(profiler.RegisterProfilerCommand())
	root.AddCommand(debug.RegisterLogLevelCommand())
	root.AddCommand(RegisterTimeConvertCommand())
	root.AddCommand(grpc.RegisterPlatformDataCommand(controllers, int(cfg.ControllerPort)))
	rozeconfig := rozecfg.Load(dropletctl.ConfigPath)

	root.AddCommand(RegisterUpdateCQCommand(rozeconfig.TSDBAuth.Username, rozeconfig.TSDBAuth.Password))

	dropletCmd.AddCommand(queue.RegisterCommand(dropletctl.DROPLETCTL_QUEUE, []string{
		"1-receiver-to-statsd",
		"1-receiver-to-syslog",
		"1-receiver-to-meta-packet",
		"2-meta-packet-block-to-labeler",
		"3-meta-packet-block-to-pcap-app",
	}))
	dropletCmd.AddCommand(adapter.RegisterCommand(dropletctl.DROPLETCTL_ADAPTER))
	dropletCmd.AddCommand(labeler.RegisterCommand(dropletctl.DROPLETCTL_LABELER))
	dropletCmd.AddCommand(rpc.RegisterRpcCommand())

	rozeCmd.AddCommand(queue.RegisterCommand(dropletctl.DROPLETCTL_ROZE_QUEUE, []string{"1-recv-unmarshall"}))
	rozeCmd.AddCommand(debug.ClientRegisterSimple(roze.CMD_PLATFORMDATA, debug.CmdHelper{"platformData [filter]", "show roze platform data statistics"}, nil))
	rozeCmd.AddCommand(receiver.RegisterTridentStatusCommand())

	streamCmd.AddCommand(queue.RegisterCommand(dropletctl.DROPLETCTL_STREAM_QUEUE, []string{
		"1-receive-to-decode-l4",
		"1-receive-to-decode-l7",
		"2-decode-to-es-writer-queue-l4",
		"2-decode-to-es-writer-http-l7",
		"2-decode-to-es-writer-dns-l7",
	}))
	streamCmd.AddCommand(debug.ClientRegisterSimple(stream.CMD_PLATFORMDATA, debug.CmdHelper{"platformData [filter]", "show stream platform data statistics"}, nil))
	streamCmd.AddCommand(RegisterReceiveFlowLogCommand())
	streamconfig := streamcfg.Load(dropletctl.ConfigPath)
	streamCmd.AddCommand(dbwriter.RegisterESIndexHandleCommand(streamconfig.ESHostPorts, streamconfig.ESAuth.User, streamconfig.ESAuth.Password))

	root.GenBashCompletionFile("/usr/share/bash-completion/completions/droplet-ctl")
	root.SetArgs(os.Args[1:])
	root.Execute()
}

// 从字符串中解析出所有时间(大于100000000)
func getTimeInts(ts string) []time.Time {
	ints := make([]string, 0)
	j := 0
	for i := 0; i < len(ts); i++ {
		if unicode.IsDigit(rune(ts[i])) {
			if len(ints) <= j {
				ints = append(ints, "")
			}
			ints[j] = ints[j] + ts[i:i+1]
		} else {
			if len(ints) > j {
				j++
			}
		}
	}
	times := make([]time.Time, 0)
	for _, k := range ints {
		timeInt, err := strconv.ParseInt(k, 10, 64)
		if err == nil && timeInt > 100000000 {
			if timeInt > 100000000000000000 {
				times = append(times, time.Unix(0, timeInt))
			} else {
				times = append(times, time.Unix(timeInt, 0))
			}
		}
	}
	return times
}

func RegisterTimeConvertCommand() *cobra.Command {
	eg := "time format eg: '2020-03-27T07:06:00Z', '1585292760000000000', '1585292760'"
	cmd := &cobra.Command{
		Use:   "tc",
		Short: "time convert." + eg,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Printf("input time to convert. %s \n", eg)
				return
			}
			timeToConvert := args[0]
			timeInt, err := strconv.ParseInt(timeToConvert, 10, 64)
			var ts time.Time
			if err == nil {
				if timeInt > 100000000000000000 {
					ts = time.Unix(0, timeInt)
				} else {
					ts = time.Unix(timeInt, 0)
				}
			} else {
				err = ts.UnmarshalText([]byte(timeToConvert))
				if err != nil {
					times := getTimeInts(timeToConvert)
					if len(times) == 0 {
						fmt.Printf("unsupport time format '%s'\n", timeToConvert)
						fmt.Println(eg)
					} else {
						fmt.Printf("'%s' is convert to:\n", timeToConvert)
						for _, t := range times {
							fmt.Printf("Unix:     %d\nUnixNano: %d\nString:   %s\n\n", t.Unix(), t.UnixNano(), t)
						}
					}
					return
				}
			}
			fmt.Printf("'%s' is convert to:\n  Unix: %d\n  UnixNano: %d\n  String: %s\n", timeToConvert, ts.Unix(), ts.UnixNano(), ts)
		},
	}

	return cmd
}

func RegisterUpdateCQCommand(tsdbUser, tsdbPassword string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cq-update",
		Short: "update continuous queries",
		Run: func(cmd *cobra.Command, args []string) {
			logging.SetLevel(logging.WARNING, "")
			err := store.UpdateCQs("http://127.0.0.1:20044", tsdbUser, tsdbPassword)
			if err != nil {
				fmt.Println("failed", err)
			} else {
				fmt.Println("success")
			}
		},
	}
	return cmd
}

func RegisterReceiveFlowLogCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flow-print",
		Short: "print publishing flow",
		Run: func(cmd *cobra.Command, args []string) {
			sub, err := zmq.NewSubscriber("127.0.0.1", streamcfg.DefaultBrokerZMQPort, 1000000, zmq.CLIENT)
			if err != nil {
				fmt.Println(err)
				return
			}
			for {
				bytes, err := sub.Recv()
				if err != nil {
					fmt.Println(err)
					return
				}
				flow := &dfi.Flow{}
				if e := flow.Unmarshal(bytes); e != nil {
					fmt.Println(err)
					return
				}
				fmt.Println(flow)
			}
		},
	}
	return cmd
}
