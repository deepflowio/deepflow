package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
	"unicode"

	"github.com/spf13/cobra"
	"server/ingester/droplet/adapter"
	"server/libs/debug"
	"server/libs/grpc"
	"server/libs/receiver"

	"server/ingester/config"
	"server/ingester/droplet/labeler"
	"server/ingester/droplet/profiler"
	"server/ingester/droplet/queue"
	"server/ingester/dropletctl"
	"server/ingester/dropletctl/rpc"
	"server/ingester/roze/roze"
	"server/ingester/stream/stream"
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
	}))
	streamCmd.AddCommand(debug.ClientRegisterSimple(stream.CMD_PLATFORMDATA, debug.CmdHelper{"platformData [filter]", "show stream platform data statistics"}, nil))

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
