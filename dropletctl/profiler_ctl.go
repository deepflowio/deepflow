package dropletctl

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	CONFIG_CMD_PROFILER_ON = iota
	CONFIG_CMD_PROFILER_OFF
	CONFIG_CMD_PROFILER_STATUS
)

func sendProfilerOn(args []string) {
	_, messageBuffer, err := SendToDroplet(DROPLETCTL_CONFIG, CONFIG_CMD_PROFILER_ON, nil)
	if err != nil {
		fmt.Println(err)
	}

	message := strings.TrimSpace(messageBuffer.String())
	fmt.Println(message)
}

func sendProfilerOff(args []string) {
	_, messageBuffer, err := SendToDroplet(DROPLETCTL_CONFIG, CONFIG_CMD_PROFILER_OFF, nil)
	if err != nil {
		fmt.Println(err)
	}

	message := strings.TrimSpace(messageBuffer.String())
	fmt.Println(message)
}

func sendProfilerStatus(args []string) {
	_, messageBuffer, err := SendToDroplet(DROPLETCTL_CONFIG, CONFIG_CMD_PROFILER_STATUS, nil)
	if err != nil {
		fmt.Println(err)
	}

	message := strings.TrimSpace(messageBuffer.String())
	fmt.Println(message)
}

func RegisterProfilerCommand() *cobra.Command {
	profiler := &cobra.Command{
		Use:   "profiler",
		Short: "enable/disable droplet profiler option",
	}

	profilerOn := &cobra.Command{
		Use:   "on",
		Short: "enable droplet profiler option",
		Run: func(cmd *cobra.Command, args []string) {
			sendProfilerOn(args)
		},
	}

	profilerOff := &cobra.Command{
		Use:   "off",
		Short: "disable droplet profiler option",
		Run: func(cmd *cobra.Command, args []string) {
			sendProfilerOff(args)
		},
	}

	profilerStatus := &cobra.Command{
		Use:   "status",
		Short: "show droplet profiler status",
		Run: func(cmd *cobra.Command, args []string) {
			sendProfilerStatus(args)
		},
	}

	profiler.AddCommand(profilerOn)
	profiler.AddCommand(profilerOff)
	profiler.AddCommand(profilerStatus)

	return profiler
}
