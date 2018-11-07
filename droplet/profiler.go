package droplet

import (
	"bytes"
	"encoding/gob"
	"net"
	"net/http"

	"gitlab.x.lan/yunshan/droplet/dropletctl"
)

var profilerServer *ProfilerServer = nil

type ProfilerServer http.Server

func RegisterProfilerCommand() {
	dropletctl.Register(dropletctl.DROPLETCTL_CONFIG, profilerServer)
}

func (s *ProfilerServer) RecvCommand(conn *net.UDPConn, port int, operate uint16, args *bytes.Buffer) {
	switch operate {
	case dropletctl.CONFIG_CMD_PROFILER_ON:
		recvProfilerOn(conn, port, args)
	case dropletctl.CONFIG_CMD_PROFILER_OFF:
		recvProfilerOff(conn, port, args)
	case dropletctl.CONFIG_CMD_PROFILER_STATUS:
		recvProfilerRunningStatus(conn, port, args)
	}
}

func sendToDropletCtl(conn *net.UDPConn, port int, info interface{}) {
	buffer := bytes.Buffer{}
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(info); err != nil {
		log.Errorf("encoder.Encode: %s", err)
		dropletctl.SendToDropletCtl(conn, port, 1, nil)
		return
	}
	dropletctl.SendToDropletCtl(conn, port, 0, &buffer)
}

func recvProfilerOn(conn *net.UDPConn, port int, args *bytes.Buffer) {
	CheckAndStartProfiler()

	if isProfilerRunning() {
		sendToDropletCtl(conn, port, "Success")
	} else {
		sendToDropletCtl(conn, port, "Fail")
	}
}

func recvProfilerOff(conn *net.UDPConn, port int, args *bytes.Buffer) {
	StopProfiler()

	if !isProfilerRunning() {
		sendToDropletCtl(conn, port, "Success")
	} else {
		sendToDropletCtl(conn, port, "Fail")
	}
}

func recvProfilerRunningStatus(conn *net.UDPConn, port int, args *bytes.Buffer) {
	if isProfilerRunning() {
		sendToDropletCtl(conn, port, "Running")
	} else {
		sendToDropletCtl(conn, port, "Stopped")
	}
}

func startProfiler() {
	if profilerServer != nil {
		return
	}

	profilerServer = (*ProfilerServer)(&http.Server{
		Addr: "0.0.0.0:8000",
	})

	log.Info("Start profiler on http 0.0.0.0:8000")
	go func() {
		if err := (*http.Server)(profilerServer).ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Warning(err)
			}
			profilerServer = nil
		}
	}()
}

func StopProfiler() {
	if isProfilerRunning() {
		if err := (*http.Server)(profilerServer).Shutdown(nil); err != nil {
			log.Infof("Close profiler failed as %v", err)
		} else {
			log.Info("Close profiler on http 0.0.0.0:8000")
		}

		profilerServer = nil
	}
}

func StartProfiler() {
	startProfiler()
}

func CheckAndStartProfiler() {
	if !isProfilerRunning() {
		startProfiler()
	}
}

func isProfilerRunning() bool {
	return profilerServer != nil
}
