//go:build linux && xdp
// +build linux,xdp

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

package main

import (
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"strings"
	"time"

	. "github.com/deepflowio/deepflow/server/libs/logger"
	. "github.com/deepflowio/deepflow/server/libs/xdppacket"
	. "github.com/deepflowio/deepflow/server/libs/xdppacket/cmd/common"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger(os.Args[0])

var rx = flag.Int("r", 0, "Specify receive or send, "+
	"rx:0, tx:1, multi-pkt-rx:2, multi-pkt-tx:3, "+
	"multi-queue-rx:4, multi-queue-tx:5, "+
	"multi-queue-single-pkt-rx:6, multi-queue-single-pkt-tx:7, "+
	"multi-queue-multi-pkt-rx:8, multi-queue-multi-pkt-tx:9, "+
	"single-queue-single-pkt-full-duplex:11")
var queueCount = flag.Int("q", 1, "Specify interface queue count, read packet from queue id[0,queueCount), default is 1")
var xdpMode = flag.Int("m", 0, "Specify xdp mode, 0(default) is DRV(depend on interface driver), 1 is skb(depend on kernel>=4.19)")
var ioMode = flag.Int("M", 0, "Specify I/O mode, 0(default) is nonpoll, 1 is poll, 2 is mix")
var timeout = flag.Int("t", 100, "poll timeout only for nonblock I/O mode, uint: ms, default: 100")

var actualXdpMode OptXDPMode = DFLT_XDP_MODE
var actualIOMode OptIoMode = DFLT_IO_MODE
var actualPollTimeOut OptPollTimeout = OptPollTimeout(DFLT_POLL_TIMEOUT)

func checkIfMountBpffs() bool {
	cmd := exec.Command("/usr/bin/bash", "-c", "mount | grep bpf")
	check, _ := cmd.Output()

	return len(check) > 0
}

func checkAndMountBpffs() bool {
	isMount := checkIfMountBpffs()
	if isMount == true {
		return true
	}

	cmd := exec.Command("/usr/bin/bash", "-c", "mount -t bpf bpffs /sys/fs/bpf/")
	mount, _ := cmd.Output()
	if len(mount) > 0 {
		log.Debugf("mount bpffs failed")
		return false
	}

	isMount = checkIfMountBpffs()
	if isMount == false {
		log.Debugf("verify if mount success failed")
		return false
	}

	return true
}

func isUnRecoverError(err error) bool {
	if err == ErrSocketClosed || err == ErrReadFunctionNil {
		log.Debugf("err is %v", err)
		return true
	}
	return false
}

func OneQueueRxTx(queueID int) {
	xp, err := NewXDPPacket(*Ifname, OptQueueCount(*queueCount), OptQueueID(queueID),
		actualXdpMode, actualIOMode, actualPollTimeOut, OptNumFrames(*FrameNum))
	if err != nil {
		log.Errorf("new xdp socket failed as %v", err)
		return
	}
	defer xp.Close()

	if *StatsInterval > 0 {
		go func() {
			oldStats := XDPStats{}
			stats := xp.GetStats()
			for _ = range time.NewTicker(time.Duration(*StatsInterval) * time.Second).C {
				if xp.CheckIfXDPSocketClosed() {
					break
				}
				fmt.Println(stats.Minus(oldStats))
				oldStats, stats = stats, xp.GetStats()
			}
		}()
	}

	if *rx == 0 {
		go func() {
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				_, _, err := xp.ZeroCopyReadPacket()
				// pkt, ci, err := xp.ZeroCopyReadPacket()
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debug("zero read failed as", err)
					continue
				}
				// 测试准确性时方可打开，因其影响性能
				// log.Debugf("ci:%#vpacket:%v", ci, DumpPacket(pkt))
			}
		}()
	} else if *rx == 1 {
		go func() {
			pkt := GeneratePacket(*SrcMac, *DstMac, *SrcIp, *DstIp, 0)
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				err = xp.WritePacket(pkt)
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debugf("send packet failed as %v", err)
					continue
				}
			}
		}()
	} else if *rx == 2 {
		go func() {
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				_, _, err = xp.ZeroCopyReadMultiPackets()
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debug("zero read multi packets failed as", err)
					continue
				}
			}
		}()
	} else if *rx == 3 {
		go func() {
			pkts := make([][]byte, 0, DFLT_BATCH_SIZE)
			pkt := GeneratePacket(*SrcMac, *DstMac, *SrcIp, *DstIp, 0)
			for i := 0; i < cap(pkts); i++ {
				pkts = append(pkts, pkt)
			}
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				n, err := xp.WriteMultiPackets(pkts)
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debugf("send packet failed as %v", err)
					continue
				}
				if n < len(pkts) {
					log.Debugf("only send %v packets, actual %v packets", n, len(pkts))
				}
			}
		}()
	}

	xp.ClearEbpfProg()
}

func MultiQueueRxTx() {
	xp, err := NewXDPMultiQueue(*Ifname, OptQueueCount(*queueCount),
		actualXdpMode, actualIOMode, actualPollTimeOut, OptNumFrames(*FrameNum))
	if err != nil {
		log.Errorf("new xdp socket failed as %v", err)
		return
	}
	defer xp.Close()

	if *StatsInterval > 0 {
		go func() {
			oldStats := XDPStats{}
			stats := xp.GetStats()
			for range time.NewTicker(time.Duration(*StatsInterval) * time.Second).C {
				fmt.Println(stats.Minus(oldStats))
				oldStats, stats = stats, xp.GetStats()
			}
		}()
	}

	if *rx == 4 {
		go func() {
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				_, _, err = xp.ZeroCopyReadPacket()
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debug("multi queue zero read failed as", err)
					continue
				}
			}
		}()
	} else if *rx == 5 {
		pkts := make([][]byte, 0, DFLT_BATCH_SIZE)
		for i := 0; i < cap(pkts); i++ {
			pkt := GeneratePacket(*SrcMac, *DstMac, *SrcIp, *DstIp, i)
			pkts = append(pkts, pkt)
		}
		go func() {
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				n, err := xp.WritePacket(pkts)
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debugf("multi queue send packet failed as %v", err)
					continue
				}
				if n < len(pkts) {
					log.Debugf("multi queue only send %v packets", n)
				}
			}
		}()
	} else if *rx == 6 {
		xsks := GetXDPSocketFromMultiQueue(xp)
		rxFunc := func(s *XDPPacket, id int) {
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				_, _, err = s.ZeroCopyReadPacket()
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debugf("queue %v zero read failed as %v", id, err)
					continue
				}
			}
		}

		for idx, s := range xsks {
			log.Debugf("queue %v xdp socket %v", idx, s)
			go rxFunc(s, idx)
		}
	} else if *rx == 7 {
		xsks := GetXDPSocketFromMultiQueue(xp)
		txFunc := func(s *XDPPacket, id int) {
			pkt := GeneratePacket(*SrcMac, *DstMac, *SrcIp, *DstIp, id)

			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				err := s.WritePacket(pkt)
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debugf("queue %v send packet failed as %v", id, err)
					continue
				}
			}
		}

		for idx, s := range xsks {
			log.Debugf("queue %v xdp socket %v", idx, s)
			go txFunc(s, idx)
		}
	} else if *rx == 8 {
		xsks := GetXDPSocketFromMultiQueue(xp)
		rxFunc := func(s *XDPPacket, id int) {
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				_, _, err := s.ZeroCopyReadMultiPackets()
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debugf("queue %v multi send packet failed as %v", id, err)
					continue
				}
			}
		}

		for idx, s := range xsks {
			log.Debugf("queue %v xdp socket %v", idx, s)
			go rxFunc(s, idx)
		}
	} else if *rx == 9 {
		xsks := GetXDPSocketFromMultiQueue(xp)
		txFunc := func(s *XDPPacket, id int) {
			pkts := make([][]byte, 0, DFLT_BATCH_SIZE)
			pkt := GeneratePacket(*SrcMac, *DstMac, *SrcIp, *DstIp, 0)
			for i := 0; i < cap(pkts); i++ {
				pkts = append(pkts, pkt)
			}

			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				n, err := s.WriteMultiPackets(pkts)
				if err != nil {
					if isUnRecoverError(err) {
						break
					}
					log.Debugf("queue %v send packet failed as %v", id, err)
					continue
				}
				if n < len(pkts) {
					log.Debugf("only send %v packets", n)
				}
			}
		}

		for idx, s := range xsks {
			log.Debugf("queue %v xdp socket %v", idx, s)
			go txFunc(s, idx)
		}
	}
	xp.ClearEbpfProg()
}

func FullDuplexRxTx() {
	xp, err := NewXDPPacket(*Ifname, OptQueueCount(*queueCount),
		actualXdpMode, actualIOMode, actualPollTimeOut, OptNumFrames(*FrameNum))
	if err != nil {
		log.Errorf("new xdp socket failed as %v", err)
		return
	}
	defer xp.Close()

	if *StatsInterval > 0 {
		go func() {
			oldStats := XDPStats{}
			stats := xp.GetStats()
			for range time.NewTicker(time.Duration(*StatsInterval) * time.Second).C {
				if xp.CheckIfXDPSocketClosed() {
					break
				}
				fmt.Println(stats.Minus(oldStats))
				oldStats, stats = stats, xp.GetStats()
			}
		}()
	}

	go func() {
		count := GetPktCount(*PktCount)
		for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
			_, _, err = xp.ZeroCopyReadPacket()
			if err != nil {
				if isUnRecoverError(err) {
					break
				}
				log.Debug("zero read failed as", err)
				continue
			}
		}
	}()
	go func() {
		pkt := GeneratePacket(*SrcMac, *DstMac, *SrcIp, *DstIp, 0)
		count := GetPktCount(*PktCount)
		for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
			err = xp.WritePacket(pkt)
			if err != nil {
				if isUnRecoverError(err) {
					break
				}
				log.Debugf("send packet failed as %v", err)
				continue
			}
		}
	}()

	xp.ClearEbpfProg()
}

func main() {
	EnableStdoutLog()

	flag.Parse()
	log.Debugf("option---ifname:%v, rx:%v, queue count:%v, xdp mode:%v, "+
		"I/O mode:%v, stats interval:%v",
		*Ifname, *rx, *queueCount, *xdpMode, *ioMode, *StatsInterval)

	level, err := logging.LogLevel(strings.ToUpper(*LogLevel))
	if err != nil {
		log.Debugf("error log level %v", *LogLevel)
		return
	}
	logging.SetLevel(level, "")

	if *Ifname == "" {
		log.Error("must specify interface name")
		return
	}
	if err = ClearIfaceResidueXDPResources(*Ifname); err != nil {
		log.Error(err)
		return
	}

	if *EnableProfile {
		StartProfiler()
	}

	if *rx&0x1 == 0x1 {
		if *SrcMac == "" || *DstMac == "" || *SrcIp == "" || *DstIp == "" {
			log.Error("must specify srcMac, dstMac, srcIp, dstIp")
			return
		}
	}

	ok := checkAndMountBpffs()
	if ok == false {
		log.Error("not mount bpffs")
		return
	}

	if *xdpMode != 0 {
		actualXdpMode = XDP_MODE_SKB
	}
	if *ioMode != 0 {
		actualIOMode = OptIoMode(*ioMode)
	}
	if *timeout != 0 {
		actualPollTimeOut = OptPollTimeout(time.Duration(*timeout) * time.Millisecond)
	}

	if *rx < 4 {
		for i := 1; i < *queueCount; i++ {
			go OneQueueRxTx(i)
		}
		OneQueueRxTx(0)
	} else if *rx == 11 {
		FullDuplexRxTx()
	} else {
		MultiQueueRxTx()
	}

	os.Exit(0)
}
