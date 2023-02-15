//go:build linux
// +build linux

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
	"os/signal"
	"strings"
	"syscall"
	"time"

	units "github.com/docker/go-units"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	logging "github.com/op/go-logging"

	. "github.com/deepflowio/deepflow/server/libs/logger"
	. "github.com/deepflowio/deepflow/server/libs/xdppacket/cmd/common"
)

const (
	DEFAULT_BLOCK_SIZE     = 1 * units.MiB
	DEFAULT_FRAME_SIZE     = 1 << 16 // only
	DEFULT_AFPACKET_BLOCKS = 1 * units.KiB
	POLL_TIMEOUT           = 100 * time.Millisecond
	DIR_RX                 = 0
	DIR_TX                 = 1
)

var log = logging.MustGetLogger(os.Args[0])

var direction = flag.Int("r", 0, "Specify receive or send, "+
	"af_packet rx:0, af_packet tx:1")

func AfPacketRxTx() {
	var pkts, bytes uint64

	afPacket, err := afpacket.NewTPacket(
		afpacket.OptPollTimeout(POLL_TIMEOUT),
		afpacket.OptBlockSize(DEFAULT_BLOCK_SIZE),
		afpacket.OptFrameSize(DEFAULT_FRAME_SIZE),
		afpacket.OptNumBlocks(DEFULT_AFPACKET_BLOCKS),
		afpacket.OptInterface(*Ifname),
	)
	if err != nil {
		log.Error("AF_PACKET init error", err)
		os.Exit(1)
	}

	if *StatsInterval > 0 {
		go func() {
			var oldPkts, oldBytes, nowPkts, nowBytes uint64
			for range time.NewTicker(time.Duration(*StatsInterval) * time.Second).C {
				stats, statsV3, _ := afPacket.SocketStats()
				nowPkts, nowBytes = pkts, bytes

				fmt.Printf("%12s\t%12s\t%4s%8s\t%8s\t%4s%8s\t%8s\t%8s\n",
					"rx-tx-pkts", "rx-tx-bytes", "|", "v1v2-pkts", "v1v2-drops", "|",
					"v3_pkts", "v3_drops", "Freezes")
				fmt.Printf("%12d\t%12d\t%4s%8d\t%8d\t%4s%8d\t%8d\t%8d\n",
					pkts-oldPkts, bytes-oldBytes, "|",
					stats.Packets(), stats.Drops(), "|",
					statsV3.Packets(), statsV3.Drops(), statsV3.QueueFreezes())

				oldPkts, oldBytes = nowPkts, nowBytes
				afPacket.InitSocketStats()

			}
		}()
	}

	if *direction == DIR_RX {
		go func() {
			var ci gopacket.CaptureInfo
			count := GetPktCount(*PktCount)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				_, ci, err = afPacket.ZeroCopyReadPacketData()
				if err != nil {
					fmt.Println("========afPacket zero read failed as", err)
					time.Sleep(time.Second)
					continue
				}
				pkts += 1
				bytes += uint64(ci.Length)
			}
		}()
	} else if *direction == DIR_TX {
		go func() {
			pkt := GeneratePacket(*SrcMac, *DstMac, *SrcIp, *DstIp, 0)
			count := GetPktCount(*PktCount)
			length := len(pkt)
			for i := 0; count == PKT_CNT_INFINITE || i < count; i++ {
				err = afPacket.WritePacketData(pkt)
				if err != nil {
					fmt.Printf("afpacket send packet failed as %v\n", err)
					time.Sleep(time.Second)
					continue
				}
				pkts += 1
				bytes += uint64(length)
			}
		}()
	}
}

func main() {
	EnableStdoutLog()

	flag.Parse()
	fmt.Printf("option---ifname:%v, rx:%v, stats interval:%v\n",
		*Ifname, *direction, *StatsInterval)

	level, err := logging.LogLevel(strings.ToUpper(*LogLevel))
	if err != nil {
		fmt.Printf("error log level %v\n", *LogLevel)
		return
	}
	logging.SetLevel(level, "")

	if *Ifname == "" {
		fmt.Println("must specify interface name")
		return
	}

	if *EnableProfile {
		StartProfiler()
	}

	if *direction == DIR_TX {
		if *SrcMac == "" || *DstMac == "" || *SrcIp == "" || *DstIp == "" {
			fmt.Println("must specify srcMac, dstMac, srcIp, dstIp")
			return
		}
	}

	AfPacketRxTx()

	signalChannel := make(chan os.Signal, 3)
	signal.Notify(signalChannel, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGINT)
	sig := <-signalChannel
	fmt.Println("end as catch signal: ", sig)

	os.Exit(0)
}
