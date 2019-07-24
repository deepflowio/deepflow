// +build linux,xdp

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	logging "github.com/op/go-logging"
	. "gitlab.x.lan/yunshan/droplet-libs/logger"
	"gitlab.x.lan/yunshan/droplet-libs/utils"
	. "gitlab.x.lan/yunshan/droplet-libs/xdppacket"
)

var log = logging.MustGetLogger(os.Args[0])

var rx = flag.Int("r", 0, "Specify receive or send, rx:0, tx:1, multi-rx:2, "+
	"multi-tx:3, multi-queue-rx:4, multi-queue-tx:5, multi-to-single-rx:6, multi-to-single-tx:7, full-duplex:11")
var ifname = flag.String("i", "", "Specify interface name")
var statsInterval = flag.Int("s", 0, "Specify stats interval, unit: second")
var queueCount = flag.Int("q", 1, "Specify interface queue count, read packet from queue id[0,queueCount), default is 1")
var xdpMode = flag.Int("m", 0, "Specify xdp mode, 0(default) is zero copy, 1 is copy")
var ioMode = flag.Int("M", 0, "Specify I/O mode, 0(default) is block, 1 is nonblock")
var srcMac = flag.String("srcMac", "", "source MAC")
var dstMac = flag.String("dstMac", "", "source MAC")
var srcIp = flag.String("srcIp", "", "source MAC")
var dstIp = flag.String("dstIp", "", "source MAC")
var enableProfile = flag.Bool("p", true, "if enable Profile")
var pktCount = flag.Int("c", 0, "specify receive or send packet count, default always")
var logLevel = flag.String("l", "Info", "specify log level(ingore case)"+
	"[CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG], default is INFO")

func getPktCount(count int) int {
	if count == 0 {
		return math.MaxInt32
	}

	return count
}

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
		fmt.Printf("mount bpffs failed\n")
		return false
	}

	isMount = checkIfMountBpffs()
	if isMount == false {
		fmt.Printf("verify if mount success failed\n")
		return false
	}

	return true
}

func startProfiler() {
	go func() {
		if err := http.ListenAndServe("0.0.0.0:8008", nil); err != nil {
			fmt.Println("Start pprof on http 0.0.0.0:8008 failed")
			os.Exit(1)
		}
	}()
}

// increase仅对dMac, dIp有效
func generatePacket(sMac, dMac, sIp, dIp string, increase int) []byte {
	buffer := gopacket.NewSerializeBuffer()
	lays := make([]gopacket.SerializableLayer, 0, 5)
	opt := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	srcMac, err := net.ParseMAC(sMac)
	if err != nil {
		fmt.Printf("error srcMac:%v", srcMac)
	}
	dstMac, err := net.ParseMAC(dMac)
	if err != nil {
		fmt.Printf("error dstMac:%v", dstMac)
	}
	dstMac[5] += byte(increase)
	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	srcIp := net.ParseIP(sIp)
	dstIp := net.ParseIP(dIp)
	dstIp[3] += byte(increase)
	ip := layers.IPv4{
		Version: 4, SrcIP: srcIp, DstIP: dstIp,
		Protocol: layers.IPProtocolUDP, TTL: 64,
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(1111),
		DstPort: layers.UDPPort(2222),
	}
	udp.SetNetworkLayerForChecksum(&ip)

	lays = append(lays, &eth)
	lays = append(lays, &ip)
	lays = append(lays, &udp)
	gopacket.SerializeLayers(buffer, opt, lays...)
	pkt := buffer.Bytes()
	fmt.Printf("generate packet(len:%v):\n%s", len(pkt),
		hex.Dump(pkt[:utils.Min(len(pkt), 128)]))

	return pkt
}

func OneQueueRxTx(xdpMode OptXDPMode, ioMode OptIoMode) {
	xp, err := NewXDPPacket(*ifname, OptQueueCount(*queueCount),
		xdpMode, ioMode)
	if err != nil {
		fmt.Printf("new xdp socket failed as %v\n", err)
		return
	}
	defer xp.Close()

	if *statsInterval > 0 {
		go func() {
			oldStats := &XDPStats{}
			stats := xp.GetStats()
			for range time.NewTicker(time.Duration(*statsInterval) * time.Second).C {
				fmt.Println(stats.Minus(oldStats))
				oldStats, stats = stats, xp.GetStats()
			}
		}()
	}

	if *rx == 0 {
		go func() {
			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				_, _, err = xp.ZeroCopyReadPacket()
				if err != nil {
					fmt.Println("========zero read failed as", err)
					time.Sleep(time.Second)
					continue
				}
			}
		}()
	} else if *rx == 1 {
		go func() {
			pkt := generatePacket(*srcMac, *dstMac, *srcIp, *dstIp, 0)
			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				err = xp.WritePacket(pkt)
				if err != nil {
					fmt.Printf("send packet failed as %v\n", err)
					time.Sleep(time.Second)
					continue
				}
			}
		}()
	} else if *rx == 2 {
		go func() {
			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				_, _, err = xp.ZeroCopyReadMultiPackets()
				if err != nil {
					fmt.Println("========zero read multi packets failed as", err)
					time.Sleep(time.Second)
					continue
				}
			}
		}()
	} else if *rx == 3 {
		go func() {
			pkts := make([][]byte, 0, DFLT_BATCH_SIZE)
			pkt := generatePacket(*srcMac, *dstMac, *srcIp, *dstIp, 0)
			for i := 0; i < cap(pkts); i++ {
				pkts = append(pkts, pkt)
			}
			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				n, err := xp.WriteMultiPackets(pkts)
				if err != nil {
					fmt.Printf("send packet failed as %v\n", err)
					time.Sleep(time.Second)
					continue
				}
				if n < len(pkts) {
					fmt.Printf("only send %v packets\n", n)
				}
			}
		}()
	}

	xp.ClearEbpfProg()
}

func MultiQueueRxTx(xdpMode OptXDPMode, ioMode OptIoMode) {
	xp, err := NewXDPMultiQueue(*ifname, OptQueueCount(*queueCount),
		xdpMode, ioMode)
	if err != nil {
		fmt.Printf("new xdp socket failed as %v\n", err)
		return
	}
	defer xp.Close()

	if *statsInterval > 0 {
		go func() {
			oldStats := &XDPStats{}
			stats := xp.GetStats().Stats[0]
			for range time.NewTicker(time.Duration(*statsInterval) * time.Second).C {
				fmt.Println(stats.Minus(oldStats))
				oldStats, stats = stats, xp.GetStats().Stats[0]
			}
		}()
	}

	if *rx == 4 {
		go func() {
			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				_, _, err = xp.ZeroCopyReadPacket()
				if err != nil {
					fmt.Println("========multi queue zero read failed as", err)
					time.Sleep(time.Second)
					continue
				}
			}
		}()
	} else if *rx == 5 {
		pkts := make([][]byte, 0, DFLT_BATCH_SIZE)
		for i := 0; i < cap(pkts); i++ {
			pkt := generatePacket(*srcMac, *dstMac, *srcIp, *dstIp, i)
			pkts = append(pkts, pkt)
		}
		go func() {
			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				n, err := xp.WritePacket(pkts)
				if err != nil {
					fmt.Printf("multi queue send packet failed as %v\n", err)
					time.Sleep(time.Second)
					continue
				}
				if n < len(pkts) {
					fmt.Printf("multi queue only send %v packets\n", n)
				}
			}
		}()
	} else if *rx == 6 {
		xsks := GetXDPSocketFromMultiQueue(xp)
		rxFunc := func(s *XDPPacket, id int) {
			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				_, _, err = s.ZeroCopyReadPacket()
				if err != nil {
					fmt.Printf("========queue %v zero read failed as %v\n", id, err)
					time.Sleep(time.Second)
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
			pkt := generatePacket(*srcMac, *dstMac, *srcIp, *dstIp, id)

			count := getPktCount(*pktCount)
			for i := 0; i < count; i++ {
				err := s.WritePacket(pkt)
				if err != nil {
					fmt.Printf("queue %v send packet failed as %v\n", id, err)
					time.Sleep(time.Second)
					continue
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

func FullDuplexRxTx(xdpMode OptXDPMode, ioMode OptIoMode) {
	xp, err := NewXDPPacket(*ifname, OptQueueCount(*queueCount),
		xdpMode, ioMode)
	if err != nil {
		fmt.Printf("new xdp socket failed as %v\n", err)
		return
	}
	defer xp.Close()

	if *statsInterval > 0 {
		go func() {
			oldStats := &XDPStats{}
			stats := xp.GetStats()
			for range time.NewTicker(time.Duration(*statsInterval) * time.Second).C {
				fmt.Println(stats.Minus(oldStats))
				oldStats, stats = stats, xp.GetStats()
			}
		}()
	}

	go func() {
		count := getPktCount(*pktCount)
		for i := 0; i < count; i++ {
			_, _, err = xp.ZeroCopyReadPacket()
			if err != nil {
				fmt.Println("========zero read failed as", err)
				time.Sleep(time.Second)
				continue
			}
		}
	}()
	go func() {
		pkt := generatePacket(*srcMac, *dstMac, *srcIp, *dstIp, 0)
		count := getPktCount(*pktCount)
		for i := 0; i < count; i++ {
			err = xp.WritePacket(pkt)
			if err != nil {
				fmt.Printf("send packet failed as %v\n", err)
				time.Sleep(time.Second)
				continue
			}
		}
	}()

	xp.ClearEbpfProg()
}

func main() {
	EnableStdoutLog()

	flag.Parse()
	fmt.Printf("option---ifname:%v, rx:%v, queue count:%v, xdp mode:%v, "+
		"I/O mode:%v, stats interval:%v\n",
		*ifname, *rx, *queueCount, *xdpMode, *ioMode, *statsInterval)

	level, err := logging.LogLevel(strings.ToUpper(*logLevel))
	if err != nil {
		fmt.Printf("error log level %v\n", *logLevel)
		return
	}
	logging.SetLevel(level, "")

	if *ifname == "" {
		fmt.Println("must specify interface name")
		return
	}

	if *enableProfile {
		startProfiler()
	}

	if *rx&0x1 == 0x1 {
		if *srcMac == "" || *dstMac == "" || *srcIp == "" || *dstIp == "" {
			fmt.Println("must specify srcMac, dstMac, srcIp, dstIp")
			return
		}
	}

	ok := checkAndMountBpffs()
	if ok == false {
		fmt.Printf("not mount bpffs\n")
		return
	}

	mode := XDP_MODE_DRV
	if *xdpMode != 0 {
		mode = XDP_MODE_SKB
	}
	iom := IO_MODE_BLOCK
	if *ioMode != 0 {
		iom = IO_MODE_NONBLOCK
	}

	if *rx < 4 {
		OneQueueRxTx(mode, iom)
	} else if *rx == 11 {
		FullDuplexRxTx(mode, iom)
	} else {
		MultiQueueRxTx(mode, iom)
	}

	os.Exit(0)
}
