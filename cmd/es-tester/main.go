package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"math/rand"

	logging "github.com/op/go-logging"
	"gitlab.x.lan/yunshan/droplet-libs/logger"
	"gitlab.x.lan/yunshan/droplet-libs/stats"

	"github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/datatype"
	"gitlab.x.lan/yunshan/droplet-libs/grpc"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet/stream/common"
	"gitlab.x.lan/yunshan/droplet/stream/dbwriter"
	"gitlab.x.lan/yunshan/droplet/stream/geo"
)

var log = logging.MustGetLogger("es-tester")

var rate = flag.Int("r", 10000, "send rate per thread")
var threads = flag.Int("t", 1, "handle thread count")
var addr = flag.String("a", "172.20.1.171:30042", "es addr")
var trisolarisAddr = flag.String("i", "172.20.1.128", "trisolaris addr")

func GenData(id int, out queue.QueueWriter) {
	expectRate := *rate
	checkCount := expectRate / 10

	expectDuration := time.Second / 10

	count := 0
	start := time.Now()

	for {
		f := datatype.AcquireTaggedFlow()
		f.FlowPerfStats = &datatype.FlowPerfStats{}
		f.StartTime = time.Duration(time.Now().UnixNano()) - time.Second
		f.EndTime = time.Duration(time.Now().UnixNano())
		f.Duration = time.Second
		f.FlowKey.MACSrc = datatype.MacInt(rand.Intn(100))
		f.FlowKey.MACDst = datatype.MacInt(rand.Intn(100))
		f.EthType = layers.EthernetTypeIPv4
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].CastTypeMap = uint8(rand.Intn(64))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].CastTypeMap = uint8(rand.Intn(64))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].PacketSizeMap = uint16(rand.Intn(128))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].PacketSizeMap = uint16(rand.Intn(128))
		f.VLAN = uint16(rand.Intn(1024))

		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L3EpcID = int32(rand.Intn(64) - 2)
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L3EpcID = int32(rand.Intn(64) - 2)
		f.IPSrc = datatype.IPv4Int(rand.Intn(0xfff))
		f.IPDst = datatype.IPv4Int(rand.Intn(0xfff))

		f.Proto = layers.IPProtocolIPv4
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TTLMap = uint16(rand.Intn(256))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TTLMap = uint16(rand.Intn(256))

		f.PortSrc = uint16(rand.Intn(1000) + 30000)
		f.PortDst = uint16(rand.Intn(1000))

		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TCPFlags = uint8(rand.Intn(128))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TCPFlags = uint8(rand.Intn(128))

		f.FlowPerfStats.L7Protocol = datatype.L7Protocol(rand.Intn(3))

		f.CloseType = datatype.CloseType(rand.Intn(20))
		f.FlowSource = datatype.FlowSource(rand.Intn(3))
		f.FlowID = uint64(rand.Intn(0xffff))
		f.TapType = datatype.TapType(3)
		f.TapPort = uint32(rand.Intn(2560))
		f.VtapId = uint16(rand.Intn(1024))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].IsL2End = true
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].IsL2End = false
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].IsL3End = true
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].IsL3End = false

		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].PacketCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].PacketCount = uint64(rand.Intn(0xffffff))

		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].ByteCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].ByteCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L3ByteCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L3ByteCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].L4ByteCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].L4ByteCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TotalPacketCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TotalPacketCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_SRC].TotalByteCount = uint64(rand.Intn(0xffffff))
		f.FlowMetricsPeers[datatype.FLOW_METRICS_PEER_DST].TotalByteCount = uint64(rand.Intn(0xffffff))

		f.L7PerfStats.RequestCount = uint32(rand.Intn(0xffff))
		f.L7PerfStats.ResponseCount = uint32(rand.Intn(0xffff))
		f.L7PerfStats.ErrClientCount = uint32(rand.Intn(0xffff))
		f.L7PerfStats.ErrServerCount = uint32(rand.Intn(0xffff))
		f.L7PerfStats.ErrTimeout = uint32(rand.Intn(0xffff))

		f.TCPPerfStats.TcpPerfCountsPeers[0].RetransCount = uint32(rand.Intn(0xff))
		f.TCPPerfStats.TcpPerfCountsPeers[1].RetransCount = uint32(rand.Intn(0xff))
		f.TCPPerfStats.TcpPerfCountsPeers[0].ZeroWinCount = uint32(rand.Intn(0xff))
		f.TCPPerfStats.TcpPerfCountsPeers[1].ZeroWinCount = uint32(rand.Intn(0xff))

		out.Put(f)
		count++
		if count%checkCount == 0 {
			actualDuration := time.Since(start)
			if actualDuration < expectDuration {
				time.Sleep(expectDuration - actualDuration)
			}
			start = time.Now()
		}
		if count%(expectRate*5) == 0 {
			t := fmt.Sprintf("%s", time.Now())[:19]
			fmt.Printf("%s id %d, put %d\n", t, id, count)
		}
	}
}

func main() {
	flag.Parse()
	logger.EnableFileLog("/var/log/droplet/es-tester.log")
	logLevel, _ := logging.LogLevel("WARNING")
	logging.SetLevel(logLevel, "")

	stats.RegisterGcMonitor()
	stats.SetRemotes(net.UDPAddr{Port: 20048})
	stats.SetMinInterval(10 * time.Second)

	geo.NewGeoTree()
	fmt.Println("starting")

	platformDataTable := grpc.NewPlatformInfoTable([]net.IP{net.ParseIP(*trisolarisAddr).To4()}, 20035, "stream-tester", 65535, "", nil)
	platformDataTable.Start()

	esWriterQueues := queue.NewOverwriteQueues("es_writer_queues", uint8(*threads), 1024*1024)
	for i := 0; i < *threads; i++ {
		q := esWriterQueues[i]
		esWriter := &dbwriter.ESWriter{
			AppName:   "l4_flow_log",
			DataType:  "flow",
			Addresses: []string{*addr},
			RetentionPolicy: common.RetentionPolicy{
				Interval:   0,
				SplitSize:  common.Interval(86400 * time.Second),
				Slots:      7322,
				AliveSlots: 31,
			},
			OpLoadFactor: 10,
			ESQueue:      q,
		}

		esWriter.Open()
		go esWriter.Run()
		go GenData(i, q)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	for {
		sig := <-signalChannel
		if sig == os.Interrupt {
			break
		}
	}
}
