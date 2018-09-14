package capture

import (
	"io"
	"net"
	"runtime"
	"time"

	"github.com/docker/go-units"
	"github.com/google/gopacket/afpacket"
	. "github.com/google/gopacket/layers"
	"gitlab.x.lan/yunshan/droplet-libs/queue"
	"gitlab.x.lan/yunshan/droplet-libs/stats"
	. "gitlab.x.lan/yunshan/droplet-libs/utils"
	"golang.org/x/net/bpf"
)

func StartCapture(interfaceName string, ip net.IP, isTapInterface bool, outputQueue queue.MultiQueueWriter) (io.Closer, error) {
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		return nil, err
	}
	tPacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(interfaceName),
		afpacket.OptPollTimeout(100*time.Millisecond),
		afpacket.OptBlockSize(1*units.MiB),
		afpacket.OptFrameSize(65536),
		afpacket.OptNumBlocks(1024), // 1GiB in total
	)
	if err != nil {
		log.Warning("AF_PACKET init error", err)
		return nil, err
	}

	instructions := []bpf.Instruction{ // rx only
		bpf.LoadExtension{Num: bpf.ExtType},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(LinuxSLLPacketTypeOutgoing), SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 65535}, // default accept up to 64KB
	}
	rawInstructions, err := bpf.Assemble(instructions)
	if err != nil {
		log.Warning("Assemble bpf failed, bpf won't work")
	}

	if err := tPacket.SetBPF(rawInstructions); err != nil {
		log.Warning("BPF inject failed:", err)
	}

	dataHandler := (&DataHandler{
		ip:    IpToUint32(ip),
		queue: outputQueue,
	}).Init()

	handler := PacketHandler(dataHandler)
	if isTapInterface {
		handler = (*TapHandler)(dataHandler)
	}

	cap := &Capture{
		tPacket: tPacket,
		counter: &PacketCounter{},
		handler: handler,
	}
	cap.Start()
	stats.RegisterCountable("capture", cap)
	instance := io.Closer(cap)
	runtime.SetFinalizer(instance, func(c io.Closer) { c.Close() })
	return instance, nil
}
